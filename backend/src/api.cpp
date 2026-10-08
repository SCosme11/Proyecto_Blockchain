#include "api.h"

#define CPPHTTPLIB_THREAD_POOL_COUNT 32
#include <httplib.h>

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <thread>
#include <type_traits>

#include "crypto.h"

using nlohmann::json;

namespace {

// The guide fixes the valid node-count range at 10-20; it is not meant to be configurable.
constexpr int kMinNodes = 10;
constexpr int kMaxNodes = 20;
constexpr int kMinDifficulty = 1;
constexpr int kMaxDifficulty = 6;  // hex zero digits

struct HttpError : std::runtime_error {
    int status;
    json extra;
    HttpError(int s, const std::string& m, json e = nullptr) : std::runtime_error(m), status(s), extra(std::move(e)) {}
};

void send(httplib::Response& res, const json& j, int status = 200) {
    res.status = status;
    res.set_content(j.dump(), "application/json");
}

json body(const httplib::Request& req) {
    json j;
    try {
        j = json::parse(req.body);
    } catch (...) {
        throw HttpError(400, "request body must be valid JSON");
    }
    // `[]`, `5` or `"x"` parse fine but would make every later `.value()` throw.
    if (!j.is_object()) throw HttpError(400, "request body must be a JSON object");
    return j;
}

// Strict type check: nlohmann's get<int>() silently accepts floats/bools, which would let
// `{"nodes": 10.7}` or `{"nodes": true}` through as valid integers.
template <typename T>
void require_type(const json& v, const char* key) {
    bool ok = true;
    if constexpr (std::is_same_v<T, bool>) ok = v.is_boolean();
    else if constexpr (std::is_integral_v<T>) ok = v.is_number_integer();
    else if constexpr (std::is_floating_point_v<T>) ok = v.is_number();
    else if constexpr (std::is_same_v<T, std::string>) ok = v.is_string();
    if (!ok) throw HttpError(400, std::string("invalid type for field: ") + key);
}

template <typename T>
T field(const json& j, const char* key) {
    if (!j.contains(key) || j[key].is_null()) throw HttpError(400, std::string("missing field: ") + key);
    require_type<T>(j[key], key);
    try {
        return j[key].get<T>();
    } catch (...) {
        throw HttpError(400, std::string("invalid type for field: ") + key);
    }
}

// Optional field: absent or null -> `def`; present with the wrong type -> 400 (never a 500).
template <typename T>
T opt(const json& j, const char* key, T def) {
    if (!j.contains(key) || j[key].is_null()) return def;
    return field<T>(j, key);
}

// Path ids come from `(\d+)`, so they can still overflow int; report that as a plain 404.
int64_t path_i64(const std::string& digits) {
    try {
        return std::stoll(digits);
    } catch (...) {
        throw HttpError(404, "id out of range");
    }
}

int path_id(const std::string& digits) {
    try {
        return std::stoi(digits);
    } catch (...) {
        throw HttpError(404, "id out of range");
    }
}

// Wraps a handler so exceptions become JSON errors.
template <typename F>
httplib::Server::Handler wrap(F fn) {
    return [fn](const httplib::Request& req, httplib::Response& res) {
        try {
            fn(req, res);
        } catch (const HttpError& e) {
            json j = {{"error", e.what()}};
            if (!e.extra.is_null()) j["details"] = e.extra;
            send(res, j, e.status);
        } catch (const DbError& e) {
            send(res, {{"error", std::string("database: ") + e.what()}}, 500);
        } catch (const json::exception& e) {
            // A malformed/mistyped client payload that slipped past a handler's own checks.
            send(res, {{"error", std::string("malformed request: ") + e.what()}}, 400);
        } catch (const std::out_of_range&) {
            send(res, {{"error", "numeric value out of range"}}, 400);
        } catch (const std::invalid_argument&) {
            send(res, {{"error", "invalid numeric value"}}, 400);
        } catch (const std::exception& e) {
            send(res, {{"error", e.what()}}, 500);
        }
    };
}

json parse_json_col(const std::string& s) {
    try {
        return json::parse(s);
    } catch (...) {
        return nullptr;
    }
}

const char* kWorkSelect =
    "SELECT w.id, w.agent_name, w.artifact_type, w.filename, w.size_bytes, w.work_hash, w.metrics::text AS metrics, "
    "w.score::text AS score, w.category, w.reasons::text AS reasons, w.rules_version, w.rules_hash, w.status, "
    "to_char(w.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at, "
    "t.tx_id, t.decision, t.block_height, au.name AS auditor_name "
    "FROM work_items w LEFT JOIN transactions t ON t.work_item_id = w.id "
    "LEFT JOIN auditors au ON au.id = t.auditor_id ";

json work_json(const Result& r, int i) {
    auto opt = [&](const char* c) { return r.is_null(i, c) ? json(nullptr) : json(r.str(i, c)); };
    return {{"id", r.i64(i, "id")},
            {"agent_name", r.str(i, "agent_name")},
            {"artifact_type", r.str(i, "artifact_type")},
            {"filename", r.str(i, "filename")},
            {"size_bytes", r.i64(i, "size_bytes")},
            {"work_hash", r.str(i, "work_hash")},
            {"metrics", parse_json_col(r.str(i, "metrics"))},
            {"score", r.str(i, "score")},
            {"category", r.str(i, "category")},
            {"reasons", parse_json_col(r.str(i, "reasons"))},
            {"rules_version", r.str(i, "rules_version")},
            {"rules_hash", r.str(i, "rules_hash")},
            {"status", r.str(i, "status")},
            {"created_at", r.str(i, "created_at")},
            {"tx_id", opt("tx_id")},
            {"decision", opt("decision")},
            {"block_height", r.is_null(i, "block_height") ? json(nullptr) : json(r.i64(i, "block_height"))},
            {"auditor_name", opt("auditor_name")}};
}

const char* kTxDetailSelect =
    "SELECT t.tx_id, t.work_item_id, t.canonical, t.signature, t.decision, t.comment, t.timestamp_ms, t.status, "
    "t.block_height, t.block_index, a.id AS auditor_id, a.name AS auditor_name, a.fingerprint, a.public_key_spki, "
    "w.agent_name, w.artifact_type, w.filename, w.work_hash, w.score::text AS score "
    "FROM transactions t JOIN auditors a ON a.id = t.auditor_id JOIN work_items w ON w.id = t.work_item_id ";

json tx_json(const Result& r, int i, bool verify) {
    json j = {{"tx_id", r.str(i, "tx_id")},
              {"work_item_id", r.i64(i, "work_item_id")},
              {"canonical", r.str(i, "canonical")},
              {"signature", r.str(i, "signature")},
              {"decision", r.str(i, "decision")},
              {"comment", r.str(i, "comment")},
              {"timestamp_ms", r.i64(i, "timestamp_ms")},
              {"status", r.str(i, "status")},
              {"block_height", r.is_null(i, "block_height") ? json(nullptr) : json(r.i64(i, "block_height"))},
              {"auditor", {{"id", r.i64(i, "auditor_id")},
                           {"name", r.str(i, "auditor_name")},
                           {"fingerprint", r.str(i, "fingerprint")}}},
              {"work", {{"agent_name", r.str(i, "agent_name")},
                        {"artifact_type", r.str(i, "artifact_type")},
                        {"filename", r.str(i, "filename")},
                        {"work_hash", r.str(i, "work_hash")},
                        {"score", r.str(i, "score")}}}};
    if (verify) {
        j["signature_valid"] =
            crypto::verify_p256(r.str(i, "public_key_spki"), r.str(i, "canonical"), r.str(i, "signature"));
        j["tx_id_valid"] = chain::tx_id(r.str(i, "canonical"), r.str(i, "signature")) == r.str(i, "tx_id");
    }
    return j;
}

json block_json(const BlockRow& b) {
    const auto& h = b.header;
    return {{"height", h.height},
            {"hash", b.hash},
            {"prev_hash", h.prev_hash},
            {"merkle_root", h.merkle_root},
            {"timestamp_ms", h.timestamp_ms},
            {"mode", b.mode},
            {"nonce", h.nonce},
            {"difficulty_hex_zeros", h.difficulty_hex_zeros},
            {"proposer", h.proposer},
            {"proposer_signature", b.proposer_signature},
            {"quorum_stake", b.quorum_stake},
            {"total_stake", b.total_stake},
            {"tx_count", b.tx_count},
            {"header_preimage", chain::canonical_header(h)}};
}

}  // namespace

void register_routes(httplib::Server& svr, AppContext& ctx) {
    Db& db = ctx.db;

    svr.set_default_headers({{"Access-Control-Allow-Origin", "*"},
                             {"Access-Control-Allow-Headers", "Content-Type"},
                             {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"}});
    svr.Options(R"(/api/.*)", [](const httplib::Request&, httplib::Response& res) { res.status = 204; });

    // ---------------- meta ----------------
    svr.Get("/api/health", wrap([&](const httplib::Request&, httplib::Response& res) {
                db.exec("SELECT 1");
                send(res, {{"ok", true}});
            }));

    svr.Get("/api/config", wrap([&](const httplib::Request&, httplib::Response& res) {
                send(res, {{"rules_version", ctx.rules.version()},
                           {"rules_hash", ctx.rules.hash()},
                           {"rules", ctx.rules.rules()},
                           {"tx_version", chain::kTxVersion},
                           {"initial_stake", ctx.initial_stake},
                           {"max_tx_per_block", ctx.max_tx_per_block},
                           {"min_nodes", kMinNodes},
                           {"max_nodes", kMaxNodes},
                           {"min_difficulty_hex_zeros", kMinDifficulty},
                           {"max_difficulty_hex_zeros", kMaxDifficulty},
                           {"quorum_numerator", 2},
                           {"quorum_denominator", 3},
                           {"block_reward", ctx.block_reward},
                           {"pos_reward", ctx.pos_reward},
                           {"tx_value", ctx.tx_value},
                           {"reward_confirmations", 6},
                           {"timestamp_skew_ms", ctx.timestamp_skew_ms}});
            }));

    svr.Get("/api/stats", wrap([&](const httplib::Request&, httplib::Response& res) {
                Result r = db.exec(
                    "SELECT "
                    "(SELECT count(*) FROM work_items) AS work_total,"
                    "(SELECT count(*) FROM work_items WHERE category='LOW') AS low,"
                    "(SELECT count(*) FROM work_items WHERE category='MEDIUM') AS medium,"
                    "(SELECT count(*) FROM work_items WHERE category='HIGH') AS high,"
                    "(SELECT count(*) FROM work_items WHERE status='pending_review') AS pending_review,"
                    "(SELECT count(*) FROM transactions WHERE status='mempool') AS mempool,"
                    "(SELECT count(*) FROM transactions WHERE status='confirmed') AS confirmed,"
                    "(SELECT max(height) FROM blocks) AS height,"
                    "(SELECT count(*) FROM auditors) AS auditors,"
                    "(SELECT count(*) FROM nodes) AS nodes");
                json j;
                for (const char* k : {"work_total", "low", "medium", "high", "pending_review", "mempool", "confirmed",
                                      "height", "auditors", "nodes"})
                    j[k] = r.i64(0, k);
                j["consensus_running"] = ctx.consensus.running();
                j["consensus_mode"] = ctx.consensus.running() ? ctx.consensus.snapshot().value("mode", "") : "";
                j["total_stake"] = ctx.ledger.total_active_stake();
                send(res, j);
            }));

    // ---------------- agent work ----------------
    svr.Post("/api/work", wrap([&](const httplib::Request& req, httplib::Response& res) {
                 json b = body(req);
                 std::string agent = field<std::string>(b, "agent_name");
                 std::string type = field<std::string>(b, "artifact_type");
                 std::string filename = opt<std::string>(b, "filename", "output.txt");
                 if (filename.empty() || filename.size() > 255) throw HttpError(400, "filename must be 1-255 chars");
                 if (agent.empty() || agent.size() > 100) throw HttpError(400, "agent_name must be 1-100 chars");
                 if (!ctx.rules.valid_artifact_type(type)) throw HttpError(400, "unknown artifact_type: " + type);

                 crypto::Bytes content;
                 if (b.contains("content_b64") && b["content_b64"].is_string()) {
                     if (!crypto::base64_decode(b["content_b64"].get<std::string>(), content))
                         throw HttpError(400, "content_b64 is not valid base64");
                 } else if (b.contains("content_text") && b["content_text"].is_string()) {
                     std::string t = b["content_text"].get<std::string>();
                     content.assign(t.begin(), t.end());
                 } else {
                     throw HttpError(400, "provide content_b64 or content_text");
                 }
                 if (content.empty()) throw HttpError(400, "artifact content is empty");

                 json mj = b.contains("metrics") && !b["metrics"].is_null() ? b["metrics"] : json::object();
                 if (!mj.is_object()) throw HttpError(400, "metrics must be an object");
                 Metrics m;
                 m.artifact_type = type;
                 m.self_confidence = opt<double>(mj, "self_confidence", 0.0);
                 m.tests_passed_ratio = opt<double>(mj, "tests_passed_ratio", 0.0);
                 m.lines_changed = opt<int>(mj, "lines_changed", 0);
                 m.has_external_side_effects = opt<bool>(mj, "has_external_side_effects", false);
                 if (m.self_confidence < 0 || m.self_confidence > 1)
                     throw HttpError(400, "metrics.self_confidence must be in [0,1]");
                 if (m.tests_passed_ratio < 0 || m.tests_passed_ratio > 1)
                     throw HttpError(400, "metrics.tests_passed_ratio must be in [0,1]");
                 if (m.lines_changed < 0) throw HttpError(400, "metrics.lines_changed must be >= 0");
                 json stored_metrics = {{"self_confidence", m.self_confidence},
                                        {"tests_passed_ratio", m.tests_passed_ratio},
                                        {"lines_changed", m.lines_changed},
                                        {"has_external_side_effects", m.has_external_side_effects}};

                 Classification c = ctx.rules.classify(m);
                 std::string status = c.category == "LOW"      ? "rework_required"
                                      : c.category == "HIGH"   ? "auto_accepted"
                                                               : "pending_review";
                 std::string work_hash = crypto::sha256_hex(content);

                 auto l = db.lock();
                 Result ins = db.exec(
                     "INSERT INTO work_items (agent_name, artifact_type, filename, content, size_bytes, work_hash, "
                     "metrics, score, category, reasons, rules_version, rules_hash, status) "
                     "VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::numeric,$9,$10::jsonb,$11,$12,$13) RETURNING id",
                     {agent, type, filename, Param::bytes(content), static_cast<int64_t>(content.size()), work_hash,
                      stored_metrics.dump(), c.score, c.category, json(c.reasons).dump(), ctx.rules.version(),
                      ctx.rules.hash(), status});
                 int64_t id = ins.i64(0, "id");
                 Result r = db.exec(std::string(kWorkSelect) + "WHERE w.id = $1", {id});
                 json j = work_json(r, 0);
                 j["breakdown"] = c.breakdown;
                 send(res, j, 201);
             }));

    svr.Get("/api/work", wrap([&](const httplib::Request& req, httplib::Response& res) {
                std::string cat = req.get_param_value("category");
                Result r = cat.empty()
                               ? db.exec(std::string(kWorkSelect) + "ORDER BY w.id DESC LIMIT 200")
                               : db.exec(std::string(kWorkSelect) + "WHERE w.category = $1 ORDER BY w.id DESC LIMIT 200",
                                         {cat});
                json arr = json::array();
                for (int i = 0; i < r.rows(); ++i) arr.push_back(work_json(r, i));
                send(res, arr);
            }));

    svr.Get(R"(/api/work/(\d+)/content)", wrap([&](const httplib::Request& req, httplib::Response& res) {
                Result r = db.exec("SELECT filename, work_hash, content FROM work_items WHERE id = $1",
                                   {path_i64(req.matches[1])});
                if (r.rows() == 0) throw HttpError(404, "work item not found");
                send(res, {{"filename", r.str(0, "filename")},
                           {"work_hash", r.str(0, "work_hash")},
                           {"content_b64", crypto::base64_encode(r.bytea(0, "content"))}});
            }));

    svr.Get("/api/review-queue", wrap([&](const httplib::Request&, httplib::Response& res) {
                Result r = db.exec(std::string(kWorkSelect) +
                                   "WHERE w.category = 'MEDIUM' AND w.status = 'pending_review' ORDER BY w.id");
                json arr = json::array();
                for (int i = 0; i < r.rows(); ++i) arr.push_back(work_json(r, i));
                send(res, arr);
            }));

    // ---------------- auditors ----------------
    svr.Post("/api/auditors", wrap([&](const httplib::Request& req, httplib::Response& res) {
                 json b = body(req);
                 std::string name = field<std::string>(b, "name");
                 std::string spki = field<std::string>(b, "public_key_spki");
                 if (name.empty() || name.size() > 100) throw HttpError(400, "name must be 1-100 chars");
                 if (!crypto::is_p256_spki(spki)) throw HttpError(400, "public_key_spki must be an ECDSA P-256 key");
                 std::string fpr = crypto::fingerprint(spki);
                 auto l = db.lock();
                 Result r = db.exec(
                     "INSERT INTO auditors (name, public_key_spki, fingerprint) VALUES ($1,$2,$3) "
                     "ON CONFLICT (public_key_spki) DO UPDATE SET name = auditors.name "
                     "RETURNING id, name, fingerprint",
                     {name, spki, fpr});
                 send(res, {{"id", r.i64(0, "id")}, {"name", r.str(0, "name")}, {"fingerprint", r.str(0, "fingerprint")}},
                      201);
             }));

    svr.Get("/api/auditors", wrap([&](const httplib::Request&, httplib::Response& res) {
                Result r = db.exec(
                    "SELECT a.id, a.name, a.fingerprint, count(t.tx_id) AS signed "
                    "FROM auditors a LEFT JOIN transactions t ON t.auditor_id = a.id GROUP BY a.id ORDER BY a.id");
                json arr = json::array();
                for (int i = 0; i < r.rows(); ++i)
                    arr.push_back({{"id", r.i64(i, "id")},
                                   {"name", r.str(i, "name")},
                                   {"fingerprint", r.str(i, "fingerprint")},
                                   {"signed", r.i64(i, "signed")}});
                send(res, arr);
            }));

    // ---------------- transactions ----------------
    svr.Post("/api/transactions", wrap([&](const httplib::Request& req, httplib::Response& res) {
                 json b = body(req);
                 int64_t work_id = field<int64_t>(b, "work_item_id");
                 int64_t auditor_id = field<int64_t>(b, "auditor_id");
                 std::string decision = field<std::string>(b, "decision");
                 std::string comment = opt<std::string>(b, "comment", "");
                 int64_t ts = field<int64_t>(b, "timestamp_ms");
                 std::string sig = field<std::string>(b, "signature");

                 if (decision != "APPROVED" && decision != "REJECTED")
                     throw HttpError(400, "decision must be APPROVED or REJECTED");
                 if (std::llabs(now_ms() - ts) > ctx.timestamp_skew_ms)
                     throw HttpError(400, "timestamp outside allowed clock skew");

                 auto l = db.lock();
                 Result w = db.exec(
                     "SELECT work_hash, artifact_type, score::text AS score, rules_hash, category, status "
                     "FROM work_items WHERE id = $1",
                     {work_id});
                 if (w.rows() == 0) throw HttpError(404, "work item not found");
                 if (w.str(0, "category") != "MEDIUM")
                     throw HttpError(400, "only MEDIUM-confidence work requires a human signature");
                 if (w.str(0, "status") != "pending_review") throw HttpError(409, "work item already signed");

                 Result a = db.exec("SELECT public_key_spki, fingerprint FROM auditors WHERE id = $1", {auditor_id});
                 if (a.rows() == 0) throw HttpError(404, "auditor not registered");

                 chain::TxFields f;
                 f.work_item_id = work_id;
                 f.work_hash = w.str(0, "work_hash");
                 f.artifact_type = w.str(0, "artifact_type");
                 f.score = w.str(0, "score");
                 f.rules_hash = w.str(0, "rules_hash");
                 f.decision = decision;
                 f.comment_hash = crypto::sha256_hex(comment);
                 f.auditor_fpr = a.str(0, "fingerprint");
                 f.timestamp_ms = ts;
                 std::string canonical = chain::canonical(f);

                 // The server rebuilds the payload from its own records; the client's copy must match,
                 // which proves the auditor saw (and signed) the same facts.
                 if (b.contains("canonical") && b["canonical"].is_string() && b["canonical"] != canonical)
                     throw HttpError(400, "canonical mismatch",
                                     {{"expected", canonical}, {"received", b["canonical"]}});
                 if (!crypto::verify_p256(a.str(0, "public_key_spki"), canonical, sig))
                     throw HttpError(400, "bad signature");

                 std::string id = chain::tx_id(canonical, sig);
                 Db::Transaction t(db);
                 db.exec(
                     "INSERT INTO transactions (tx_id, work_item_id, auditor_id, canonical, signature, decision, "
                     "comment, timestamp_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
                     {id, work_id, auditor_id, canonical, sig, decision, comment, ts});
                 db.exec("UPDATE work_items SET status = 'signed' WHERE id = $1", {work_id});
                 t.commit();

                 Result r = db.exec(std::string(kTxDetailSelect) + "WHERE t.tx_id = $1", {id});
                 send(res, tx_json(r, 0, true), 201);
             }));

    svr.Get("/api/mempool", wrap([&](const httplib::Request&, httplib::Response& res) {
                Result r = db.exec(std::string(kTxDetailSelect) + "WHERE t.status = 'mempool' ORDER BY t.timestamp_ms");
                json arr = json::array();
                for (int i = 0; i < r.rows(); ++i) arr.push_back(tx_json(r, i, true));
                send(res, arr);
            }));

    svr.Get(R"(/api/transactions/([0-9a-f]{64}))", wrap([&](const httplib::Request& req, httplib::Response& res) {
                Result r = db.exec(std::string(kTxDetailSelect) + "WHERE t.tx_id = $1", {std::string(req.matches[1])});
                if (r.rows() == 0) throw HttpError(404, "transaction not found");
                send(res, tx_json(r, 0, true));
            }));

    // ---------------- nodes & consensus ----------------
    auto nodes_json = [&]() {
        Result r = db.exec("SELECT id, name, public_key_spki, stake, active, slashed, dishonest, blocks_proposed, "
                           "balance, locked FROM nodes ORDER BY name");
        json arr = json::array();
        for (int i = 0; i < r.rows(); ++i)
            arr.push_back({{"id", r.i64(i, "id")},
                           {"name", r.str(i, "name")},
                           {"fingerprint", crypto::fingerprint(r.str(i, "public_key_spki"))},
                           {"stake", r.i64(i, "stake")},
                           {"locked", r.i64(i, "locked")},
                           {"balance", r.i64(i, "balance")},
                           {"active", r.str(i, "active") == "t"},
                           {"slashed", r.str(i, "slashed") == "t"},
                           {"dishonest", r.str(i, "dishonest") == "t"},
                           {"blocks_proposed", r.i64(i, "blocks_proposed")}});
        return arr;
    };

    svr.Get("/api/nodes",
            wrap([nodes_json](const httplib::Request&, httplib::Response& res) { send(res, nodes_json()); }));

    // "El número de nodos N se elige en la interfaz y debe cumplir 10 <= N <= 20".
    svr.Post("/api/nodes", wrap([&, nodes_json](const httplib::Request& req, httplib::Response& res) {
                 json b = body(req);
                 int n = opt<int>(b, "count", kMinNodes);
                 int64_t stake = opt<int64_t>(b, "stake", ctx.initial_stake);
                 if (n < kMinNodes || n > kMaxNodes)
                     throw HttpError(400, "count must be between " + std::to_string(kMinNodes) + " and " +
                                              std::to_string(kMaxNodes));
                 if (stake < 0) throw HttpError(400, "stake must be >= 0");
                 ctx.ledger.ensure_nodes(n, stake);
                 send(res, nodes_json(), 201);
             }));

    svr.Post(R"(/api/nodes/(\d+)/stake)", wrap([&, nodes_json](const httplib::Request& req, httplib::Response& res) {
                 int id = path_id(req.matches[1]);
                 int64_t delta = field<int64_t>(body(req), "delta");
                 std::string err;
                 if (!ctx.ledger.adjust_stake(id, delta, err)) {
                     throw HttpError(err == "node not found" ? 404 : 409, err);
                 }
                 send(res, nodes_json());
             }));

    svr.Post(R"(/api/nodes/(\d+)/dishonest)", wrap([&, nodes_json](const httplib::Request& req, httplib::Response& res) {
                 int id = path_id(req.matches[1]);
                 bool dishonest = opt<bool>(body(req), "dishonest", true);
                 std::string err;
                 if (!ctx.ledger.set_dishonest(id, dishonest, err)) throw HttpError(404, err);
                 send(res, nodes_json());
             }));

    svr.Get("/api/nodes/sync", wrap([&](const httplib::Request&, httplib::Response& res) {
                BlockRow tip = ctx.ledger.tip();
                send(res, ctx.network.status(tip.header.height, tip.hash));
            }));

    // A peer (here: the reference chain, or a deliberately bad one) sends a whole chain to one
    // node; the node validates every block and applies the longest-valid-chain rule.
    // kind: valid (full reference chain) | shorter (reference minus its last block) |
    //       tampered (full length, one intermediate block altered)
    auto deliver_chain = [&ctx](int id, const std::string& kind) {
        std::vector<ChainBlock> candidate = ctx.ledger.export_chain();
        if (kind == "shorter") {
            if (candidate.size() < 2) throw HttpError(409, "seal at least one block first");
            candidate.pop_back();
        } else if (kind == "tampered") {
            if (candidate.size() < 3) throw HttpError(409, "seal at least two blocks first (need an intermediate block)");
            std::string& h = candidate[candidate.size() / 2].block.hash;
            h[0] = (h[0] == 'f') ? '0' : 'f';
        } else if (kind != "valid") {
            throw HttpError(400, "kind must be valid | shorter | tampered");
        }
        auto out = ctx.network.receive_chain(ctx.ledger, id, candidate, ctx.ledger.node_keys());
        ctx.ledger.log_event(out.accepted ? "chain_accepted" : "chain_rejected",
                             "Nodo #" + std::to_string(id) + (out.accepted ? " adoptó" : " rechazó") + " una cadena recibida (" +
                                 kind + "): " + out.reason);
        return out;
    };

    svr.Post(R"(/api/nodes/(\d+)/resync)", wrap([&ctx, deliver_chain](const httplib::Request& req, httplib::Response& res) {
                 int id = path_id(req.matches[1]);
                 auto out = deliver_chain(id, "valid");
                 if (!out.accepted && out.reason == "node has no chain copy yet") throw HttpError(404, out.reason);
                 BlockRow tip = ctx.ledger.tip();
                 send(res, {{"accepted", out.accepted},
                            {"reason", out.reason},
                            {"nodes", ctx.network.status(tip.header.height, tip.hash)}});
             }));

    svr.Post(R"(/api/nodes/(\d+)/receive-chain)",
             wrap([&ctx, deliver_chain](const httplib::Request& req, httplib::Response& res) {
                 int id = path_id(req.matches[1]);
                 std::string kind = opt<std::string>(body(req), "kind", "valid");
                 auto out = deliver_chain(id, kind);
                 if (!out.accepted && out.reason == "node has no chain copy yet") throw HttpError(404, out.reason);
                 BlockRow tip = ctx.ledger.tip();
                 send(res, {{"accepted", out.accepted},
                            {"reason", out.reason},
                            {"nodes", ctx.network.status(tip.header.height, tip.hash)}});
             }));

    svr.Get("/api/rewards", wrap([&](const httplib::Request&, httplib::Response& res) {
                int64_t tip_h = ctx.ledger.tip_height();
                json arr = json::array();
                for (const auto& w : ctx.ledger.rewards())
                    arr.push_back({{"height", w.height},
                                   {"miner", w.miner_name},
                                   {"confirmed", w.confirmed},
                                   {"amount", w.amount},
                                   {"confirmations", std::max<int64_t>(0, tip_h - w.height)},
                                   {"remaining_confirmations", std::max<int64_t>(0, w.height + 6 - tip_h)}});
                send(res, arr);
            }));

    // Asking for a reward before it has matured is refused with the exact number of missing
    // confirmations (and written to the log); once matured it is already credited.
    svr.Post(R"(/api/rewards/(\d+)/claim)", wrap([&](const httplib::Request& req, httplib::Response& res) {
                 int64_t height = path_i64(req.matches[1]);
                 auto w = ctx.ledger.reward(height);
                 if (!w) throw HttpError(404, "el bloque #" + std::to_string(height) + " no tiene recompensa PoW");
                 int64_t tip_h = ctx.ledger.tip_height();
                 if (!w->confirmed) {
                     int64_t missing = std::max<int64_t>(1, w->height + 6 - tip_h);
                     std::string msg = "recompensa pendiente: faltan " + std::to_string(missing) + " confirmaciones";
                     ctx.ledger.log_event("reward_claim_rejected", "Reclamo rechazado del bloque #" + std::to_string(height) + ": " + msg);
                     throw HttpError(409, msg);
                 }
                 send(res, {{"height", w->height}, {"miner", w->miner_name}, {"amount", w->amount}, {"credited", true}});
             }));

    // Unified "bitácora": bloque minado/sellado, ronda rechazada, castigo (slashing) y
    // recompensa acreditada, mezclados y ordenados del más reciente al más antiguo -- lo que
    // pide la sección 6 de la guía ("Registren eventos... en una bitácora visible").
    svr.Get("/api/events", wrap([&](const httplib::Request& req, httplib::Response& res) {
                int limit = 50;
                try {
                    if (!req.get_param_value("limit").empty()) limit = std::stoi(req.get_param_value("limit"));
                } catch (...) {
                }
                limit = std::max(1, std::min(limit, 500));
                auto ts_expr = [](const char* col) {
                    return std::string("to_char(") + col + " AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')";
                };

                std::vector<json> events;

                Result rounds = db.exec(
                    std::string("SELECT mode, attempt, proposer, block_height, outcome, ") + ts_expr("created_at") +
                    " AS ts FROM consensus_rounds ORDER BY id DESC LIMIT 200");
                for (int i = 0; i < rounds.rows(); ++i) {
                    std::string outcome = rounds.str(i, "outcome");
                    std::string mode = rounds.str(i, "mode");
                    std::string proposer = rounds.is_null(i, "proposer") ? "?" : rounds.str(i, "proposer");
                    std::string msg;
                    if (outcome == "sealed") {
                        msg = (mode == "pow" ? "Bloque minado (PoW) #" : "Bloque sellado (PoS) #") +
                              rounds.str(i, "block_height") + " por " + proposer;
                    } else {
                        msg = "Ronda " + mode + " rechazada (" + outcome + "), proponente " + proposer;
                    }
                    events.push_back({{"type", outcome == "sealed" ? "block" : "round_rejected"},
                                      {"message", msg},
                                      {"created_at", rounds.str(i, "ts")}});
                }

                Result slashes = db.exec(
                    std::string("SELECT n.name, se.reason, se.stake_before, se.stake_after, se.block_height, ") +
                    ts_expr("se.created_at") +
                    " AS ts FROM slashing_events se JOIN nodes n ON n.id = se.validator_id ORDER BY se.id DESC LIMIT 200");
                for (int i = 0; i < slashes.rows(); ++i) {
                    std::string msg = "Castigo a " + slashes.str(i, "name") + " (" + slashes.str(i, "reason") +
                                      "): stake " + slashes.str(i, "stake_before") + " -> " +
                                      slashes.str(i, "stake_after");
                    events.push_back({{"type", "slash"}, {"message", msg}, {"created_at", slashes.str(i, "ts")}});
                }

                Result rewards = db.exec(
                    std::string("SELECT pr.height, n.name, ") + ts_expr("pr.confirmed_at") +
                    " AS ts FROM pow_rewards pr JOIN nodes n ON n.id = pr.miner_id "
                    "WHERE pr.confirmed AND pr.confirmed_at IS NOT NULL ORDER BY pr.confirmed_at DESC LIMIT 200");
                for (int i = 0; i < rewards.rows(); ++i) {
                    std::string msg = "Recompensa acreditada a " + rewards.str(i, "name") + " por el bloque #" +
                                      rewards.str(i, "height");
                    events.push_back({{"type", "reward_confirmed"}, {"message", msg}, {"created_at", rewards.str(i, "ts")}});
                }

                Result logs = db.exec(std::string("SELECT type, message, ") + ts_expr("created_at") +
                                      " AS ts FROM event_log ORDER BY id DESC LIMIT 200");
                for (int i = 0; i < logs.rows(); ++i)
                    events.push_back({{"type", logs.str(i, "type")},
                                      {"message", logs.str(i, "message")},
                                      {"created_at", logs.str(i, "ts")}});

                std::sort(events.begin(), events.end(), [](const json& a, const json& b) {
                    return a["created_at"].get<std::string>() > b["created_at"].get<std::string>();
                });
                if (static_cast<int>(events.size()) > limit) events.resize(limit);
                send(res, json(events));
            }));

    svr.Post("/api/consensus/propose", wrap([&](const httplib::Request& req, httplib::Response& res) {
                 json b = body(req);
                 ConsensusParams p;
                 p.mode = opt<std::string>(b, "mode", "pos");
                 if (p.mode != "pow" && p.mode != "pos") throw HttpError(400, "mode must be 'pow' or 'pos'");
                 p.node_count = opt<int>(b, "nodes", kMinNodes);
                 if (p.node_count < kMinNodes || p.node_count > kMaxNodes)
                     throw HttpError(400, "nodes must be between " + std::to_string(kMinNodes) + " and " +
                                              std::to_string(kMaxNodes));
                 p.difficulty_hex_zeros = opt<int>(b, "difficulty_hex_zeros", 4);
                 if (p.mode == "pow" &&
                     (p.difficulty_hex_zeros < kMinDifficulty || p.difficulty_hex_zeros > kMaxDifficulty))
                     throw HttpError(400, "difficulty_hex_zeros must be between " + std::to_string(kMinDifficulty) +
                                              " and " + std::to_string(kMaxDifficulty));
                 p.abstain_count = opt<int>(b, "abstain", 0);
                 if (p.abstain_count < 0 || p.abstain_count > p.node_count)
                     throw HttpError(400, "abstain must be 0-" + std::to_string(p.node_count));
                 p.punishment_rule = opt<std::string>(b, "punishment_rule", "A");
                 if (p.mode == "pos" && p.punishment_rule != "A" && p.punishment_rule != "B")
                     throw HttpError(400, "punishment_rule must be 'A' or 'B'");
                 p.alpha = opt<double>(b, "alpha", 1.0);
                 if (p.mode == "pos" && p.punishment_rule == "B" && (p.alpha <= 0 || p.alpha > 1))
                     throw HttpError(400, "alpha must satisfy 0 < alpha <= 1");
                 p.validators = opt<int>(b, "validators", 0);
                 if (p.validators < 0 || p.validators > p.node_count)
                     throw HttpError(400, "validators must be 0-" + std::to_string(p.node_count) + " (0 = all with stake)");
                 p.bet_pct = opt<int>(b, "bet_pct", 100);
                 if (p.bet_pct < 1 || p.bet_pct > 100) throw HttpError(400, "bet_pct must be between 1 and 100");
                 p.vote_window_ms = opt<int>(b, "vote_window_ms", 0);
                 if (p.vote_window_ms < 0 || p.vote_window_ms > 30000)
                     throw HttpError(400, "vote_window_ms must be between 0 and 30000");
                 if (b.contains("seed") && !b["seed"].is_null()) {
                     p.seed = static_cast<uint64_t>(field<int64_t>(b, "seed"));
                     p.has_seed = true;
                 }
                 if (b.contains("bets") && !b["bets"].is_null()) {
                     if (!b["bets"].is_object()) throw HttpError(400, "bets must be an object {node-name: amount}");
                     for (auto it = b["bets"].begin(); it != b["bets"].end(); ++it) {
                         if (!it.value().is_number_integer()) throw HttpError(400, "bet of '" + it.key() + "' must be an integer");
                         p.bets[it.key()] = it.value().get<int64_t>();
                     }
                 }
                 std::string err;
                 int status = 409;
                 if (!ctx.consensus.start(p, err, status)) throw HttpError(status, err);
                 send(res, ctx.consensus.snapshot(), 202);
             }));

    // External vote on behalf of a validator while a PoS round is in VOTACION. Anything that
    // is not a legitimate, first vote of a validator of this round is refused with a clear reason.
    svr.Post("/api/consensus/vote", wrap([&](const httplib::Request& req, httplib::Response& res) {
                 json b = body(req);
                 std::string validator = field<std::string>(b, "validator");
                 std::string vote = opt<std::string>(b, "vote", "yes");
                 std::string message;
                 int status = 200;
                 if (!ctx.consensus.submit_vote(validator, vote, message, status)) throw HttpError(status, message);
                 send(res, {{"accepted", true}, {"message", message}});
             }));

    svr.Post("/api/consensus/stop", wrap([&](const httplib::Request&, httplib::Response& res) {
                 ctx.consensus.stop();
                 send(res, {{"stopping", true}});
             }));

    svr.Get("/api/consensus/status",
            wrap([&](const httplib::Request&, httplib::Response& res) { send(res, ctx.consensus.snapshot()); }));

    // Server-Sent Events: live consensus telemetry (fast while a round runs, slow when idle).
    svr.Get("/api/consensus/stream", [&](const httplib::Request&, httplib::Response& res) {
        res.set_header("Cache-Control", "no-cache");
        res.set_header("X-Accel-Buffering", "no");
        res.set_chunked_content_provider("text/event-stream", [&](size_t, httplib::DataSink& sink) {
            bool was_running = ctx.consensus.running();
            std::string msg = "data: " + ctx.consensus.snapshot().dump() + "\n\n";
            if (!sink.write(msg.data(), msg.size())) return false;
            for (int i = 0; i < (was_running ? 2 : 10); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (ctx.consensus.running() != was_running) break;
            }
            return sink.is_writable();
        });
    });

    svr.Get("/api/rounds", wrap([&](const httplib::Request&, httplib::Response& res) {
                Result r = db.exec(
                    "SELECT id, mode, attempt, proposer, participants::text AS participants, block_height, "
                    "quorum_stake, total_stake, duration_ms, outcome FROM consensus_rounds ORDER BY id DESC LIMIT 25");
                json arr = json::array();
                for (int i = 0; i < r.rows(); ++i)
                    arr.push_back({{"id", r.i64(i, "id")},
                                   {"mode", r.str(i, "mode")},
                                   {"attempt", r.i64(i, "attempt")},
                                   {"proposer", r.is_null(i, "proposer") ? json(nullptr) : json(r.str(i, "proposer"))},
                                   {"participants", parse_json_col(r.str(i, "participants"))},
                                   {"block_height",
                                    r.is_null(i, "block_height") ? json(nullptr) : json(r.i64(i, "block_height"))},
                                   {"quorum_stake", r.i64(i, "quorum_stake")},
                                   {"total_stake", r.i64(i, "total_stake")},
                                   {"duration_ms", r.i64(i, "duration_ms")},
                                   {"outcome", r.str(i, "outcome")}});
                send(res, arr);
            }));

    // ---------------- chain ----------------
    svr.Get("/api/blocks", wrap([&](const httplib::Request&, httplib::Response& res) {
                Result r = db.exec("SELECT * FROM blocks ORDER BY height DESC LIMIT 200");
                json arr = json::array();
                for (int i = 0; i < r.rows(); ++i) arr.push_back(block_json(block_from_result(r, i)));
                send(res, arr);
            }));

    svr.Get(R"(/api/blocks/(\d+))", wrap([&](const httplib::Request& req, httplib::Response& res) {
                std::string h = std::to_string(path_i64(req.matches[1]));
                Result r = db.exec("SELECT * FROM blocks WHERE height = $1", {h});
                if (r.rows() == 0) throw HttpError(404, "block not found");
                json j = block_json(block_from_result(r, 0));
                Result t = db.exec(std::string(kTxDetailSelect) + "WHERE t.block_height = $1 ORDER BY t.block_index", {h});
                json txs = json::array();
                for (int i = 0; i < t.rows(); ++i) txs.push_back(tx_json(t, i, true));
                j["transactions"] = txs;

                Result vo = db.exec(
                    "SELECT v.name, bv.signature, bv.stake_at_vote FROM block_votes bv "
                    "JOIN nodes v ON v.id = bv.validator_id WHERE bv.block_height = $1 ORDER BY bv.id",
                    {h});
                json votes = json::array();
                for (int i = 0; i < vo.rows(); ++i)
                    votes.push_back({{"validator", vo.str(i, "name")},
                                     {"signature", vo.str(i, "signature")},
                                     {"stake", vo.i64(i, "stake_at_vote")}});
                j["votes"] = votes;
                send(res, j);
            }));

    svr.Get("/api/chain/verify", wrap([&](const httplib::Request&, httplib::Response& res) {
                send(res, ctx.ledger.verify_chain());
            }));

    // ---------------- demo helpers ----------------
    // Simulates an insider editing the database directly, to show the chain detects it.
    svr.Post("/api/demo/tamper", wrap([&](const httplib::Request& req, httplib::Response& res) {
                 json tb = body(req);
                 std::string kind = opt<std::string>(tb, "kind", "tx_decision");
                 int b_node = static_cast<int>(opt<int64_t>(tb, "node_id", -1));
                 auto l = db.lock();
                 json out = {{"kind", kind}};
                 if (kind == "node_copy") {
                     // Corrupts a block in the MIDDLE of one node's own copy (not the reference chain).
                     int target = -1;
                     if (b_node >= 0) target = b_node;
                     std::string err;
                     int node_hit = 0;
                     int64_t height_hit = 0;
                     if (!ctx.network.tamper(ctx.ledger, target, ctx.ledger.node_keys(), err, &node_hit, &height_hit))
                         throw HttpError(409, err);
                     db.exec("INSERT INTO tamper_log (kind, target) VALUES ($1,$2)", {kind, std::to_string(node_hit)});
                     out["target"] = "node #" + std::to_string(node_hit) + "'s local chain copy";
                     out["change"] = "block #" + std::to_string(height_hit) +
                                     " altered in its own copy; the node must now reject new blocks and invalid chains";
                     ctx.ledger.log_event("tamper", "Copia local del nodo #" + std::to_string(node_hit) +
                                                        " manipulada en el bloque #" + std::to_string(height_hit));
                     send(res, out);
                     return;
                 }
                 if (kind == "reward_amount") {
                     Result pr = db.exec("SELECT height FROM pow_rewards WHERE confirmed ORDER BY height DESC LIMIT 1");
                     if (pr.rows() == 0) throw HttpError(409, "no confirmed PoW reward yet");
                     std::string h = pr.str(0, "height");
                     db.exec("INSERT INTO tamper_log (kind, target, original_text) VALUES ($1,$2,'confirmed')",
                             {kind, h});
                     db.exec("UPDATE pow_rewards SET confirmed = false WHERE height = $1", {h});
                     out["target"] = "reward for block #" + h;
                     out["change"] = "reward confirmation flag falsified";
                     send(res, out);
                     return;
                 }
                 if (kind == "validator_signature") {
                     Result b = db.exec(
                         "SELECT height FROM blocks WHERE height > 0 ORDER BY height DESC LIMIT 1");
                     if (b.rows() == 0) throw HttpError(409, "seal at least one block first");
                     std::string h = b.str(0, "height");
                     Result v = db.exec(
                         "SELECT id, signature FROM block_votes WHERE block_height = $1 ORDER BY id LIMIT 1", {h});
                     if (v.rows() == 0) throw HttpError(409, "that block has no recorded votes");
                     std::string vote_id = v.str(0, "id");
                     db.exec("INSERT INTO tamper_log (kind, target, original_text) VALUES ($1,$2,$3)",
                             {kind, vote_id, v.str(0, "signature")});
                     db.exec("UPDATE block_votes SET signature = overlay(signature placing '00' from 1 for 2) "
                             "WHERE id = $1",
                             {vote_id});
                     out["target"] = "a validator's vote on block #" + h;
                     out["change"] = "vote signature corrupted";
                     send(res, out);
                     return;
                 }

                 if (kind == "intermediate_block" || kind == "block_hash") {
                     // Alters the stored header of a block that is NOT the tip: its own hash
                     // ("block_hash") or the link to its predecessor ("intermediate_block").
                     Result bl = db.exec("SELECT height FROM blocks WHERE height > 0 ORDER BY height");
                     if (bl.rows() < 2) throw HttpError(409, "seal at least two blocks first (need an intermediate block)");
                     std::string h = bl.str((bl.rows() - 1) / 2, "height");
                     std::string col = kind == "block_hash" ? "hash" : "prev_hash";
                     Result cur = db.exec("SELECT " + col + " AS v FROM blocks WHERE height = $1", {h});
                     db.exec("INSERT INTO tamper_log (kind, target, original_text) VALUES ($1,$2,$3)",
                             {kind, h, cur.str(0, "v")});
                     db.exec("UPDATE blocks SET " + col + " = (CASE WHEN left(" + col + ",1) = 'f' THEN '0' ELSE 'f' END) "
                             "|| substr(" + col + ",2) WHERE height = $1", {h});
                     out["target"] = "block #" + h + " (intermediate)";
                     out["change"] = kind == "block_hash" ? "its stored hash was altered" : "its hash_anterior was altered";
                     ctx.ledger.log_event("tamper", "Bloque intermedio #" + h + " manipulado (" + kind + ")");
                     send(res, out);
                     return;
                 }

                 Result t = db.exec(
                     "SELECT tx_id, canonical, comment, work_item_id, block_height FROM transactions "
                     "WHERE status = 'confirmed' ORDER BY block_height DESC, block_index LIMIT 1");
                 if (t.rows() == 0) throw HttpError(409, "mine a block that contains a transaction first");
                 std::string tx = t.str(0, "tx_id");
                 out["target"] = "tx " + tx.substr(0, 12) + " in block #" + t.str(0, "block_height");

                 if (kind == "tx_decision") {
                     std::string c = t.str(0, "canonical");
                     bool approved = c.find("|APPROVED|") != std::string::npos;
                     std::string from = approved ? "|APPROVED|" : "|REJECTED|";
                     std::string to = approved ? "|REJECTED|" : "|APPROVED|";
                     std::string edited = c;
                     edited.replace(edited.find(from), from.size(), to);
                     db.exec("INSERT INTO tamper_log (kind, target, original_text) VALUES ($1,$2,$3)", {kind, tx, c});
                     db.exec("UPDATE transactions SET canonical = $1, decision = $2 WHERE tx_id = $3",
                             {edited, to.substr(1, to.size() - 2), tx});
                     out["change"] = "decision flipped " + from.substr(1, from.size() - 2) + " -> " +
                                     to.substr(1, to.size() - 2);
                 } else if (kind == "comment") {
                     db.exec("INSERT INTO tamper_log (kind, target, original_text) VALUES ($1,$2,$3)",
                             {kind, tx, t.str(0, "comment")});
                     db.exec("UPDATE transactions SET comment = comment || ' (edited later)' WHERE tx_id = $1", {tx});
                     out["change"] = "reviewer comment edited";
                 } else if (kind == "artifact") {
                     std::string wid = t.str(0, "work_item_id");
                     Result w = db.exec("SELECT content FROM work_items WHERE id = $1", {wid});
                     Param orig = Param::bytes(w.bytea(0, "content"));
                     db.exec("INSERT INTO tamper_log (kind, target, original_bytes) VALUES ($1,$2,$3)",
                             {kind, wid, orig});
                     db.exec("UPDATE work_items SET content = content || '\\x0a2f2f2073696c656e74206564697421'::bytea "
                             "WHERE id = $1",
                             {wid});
                     out["target"] = "artifact of work item #" + wid;
                     out["change"] = "artifact bytes modified after approval";
                 } else {
                     throw HttpError(400,
                                     "kind must be tx_decision | comment | artifact | validator_signature | "
                                     "node_copy | reward_amount | intermediate_block | block_hash");
                 }
                 send(res, out);
             }));

    svr.Post("/api/demo/restore", wrap([&](const httplib::Request&, httplib::Response& res) {
                 Db::Transaction t(db);
                 Result r = db.exec("SELECT id, kind, target, original_text, original_bytes FROM tamper_log ORDER BY id DESC");
                 for (int i = 0; i < r.rows(); ++i) {
                     std::string kind = r.str(i, "kind"), target = r.str(i, "target");
                     if (kind == "validator_signature") {
                         db.exec("UPDATE block_votes SET signature = $1 WHERE id = $2::bigint",
                                 {r.str(i, "original_text"), target});
                     } else if (kind == "reward_amount") {
                         db.exec("UPDATE pow_rewards SET confirmed = true WHERE height = $1::bigint", {target});
                     } else if (kind == "intermediate_block" || kind == "block_hash") {
                         db.exec(std::string("UPDATE blocks SET ") + (kind == "block_hash" ? "hash" : "prev_hash") +
                                     " = $1 WHERE height = $2::bigint",
                                 {r.str(i, "original_text"), target});
                     } else if (kind == "node_copy") {
                         ctx.network.receive_chain(ctx.ledger, std::stoi(target), ctx.ledger.export_chain(),
                                                   ctx.ledger.node_keys());
                     } else if (kind == "tx_decision") {
                         std::string c = r.str(i, "original_text");
                         chain::TxFields f;
                         chain::parse_canonical(c, f);
                         db.exec("UPDATE transactions SET canonical = $1, decision = $2 WHERE tx_id = $3",
                                 {c, f.decision, target});
                     } else if (kind == "comment") {
                         db.exec("UPDATE transactions SET comment = $1 WHERE tx_id = $2",
                                 {r.str(i, "original_text"), target});
                     } else if (kind == "artifact") {
                         db.exec("UPDATE work_items SET content = $1 WHERE id = $2",
                                 {Param::bytes(r.bytea(i, "original_bytes")), target});
                     }
                 }
                 db.exec("DELETE FROM tamper_log");
                 t.commit();
                 send(res, {{"restored", r.rows()}});
             }));

    svr.Post("/api/demo/reset", wrap([&](const httplib::Request&, httplib::Response& res) {
                 if (ctx.consensus.running()) throw HttpError(409, "stop the consensus round first");
                 std::lock_guard<std::mutex> chain_lock(ctx.ledger.chain_mu);
                 Db::Transaction t(db);
                 db.exec("DELETE FROM tamper_log");
                 db.exec("DELETE FROM event_log");
                 db.exec("DELETE FROM slashing_events");
                 db.exec("DELETE FROM pow_rewards");
                 db.exec("DELETE FROM block_votes");
                 db.exec("DELETE FROM consensus_rounds");
                 db.exec("DELETE FROM transactions");
                 db.exec("DELETE FROM work_items");
                 db.exec("DELETE FROM blocks WHERE height > 0");
                 db.exec(
                     "UPDATE nodes SET stake = $1, active = true, slashed = false, dishonest = false, "
                     "blocks_proposed = 0, balance = 0, locked = 0",
                     {ctx.initial_stake});
                 t.commit();
                 ctx.network.reset();
                 send(res, {{"reset", true}});
             }));
}
