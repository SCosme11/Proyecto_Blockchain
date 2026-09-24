#include "api.h"

#define CPPHTTPLIB_THREAD_POOL_COUNT 32
#include <httplib.h>

#include <chrono>
#include <thread>

#include "crypto.h"

using nlohmann::json;

namespace {

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
    try {
        return json::parse(req.body);
    } catch (...) {
        throw HttpError(400, "request body must be valid JSON");
    }
}

template <typename T>
T field(const json& j, const char* key) {
    if (!j.contains(key) || j[key].is_null()) throw HttpError(400, std::string("missing field: ") + key);
    try {
        return j[key].get<T>();
    } catch (...) {
        throw HttpError(400, std::string("invalid type for field: ") + key);
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
            {"difficulty_bits", h.difficulty_bits},
            {"nonce", h.nonce},
            {"miner", h.miner},
            {"miner_signature", b.miner_signature},
            {"tx_count", b.tx_count},
            {"header_preimage", chain::header_prefix(h) + std::to_string(h.nonce)}};
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
                           {"default_difficulty", ctx.default_difficulty},
                           {"max_tx_per_block", ctx.max_tx_per_block},
                           {"max_miners", ctx.max_miners},
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
                    "(SELECT count(*) FROM miners) AS miners");
                json j;
                for (const char* k : {"work_total", "low", "medium", "high", "pending_review", "mempool", "confirmed",
                                      "height", "auditors", "miners"})
                    j[k] = r.i64(0, k);
                j["mining"] = ctx.miner.running();
                send(res, j);
            }));

    // ---------------- agent work ----------------
    svr.Post("/api/work", wrap([&](const httplib::Request& req, httplib::Response& res) {
                 json b = body(req);
                 std::string agent = field<std::string>(b, "agent_name");
                 std::string type = field<std::string>(b, "artifact_type");
                 std::string filename = b.value("filename", "output.txt");
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

                 json mj = b.value("metrics", json::object());
                 Metrics m;
                 m.artifact_type = type;
                 m.self_confidence = mj.value("self_confidence", 0.0);
                 m.tests_passed_ratio = mj.value("tests_passed_ratio", 0.0);
                 m.lines_changed = mj.value("lines_changed", 0);
                 m.has_external_side_effects = mj.value("has_external_side_effects", false);
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
                                   {std::string(req.matches[1])});
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
                 std::string comment = b.value("comment", "");
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

    // ---------------- miners & mining ----------------
    auto miners_json = [&]() {
        Result r = db.exec("SELECT id, name, public_key_spki, blocks_mined FROM miners ORDER BY name");
        json arr = json::array();
        for (int i = 0; i < r.rows(); ++i)
            arr.push_back({{"id", r.i64(i, "id")},
                           {"name", r.str(i, "name")},
                           {"fingerprint", crypto::fingerprint(r.str(i, "public_key_spki"))},
                           {"blocks_mined", r.i64(i, "blocks_mined")}});
        return arr;
    };

    svr.Get("/api/miners", wrap([&](const httplib::Request&, httplib::Response& res) { send(res, miners_json()); }));

    svr.Post("/api/miners", wrap([&](const httplib::Request& req, httplib::Response& res) {
                 int n = body(req).value("count", 4);
                 if (n < 1 || n > ctx.max_miners) throw HttpError(400, "count out of range");
                 ctx.ledger.ensure_miners(n);
                 send(res, miners_json(), 201);
             }));

    svr.Post("/api/mine", wrap([&](const httplib::Request& req, httplib::Response& res) {
                 json b = body(req);
                 int n = b.value("miners", 4);
                 int bits = b.value("difficulty_bits", ctx.default_difficulty);
                 if (n < 1 || n > ctx.max_miners)
                     throw HttpError(400, "miners must be 1-" + std::to_string(ctx.max_miners));
                 if (bits < 1 || bits > 32) throw HttpError(400, "difficulty_bits must be 1-32");
                 std::string err;
                 if (!ctx.miner.start(n, bits, err)) throw HttpError(409, err);
                 send(res, ctx.miner.snapshot(), 202);
             }));

    svr.Post("/api/mine/stop", wrap([&](const httplib::Request&, httplib::Response& res) {
                 ctx.miner.stop();
                 send(res, {{"stopping", true}});
             }));

    svr.Get("/api/mine/status",
            wrap([&](const httplib::Request&, httplib::Response& res) { send(res, ctx.miner.snapshot()); }));

    // Server-Sent Events: live mining telemetry (fast while a round runs, slow when idle).
    svr.Get("/api/mine/stream", [&](const httplib::Request&, httplib::Response& res) {
        res.set_header("Cache-Control", "no-cache");
        res.set_header("X-Accel-Buffering", "no");
        res.set_chunked_content_provider("text/event-stream", [&](size_t, httplib::DataSink& sink) {
            bool was_running = ctx.miner.running();
            std::string msg = "data: " + ctx.miner.snapshot().dump() + "\n\n";
            if (!sink.write(msg.data(), msg.size())) return false;
            for (int i = 0; i < (was_running ? 2 : 10); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (ctx.miner.running() != was_running) break;
            }
            return sink.is_writable();
        });
    });

    svr.Get("/api/rounds", wrap([&](const httplib::Request&, httplib::Response& res) {
                Result r = db.exec(
                    "SELECT id, difficulty_bits, participants::text AS participants, winner, block_height, duration_ms, "
                    "hashes_total, outcome FROM mining_rounds ORDER BY id DESC LIMIT 25");
                json arr = json::array();
                for (int i = 0; i < r.rows(); ++i)
                    arr.push_back({{"id", r.i64(i, "id")},
                                   {"difficulty_bits", r.i64(i, "difficulty_bits")},
                                   {"participants", parse_json_col(r.str(i, "participants"))},
                                   {"winner", r.is_null(i, "winner") ? json(nullptr) : json(r.str(i, "winner"))},
                                   {"block_height",
                                    r.is_null(i, "block_height") ? json(nullptr) : json(r.i64(i, "block_height"))},
                                   {"duration_ms", r.i64(i, "duration_ms")},
                                   {"hashes_total", r.i64(i, "hashes_total")},
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
                std::string h = req.matches[1];
                Result r = db.exec("SELECT * FROM blocks WHERE height = $1", {h});
                if (r.rows() == 0) throw HttpError(404, "block not found");
                json j = block_json(block_from_result(r, 0));
                Result t = db.exec(std::string(kTxDetailSelect) + "WHERE t.block_height = $1 ORDER BY t.block_index", {h});
                json txs = json::array();
                for (int i = 0; i < t.rows(); ++i) txs.push_back(tx_json(t, i, true));
                j["transactions"] = txs;
                send(res, j);
            }));

    svr.Get("/api/chain/verify", wrap([&](const httplib::Request&, httplib::Response& res) {
                send(res, ctx.ledger.verify_chain());
            }));

    // ---------------- demo helpers ----------------
    // Simulates an insider editing the database directly, to show the chain detects it.
    svr.Post("/api/demo/tamper", wrap([&](const httplib::Request& req, httplib::Response& res) {
                 std::string kind = body(req).value("kind", "tx_decision");
                 auto l = db.lock();
                 json out = {{"kind", kind}};
                 if (kind == "block_nonce") {
                     Result b = db.exec("SELECT height, nonce FROM blocks WHERE height > 0 ORDER BY height DESC LIMIT 1");
                     if (b.rows() == 0) throw HttpError(409, "mine at least one block first");
                     std::string h = b.str(0, "height");
                     db.exec("INSERT INTO tamper_log (kind, target, original_text) VALUES ($1,$2,$3)",
                             {kind, h, b.str(0, "nonce")});
                     db.exec("UPDATE blocks SET nonce = nonce + 1 WHERE height = $1", {h});
                     out["target"] = "block #" + h;
                     out["change"] = "nonce incremented by 1";
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
                     throw HttpError(400, "kind must be tx_decision | comment | artifact | block_nonce");
                 }
                 send(res, out);
             }));

    svr.Post("/api/demo/restore", wrap([&](const httplib::Request&, httplib::Response& res) {
                 Db::Transaction t(db);
                 Result r = db.exec("SELECT id, kind, target, original_text, original_bytes FROM tamper_log ORDER BY id DESC");
                 for (int i = 0; i < r.rows(); ++i) {
                     std::string kind = r.str(i, "kind"), target = r.str(i, "target");
                     if (kind == "block_nonce") {
                         db.exec("UPDATE blocks SET nonce = $1::bigint WHERE height = $2",
                                 {r.str(i, "original_text"), target});
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
                 if (ctx.miner.running()) throw HttpError(409, "stop the mining round first");
                 std::lock_guard<std::mutex> chain_lock(ctx.ledger.chain_mu);
                 Db::Transaction t(db);
                 db.exec("DELETE FROM tamper_log");
                 db.exec("DELETE FROM mining_rounds");
                 db.exec("DELETE FROM transactions");
                 db.exec("DELETE FROM work_items");
                 db.exec("DELETE FROM blocks WHERE height > 0");
                 db.exec("UPDATE miners SET blocks_mined = 0");
                 t.commit();
                 send(res, {{"reset", true}});
             }));
}
