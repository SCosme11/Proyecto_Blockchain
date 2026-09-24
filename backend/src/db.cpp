#include "db.h"

#include "crypto.h"
#include "env.h"

std::vector<unsigned char> Result::bytea(int row, const char* col) const {
    size_t len = 0;
    unsigned char* raw = PQunescapeBytea(reinterpret_cast<const unsigned char*>(PQgetvalue(r_.get(), row, idx(col))), &len);
    std::vector<unsigned char> out(raw, raw + len);
    PQfreemem(raw);
    return out;
}

int Result::affected() const {
    const char* n = PQcmdTuples(r_.get());
    return (n && *n) ? std::stoi(n) : 0;
}

int Result::idx(const char* col) const {
    int i = PQfnumber(r_.get(), col);
    if (i < 0) throw DbError(std::string("no such column: ") + col);
    return i;
}

Db::~Db() {
    if (conn_) PQfinish(conn_);
}

static std::string quote_conn(const std::string& v) {
    std::string out = "'";
    for (char c : v) {
        if (c == '\'' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out + "'";
}

std::string Db::conninfo_from_env() {
    std::string ci;
    auto add = [&](const char* key, const char* var, const char* def) {
        std::string v = env::get(var, def);
        if (!v.empty()) ci += std::string(key) + "=" + quote_conn(v) + " ";
    };
    add("host", "PGHOST", "localhost");
    add("port", "PGPORT", "5432");
    add("dbname", "PGDATABASE", "ai_ledger");
    add("user", "PGUSER", "postgres");
    add("password", "PGPASSWORD", "");
    add("sslmode", "PGSSLMODE", "prefer");
    return ci + "connect_timeout='5' application_name='ai_agent_ledger'";
}

void Db::connect(const std::string& conninfo) {
    auto l = lock();
    if (conn_) PQfinish(conn_);
    conn_ = PQconnectdb(conninfo.c_str());
    if (PQstatus(conn_) != CONNECTION_OK) {
        std::string msg = PQerrorMessage(conn_);
        PQfinish(conn_);
        conn_ = nullptr;
        throw DbError("postgres connection failed: " + msg);
    }
    PQsetNoticeProcessor(conn_, [](void*, const char*) {}, nullptr);
}

Result Db::exec(const std::string& sql, const std::vector<Param>& params) {
    auto l = lock();
    if (!conn_) throw DbError("not connected");
    if (PQstatus(conn_) != CONNECTION_OK) PQreset(conn_);

    std::vector<const char*> values;
    std::vector<int> lengths, formats;
    for (const auto& p : params) {
        values.push_back(p.value ? p.value->data() : nullptr);
        lengths.push_back(p.value ? static_cast<int>(p.value->size()) : 0);
        formats.push_back(p.binary ? 1 : 0);
    }
    PGresult* r = PQexecParams(conn_, sql.c_str(), static_cast<int>(params.size()), nullptr, values.data(),
                               lengths.data(), formats.data(), 0);
    ExecStatusType st = PQresultStatus(r);
    if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
        std::string msg = PQresultErrorMessage(r);
        PQclear(r);
        throw DbError(msg);
    }
    return Result(r);
}

void Db::exec_script(const std::string& sql) {
    auto l = lock();
    PGresult* r = PQexec(conn_, sql.c_str());
    ExecStatusType st = PQresultStatus(r);
    std::string msg = PQresultErrorMessage(r);
    PQclear(r);
    if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) throw DbError(msg);
}

Db::Transaction::Transaction(Db& db) : db_(db), lock_(db.lock()) { db_.exec("BEGIN"); }

Db::Transaction::~Transaction() {
    if (!done_) {
        try {
            db_.exec("ROLLBACK");
        } catch (...) {
        }
    }
}

void Db::Transaction::commit() {
    db_.exec("COMMIT");
    done_ = true;
}
