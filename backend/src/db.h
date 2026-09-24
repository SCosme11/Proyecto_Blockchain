#pragma once
#include <libpq-fe.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// Small RAII wrapper over libpq. One connection guarded by a recursive mutex;
// hold a Db::Lock (or a Db::Transaction) to run several statements atomically.
struct DbError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct Param {
    std::optional<std::string> value;
    bool binary = false;

    Param(std::nullopt_t) {}
    Param(const std::string& v) : value(v) {}
    Param(const char* v) : value(std::string(v)) {}
    Param(int64_t v) : value(std::to_string(v)) {}
    Param(int v) : value(std::to_string(v)) {}
    Param(uint64_t v) : value(std::to_string(v)) {}
    static Param bytes(const std::vector<unsigned char>& b) {
        Param p(std::string(b.begin(), b.end()));
        p.binary = true;
        return p;
    }
};

class Result {
public:
    explicit Result(PGresult* r) : r_(r, PQclear) {}
    int rows() const { return PQntuples(r_.get()); }
    bool null(int row, int col) const { return PQgetisnull(r_.get(), row, col); }
    std::string str(int row, int col) const { return PQgetvalue(r_.get(), row, col); }
    std::string str(int row, const char* col) const { return str(row, idx(col)); }
    int64_t i64(int row, const char* col) const { return std::stoll(str(row, col)); }
    bool is_null(int row, const char* col) const { return null(row, idx(col)); }
    // Decodes a bytea column returned in text (hex) format.
    std::vector<unsigned char> bytea(int row, const char* col) const;
    int affected() const;

private:
    int idx(const char* col) const;
    std::shared_ptr<PGresult> r_;
};

class Db {
public:
    ~Db();
    void connect(const std::string& conninfo);
    Result exec(const std::string& sql, const std::vector<Param>& params = {});
    void exec_script(const std::string& sql);  // multi-statement, no params

    using Lock = std::unique_lock<std::recursive_mutex>;
    Lock lock() { return Lock(mu_); }

    class Transaction {
    public:
        explicit Transaction(Db& db);
        ~Transaction();
        void commit();

    private:
        Db& db_;
        Lock lock_;
        bool done_ = false;
    };

    static std::string conninfo_from_env();

private:
    PGconn* conn_ = nullptr;
    std::recursive_mutex mu_;
};
