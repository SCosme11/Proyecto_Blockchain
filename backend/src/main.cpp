// AI Agent Accountability Ledger — C++ node.
// Loads .env, connects to Postgres (creating the database if needed), applies the schema,
// ensures the genesis block, then serves the REST/SSE API (and the built frontend, if present).
#define CPPHTTPLIB_THREAD_POOL_COUNT 32
#include <httplib.h>

#include <cstdio>
#include <filesystem>
#include <iostream>

#include "api.h"
#include "env.h"

static void connect_or_create(Db& db) {
    try {
        db.connect(Db::conninfo_from_env());
        return;
    } catch (const DbError& e) {
        std::string msg = e.what();
        if (msg.find("does not exist") == std::string::npos) throw;
    }
    std::string name = env::get("PGDATABASE", "ai_ledger");
    std::cout << "database '" << name << "' not found, creating it..." << std::endl;
    {
        Db admin;
        std::string ci = Db::conninfo_from_env();
        std::string target = "dbname='" + name + "'";
        auto pos = ci.find(target);
        if (pos != std::string::npos) ci.replace(pos, target.size(), "dbname='postgres'");
        admin.connect(ci);
        std::string quoted = "\"";
        for (char c : name) quoted += (c == '"') ? std::string("\"\"") : std::string(1, c);
        admin.exec("CREATE DATABASE " + quoted + "\"");
    }
    db.connect(Db::conninfo_from_env());
}

int main() {
    std::string env_file = env::load_nearest();
    std::cout << "AI Agent Ledger node\n  env file: " << (env_file.empty() ? "(none, using process env)" : env_file)
              << std::endl;

    RulesEngine rules;
    std::string err;
    std::string rules_path = env::get("RULES_PATH", "rules/confidence_rules.json");
    if (!rules.load(rules_path, err)) {
        std::cerr << "error: " << err << "\n  (run the server from the backend/ directory)" << std::endl;
        return 1;
    }
    std::cout << "  rules: " << rules.version() << " (" << rules.hash().substr(0, 16) << "...)" << std::endl;

    Db db;
    try {
        connect_or_create(db);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n  check PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE in .env"
                  << std::endl;
        return 1;
    }

    Ledger ledger(db);
    try {
        ledger.apply_schema(env::get("SCHEMA_PATH", "../db/schema.sql"));
        ledger.ensure_genesis();
    } catch (const std::exception& e) {
        std::cerr << "error initialising schema: " << e.what() << std::endl;
        return 1;
    }
    std::cout << "  chain height: " << ledger.tip().header.height << std::endl;

    MiningCoordinator miner(ledger, db, env::get_int("MAX_TX_PER_BLOCK", 10));
    AppContext ctx{db,
                   ledger,
                   rules,
                   miner,
                   env::get_int("DEFAULT_DIFFICULTY_BITS", 20),
                   env::get_int("MAX_TX_PER_BLOCK", 10),
                   env::get_int("MAX_MINERS", 16),
                   static_cast<int64_t>(env::get_int("TIMESTAMP_SKEW_SECONDS", 300)) * 1000};

    httplib::Server svr;
    svr.set_payload_max_length(25 * 1024 * 1024);
    register_routes(svr, ctx);

    std::string dist = env::get("FRONTEND_DIST", "../frontend/dist");
    if (std::filesystem::exists(dist) && svr.set_mount_point("/", dist))
        std::cout << "  serving frontend from " << dist << std::endl;

    std::string host = env::get("SERVER_HOST", "127.0.0.1");
    int port = env::get_int("SERVER_PORT", 8080);
    std::cout << "  listening on http://" << host << ":" << port << std::endl;
    if (!svr.listen(host, port)) {
        std::cerr << "error: could not bind " << host << ":" << port << std::endl;
        return 1;
    }
    return 0;
}
