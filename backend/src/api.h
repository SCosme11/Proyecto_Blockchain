#pragma once
#include "confidence.h"
#include "db.h"
#include "ledger.h"
#include "miner.h"

namespace httplib {
class Server;
}

struct AppContext {
    Db& db;
    Ledger& ledger;
    RulesEngine& rules;
    MiningCoordinator& miner;
    int default_difficulty;
    int max_tx_per_block;
    int max_miners;
    int64_t timestamp_skew_ms;
};

void register_routes(httplib::Server& svr, AppContext& ctx);
