#pragma once
#include "confidence.h"
#include "consensus.h"
#include "db.h"
#include "ledger.h"
#include "network.h"

namespace httplib {
class Server;
}

struct AppContext {
    Db& db;
    Ledger& ledger;
    ConsensusCoordinator& consensus;
    NodeNetwork& network;
    RulesEngine& rules;
    int64_t initial_stake;
    int max_tx_per_block;
    int64_t timestamp_skew_ms;
};

void register_routes(httplib::Server& svr, AppContext& ctx);
