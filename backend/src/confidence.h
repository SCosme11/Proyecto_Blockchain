#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

// Business-rule "auditor" that classifies AI-agent work into LOW / MEDIUM / HIGH confidence.
// Only MEDIUM work requires a human signature and therefore reaches the chain.
struct Metrics {
    std::string artifact_type;
    double self_confidence = 0;     // agent's own confidence, 0..1
    double tests_passed_ratio = 0;  // objective validation signal, 0..1
    int lines_changed = 0;          // size of the change / artifact
    bool has_external_side_effects = false;
};

struct Classification {
    std::string score;  // fixed 4 decimals; this exact string is signed into the transaction
    std::string category;
    std::vector<std::string> reasons;
    nlohmann::json breakdown;
};

class RulesEngine {
public:
    bool load(const std::string& path, std::string& err);
    Classification classify(const Metrics& m) const;
    bool valid_artifact_type(const std::string& t) const;

    const std::string& version() const { return version_; }
    const std::string& hash() const { return hash_; }
    const nlohmann::json& rules() const { return rules_; }

private:
    nlohmann::json rules_;
    std::string version_;
    std::string hash_;
};
