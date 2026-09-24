#include "confidence.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>

#include "crypto.h"

using nlohmann::json;

namespace {

double clamp01(double v) { return std::max(0.0, std::min(1.0, v)); }

int rank(const std::string& c) { return c == "LOW" ? 0 : c == "MEDIUM" ? 1 : 2; }

std::string fmt(double v, int decimals) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.*f", decimals, v);
    return buf;
}

}  // namespace

bool RulesEngine::load(const std::string& path, std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open rules file: " + path;
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    std::string raw = ss.str();
    try {
        rules_ = json::parse(raw);
        version_ = rules_.at("version").get<std::string>();
        rules_.at("weights");
        rules_.at("thresholds");
        rules_.at("artifact_type_risk");
    } catch (const std::exception& e) {
        err = std::string("invalid rules file: ") + e.what();
        return false;
    }
    // Hash of the exact file bytes: any edit to the policy yields a new rules_hash on-chain.
    hash_ = crypto::sha256_hex(raw);
    return true;
}

bool RulesEngine::valid_artifact_type(const std::string& t) const {
    return rules_["artifact_type_risk"].contains(t);
}

Classification RulesEngine::classify(const Metrics& m) const {
    const json& w = rules_["weights"];
    const json& th = rules_["thresholds"];
    const json& ov = rules_.value("overrides", json::object());

    double risk = rules_["artifact_type_risk"].value(m.artifact_type, 0.5);
    double scale = rules_.value("change_size_scale_lines", 400.0);

    double s_self = clamp01(m.self_confidence);
    double s_tests = clamp01(m.tests_passed_ratio);
    double s_size = 1.0 - clamp01(m.lines_changed / scale);  // smaller changes are easier to trust
    double s_risk = 1.0 - clamp01(risk);

    double score = w.value("self_confidence", 0.0) * s_self + w.value("tests_passed_ratio", 0.0) * s_tests +
                   w.value("change_size", 0.0) * s_size + w.value("artifact_risk", 0.0) * s_risk;
    score = clamp01(score);

    Classification c;
    c.score = fmt(score, 4);
    // Re-parse the rounded value so thresholds apply to exactly what gets signed.
    double rounded = std::stod(c.score);

    double high = th.value("high", 0.8), low = th.value("low", 0.45);
    if (rounded >= high) {
        c.category = "HIGH";
        c.reasons.push_back("score " + c.score + " >= high threshold " + fmt(high, 2));
    } else if (rounded < low) {
        c.category = "LOW";
        c.reasons.push_back("score " + c.score + " < low threshold " + fmt(low, 2));
    } else {
        c.category = "MEDIUM";
        c.reasons.push_back("score " + c.score + " within [" + fmt(low, 2) + ", " + fmt(high, 2) + ")");
    }

    // Overrides: policy that the weighted score is not allowed to bypass.
    double min_tests = ov.value("min_tests_ratio_for_non_low", -1.0);
    if (min_tests >= 0 && s_tests < min_tests && c.category != "LOW") {
        c.category = "LOW";
        c.reasons.push_back("override: tests passed " + fmt(s_tests, 2) + " < minimum " + fmt(min_tests, 2) +
                            " -> LOW (rework)");
    }
    std::string se_cap = ov.value("external_side_effects_max_category", "");
    if (m.has_external_side_effects && !se_cap.empty() && rank(c.category) > rank(se_cap)) {
        c.category = se_cap;
        c.reasons.push_back("override: external side effects cap category at " + se_cap +
                            " (human must approve)");
    }
    int max_lines_high = ov.value("max_lines_for_high", -1);
    if (max_lines_high >= 0 && m.lines_changed > max_lines_high && c.category == "HIGH") {
        c.category = "MEDIUM";
        c.reasons.push_back("override: " + std::to_string(m.lines_changed) + " lines > " +
                            std::to_string(max_lines_high) + " cannot be auto-accepted");
    }

    c.breakdown = {
        {"self_confidence", {{"signal", s_self}, {"weight", w.value("self_confidence", 0.0)}}},
        {"tests_passed_ratio", {{"signal", s_tests}, {"weight", w.value("tests_passed_ratio", 0.0)}}},
        {"change_size", {{"signal", s_size}, {"weight", w.value("change_size", 0.0)}}},
        {"artifact_risk", {{"signal", s_risk}, {"weight", w.value("artifact_risk", 0.0)}}},
    };
    return c;
}
