#include "env.h"

#include <cstdlib>
#include <fstream>

namespace env {

static std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static void set_if_absent(const std::string& k, const std::string& v) {
    if (std::getenv(k.c_str())) return;
#ifdef _WIN32
    _putenv_s(k.c_str(), v.c_str());
#else
    setenv(k.c_str(), v.c_str(), 0);
#endif
}

bool load_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        if (val.size() >= 2 && (val.front() == '"' || val.front() == '\'') && val.back() == val.front())
            val = val.substr(1, val.size() - 2);
        set_if_absent(key, val);
    }
    return true;
}

std::string load_nearest() {
    for (const char* p : {".env", "../.env", "../../.env"}) {
        if (load_file(p)) return p;
    }
    return "";
}

std::string get(const std::string& key, const std::string& def) {
    const char* v = std::getenv(key.c_str());
    return (v && *v) ? std::string(v) : def;
}

int get_int(const std::string& key, int def) {
    try {
        return std::stoi(get(key, std::to_string(def)));
    } catch (...) {
        return def;
    }
}

}  // namespace env
