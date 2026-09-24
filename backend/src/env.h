#pragma once
#include <string>

// Minimal .env loader. Values already present in the process environment win.
namespace env {

bool load_file(const std::string& path);
// Looks for .env in the cwd and up to two parent directories.
std::string load_nearest();
std::string get(const std::string& key, const std::string& def = "");
int get_int(const std::string& key, int def);

}  // namespace env
