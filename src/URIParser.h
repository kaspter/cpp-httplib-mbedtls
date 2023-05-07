#include <iostream>
#include <regex>
#include <string>


typedef struct {
    std::string scheme;
    std::string host;
    int         port;
    std::string absPath;
    std::string query;
} uri_t;



inline void URIparse(const std::string &scheme_host_port) {
  const static std::regex re(
      R"((?:([a-z]+):\/\/)?(?:\[([\d:]+)\]|([^:/?#]+))(?::(\d+))?)");

  std::smatch m;
  if (std::regex_match(scheme_host_port, m, re)) {
    auto scheme = m[1].str();

    if (!scheme.empty() && (scheme != "http" && scheme != "https")) {
      return;
    }

    auto is_ssl = scheme == "https";

    auto host = m[2].str();
    if (host.empty()) { host = m[3].str(); }

    auto port_str = m[4].str();
    auto port = !port_str.empty() ? std::stoi(port_str) : (is_ssl ? 443 : 80);
  }
}


// http_URL = "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]]

// Get http uri details from the provided url string
inline bool GetURIDetails(const std::string& url, uri_t& uri) {
    std::regex re(
        R"(^(([^:\/?#]+):)?(//([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?)",
        std::regex::extended);

    std::smatch m;
    if (std::regex_match(url, m, re)) {
        uri.scheme = m[2];
        uri.host = m[4];
        uri.port = 80; // Default port for http

        // Parse port if it is provided
        if (!m[4].str().empty()) {
            std::string port_str = m[4].str().substr(
                m[4].str().find(":") + 1);
            if (!port_str.empty()) {
                uri.port = std::stoi(port_str);
            }
        }

        uri.absPath = m[5];
        uri.query = m[7];

        return true;
    }

    return false;
}
