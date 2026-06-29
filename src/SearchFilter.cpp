#include "SearchFilter.h"

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <cctype>

//  Utility: case-insensitive string contains
static bool ciContains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    std::string h = haystack, n = needle;
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
    return h.find(n) != std::string::npos;
}

//  byIP — exact match or prefix match
std::vector<LogEntry>
SearchFilter::byIP(const std::vector<LogEntry>& entries, const std::string& ip) {
    std::vector<LogEntry> result;
    for (const auto& e : entries) {
        if (e.sourceIP == ip ||
            e.sourceIP.substr(0, ip.size()) == ip) {
            result.push_back(e);
        }
    }
    return result;
}

//  byTimestamp — substring match in raw timestamp string
std::vector<LogEntry>
SearchFilter::byTimestamp(const std::vector<LogEntry>& entries,
                          const std::string& fragment) {
    std::vector<LogEntry> result;
    for (const auto& e : entries) {
        if (ciContains(e.timestamp, fragment)) {
            result.push_back(e);
        }
    }
    return result;
}
//  byMethod — case-insensitive exact method match
std::vector<LogEntry>
SearchFilter::byMethod(const std::vector<LogEntry>& entries,
                       const std::string& method) {
    std::string target = method;
    std::transform(target.begin(), target.end(), target.begin(), ::toupper);

    std::vector<LogEntry> result;
    for (const auto& e : entries) {
        if (e.method == target) {
            result.push_back(e);
        }
    }
    return result;
}

//  byStatusRange — inclusive status code range filter
std::vector<LogEntry>
SearchFilter::byStatusRange(const std::vector<LogEntry>& entries,
                            int minCode, int maxCode) {
    std::vector<LogEntry> result;
    for (const auto& e : entries) {
        if (e.statusCode >= minCode && e.statusCode <= maxCode) {
            result.push_back(e);
        }
    }
    return result;
}

//  byPath — case-insensitive keyword search in path
std::vector<LogEntry>
SearchFilter::byPath(const std::vector<LogEntry>& entries,
                     const std::string& keyword) {
    std::vector<LogEntry> result;
    for (const auto& e : entries) {
        if (ciContains(e.path, keyword)) {
            result.push_back(e);
        }
    }
    return result;
}

//  errorsOnly — status >= 400
std::vector<LogEntry>
SearchFilter::errorsOnly(const std::vector<LogEntry>& entries) {
    return byStatusRange(entries, 400, 599);
}

//  suspiciousOnly — DELETE or PUT methods
std::vector<LogEntry>
SearchFilter::suspiciousOnly(const std::vector<LogEntry>& entries) {
    std::vector<LogEntry> result;
    for (const auto& e : entries) {
        if (e.method == "DELETE" || e.method == "PUT") {
            result.push_back(e);
        }
    }
    return result;
}

//  printEntries — aligned table output
void SearchFilter::printEntries(const std::vector<LogEntry>& entries, int maxRows) {
    const std::string DIV(100, '-');

    if (entries.empty()) {
        std::cout << "\n  [INFO] No matching records found.\n";
        return;
    }

    int total = static_cast<int>(entries.size());
    int shown = (maxRows > 0 && total > maxRows) ? maxRows : total;

    std::cout << '\n'
              << std::left
              << std::setw(6)  << " #"
              << std::setw(18) << " IP Address"
              << std::setw(24) << " Timestamp"
              << std::setw(8)  << " Method"
              << std::setw(28) << " Path"
              << std::setw(7)  << " Status"
              << " Size\n";
    std::cout << DIV << '\n';

    for (int i = 0; i < shown; ++i) {
        const auto& e = entries[i];
        // Truncate long paths
        std::string path = e.path;
        if (path.size() > 26) path = path.substr(0, 23) + "...";

        std::string ts = e.timestamp;
        if (ts.size() > 22) ts = ts.substr(0, 22);

        std::cout << std::left
                  << std::setw(6)  << (" " + std::to_string(i + 1))
                  << std::setw(18) << (" " + e.sourceIP)
                  << std::setw(24) << (" " + ts)
                  << std::setw(8)  << (" " + e.method)
                  << std::setw(28) << (" " + path)
                  << std::setw(7)  << (" " + std::to_string(e.statusCode))
                  << " " << e.responseSize << '\n';
    }

    std::cout << DIV << '\n';
    std::cout << "  Showing " << shown << " of " << total << " records.\n";
}
