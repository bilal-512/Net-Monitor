#include "LogParser.h"

#include <fstream>
#include <sstream>
#include <regex>
#include <iostream>
#include <stdexcept>

// ---------------------------------------------------------------------------
//  Regex matching the log format:
//  IP - - [Timestamp] "METHOD PATH PROTOCOL" STATUS SIZE "REFERRER" "UA"
//  Example:
//  172.25.74.111 - - [Jul 01 2026, 01:15:58] "GET /home HTTP/1.1" 301 6713
//                    "https://www.facebook.com" "Mozilla/5.0 ..."
// ---------------------------------------------------------------------------
static const std::regex LOG_REGEX(
    R"RAW(^(\S+) - - \[([^\]]+)\] "([A-Z]+) ([^ ]+) ([^"]+)" ([0-9]+) ([0-9]+) "([^"]*)" "([^"]*)")RAW"
);

bool LogParser::parseLine(const std::string& line, LogEntry& entry) {
    std::smatch m;
    if (!std::regex_search(line, m, LOG_REGEX)) {
        return false;
    }
    try {
        entry.sourceIP     = m[1].str();
        entry.timestamp    = m[2].str();
        entry.method       = m[3].str();
        entry.path         = m[4].str();
        entry.protocol     = m[5].str();
        entry.statusCode   = std::stoi(m[6].str());
        entry.responseSize = std::stoll(m[7].str());
        entry.referrer     = m[8].str();
        entry.userAgent    = m[9].str();
        return true;
    } catch (...) {
        // stoi/stoll failed — treat as invalid
        return false;
    }
}

bool LogParser::loadFile(const std::string& filename,
                         std::vector<LogEntry>& entries,
                         ProcessingStats&       stats) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Cannot open file: " << filename << '\n';
        return false;
    }

    stats.filename     = filename;
    stats.totalLines   = 0;
    stats.validEntries = 0;
    stats.invalidEntries = 0;
    entries.clear();

    std::string line;
    while (std::getline(file, line)) {
        // Skip blank lines
        if (line.empty() || line.find_first_not_of(" \t\r\n") == std::string::npos) {
            continue;
        }

        ++stats.totalLines;
        LogEntry entry;
        entry.lineNumber = stats.totalLines;

        if (parseLine(line, entry)) {
            ++stats.validEntries;
            entries.push_back(std::move(entry));
        } else {
            ++stats.invalidEntries;
            // Keep track but do not add to entries
        }
    }

    file.close();
    return true;
}

// Timestamp format: "Jul 01 2026, 01:15:58"
// Hour is the first two digits after ", "
int LogParser::extractHour(const std::string& timestamp) {
    // Find the comma separating date from time
    auto comma = timestamp.find(',');
    if (comma == std::string::npos || comma + 2 >= timestamp.size()) {
        return -1;
    }
    try {
        // Skip ", " then read 2 characters
        return std::stoi(timestamp.substr(comma + 2, 2));
    } catch (...) {
        return -1;
    }
}

// Extract "Jul 01 2026" from "Jul 01 2026, 01:15:58"
std::string LogParser::extractDate(const std::string& timestamp) {
    auto comma = timestamp.find(',');
    if (comma == std::string::npos) {
        return timestamp;
    }
    return timestamp.substr(0, comma);
}
