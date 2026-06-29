#pragma once

#include <vector>
#include <string>
#include "LogEntry.h"

//  SearchFilter — filter and search over a set of LogEntries
class SearchFilter {
public:
    //  Individual filters — each returns a subset of entries matching criteria

    // Match entries where sourceIP equals or starts with the given prefix.
    static std::vector<LogEntry>
    byIP(const std::vector<LogEntry>& entries, const std::string& ip);

    // Match entries where the timestamp contains the given date/time substring.
    // e.g. "Jun 29", "2026", "15:"
    static std::vector<LogEntry>
    byTimestamp(const std::vector<LogEntry>& entries, const std::string& fragment);

    // Match entries where method equals the given string (case-insensitive).
    static std::vector<LogEntry>
    byMethod(const std::vector<LogEntry>& entries, const std::string& method);

    // Match entries where status code is within [minCode, maxCode].
    static std::vector<LogEntry>
    byStatusRange(const std::vector<LogEntry>& entries, int minCode, int maxCode);

    // Match entries where path contains the given keyword.
    static std::vector<LogEntry>
    byPath(const std::vector<LogEntry>& entries, const std::string& keyword);

    // Convenience: return only error entries (status >= 400).
    static std::vector<LogEntry>
    errorsOnly(const std::vector<LogEntry>& entries);

    // Convenience: return only entries flagged as suspicious based on method.
    static std::vector<LogEntry>
    suspiciousOnly(const std::vector<LogEntry>& entries);

    //  Print helpers

    // Print a table of log entries to stdout.
    // maxRows limits output; pass 0 for unlimited.
    static void printEntries(const std::vector<LogEntry>& entries, int maxRows = 50);
};
