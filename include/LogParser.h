#pragma once

#include <string>
#include <vector>
#include "LogEntry.h"

//  LogParser — parses raw log files into structured LogEntry vectors
class LogParser {
public:
    // Parse a single log line into a LogEntry.
    // Returns true on success, false if the line is malformed.
    static bool parseLine(const std::string& line, LogEntry& entry);

    // Load an entire log file. Populates entries and stats.
    // Returns true if the file was opened successfully.
    static bool loadFile(const std::string& filename,
                         std::vector<LogEntry>& entries,
                         ProcessingStats&       stats);

    // Extract the hour (0-23) from a raw timestamp string.
    // Returns -1 if parsing fails.
    static int extractHour(const std::string& timestamp);

    // Extract the date portion ("Jun 29 2026") from a raw timestamp string.
    static std::string extractDate(const std::string& timestamp);
};
