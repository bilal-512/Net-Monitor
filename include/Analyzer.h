#pragma once

#include <vector>
#include <string>
#include "LogEntry.h"

//  Analyzer — computes statistical insights over a set of LogEntries
class Analyzer {
public:
    // Build an AnalysisStats object from a set of parsed log entries.
    static AnalysisStats analyze(const std::vector<LogEntry>& entries);

    // Return the top N most active IPs sorted by request count descending.
    static std::vector<std::pair<std::string, int>>
    topActiveIPs(const AnalysisStats& stats, int n = 10);

    // Return the top N most requested paths sorted by count descending.
    static std::vector<std::pair<std::string, int>>
    topPaths(const AnalysisStats& stats, int n = 10);

    // Return the peak hour (0-23) with the highest request count.
    static int peakHour(const AnalysisStats& stats);

    // Print a human-readable activity summary to stdout.
    static void printSummary(const AnalysisStats& stats);
};
