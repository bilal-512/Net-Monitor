#include "Analyzer.h"
#include "LogParser.h"

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <set>

// ---------------------------------------------------------------------------
//  analyze — single pass over entries; fills every field of AnalysisStats
// ---------------------------------------------------------------------------
AnalysisStats Analyzer::analyze(const std::vector<LogEntry>& entries) {
    AnalysisStats stats;
    stats.totalRequests = static_cast<int>(entries.size());

    std::set<std::string> uniqueIPSet;

    for (const auto& e : entries) {
        // IPs
        uniqueIPSet.insert(e.sourceIP);
        stats.ipRequestCounts[e.sourceIP]++;

        // Methods
        stats.methodCounts[e.method]++;

        // Paths (strip query string for grouping)
        std::string basePath = e.path;
        auto qmark = basePath.find('?');
        if (qmark != std::string::npos) {
            basePath = basePath.substr(0, qmark);
        }
        stats.pathCounts[basePath]++;

        // Status codes
        stats.statusCodeCounts[e.statusCode]++;

        // Error / success classification
        if (e.statusCode >= 400) {
            ++stats.errorCount;
        } else {
            ++stats.successCount;
        }

        // Hourly distribution
        int hour = LogParser::extractHour(e.timestamp);
        if (hour >= 0 && hour <= 23) {
            stats.hourlyCounts[hour]++;
        }
    }

    stats.uniqueIPs = static_cast<int>(uniqueIPSet.size());
    return stats;
}

//  topActiveIPs — return top N IPs by request count
std::vector<std::pair<std::string, int>>
Analyzer::topActiveIPs(const AnalysisStats& stats, int n) {
    std::vector<std::pair<std::string, int>> vec(
        stats.ipRequestCounts.begin(), stats.ipRequestCounts.end()
    );
    std::sort(vec.begin(), vec.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    if (n > 0 && static_cast<int>(vec.size()) > n) {
        vec.resize(n);
    }
    return vec;
}

//  topPaths — return top N paths by request count
std::vector<std::pair<std::string, int>>
Analyzer::topPaths(const AnalysisStats& stats, int n) {
    std::vector<std::pair<std::string, int>> vec(
        stats.pathCounts.begin(), stats.pathCounts.end()
    );
    std::sort(vec.begin(), vec.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    if (n > 0 && static_cast<int>(vec.size()) > n) {
        vec.resize(n);
    }
    return vec;
}

//  peakHour — hour (0-23) with the most requests
int Analyzer::peakHour(const AnalysisStats& stats) {
    if (stats.hourlyCounts.empty()) return -1;
    return std::max_element(
        stats.hourlyCounts.begin(), stats.hourlyCounts.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; }
    )->first;
}

//  printSummary — formatted activity report to stdout
void Analyzer::printSummary(const AnalysisStats& stats) {
    const std::string SEP(70, '=');
    const std::string DIV(70, '-');

    std::cout << '\n' << SEP << '\n';
    std::cout << "              ACTIVITY ANALYSIS SUMMARY\n";
    std::cout << SEP << '\n';

    // --- Overview ---
    std::cout << "\n  [OVERVIEW]\n";
    std::cout << DIV << '\n';
    std::cout << std::left
              << std::setw(30) << "  Total Requests"
              << stats.totalRequests << '\n'
              << std::setw(30) << "  Unique IP Addresses"
              << stats.uniqueIPs << '\n'
              << std::setw(30) << "  Successful Responses"
              << stats.successCount << '\n'
              << std::setw(30) << "  Error Responses"
              << stats.errorCount << '\n';

    // --- HTTP Methods ---
    std::cout << "\n  [REQUEST METHODS]\n";
    std::cout << DIV << '\n';
    for (const auto& [method, count] : stats.methodCounts) {
        std::cout << std::left << std::setw(30) << ("  " + method) << count << '\n';
    }

    // --- Status Code Distribution ---
    std::cout << "\n  [STATUS CODE DISTRIBUTION]\n";
    std::cout << DIV << '\n';
    for (const auto& [code, count] : stats.statusCodeCounts) {
        std::cout << std::left
                  << std::setw(30) << ("  HTTP " + std::to_string(code))
                  << count << '\n';
    }

    // --- Top 10 Active IPs ---
    std::cout << "\n  [TOP 10 MOST ACTIVE IPs]\n";
    std::cout << DIV << '\n';
    std::cout << std::left
              << std::setw(22) << "  IP Address"
              << "Requests\n";
    std::cout << DIV << '\n';
    auto topIPs = topActiveIPs(stats, 10);
    int rank = 1;
    for (const auto& [ip, count] : topIPs) {
        std::cout << std::left
                  << std::setw(4)  << ("  " + std::to_string(rank++) + ".")
                  << std::setw(20) << ip
                  << count << '\n';
    }

    // --- Top 10 Requested Paths ---
    std::cout << "\n  [TOP 10 MOST REQUESTED PATHS]\n";
    std::cout << DIV << '\n';
    std::cout << std::left
              << std::setw(32) << "  Path"
              << "Requests\n";
    std::cout << DIV << '\n';
    auto paths = topPaths(stats, 10);
    rank = 1;
    for (const auto& [path, count] : paths) {
        std::cout << std::left
                  << std::setw(4)  << ("  " + std::to_string(rank++) + ".")
                  << std::setw(30) << path
                  << count << '\n';
    }

    // --- Hourly Distribution ---
    std::cout << "\n  [HOURLY REQUEST DISTRIBUTION]\n";
    std::cout << DIV << '\n';
    int peak = peakHour(stats);
    for (int h = 0; h < 24; ++h) {
        auto it = stats.hourlyCounts.find(h);
        int  cnt = (it != stats.hourlyCounts.end()) ? it->second : 0;

        // Build a simple bar
        int bars = cnt * 30 / std::max(stats.totalRequests, 1);
        std::string bar(bars, '#');

        std::ostringstream label;
        label << "  " << std::setw(2) << std::setfill('0') << h
              << ":00" << std::setfill(' ');
        std::cout << std::left
                  << std::setw(10) << label.str()
                  << std::setw(5)  << cnt
                  << ' ' << bar;
        if (h == peak) std::cout << " << PEAK";
        std::cout << '\n';
    }

    std::cout << SEP << '\n';
}
