#include "ReportGenerator.h"
#include "Analyzer.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <sys/stat.h>   // mkdir / stat
#include <algorithm>

//  currentTimestamp
std::string ReportGenerator::currentTimestamp(bool filenameSafe) {
    auto now  = std::chrono::system_clock::now();
    auto tt   = std::chrono::system_clock::to_time_t(now);
    std::tm   tm{};
    localtime_r(&tt, &tm);

    std::ostringstream oss;
    if (filenameSafe) {
        oss << std::put_time(&tm, "%Y%m%d_%H%M%S");
    } else {
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    }
    return oss.str();
}

//  ensureDir — create directory if it doesn't already exist
bool ReportGenerator::ensureDir(const std::string& dir) {
    struct stat st;
    if (stat(dir.c_str(), &st) == 0) {
        return true;  // Already exists
    }
    // Try to create it (Unix only; mode 0755)
    return (mkdir(dir.c_str(), 0755) == 0);
}

//  buildReport — populate Report metadata from stats and alerts
Report ReportGenerator::buildReport(const AnalysisStats&      stats,
                                    const std::vector<Alert>& alerts,
                                    const ProcessingStats&    procStats) {
    Report r;
    r.generatedDate = currentTimestamp();

    std::ostringstream summary;
    summary << "Processed " << procStats.totalLines << " log lines from '"
            << procStats.filename << "'. "
            << procStats.validEntries << " valid, "
            << procStats.invalidEntries << " invalid. "
            << stats.totalRequests << " total requests from "
            << stats.uniqueIPs << " unique IPs. "
            << stats.errorCount << " error responses detected.";
    r.analysisSummary = summary.str();

    // Security findings
    for (const auto& a : alerts) {
        std::ostringstream f;
        f << "[" << severityToString(a.severity) << "] "
          << a.alertType << " — " << a.ip << ": " << a.description;
        r.securityFindings.push_back(f.str());
    }

    // Recommendations based on findings
    bool hasBlocked  = false, hasRate = false, hasSpike = false;
    for (const auto& a : alerts) {
        if (a.alertType == "BLOCKED_IP_ACCESS")  hasBlocked = true;
        if (a.alertType == "RATE_LIMIT_EXCEEDED") hasRate   = true;
        if (a.alertType == "TRAFFIC_SPIKE")       hasSpike  = true;
    }
    if (hasBlocked)
        r.recommendations.push_back(
            "Block flagged IPs at the firewall level immediately.");
    if (hasRate)
        r.recommendations.push_back(
            "Implement server-side rate limiting (e.g. nginx limit_req).");
    if (hasSpike)
        r.recommendations.push_back(
            "Investigate traffic spike periods for DDoS or scraping activity.");
    if (stats.errorCount > stats.totalRequests / 4)
        r.recommendations.push_back(
            "High error rate detected — review application error handling.");
    if (r.recommendations.empty())
        r.recommendations.push_back(
            "No immediate action required. Continue routine monitoring.");

    return r;
}

//  printReport — stdout display
void ReportGenerator::printReport(const Report&             report,
                                  const AnalysisStats&      stats,
                                  const std::vector<Alert>& alerts,
                                  const ProcessingStats&    procStats) {
    (void)stats;   // summary already encoded in Report::analysisSummary
    (void)alerts;  // findings already encoded in Report::securityFindings
    const std::string SEP(70, '=');
    const std::string DIV(70, '-');


    std::cout << '\n' << SEP << '\n';
    std::cout << "              MONITORING REPORT\n";
    std::cout << SEP << '\n';

    std::cout << "  Generated : " << report.generatedDate    << '\n';
    std::cout << "  Source    : " << procStats.filename      << '\n';
    std::cout << '\n';

    std::cout << "  [ANALYSIS SUMMARY]\n" << DIV << '\n';
    std::cout << "  " << report.analysisSummary << "\n\n";

    std::cout << "  [SECURITY FINDINGS]\n" << DIV << '\n';
    if (report.securityFindings.empty()) {
        std::cout << "  No security findings.\n";
    } else {
        for (const auto& f : report.securityFindings) {
            std::cout << "  " << f << '\n';
        }
    }
    std::cout << '\n';

    std::cout << "  [RECOMMENDATIONS]\n" << DIV << '\n';
    for (const auto& rec : report.recommendations) {
        std::cout << "  * " << rec << '\n';
    }

    std::cout << SEP << '\n';
}

//  exportTXT — write full report to a .txt file
std::string ReportGenerator::exportTXT(const Report&             report,
                                       const AnalysisStats&      stats,
                                       const std::vector<Alert>& alerts,
                                       const ProcessingStats&    procStats,
                                       const std::string&        outputDir) {
    if (!ensureDir(outputDir)) {
        std::cerr << "[ERROR] Cannot create output directory: " << outputDir << '\n';
        return "";
    }

    std::string filename = outputDir + "/report_" +
                           currentTimestamp(true) + ".txt";
    std::ofstream out(filename);
    if (!out.is_open()) {
        std::cerr << "[ERROR] Cannot write to: " << filename << '\n';
        return "";
    }

    const std::string SEP(70, '=');
    const std::string DIV(70, '-');

    out << SEP << '\n';
    out << "    NETWORK MONITORING & LOG ANALYSIS REPORT\n";
    out << SEP << '\n';
    out << "  Generated : " << report.generatedDate << '\n';
    out << "  Source    : " << procStats.filename   << '\n';
    out << '\n';

    // Processing statistics
    out << "  [PROCESSING STATISTICS]\n" << DIV << '\n';
    out << std::left
        << std::setw(30) << "  Total Lines Read"    << procStats.totalLines    << '\n'
        << std::setw(30) << "  Valid Entries"        << procStats.validEntries  << '\n'
        << std::setw(30) << "  Invalid/Corrupt Lines"<< procStats.invalidEntries<< '\n';
    out << '\n';

    // Activity overview
    out << "  [ACTIVITY OVERVIEW]\n" << DIV << '\n';
    out << std::left
        << std::setw(30) << "  Total Requests"       << stats.totalRequests << '\n'
        << std::setw(30) << "  Unique IP Addresses"  << stats.uniqueIPs     << '\n'
        << std::setw(30) << "  Error Responses (4xx/5xx)" << stats.errorCount  << '\n'
        << std::setw(30) << "  Success Responses"    << stats.successCount  << '\n';
    out << '\n';

    // Top 10 Active IPs
    out << "  [TOP 10 ACTIVE IPs]\n" << DIV << '\n';
    auto topIPs = Analyzer::topActiveIPs(stats, 10);
    int rank = 1;
    for (const auto& [ip, cnt] : topIPs) {
        out << std::left
            << std::setw(4)  << ("  " + std::to_string(rank++))
            << std::setw(20) << ip
            << cnt << '\n';
    }
    out << '\n';

    // Top 10 Paths
    out << "  [TOP 10 REQUESTED PATHS]\n" << DIV << '\n';
    auto topPths = Analyzer::topPaths(stats, 10);
    rank = 1;
    for (const auto& [path, cnt] : topPths) {
        out << std::left
            << std::setw(4)  << ("  " + std::to_string(rank++))
            << std::setw(30) << path
            << cnt << '\n';
    }
    out << '\n';

    // Security alerts
    out << "  [SECURITY ALERTS (" << alerts.size() << " total)]\n" << DIV << '\n';
    if (alerts.empty()) {
        out << "  No alerts detected.\n";
    } else {
        out << std::left
            << std::setw(6)  << "  ID"
            << std::setw(18) << "IP"
            << std::setw(26) << "Type"
            << std::setw(10) << "Severity"
            << "Description\n";
        out << DIV << '\n';
        for (const auto& a : alerts) {
            out << std::left
                << std::setw(6)  << ("  " + std::to_string(a.alertID))
                << std::setw(18) << a.ip
                << std::setw(26) << a.alertType
                << std::setw(10) << severityToString(a.severity)
                << a.description << '\n';
        }
    }
    out << '\n';

    // Recommendations
    out << "  [RECOMMENDATIONS]\n" << DIV << '\n';
    for (const auto& rec : report.recommendations) {
        out << "  * " << rec << '\n';
    }
    out << '\n' << SEP << '\n';

    out.close();
    return filename;
}

//  exportCSV — write all log entries to a CSV file
std::string ReportGenerator::exportCSV(const std::vector<LogEntry>& entries,
                                       const std::string&           outputDir) {
    if (!ensureDir(outputDir)) {
        std::cerr << "[ERROR] Cannot create output directory: " << outputDir << '\n';
        return "";
    }

    std::string filename = outputDir + "/logs_" +
                           currentTimestamp(true) + ".csv";
    std::ofstream out(filename);
    if (!out.is_open()) {
        std::cerr << "[ERROR] Cannot write to: " << filename << '\n';
        return "";
    }

    // CSV header
    out << "line_number,source_ip,timestamp,method,path,protocol,"
           "status_code,response_size,referrer,user_agent\n";

    for (const auto& e : entries) {
        // Helper lambda — wrap field in quotes and escape internal quotes
        auto quote = [](const std::string& s) -> std::string {
            std::string r = "\"";
            for (char c : s) {
                if (c == '"') r += "\"\"";
                else r += c;
            }
            r += '"';
            return r;
        };

        out << e.lineNumber        << ','
            << quote(e.sourceIP)   << ','
            << quote(e.timestamp)  << ','
            << quote(e.method)     << ','
            << quote(e.path)       << ','
            << quote(e.protocol)   << ','
            << e.statusCode        << ','
            << e.responseSize      << ','
            << quote(e.referrer)   << ','
            << quote(e.userAgent)  << '\n';
    }

    out.close();
    return filename;
}
