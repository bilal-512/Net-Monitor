#pragma once

#include <string>
#include <vector>
#include <map>

//  LogEntry — represents one parsed line from a log file
struct LogEntry {
    std::string sourceIP;       // Client IP address
    std::string timestamp;      // Raw timestamp string from log
    std::string method;         // HTTP method (GET, POST, PUT, DELETE, …)
    std::string path;           // Request path/URI
    std::string protocol;       // e.g. "HTTP/1.1"
    int         statusCode{0};  // HTTP status code
    long long   responseSize{0};// Response body size in bytes
    std::string referrer;       // HTTP Referer header value
    std::string userAgent;      // HTTP User-Agent header value
    int         lineNumber{0};  // Source line number (for tracing corrupt lines)
};


//  AlertSeverity — ordered severity levels for alerts
enum class AlertSeverity {
    LOW      = 1,
    MEDIUM   = 2,
    HIGH     = 3,
    CRITICAL = 4
};

inline std::string severityToString(AlertSeverity s) {
    switch (s) {
        case AlertSeverity::LOW:      return "LOW";
        case AlertSeverity::MEDIUM:   return "MEDIUM";
        case AlertSeverity::HIGH:     return "HIGH";
        case AlertSeverity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

//  Alert — a detected security / anomaly event
struct Alert {
    int           alertID{0};
    std::string   ip;
    std::string   alertType;
    AlertSeverity severity{AlertSeverity::LOW};
    std::string   description;
    std::string   timestamp;
};

//  ProcessingStats — log file ingestion statistics
struct ProcessingStats {
    int         totalLines{0};
    int         validEntries{0};
    int         invalidEntries{0};
    std::string filename;
};

//  AnalysisStats — derived analytics over a set of LogEntries
struct AnalysisStats {
    int totalRequests{0};
    int uniqueIPs{0};
    int errorCount{0};      // 4xx + 5xx
    int successCount{0};    // 2xx + 3xx

    std::map<std::string, int> ipRequestCounts;   // IP  -> count
    std::map<std::string, int> methodCounts;      // method -> count
    std::map<std::string, int> pathCounts;        // path -> count
    std::map<int, int>         statusCodeCounts;  // status -> count
    std::map<int, int>         hourlyCounts;      // hour(0-23) -> count
};

//  Report — generated report metadata and content
struct Report {
    std::string              generatedDate;
    std::string              analysisSummary;
    std::vector<std::string> securityFindings;
    std::vector<std::string> recommendations;
};
