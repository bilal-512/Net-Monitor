#include "ThreatDetector.h"
#include "LogParser.h"

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <map>
#include <sstream>

//  Constructor
ThreatDetector::ThreatDetector(const ThreatConfig& config)
    : config_(config) {}

void ThreatDetector::setConfig(const ThreatConfig& config) {
    config_ = config;
}

const ThreatConfig& ThreatDetector::getConfig() const {
    return config_;
}

//  makeAlert — convenience factory; auto-increments the alert ID
Alert ThreatDetector::makeAlert(const std::string& ip,
                                const std::string& type,
                                AlertSeverity      severity,
                                const std::string& description,
                                const std::string& timestamp) const {
    return Alert{nextAlertID_++, ip, type, severity, description, timestamp};
}

//  detect — run all rules in sequence and collect results
std::vector<Alert>
ThreatDetector::detect(const std::vector<LogEntry>& entries) const {
    nextAlertID_ = 1;          // Reset ID counter on each run
    std::vector<Alert> alerts;

    checkBlockedIPs      (entries, alerts);
    checkExcessiveRequests(entries, alerts);
    checkFailedLogins    (entries, alerts);
    checkDangerousMethods(entries, alerts);
    checkTrafficSpikes   (entries, alerts);   

    return alerts;
}

//  Rule 1 — Blocked IP access
void ThreatDetector::checkBlockedIPs(const std::vector<LogEntry>& entries,
                                     std::vector<Alert>& alerts) const {
    for (const auto& e : entries) {
        if (config_.blockedIPs.count(e.sourceIP)) {
            alerts.push_back(makeAlert(
                e.sourceIP,
                "BLOCKED_IP_ACCESS",
                AlertSeverity::CRITICAL,
                "Access attempt from a blacklisted IP address.",
                e.timestamp
            ));
        }
    }
}

//  Rule 2 — Excessive requests from a single IP (rate limiting)
void ThreatDetector::checkExcessiveRequests(const std::vector<LogEntry>& entries,
                                            std::vector<Alert>& alerts) const {
    std::map<std::string, int> counts;
    std::map<std::string, std::string> lastTimestamp;

    for (const auto& e : entries) {
        counts[e.sourceIP]++;
        lastTimestamp[e.sourceIP] = e.timestamp;
    }

    for (const auto& [ip, count] : counts) {
        if (count > config_.excessiveRequestLimit) {
            std::ostringstream desc;
            desc << "IP sent " << count << " requests (limit: "
                 << config_.excessiveRequestLimit << ").";
            alerts.push_back(makeAlert(
                ip,
                "RATE_LIMIT_EXCEEDED",
                AlertSeverity::HIGH,
                desc.str(),
                lastTimestamp[ip]
            ));
        }
    }
}

//  Rule 3 — Repeated failed login / authentication attempts
//           Tracked by: POST/PUT on sensitive paths returning 4xx/5xx
void ThreatDetector::checkFailedLogins(const std::vector<LogEntry>& entries,
                                       std::vector<Alert>& alerts) const {
    std::map<std::string, int>         failCounts;
    std::map<std::string, std::string> lastTimestamp;

    for (const auto& e : entries) {
        // Determine if the path is sensitive
        bool sensitive = false;
        for (const auto& kw : config_.sensitivePathKeywords) {
            if (e.path.find(kw) != std::string::npos) {
                sensitive = true;
                break;
            }
        }

        if (sensitive && e.statusCode >= 400) {
            failCounts[e.sourceIP]++;
            lastTimestamp[e.sourceIP] = e.timestamp;
        }
    }

    for (const auto& [ip, count] : failCounts) {
        if (count >= config_.failedLoginLimit) {
            std::ostringstream desc;
            desc << "IP had " << count
                 << " failed requests on sensitive paths (threshold: "
                 << config_.failedLoginLimit << ").";
            alerts.push_back(makeAlert(
                ip,
                "SUSPICIOUS_AUTH_ATTEMPT",
                AlertSeverity::HIGH,
                desc.str(),
                lastTimestamp[ip]
            ));
        }
    }
}

//  Rule 4 — Dangerous HTTP methods (DELETE / PUT on sensitive paths)
void ThreatDetector::checkDangerousMethods(const std::vector<LogEntry>& entries,
                                           std::vector<Alert>& alerts) const {
    for (const auto& e : entries) {
        if (e.method != "DELETE" && e.method != "PUT") continue;

        bool sensitive = false;
        for (const auto& kw : config_.sensitivePathKeywords) {
            if (e.path.find(kw) != std::string::npos) {
                sensitive = true;
                break;
            }
        }

        if (sensitive) {
            std::ostringstream desc;
            desc << "Dangerous method " << e.method
                 << " used on sensitive path: " << e.path;
            alerts.push_back(makeAlert(
                e.sourceIP,
                "DANGEROUS_METHOD",
                AlertSeverity::MEDIUM,
                desc.str(),
                e.timestamp
            ));
        }
    }
}

//  Rule 5 — Unusual traffic spikes (per-hour volume analysis)
void ThreatDetector::checkTrafficSpikes(const std::vector<LogEntry>& entries,
                                        std::vector<Alert>& alerts) const {
    std::map<int, int> hourlyCounts;
    for (const auto& e : entries) {
        int hour = LogParser::extractHour(e.timestamp);
        if (hour >= 0) hourlyCounts[hour]++;
    }

    for (const auto& [hour, count] : hourlyCounts) {
        if (count > config_.trafficSpikeLimit) {
            std::ostringstream desc;
            desc << "Traffic spike detected at hour " << hour
                 << ":00 — " << count << " requests (limit: "
                 << config_.trafficSpikeLimit << ").";
            alerts.push_back(makeAlert(
                "SYSTEM",
                "TRAFFIC_SPIKE",
                AlertSeverity::MEDIUM,
                desc.str(),
                std::to_string(hour) + ":00"
            ));
        }
    }
}

//  printAlerts — formatted table to stdout
void ThreatDetector::printAlerts(const std::vector<Alert>& alerts) {
    const std::string SEP(80, '=');
    const std::string DIV(80, '-');

    std::cout << '\n' << SEP << '\n';
    std::cout << "                    THREAT DETECTION REPORT\n";
    std::cout << SEP << '\n';

    if (alerts.empty()) {
        std::cout << "\n  [INFO] No suspicious activities or threats detected.\n";
        std::cout << SEP << '\n';
        return;
    }

    std::cout << '\n'
              << std::left
              << std::setw(6)  << " ID"
              << std::setw(18) << " IP Address"
              << std::setw(26) << " Alert Type"
              << std::setw(10) << " Severity"
              << " Description\n";
    std::cout << DIV << '\n';

    for (const auto& a : alerts) {
        // Truncate description if very long
        std::string desc = a.description;
        if (desc.size() > 38) desc = desc.substr(0, 35) + "...";

        std::cout << std::left
                  << std::setw(6)  << (" " + std::to_string(a.alertID))
                  << std::setw(18) << (" " + a.ip)
                  << std::setw(26) << (" " + a.alertType)
                  << std::setw(10) << (" " + severityToString(a.severity))
                  << " " << desc << '\n';
    }

    std::cout << DIV << '\n';
    std::cout << "  [SUMMARY] Total Alerts: " << alerts.size() << '\n';

    // Severity breakdown
    std::map<AlertSeverity, int> sevCount;
    for (const auto& a : alerts) sevCount[a.severity]++;
    for (const auto& [sev, cnt] : sevCount) {
        std::cout << "            " << severityToString(sev) << ": " << cnt << '\n';
    }

    std::cout << SEP << '\n';
}
