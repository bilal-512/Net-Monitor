#pragma once

#include <vector>
#include <set>
#include <string>
#include "LogEntry.h"

//  ThreatConfig — configurable thresholds for threat detection rules
struct ThreatConfig {
    // Max allowed requests from a single IP before flagging as excessive
    int excessiveRequestLimit  = 10;

    // Max allowed failed login attempts before flagging
    int failedLoginLimit       = 3;

    // Max requests in a single hour before flagging as a traffic spike
    int trafficSpikeLimit      = 20;

    // Set of IP addresses that are always considered blocked/blacklisted
    std::set<std::string> blockedIPs = {
        "10.126.10.68"    // Example blacklisted IP from sample data
    };

    // Sensitive paths to watch for dangerous HTTP methods
    std::set<std::string> sensitivePathKeywords = {
        "admin", "api", "login", "home", "user", "auth", "dashboard"
    };
};

//  ThreatDetector — runs configurable detection rules over log entries
class ThreatDetector {
public:
    explicit ThreatDetector(const ThreatConfig& config = ThreatConfig{});

    // Run all detection rules and return a list of alerts.
    std::vector<Alert> detect(const std::vector<LogEntry>& entries) const;

    // Print alerts table to stdout.
    static void printAlerts(const std::vector<Alert>& alerts);

    // Update the active configuration.
    void setConfig(const ThreatConfig& config);
    const ThreatConfig& getConfig() const;

private:
    ThreatConfig config_;
    mutable int  nextAlertID_{1};

    void checkBlockedIPs      (const std::vector<LogEntry>& entries,
                               std::vector<Alert>& alerts) const;
    void checkExcessiveRequests(const std::vector<LogEntry>& entries,
                               std::vector<Alert>& alerts) const;
    void checkFailedLogins    (const std::vector<LogEntry>& entries,
                               std::vector<Alert>& alerts) const;
    void checkTrafficSpikes   (const std::vector<LogEntry>& entries,
                               std::vector<Alert>& alerts) const;
    void checkDangerousMethods(const std::vector<LogEntry>& entries,
                               std::vector<Alert>& alerts) const;

    Alert makeAlert(const std::string& ip,
                    const std::string& type,
                    AlertSeverity      severity,
                    const std::string& description,
                    const std::string& timestamp) const;
};
