#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <iomanip>
#include <map>
#include <set>
#include <algorithm>

using namespace std;

struct LogEntry {
    string ip;
    string timestamp; 
    string method;
    string path;
    string protocol;
    int status_code;
    long long response_size;
    string referrer;
    string user_agent;
};

// Security Alert Structure
struct Alert {
    string ip;
    string type;
    string details;
    string timestamp;
};

bool parseLogLine(const string &line, LogEntry &entry) {
    static const regex log_regex(
        R"raw(^([0-9.]+) - - \[(.*?)\] "([A-Z]+) ([^ ]+) ([^"]+)" ([0-9]+) ([0-9]+) "([^"]*)" "([^"]*)")raw"
    );
    smatch match;
    if (regex_search(line, match, log_regex)) {
        entry.ip = match[1].str();
        entry.timestamp = match[2].str();
        entry.method = match[3].str();
        entry.path = match[4].str();
        entry.protocol = match[5].str();
        entry.status_code = stoi(match[6].str());
        entry.response_size = stoll(match[7].str());
        entry.referrer = match[8].str();
        entry.user_agent = match[9].str();
        return true;
    }
    return false;
}

int extractHour(const string &timestamp) {
    size_t comma_pos = timestamp.find(',');
    if (comma_pos != string::npos && comma_pos + 2 < timestamp.length()) {
        try { return stoi(timestamp.substr(comma_pos + 2, 2)); } catch (...) { return -1; }
    }
    return -1;
}

void processFile(const string &filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Error opening file: " << filename << endl;
        return;
    }

    // --- Threat Detection Configuration ---
    const int EXCESSIVE_REQUEST_LIMIT = 2; // Low for sample data; set higher (e.g., 100+) for production
    const int TRAFFIC_SPIKE_LIMIT = 3;     // Max requests allowed per hour before a spike alert triggers
    const set<string> BLOCKED_IPS = {"10.126.10.68"}; // Simulated blacklisted IPs

    // State Trackers
    map<string, int> ip_request_counts;
    map<string, int> failed_logins;
    map<int, int> hourly_counts;
    vector<Alert> alerts;

    string line;
    while (getline(file, line)) {
        LogEntry entry;
        if (parseLogLine(line, entry)) {
            
            // 1. Check for Access from Blocked IPs
            if (BLOCKED_IPS.count(entry.ip)) {
                alerts.push_back({entry.ip, "BLOCKED_IP_ACCESS", "Attempted access from a blacklisted IP address.", entry.timestamp});
            }

            // Track stats for window/threshold rules
            ip_request_counts[entry.ip]++;
            int hour = extractHour(entry.timestamp);
            if (hour != -1) { hourly_counts[hour]++; }

            // 2. Check for Excessive Requests (Rate Limiting)
            if (ip_request_counts[entry.ip] == EXCESSIVE_REQUEST_LIMIT + 1) { // Trigger alert once when threshold crossed
                alerts.push_back({entry.ip, "RATE_LIMIT_EXCEEDED", "IP exceeded maximum request limit threshold.", entry.timestamp});
            }

            // 3. Check for Repeated Failed Logins / Suspicious Auth
            // (Simulated tracking: non-GET requests on home/api/login returning client/server errors)
            if ((entry.path.find("home") != string::npos || entry.path.find("api") != string::npos) && 
                (entry.method == "POST" || entry.method == "DELETE" || entry.status_code >= 400)) {
                
                failed_logins[entry.ip]++;
                if (failed_logins[entry.ip] >= 2) { // Alert on multiple failed/destructive attempts
                    alerts.push_back({entry.ip, "SUSPICIOUS_AUTH_ATTEMPT", "Repeated failed or destructive actions on authentication endpoints.", entry.timestamp});
                }
            }

            // 4. Custom Rule-Based Alert (Example: Flagging any HTTP DELETE request)
            if (entry.method == "DELETE") {
                alerts.push_back({entry.ip, "CUSTOM_RULE_VIOLATION", "Dangerous HTTP method (DELETE) executed.", entry.timestamp});
            }
        }
    }
    file.close();

    // 5. Check for Unusual Traffic Spikes (Post-processing check)
    for (const auto &hour_data : hourly_counts) {
        if (hour_data.second > TRAFFIC_SPIKE_LIMIT) {
            alerts.push_back({"SYSTEM", "TRAFFIC_SPIKE_DETECTED", "Unusual traffic volume in hour block " + to_string(hour_data.first) + ":00 (" + to_string(hour_data.second) + " requests)", "N/A"});
        }
    }

    // ==========================================
    //          THREAT DETECTION REPORT
    // ==========================================
    cout << "\n" << string(22, '=') << " THREAT DETECTION REPORT " << string(22, '=') << endl;
    
    if (alerts.empty()) {
        cout << "[INFO] No suspicious activities or threats detected." << endl;
    } else {
        cout << left << setw(16) << "Target IP" 
             << setw(23) << "Alert Type" 
             << "Description" << endl;
        cout << string(70, '-') << endl;

        for (const auto &alert : alerts) {
            cout << left << setw(16) << alert.ip 
                 << setw(23) << alert.type 
                 << alert.details << endl;
        }
        cout << string(70, '-') << endl;
        cout << "[SUMMARY] Total Threat Incidents Flagged: " << alerts.size() << endl;
    }
    cout << string(69, '=') << endl;
}

int main() {
    string filename = "/home/bilal/Desktop/Internship-Teyzix/Network-Monitor/Network-Monitor/file1.txt";
    processFile(filename);
    return 0;
}