#include "Dashboard.h"
#include "LogParser.h"
#include "Analyzer.h"
#include "SearchFilter.h"
#include "ReportGenerator.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <limits>
#include <algorithm>

//  Constructor
// ---------------------------------------------------------------------------
Dashboard::Dashboard()
    : reportDir_("reports") {}

// ---------------------------------------------------------------------------
//  UI Helpers
// ---------------------------------------------------------------------------
void Dashboard::separator(char c, int width) {
    std::cout << std::string(width, c) << '\n';
}

void Dashboard::clearScreen() {
    // ANSI escape 
    std::cout << "\033[2J\033[H";
}

std::string Dashboard::prompt(const std::string& message) {
    std::cout << "\n  >> " << message << ": ";
    std::string input;
    std::getline(std::cin, input);
    return input;
}

int Dashboard::promptInt(const std::string& message, int defaultVal) {
    std::string raw = prompt(message + " [default: " + std::to_string(defaultVal) + "]");
    if (raw.empty()) return defaultVal;
    try   { return std::stoi(raw); }
    catch (...) { return defaultVal; }
}

void Dashboard::pause() {
    std::cout << "\n  Press ENTER to continue...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

//  Banner
void Dashboard::printBanner() {
    separator('=', 70);
    std::cout << R"(
  ███╗   ██╗███████╗████████╗    ███╗   ███╗ ██████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝    ████╗ ████║██╔═══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║       ██╔████╔██║██║   ██║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║       ██║╚██╔╝██║██║   ██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║       ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
)" << '\n';
    std::cout << "         Network Monitoring & Log Analysis System\n";
    std::cout << "                    Teyzix Internship  \n\n";
    separator('=', 70);
}

//  Main Menu
// ---------------------------------------------------------------------------
void Dashboard::printMenu() {
    std::cout << "\n";
    separator('-', 70);
    std::cout << "  MAIN MENU\n";
    separator('-', 70);
    std::cout << "  [1]  Load Log File\n";
    std::cout << "  [2]  View Activity Statistics\n";
    std::cout << "  [3]  View Threat Alerts\n";
    std::cout << "  [4]  Search & Filter Logs\n";
    std::cout << "  [5]  Export Report\n";
    std::cout << "  [6]  Configure Detection Thresholds\n";
    std::cout << "  [7]  About\n";
    std::cout << "  [0]  Exit\n";
    separator('-', 70);
}

//  Search Sub-Menu
void Dashboard::printSearchMenu() {
    std::cout << "\n";
    separator('-', 70);
    std::cout << "  SEARCH & FILTER\n";
    separator('-', 70);
    std::cout << "  [1]  Search by IP Address\n";
    std::cout << "  [2]  Search by Date / Time\n";
    std::cout << "  [3]  Filter by HTTP Method\n";
    std::cout << "  [4]  Filter by Status Code Range\n";
    std::cout << "  [5]  Search by Path Keyword\n";
    std::cout << "  [6]  Show Error Records Only (4xx/5xx)\n";
    std::cout << "  [7]  Show Suspicious Records (DELETE/PUT)\n";
    std::cout << "  [0]  Back to Main Menu\n";
    separator('-', 70);
}

//  recompute — rebuild stats and alerts from current entries_
void Dashboard::recompute() {
    analysisStats_ = Analyzer::analyze(entries_);
    alerts_        = detector_.detect(entries_);
}

//  run — main event loop
void Dashboard::run() {
    clearScreen();
    printBanner();

    while (true) {
        printMenu();

        // Status line
        if (dataLoaded_) {
            std::cout << "  Loaded: " << procStats_.filename
                      << " (" << procStats_.validEntries << " entries, "
                      << alerts_.size() << " alerts)\n";
        } else {
            std::cout << "  Status: No log file loaded.\n";
        }

        std::string choice = prompt("Enter choice");

        if (choice == "0") {
            std::cout << "\n  Goodbye!\n\n";
            break;
        } else if (choice == "1") {
            menuLoadFile();
        } else if (choice == "2") {
            if (!dataLoaded_) { std::cout << "\n  [!] Please load a log file first.\n"; pause(); continue; }
            menuViewStats();
        } else if (choice == "3") {
            if (!dataLoaded_) { std::cout << "\n  [!] Please load a log file first.\n"; pause(); continue; }
            menuViewAlerts();
        } else if (choice == "4") {
            if (!dataLoaded_) { std::cout << "\n  [!] Please load a log file first.\n"; pause(); continue; }
            menuSearch();
        } else if (choice == "5") {
            if (!dataLoaded_) { std::cout << "\n  [!] Please load a log file first.\n"; pause(); continue; }
            menuExport();
        } else if (choice == "6") {
            menuConfigureThresholds();
        } else if (choice == "7") {
            menuAbout();
        } else {
            std::cout << "\n  [!] Invalid choice. Please try again.\n";
        }
    }
}

//  [1] Load Log File
void Dashboard::menuLoadFile() {
    separator('=', 70);
    std::cout << "  LOAD LOG FILE\n";
    separator('=', 70);

    std::string filename = prompt("Enter path to log file");
    if (filename.empty()) {
        std::cout << "\n  [!] No filename entered.\n";
        pause();
        return;
    }

    std::vector<LogEntry> newEntries;
    ProcessingStats       newStats;

    std::cout << "\n  Loading file...\n";
    if (!LogParser::loadFile(filename, newEntries, newStats)) {
        std::cout << "\n  [ERROR] Failed to open: " << filename << '\n';
        pause();
        return;
    }

    entries_   = std::move(newEntries);
    procStats_ = newStats;
    recompute();
    dataLoaded_ = true;

    separator('-', 70);
    std::cout << "  File loaded successfully!\n\n";
    std::cout << std::left
              << std::setw(30) << "  Total Lines Read"   << procStats_.totalLines     << '\n'
              << std::setw(30) << "  Valid Entries"       << procStats_.validEntries   << '\n'
              << std::setw(30) << "  Invalid Lines"       << procStats_.invalidEntries << '\n'
              << std::setw(30) << "  Unique IPs"          << analysisStats_.uniqueIPs  << '\n'
              << std::setw(30) << "  Alerts Detected"     << alerts_.size()            << '\n';
    separator('-', 70);
    pause();
}

//  [2] View Activity Statistics
void Dashboard::menuViewStats() {
    Analyzer::printSummary(analysisStats_);
    pause();
}

//  [3] View Threat Alerts
void Dashboard::menuViewAlerts() {
    ThreatDetector::printAlerts(alerts_);
    pause();
}

//  [4] Search & Filter Logs
void Dashboard::menuSearch() {
    while (true) {
        printSearchMenu();
        std::string choice = prompt("Enter choice");

        if      (choice == "0") break;
        else if (choice == "1") searchByIP();
        else if (choice == "2") searchByDateTime();
        else if (choice == "3") searchByMethod();
        else if (choice == "4") searchByStatus();
        else if (choice == "5") searchByPath();
        else if (choice == "6") searchErrors();
        else if (choice == "7") searchSuspicious();
        else std::cout << "\n  [!] Invalid choice.\n";
    }
}

void Dashboard::searchByIP() {
    std::string ip = prompt("Enter IP address or prefix");
    auto results = SearchFilter::byIP(entries_, ip);
    std::cout << "\n  Results for IP: " << ip << '\n';
    SearchFilter::printEntries(results);
    pause();
}

void Dashboard::searchByDateTime() {
    std::cout << "\n  Tip: Enter a fragment like 'Jun 29', '2026', '15:' etc.\n";
    std::string frag = prompt("Enter date/time fragment");
    auto results = SearchFilter::byTimestamp(entries_, frag);
    std::cout << "\n  Results for timestamp containing: \"" << frag << "\"\n";
    SearchFilter::printEntries(results);
    pause();
}

void Dashboard::searchByMethod() {
    std::cout << "\n  Available methods: GET, POST, PUT, DELETE, HEAD, OPTIONS\n";
    std::string method = prompt("Enter HTTP method");
    auto results = SearchFilter::byMethod(entries_, method);
    std::cout << "\n  Results for method: " << method << '\n';
    SearchFilter::printEntries(results);
    pause();
}

void Dashboard::searchByStatus() {
    int minCode = promptInt("Minimum status code", 400);
    int maxCode = promptInt("Maximum status code", 599);
    auto results = SearchFilter::byStatusRange(entries_, minCode, maxCode);
    std::cout << "\n  Results for status " << minCode << "-" << maxCode << ":\n";
    SearchFilter::printEntries(results);
    pause();
}

void Dashboard::searchByPath() {
    std::string kw = prompt("Enter path keyword");
    auto results = SearchFilter::byPath(entries_, kw);
    std::cout << "\n  Results for path containing: \"" << kw << "\"\n";
    SearchFilter::printEntries(results);
    pause();
}

void Dashboard::searchErrors() {
    auto results = SearchFilter::errorsOnly(entries_);
    std::cout << "\n  All Error Records (4xx/5xx):\n";
    SearchFilter::printEntries(results);
    pause();
}

void Dashboard::searchSuspicious() {
    auto results = SearchFilter::suspiciousOnly(entries_);
    std::cout << "\n  Suspicious Records (DELETE/PUT methods):\n";
    SearchFilter::printEntries(results);
    pause();
}

//  [5] Export Report
void Dashboard::menuExport() {
    separator('=', 70);
    std::cout << "  EXPORT REPORT\n";
    separator('=', 70);
    std::cout << "  [1]  Export Full Report (.txt)\n";
    std::cout << "  [2]  Export Log Data (.csv)\n";
    std::cout << "  [3]  Export Both\n";
    std::cout << "  [0]  Back\n";
    separator('-', 70);

    std::string choice = prompt("Enter choice");

    Report report = ReportGenerator::buildReport(analysisStats_, alerts_, procStats_);

    if (choice == "0") return;

    if (choice == "1" || choice == "3") {
        std::string path = ReportGenerator::exportTXT(
            report, analysisStats_, alerts_, procStats_, reportDir_);
        if (!path.empty())
            std::cout << "\n  [OK] TXT report saved to: " << path << '\n';
    }

    if (choice == "2" || choice == "3") {
        std::string path = ReportGenerator::exportCSV(entries_, reportDir_);
        if (!path.empty())
            std::cout << "\n  [OK] CSV export saved to:  " << path << '\n';
    }

    pause();
}

//  [6] Configure Detection Thresholds
void Dashboard::menuConfigureThresholds() {
    separator('=', 70);
    std::cout << "  CONFIGURE DETECTION THRESHOLDS\n";
    separator('=', 70);

    ThreatConfig cfg = detector_.getConfig();

    std::cout << "\n  Current settings:\n";
    std::cout << "    Excessive Request Limit : " << cfg.excessiveRequestLimit  << '\n';
    std::cout << "    Failed Login Limit      : " << cfg.failedLoginLimit       << '\n';
    std::cout << "    Traffic Spike Limit     : " << cfg.trafficSpikeLimit      << '\n';
    std::cout << "    Blocked IPs             : ";
    for (const auto& ip : cfg.blockedIPs) std::cout << ip << " ";
    std::cout << '\n';

    separator('-', 70);
    std::cout << "  [1]  Change Excessive Request Limit\n";
    std::cout << "  [2]  Change Failed Login Limit\n";
    std::cout << "  [3]  Change Traffic Spike Limit\n";
    std::cout << "  [4]  Add a Blocked IP\n";
    std::cout << "  [5]  Remove a Blocked IP\n";
    std::cout << "  [0]  Back\n";
    separator('-', 70);

    std::string choice = prompt("Enter choice");

    if (choice == "1") {
        cfg.excessiveRequestLimit = promptInt("New excessive request limit", cfg.excessiveRequestLimit);
    } else if (choice == "2") {
        cfg.failedLoginLimit = promptInt("New failed login limit", cfg.failedLoginLimit);
    } else if (choice == "3") {
        cfg.trafficSpikeLimit = promptInt("New traffic spike limit", cfg.trafficSpikeLimit);
    } else if (choice == "4") {
        std::string ip = prompt("Enter IP to block");
        if (!ip.empty()) {
            cfg.blockedIPs.insert(ip);
            std::cout << "\n  [OK] IP " << ip << " added to blocklist.\n";
        }
    } else if (choice == "5") {
        std::string ip = prompt("Enter IP to remove from blocklist");
        if (cfg.blockedIPs.erase(ip)) {
            std::cout << "\n  [OK] IP " << ip << " removed from blocklist.\n";
        } else {
            std::cout << "\n  [!] IP not found in blocklist.\n";
        }
    }

    detector_.setConfig(cfg);

    // Re-run detection with updated config if data is loaded
    if (dataLoaded_) {
        alerts_ = detector_.detect(entries_);
        std::cout << "\n  [OK] Thresholds updated. Re-detected " << alerts_.size() << " alerts.\n";
    }

    pause();
}

//  [7] About
void Dashboard::menuAbout() {
    separator('=', 70);
    std::cout << "  ABOUT\n";
    separator('=', 70);
    std::cout << R"(
  Network Monitoring & Log Analysis System
  Task ID  : CPP-2
  Domain   : C/C++ Development
  Company  : Teyzix  

  Features:
    * Log file parsing with error handling
    * Activity analysis & statistics
    * Multi-rule threat detection engine
    * Configurable detection thresholds
    * Search & filtering by IP, time, method, status, path
    * TXT report & CSV export

  Technology: C++20 | STL only
  Author   : Muhammad Bilal
)";
    separator('=', 70);
    pause();
}
