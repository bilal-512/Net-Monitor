#pragma once

#include <string>
#include <vector>
#include "LogEntry.h"
#include "ThreatDetector.h"

//  Dashboard — drives the interactive command-line menu
class Dashboard {
public:
    Dashboard();

    // Start the interactive menu loop (blocking until user exits).
    void run();

private:
    // Application state
    std::vector<LogEntry> entries_;
    ProcessingStats       procStats_;
    AnalysisStats         analysisStats_;
    std::vector<Alert>    alerts_;
    ThreatDetector        detector_;
    bool                  dataLoaded_{false};

    // Output directory for reports
    std::string reportDir_;

    //  Menu handlers
    void menuLoadFile();
    void menuViewStats();
    void menuViewAlerts();
    void menuSearch();
    void menuExport();
    void menuConfigureThresholds();
    void menuAbout();

    //  Search sub-menu handlers
    void searchByIP();
    void searchByDateTime();
    void searchByMethod();
    void searchByStatus();
    void searchByPath();
    void searchErrors();
    void searchSuspicious();

    //  UI helpers
    static void printBanner();
    static void printMenu();
    static void printSearchMenu();
    static void separator(char c = '=', int width = 70);
    static std::string prompt(const std::string& message);
    static int  promptInt(const std::string& message, int defaultVal = 0);
    static void pause();
    static void clearScreen();

    // Recompute stats and alerts from current entries_.
    void recompute();
};
