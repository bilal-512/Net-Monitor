#pragma once

#include <string>
#include <vector>
#include "LogEntry.h"

//  ReportGenerator — produces TXT and CSV reports from analysis results
class ReportGenerator {
public:
    // Build a Report metadata object from current analysis state.
    static Report buildReport(const AnalysisStats&       stats,
                              const std::vector<Alert>&  alerts,
                              const ProcessingStats&     procStats);

    // Write a full human-readable TXT report to the reports/ directory.
    // Returns the path of the file written, or empty string on failure.
    static std::string exportTXT(const Report&              report,
                                 const AnalysisStats&       stats,
                                 const std::vector<Alert>&  alerts,
                                 const ProcessingStats&     procStats,
                                 const std::string&         outputDir = "reports");

    // Write a CSV file of all log entries to the reports/ directory.
    // Returns the path of the file written, or empty string on failure.
    static std::string exportCSV(const std::vector<LogEntry>& entries,
                                 const std::string&           outputDir = "reports");

    // Print the report summary to stdout (no file I/O).
    static void printReport(const Report&             report,
                            const AnalysisStats&      stats,
                            const std::vector<Alert>& alerts,
                            const ProcessingStats&    procStats);

private:
    // Get current date-time string in a filename-safe format.
    static std::string currentTimestamp(bool filenameSafe = false);

    // Ensure the output directory exists (creates it if missing).
    static bool ensureDir(const std::string& dir);
};
