#include "Dashboard.h"

//  main — entry point for the Network Monitoring & Log Analysis System
//
//  All logic is  in  Dashboard which manages the interactive
//  CLI session, loading, analysis, threat detection, search, and reporting.
int main() {
    Dashboard dashboard;
    dashboard.run();
    return 0;
}