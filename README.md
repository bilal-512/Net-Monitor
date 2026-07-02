# Network Monitoring & Log Analysis System

**Task ID:** CPP-2 | **Domain:** C/C++ Development | **Teyzix Internship**

A high-performance, modular C++ console application for processing network activity logs, detecting threats, generating statistics, and producing actionable monitoring reports.

---

## Features

| Module | Capability |
|---|---|
| **Log Parser** | Regex-based parsing of HTTP access logs; handles corrupt/invalid lines gracefully |
| **Activity Analyzer** | Total requests, unique IPs, top IPs, HTTP method breakdown, status code distribution, hourly bar chart |
| **Threat Detector** | 5 configurable detection rules with severity levels (LOW/MEDIUM/HIGH/CRITICAL) |
| **Search & Filter** | Filter by IP, date/time, HTTP method, status code range, path keyword |
| **Report Generator** | TXT report and CSV log export to `reports/` directory |
| **CLI Dashboard** | Interactive menu-driven interface; configure thresholds at runtime |

### Threat Detection Rules
1. **Blocked IP Access** — flags requests from a configurable blacklist (CRITICAL)
2. **Rate Limit Exceeded** — excessive requests from a single IP (HIGH)
3. **Suspicious Auth Attempts** — repeated failures on sensitive paths (HIGH)
4. **Dangerous Methods** — DELETE/PUT on sensitive paths like `/login`, `/api`, `/admin` (MEDIUM)
5. **Traffic Spike** — per-hour request volume exceeding threshold (MEDIUM)

---

## Project Structure

```
Network-Monitor/
├── include/
│   ├── LogEntry.h          # Core data structures
│   ├── LogParser.h         # Log file parser interface
│   ├── Analyzer.h          # Activity statistics engine
│   ├── ThreatDetector.h    # Threat detection engine
│   ├── SearchFilter.h      # Search & filtering interface
│   ├── ReportGenerator.h   # Report & export interface
│   └── Dashboard.h         # Interactive CLI controller
├── src/
│   ├── main.cpp            # Entry point
│   ├── LogParser.cpp
│   ├── Analyzer.cpp
│   ├── ThreatDetector.cpp
│   ├── SearchFilter.cpp
│   ├── ReportGenerator.cpp
│   └── Dashboard.cpp
├── data/                   # Sample log files
├── reports/                # Generated reports output here
├── build/                  # CMake build directory
└── CMakeLists.txt
```

---

## Log Format Supported

```
<IP> - - [Mon DD YYYY, HH:MM:SS] "METHOD PATH PROTOCOL" STATUS SIZE "REFERRER" "USER-AGENT"
```

Example:
```
192.168.1.1 - - [Jun 29 2026, 10:00:00] "GET /login HTTP/1.1" 200 1024 "https://google.com" "Mozilla/5.0"
```

---

## Build Instructions

### Prerequisites
- CMake ≥ 3.20
- GCC ≥ 10 or Clang ≥ 12 (C++20 support required)

### Build
```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Run
```bash
./Network-Monitor
```

---

## Usage

On launch, use the interactive menu:

```
[1]  Load Log File                 — provide path to your .log/.txt file
[2]  View Activity Statistics      — full analytics summary with hourly chart
[3]  View Threat Alerts            — table of all detected security alerts
[4]  Search & Filter Logs          — sub-menu for IP/time/method/status/path search
[5]  Export Report                 — save TXT report or CSV to reports/
[6]  Configure Detection Thresholds — adjust rate limits, blocked IPs at runtime
[7]  About
[0]  Exit
```

---

## Technology

- **Language:** C++20
- **Libraries:** STL only (`vector`, `map`, `set`, `regex`, `fstream`, `algorithm`, `chrono`, `iomanip`)
- **Build System:** CMake

---

