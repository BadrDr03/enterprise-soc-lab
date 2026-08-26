# Enterprise SOC Lab

### Detection, Threat Hunting, and Incident Response using Splunk SIEM

Enterprise-grade Security Operations Center laboratory built for learning Detection Engineering, Threat Hunting, and Incident Response.

---

## 1. Project Description

Enterprise SOC Lab is a practical cybersecurity project designed to simulate the daily operations of a Security Operations Center (SOC).

The laboratory recreates a small enterprise environment composed of an Active Directory Domain Controller, a Windows 11 workstation, a Kali Linux attacker machine, and a centralized Splunk SIEM server.

The project demonstrates the complete SOC lifecycle, including log collection, endpoint telemetry, controlled attack simulation, detection engineering, threat hunting, threat intelligence enrichment, incident investigation, and technical documentation.

Rather than focusing solely on tool installation, the project emphasizes understanding how modern SOC teams detect, analyze, investigate, and respond to cyber threats in a controlled enterprise environment.

---

## 2. Network Architecture

The lab simulates a small enterprise environment deployed on a VirtualBox NAT Network (`10.0.10.0/24`).

It includes:

- a centralized Splunk SIEM server;
- an Active Directory Domain Controller;
- a Windows 11 target endpoint;
- a Kali Linux attack simulation machine.

Windows endpoint telemetry is generated through Sysmon and forwarded to Splunk using the Splunk Universal Forwarder.

Kali Linux and Atomic Red Team are used to generate controlled security testing activity, while external Threat Intelligence services enrich public IP indicators during investigations.

![Enterprise SOC Lab Network Architecture](docs/architecture/network-diagram.png)

**Figure 1 — Enterprise SOC Lab network architecture and security data flow.**

Detailed architecture documentation is available in:

[`docs/architecture/architecture.md`](docs/architecture/architecture.md)

---

## 3. Project Scope

### Included

| Component | Status |
|---|---|
| Splunk SIEM | ✅ |
| Windows Event Logs | ✅ |
| Sysmon | ✅ |
| Active Directory | ✅ |
| Splunk Universal Forwarder | ✅ |
| Atomic Red Team | ✅ |
| Threat Hunting | ✅ |
| Detection Engineering | ✅ |
| Incident Investigation | ✅ |
| Threat Intelligence | ✅ |
| Dashboards | ✅ |
| Documentation | ✅ |

### Excluded

| Component | Reason |
|---|---|
| Docker | Outside project scope |
| SOAR | Outside project scope |
| Kubernetes | Outside project scope |
| Cloud Deployment | Outside project scope |
| Splunk Clustering | Outside project scope |
| Commercial EDR | Outside project scope |
| Production Deployment | Lab environment only |

---

## 4. Project Objectives

- Design a realistic enterprise SOC laboratory.
- Centralize endpoint telemetry using Splunk SIEM.
- Monitor Windows security events and Sysmon telemetry.
- Develop detection logic for multiple attack scenarios.
- Generate controlled security events using Atomic Red Team and Kali Linux.
- Perform threat hunting activities using Splunk SPL.
- Investigate security incidents using SOC methodologies.
- Apply the Five Whys technique for root cause analysis.
- Integrate automated Threat Intelligence enrichment.
- Build centralized SOC monitoring dashboards.
- Apply an incident response methodology to detected activity.
- Produce professional technical documentation and incident reports.

---

## 5. Technology Stack

The SOC laboratory combines endpoint telemetry, centralized log analysis, attack simulation, threat intelligence, and custom automation.

| Component | Technology | Purpose |
|---|---|---|
| SIEM | Splunk Free | Centralized log collection, searching, detection, alerting, and dashboards |
| Endpoint Telemetry | Sysmon | Detailed Windows process, network, registry, and system activity |
| Log Forwarding | Splunk Universal Forwarder | Forwards Windows telemetry to the Splunk server |
| Endpoint | Windows 11 | Primary monitored workstation and simulation target |
| Identity Infrastructure | Windows Active Directory Domain Controller | Authentication and domain-related telemetry |
| SIEM Server | Ubuntu Server | Hosts Splunk and Threat Intelligence automation |
| Attack Simulation Machine | Kali Linux | Controlled security testing environment |
| Attack Simulation | Atomic Red Team | Generates ATT&CK-aligned security telemetry |
| Threat Intelligence | VirusTotal | IP reputation and malicious indicator enrichment |
| Threat Intelligence | AbuseIPDB | IP abuse reputation and reporting information |
| Threat Intelligence | AlienVault OTX | Threat intelligence pulse and ASN context |
| Automation | Python | Automated Threat Intelligence collection and enrichment |
| Scheduling | Cron | Periodic execution of the enrichment workflow |
| Framework | MITRE ATT&CK | Mapping simulations and detection scenarios |

---

## 6. Repository Structure

The repository separates architecture documentation, detection use cases, incident response reports, evidence, automation scripts, and Splunk dashboard documentation.

```text
enterprise-soc-lab/
│
├── docs/
│   ├── architecture/
│   │   ├── architecture.md
│   │   └── network-diagram.png
│   │
│   ├── use-cases/
│   │   ├── UC-000-Environment-Setup.md
│   │   ├── UC-001-Suspicious-PowerShell.md
│   │   ├── UC-002-Encoded-PowerShell.md
│   │   ├── UC-003-System-Information-Discovery.md
│   │   ├── UC-004-Registry-Run-Key-Persistence.md
│   │   ├── UC-005-LSASS-Credential-Dumping.md
│   │   ├── UC-006-Obfuscated-PowerShell.md
│   │   ├── UC-007-RDP-Lateral-Movement-Detection.md
│   │   ├── UC-008-Archive-Collected-Data.md
│   │   └── UC-009-HTTP-Data-Exfiltration.md
│   │
│   └── incident-reports/
│       ├── README.md
│       ├── IR-001-Suspicious-PowerShell.md
│       ├── IR-002-Encoded-PowerShell.md
│       ├── IR-003-System-Information-Discovery.md
│       ├── IR-004-Registry-Run-Key-Persistence.md
│       ├── IR-005-LSASS-Credential-Dumping.md
│       ├── IR-006-Obfuscated-PowerShell.md
│       ├── IR-007-RDP-Lateral-Movement.md
│       ├── IR-008-Archive-Collected-Data.md
│       └── IR-009-HTTP-Data-Exfiltration.md
│
├── screenshots/
│   ├── infrastructure/
│   ├── detections/
│   ├── dashboards/
│   └── threat-intelligence/
│
├── scripts/
│   └── threat-intel/
│       ├── README.md
│       ├── virustotal_lookup.py
│       ├── abuseipdb_lookup.py
│       ├── otx_lookup.py
│       ├── enrich_ip.py
│       └── auto_enrich.py
│
└── splunk/
    └── dashboards/
        └── README.md
```

Detailed SPL searches and detection logic are documented directly inside the corresponding use-case files to avoid duplicating detection content across the repository.

---

## 7. Detection Use Cases

The laboratory implements nine security detection scenarios covering multiple stages of the MITRE ATT&CK lifecycle.

| ID | Detection Scenario | ATT&CK Category |
|---|---|---|
| [UC-001](docs/use-cases/UC-001-Suspicious-PowerShell.md) | Suspicious PowerShell Execution | Execution |
| [UC-002](docs/use-cases/UC-002-Encoded-PowerShell.md) | Encoded PowerShell Execution | Execution |
| [UC-003](docs/use-cases/UC-003-System-Information-Discovery.md) | System Information Discovery | Discovery |
| [UC-004](docs/use-cases/UC-004-Registry-Run-Key-Persistence.md) | Registry Run Key Persistence | Persistence |
| [UC-005](docs/use-cases/UC-005-LSASS-Credential-Dumping.md) | LSASS Credential Dumping | Credential Access |
| [UC-006](docs/use-cases/UC-006-Obfuscated-PowerShell.md) | Obfuscated PowerShell | Defense Evasion |
| [UC-007](docs/use-cases/UC-007-RDP-Lateral-Movement-Detection.md) | RDP Lateral Movement | Lateral Movement |
| [UC-008](docs/use-cases/UC-008-Archive-Collected-Data.md) | Archive Collected Data | Collection |
| [UC-009](docs/use-cases/UC-009-HTTP-Data-Exfiltration.md) | HTTP Data Exfiltration | Exfiltration |

Each use case documents the attack simulation, generated telemetry, Splunk investigation, detection logic, evidence, MITRE ATT&CK mapping, and analysis.

---

## 8. Incident Response Reports

Each detection scenario is complemented by an incident response report describing how a SOC analyst could respond to the detected activity.

| Incident | Scenario | Severity |
|---|---|---|
| [IR-001](docs/incident-reports/IR-001-Suspicious-PowerShell.md) | Suspicious PowerShell | Medium |
| [IR-002](docs/incident-reports/IR-002-Encoded-PowerShell.md) | Encoded PowerShell | High |
| [IR-003](docs/incident-reports/IR-003-System-Information-Discovery.md) | System Information Discovery | Medium |
| [IR-004](docs/incident-reports/IR-004-Registry-Run-Key-Persistence.md) | Registry Run Key Persistence | High |
| [IR-005](docs/incident-reports/IR-005-LSASS-Credential-Dumping.md) | LSASS Credential Dumping | Critical |
| [IR-006](docs/incident-reports/IR-006-Obfuscated-PowerShell.md) | Obfuscated PowerShell | High |
| [IR-007](docs/incident-reports/IR-007-RDP-Lateral-Movement.md) | RDP Lateral Movement | High |
| [IR-008](docs/incident-reports/IR-008-Archive-Collected-Data.md) | Archive Collected Data | High |
| [IR-009](docs/incident-reports/IR-009-HTTP-Data-Exfiltration.md) | HTTP Data Exfiltration | Critical |

The reports follow the PICERL lifecycle:

```text
Preparation
     ↓
Identification
     ↓
Containment
     ↓
Eradication
     ↓
Recovery
     ↓
Lessons Learned
```

This extends the laboratory from detection engineering into SOC investigation and incident response.

Detailed incident response documentation is available in:

[`docs/incident-reports/README.md`](docs/incident-reports/README.md)

---

## 9. Automated Threat Intelligence Enrichment

The laboratory integrates automated Threat Intelligence enrichment for public destination IP addresses observed in Windows network telemetry.

Three external intelligence sources are used:

- VirusTotal
- AbuseIPDB
- AlienVault OTX

### Enrichment Pipeline

```text
Windows Network Events
        ↓
Splunk
        ↓
Scheduled Public IP Export
        ↓
public_ips.csv
        ↓
auto_enrich.py
        ↓
┌───────────────────────┐
│ VirusTotal            │
│ AbuseIPDB             │
│ AlienVault OTX        │
└───────────────────────┘
        ↓
threat_intel.csv
        ↓
Splunk Lookup
        ↓
Enriched Investigation Data
```

Splunk periodically exports observed public destination IP addresses.

The Python enrichment workflow reads these indicators, queries the configured Threat Intelligence providers, combines the results, and updates the Splunk lookup.

The process is executed automatically through a cron job, reducing the need for manual IP reputation checks during investigations.

API credentials are stored outside the repository and are not committed to GitHub.

Detailed implementation documentation is available in:

[`scripts/threat-intel/README.md`](scripts/threat-intel/README.md)

---

## 10. SOC Security Overview Dashboard

A centralized Splunk dashboard was developed to provide a high-level view of activity across the laboratory.

The dashboard includes visibility into:

1. Security Events Over Time
2. Events by Host
3. Sysmon Event Distribution
4. Authentication Activity
5. RDP Activity
6. Top External Destination IPs
7. Threat Intelligence Overview
8. PowerShell Activity
9. Detection Alerts Activity
10. Network Connections by Process

The dashboard combines operational monitoring and investigation context in a single SOC interface.

### Time Range Design

Different time ranges are intentionally used depending on the purpose of each panel.

The **Security Events Over Time** panel uses a recent monitoring window such as the last 24 hours because its purpose is to provide operational visibility into recent activity and event-volume changes.

Several investigation and laboratory-history panels use **All time** because the controlled simulations were executed at different moments and their historical telemetry remains useful for validation and investigation.

The **Threat Intelligence Overview** reads the current content of the `threat_intel.csv` lookup and therefore does not depend on a traditional Splunk event time range.

In a production SOC environment, these time windows would normally be adjusted according to operational requirements.

### Dashboard Evidence

![SOC Security Overview - Part 1](screenshots/dashboards/dashboard-soc-overview-01.png)

![SOC Security Overview - Part 2](screenshots/dashboards/dashboard-soc-overview-02.png)

![SOC Security Overview - Part 3](screenshots/dashboards/dashboard-soc-overview-03.png)

Detailed dashboard documentation is available in:

[`splunk/dashboards/README.md`](splunk/dashboards/README.md)

---

## 11. Detection and Investigation Workflow

The laboratory demonstrates an end-to-end SOC workflow rather than isolated attack simulations.

```text
Controlled Attack Simulation
        ↓
Windows Endpoint
        ↓
Sysmon / Windows Event Telemetry
        ↓
Splunk Universal Forwarder
        ↓
Splunk SIEM
        ↓
Detection Logic
        ↓
SOC Alert / Investigation
        ↓
Telemetry Correlation
        ↓
Threat Intelligence Enrichment
        ↓
Incident Classification
        ↓
Incident Response
```

This workflow demonstrates how raw endpoint telemetry can be transformed into actionable security information.

---

## 12. Key Project Results

The completed laboratory demonstrates:

- centralized Windows security monitoring using Splunk;
- detailed endpoint telemetry collection using Sysmon;
- monitoring of both a Windows workstation and Active Directory environment;
- nine documented attack and detection scenarios;
- MITRE ATT&CK-aligned detection coverage;
- Splunk alerting for suspicious activity;
- investigation of process, authentication, registry, and network telemetry;
- automated public IP Threat Intelligence enrichment;
- integration of VirusTotal, AbuseIPDB, and AlienVault OTX;
- automated enrichment execution using Python and cron;
- centralized SOC monitoring through a ten-panel Splunk dashboard;
- nine incident response reports based on detected activity;
- structured technical evidence through screenshots and documentation.

The final environment demonstrates the complete path from:

```text
Telemetry
   ↓
Detection
   ↓
Investigation
   ↓
Enrichment
   ↓
Response
```

---

## 13. Laboratory Limitations

This project was developed as an isolated educational SOC laboratory rather than a production SOC environment.

The main limitations include:

- Splunk Free ingestion and feature limitations;
- a small number of monitored endpoints;
- controlled security simulations rather than real adversary activity;
- external Threat Intelligence results dependent on public API availability and rate limits;
- periodic rather than real-time Threat Intelligence enrichment;
- no production endpoint isolation or automated remediation;
- no high-availability SIEM architecture.

These limitations were accepted because the objective of the project is to demonstrate SOC engineering, detection, investigation, automation, and incident response concepts within a reproducible virtual environment.

---

## 14. Documentation Navigation

### Architecture

[`docs/architecture/architecture.md`](docs/architecture/architecture.md)

Network design, systems, IP addressing, telemetry flow, and SOC architecture.

### Detection Use Cases

[`docs/use-cases/`](docs/use-cases/)

Attack simulation, detection logic, SPL investigation, evidence, and MITRE ATT&CK mapping for UC-001 through UC-009.

### Incident Response

[`docs/incident-reports/`](docs/incident-reports/)

SOC analyst response documentation for IR-001 through IR-009.

### Threat Intelligence

[`scripts/threat-intel/`](scripts/threat-intel/)

Python-based Threat Intelligence enrichment and automation.

### SOC Dashboard

[`splunk/dashboards/`](splunk/dashboards/)

Splunk SOC Security Overview dashboard implementation and panel documentation.

### Dashboard Evidence

[`screenshots/dashboards/`](screenshots/dashboards/)

Screenshots of the SOC Security Overview dashboard.

### Detection Evidence

[`screenshots/detections/`](screenshots/detections/)

Evidence collected during attack simulation, detection validation, and alert configuration.

### Threat Intelligence Evidence

[`screenshots/threat-intelligence/`](screenshots/threat-intelligence/)

Evidence of Threat Intelligence API integration, enrichment, lookup configuration, and automation.

### Infrastructure Evidence

[`screenshots/infrastructure/`](screenshots/infrastructure/)

Evidence related to Splunk, Sysmon, Universal Forwarder, and laboratory infrastructure.

---

## 15. Project Status

**Status: Completed SOC Laboratory**

The environment implements an end-to-end workflow covering:

```text
Architecture
    ↓
Telemetry Collection
    ↓
Controlled Attack Simulation
    ↓
Detection
    ↓
Alerting
    ↓
Investigation
    ↓
Threat Intelligence
    ↓
Dashboarding
    ↓
Incident Response
```

The laboratory serves as a practical demonstration of SOC Level 1 investigation, detection engineering fundamentals, SIEM administration, Threat Intelligence integration, automation, and incident response documentation.
