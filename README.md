# Enterprise SOC Lab

### Detection, Threat Hunting, and Incident Response using Splunk SIEM
Enterprise-grade Security Operations Center laboratory built for learning Detection Engineering, Threat Hunting, and Incident Response.

---

## Project Description

Enterprise SOC Lab is a practical cybersecurity project designed to simulate the daily operations of a Security Operations Center (SOC).

The laboratory recreates a small enterprise environment composed of an Active Directory Domain Controller, a Windows 11 workstation, a Kali Linux attacker machine, and a centralized Splunk SIEM server.

The project demonstrates the complete SOC lifecycle, including log collection, endpoint telemetry, attack simulation, detection engineering, threat hunting, threat intelligence enrichment, incident investigation, and technical documentation.

Rather than focusing solely on tool installation, the project emphasizes understanding how modern SOC teams detect, analyze, investigate, and respond to cyber threats in a controlled enterprise environment.

---

## Network Architecture

The lab simulates a small enterprise environment deployed on a VirtualBox NAT Network (`10.0.10.0/24`). It includes a centralized Splunk SIEM server, an Active Directory Domain Controller, a Windows 11 target endpoint, and a Kali Linux attacker machine.

Windows endpoint telemetry is generated through Sysmon and forwarded to Splunk using the Splunk Universal Forwarder. Kali Linux and Atomic Red Team are used to generate controlled attack activity, while external Threat Intelligence services enrich suspicious indicators during investigations.

![Enterprise SOC Lab Network Architecture](docs/architecture/network-diagram.png)

*Figure 1 — Enterprise SOC Lab network architecture and security data flow.*
---

##  Project Scope

### Included

| Component | Status |
| :--- | :---: |
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

---

### Excluded

| Component | Reason |
| :--- | :--- |
| Docker | Outside project scope |
| SOAR | Outside project scope |
| Kubernetes | Outside project scope |
| Cloud Deployment | Outside project scope |
| Splunk Clustering | Outside project scope |
| Commercial EDR | Outside project scope |
| Production Deployment | Lab environment only |

---

## Project Objectives

- Design a realistic enterprise SOC laboratory.
- Centralize endpoint telemetry using Splunk SIEM.
- Monitor Windows security events and Sysmon telemetry.
- Develop custom detection rules for multiple attack scenarios.
- Simulate attacks using Atomic Red Team and Kali Linux.
- Perform threat hunting activities using Splunk SPL.
- Investigate security incidents using SOC methodologies.
- Apply the Five Whys technique for root cause analysis.
- Produce professional technical documentation and incident reports.

---

---

## 5. Technology Stack

The SOC laboratory combines endpoint telemetry, centralized log analysis, attack simulation, threat intelligence, and custom automation.

| Component | Technology | Purpose |
|---|---|---|
| SIEM | Splunk Free | Centralized log collection, searching, detection, alerting, and dashboards |
| Endpoint Telemetry | Sysmon | Detailed Windows process, network, registry, and system activity |
| Log Forwarding | Splunk Universal Forwarder | Forwards Windows telemetry to the Splunk server |
| Endpoint | Windows 11 | Primary monitored workstation and attack simulation target |
| Identity Infrastructure | Windows Active Directory Domain Controller | Authentication and domain-related telemetry |
| SIEM Server | Ubuntu Server | Hosts the Splunk instance and Threat Intelligence automation |
| Attack Machine | Kali Linux | Used for controlled attack simulations |
| Attack Simulation | Atomic Red Team | Generates ATT&CK-aligned endpoint activity |
| Threat Intelligence | VirusTotal | IP reputation and malicious indicator enrichment |
| Threat Intelligence | AbuseIPDB | IP abuse reputation and reporting information |
| Threat Intelligence | AlienVault OTX | Threat intelligence pulse and ASN context |
| Automation | Python | Automated Threat Intelligence collection and enrichment |
| Scheduling | Cron | Periodic execution of the enrichment workflow |
| Framework | MITRE ATT&CK | Mapping attack simulations and detection scenarios |

---

## 6. Repository Structure

The repository separates architecture documentation, detection use cases, incident response reports, evidence, automation scripts, and Splunk-related content.

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
│       ├── virustotal_lookup.py
│       ├── abuseipdb_lookup.py
│       ├── otx_lookup.py
│       ├── enrich_ip.py
│       └── auto_enrich.py
│
└── splunk/
    └── dashboards/
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

The reports use the PICERL lifecycle:

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

---

## 9. Automated Threat Intelligence Enrichment

The laboratory integrates automated Threat Intelligence enrichment for public destination IP addresses observed in Windows network telemetry.

Three external intelligence sources are used:

- VirusTotal
- AbuseIPDB
- AlienVault OTX

The enrichment pipeline operates as follows:

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

- security events over time;
- events by monitored host;
- Sysmon event distribution;
- authentication activity;
- RDP activity;
- external destination IP addresses;
- Threat Intelligence enrichment;
- PowerShell activity;
- detection alerts;
- network connections by process.

The dashboard combines operational monitoring and investigation context in a single SOC interface.

### Time Range Design

Different time ranges are intentionally used depending on the purpose of each panel.

Operational panels can focus on recent activity such as the last 24 hours, allowing an analyst to quickly identify current changes or suspicious behavior.

Historical or context-oriented panels can use broader time ranges when previous laboratory events remain relevant to the investigation.

This design demonstrates the difference between **real-time SOC monitoring** and **historical investigation**.

### Dashboard Evidence

![SOC Security Overview - Part 1](screenshots/dashboards/dashboard-soc-overview-01.png)

![SOC Security Overview - Part 2](screenshots/dashboards/dashboard-soc-overview-02.png)

![SOC Security Overview - Part 3](screenshots/dashboards/dashboard-soc-overview-03.png)

---

## 11. Detection and Investigation Workflow

The laboratory demonstrates an end-to-end SOC workflow rather than isolated attack simulations.

```text
Attack Simulation
        ↓
Windows Endpoint
        ↓
Sysmon Telemetry
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
- centralized SOC monitoring through a Splunk dashboard;
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
- controlled attack simulations rather than real adversary activity;
- external Threat Intelligence results dependent on public API availability and rate limits;
- no production endpoint isolation or automated remediation;
- no high-availability SIEM architecture.

These limitations were accepted because the objective of the project is to demonstrate SOC engineering, detection, investigation, automation, and incident response concepts within a reproducible virtual environment.

---

## 14. Documentation Navigation

For detailed technical documentation, use the following sections:

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

### Dashboard Evidence

[`screenshots/dashboards/`](screenshots/dashboards/)

Screenshots of the SOC Security Overview dashboard.

### Detection Evidence

[`screenshots/detections/`](screenshots/detections/)

Evidence collected during attack simulation, detection validation, and alert configuration.

### Infrastructure Evidence

[`screenshots/infrastructure/`](screenshots/infrastructure/)

Evidence related to Splunk, Sysmon, Universal Forwarder, and laboratory infrastructure.

---

## 15. Project Status

**Status: Completed SOC Laboratory**

The environment implements an end-to-end workflow covering:

**Architecture → Telemetry Collection → Attack Simulation → Detection → Alerting → Investigation → Threat Intelligence → Dashboarding → Incident Response**

The laboratory serves as a practical demonstration of SOC Level 1 investigation, detection engineering fundamentals, SIEM administration, Threat Intelligence integration, and incident response documentation.
