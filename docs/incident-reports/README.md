# Incident Response Reports

## 1. Overview

This directory contains the incident response reports developed for the Enterprise SOC Lab.

Each report corresponds to one detection use case implemented and validated in the laboratory.

The purpose of these reports is different from the technical use-case documentation located in:

```text
docs/use-cases/
```

The use-case documentation explains how an attack technique was simulated, detected, analyzed, and mapped to security telemetry.

The incident reports focus on the **SOC analyst response perspective** after the suspicious activity has been detected.

The project therefore separates:

```text
Attack Simulation & Detection
        ↓
docs/use-cases/
        ↓
Detection Triggered
        ↓
SOC Investigation & Response
        ↓
docs/incident-reports/
```

This separation avoids duplicating the complete technical detection documentation while demonstrating how each detection can transition into an incident response workflow.

---

## 2. Incident Response Methodology

The incident reports follow the **PICERL incident response lifecycle**:

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

### Preparation

Security controls, telemetry sources, detection rules, and monitoring infrastructure required before an incident occurs.

### Identification

Analysis of the detected activity to determine what occurred and whether the event represents suspicious or malicious behavior.

### Containment

Actions that could be taken to limit attacker activity and prevent the incident from spreading.

### Eradication

Removal of malicious artifacts, persistence mechanisms, attacker tooling, or the original compromise mechanism.

### Recovery

Restoration of normal operations and verification that the affected environment is secure and monitoring remains functional.

### Lessons Learned

Security observations derived from the incident that can improve future detection, investigation, and response.

Because the incidents in this project were intentionally generated inside an isolated SOC laboratory, destructive or production containment actions were not required.

The reports therefore describe the response actions that would be appropriate in a real environment while clearly distinguishing them from the actions required during the controlled simulation.

---

## 3. Incident Reports

| Incident | Detection Scenario | Category | Severity |
|---|---|---|---|
| [IR-001](IR-001-Suspicious-PowerShell.md) | Suspicious PowerShell Execution | Execution | Medium |
| [IR-002](IR-002-Encoded-PowerShell.md) | Encoded PowerShell Execution | Execution | High |
| [IR-003](IR-003-System-Information-Discovery.md) | System Information Discovery | Discovery | Medium |
| [IR-004](IR-004-Registry-Run-Key-Persistence.md) | Registry Run Key Persistence | Persistence | High |
| [IR-005](IR-005-LSASS-Credential-Dumping.md) | LSASS Credential Dumping | Credential Access | Critical |
| [IR-006](IR-006-Obfuscated-PowerShell.md) | Obfuscated PowerShell Execution | Defense Evasion | High |
| [IR-007](IR-007-RDP-Lateral-Movement.md) | RDP Lateral Movement | Lateral Movement | High |
| [IR-008](IR-008-Archive-Collected-Data.md) | Archive Collected Data | Collection | High |
| [IR-009](IR-009-HTTP-Data-Exfiltration.md) | HTTP Data Exfiltration | Exfiltration | Critical |

---

## 4. Incident Coverage

The incident reports cover multiple stages of a simulated attack lifecycle.

```text
Execution
   │
   ├── IR-001 Suspicious PowerShell
   └── IR-002 Encoded PowerShell
             ↓
Discovery
   │
   └── IR-003 System Information Discovery
             ↓
Persistence
   │
   └── IR-004 Registry Run Key Persistence
             ↓
Credential Access
   │
   └── IR-005 LSASS Credential Dumping
             ↓
Defense Evasion
   │
   └── IR-006 Obfuscated PowerShell
             ↓
Lateral Movement
   │
   └── IR-007 RDP Lateral Movement
             ↓
Collection
   │
   └── IR-008 Archive Collected Data
             ↓
Exfiltration
   │
   └── IR-009 HTTP Data Exfiltration
```

The individual simulations were performed as controlled detection scenarios.

The sequence above represents their logical relationship within an attack lifecycle and should not be interpreted as evidence that every simulation originated from one continuous real-world compromise.

---

## 5. Relationship Between Use Cases and Incident Reports

Each incident report has a corresponding technical detection use case.

| Use Case | Incident Report |
|---|---|
| UC-001 — Suspicious PowerShell | IR-001 — Suspicious PowerShell |
| UC-002 — Encoded PowerShell | IR-002 — Encoded PowerShell |
| UC-003 — System Information Discovery | IR-003 — System Information Discovery |
| UC-004 — Registry Run Key Persistence | IR-004 — Registry Run Key Persistence |
| UC-005 — LSASS Credential Dumping | IR-005 — LSASS Credential Dumping |
| UC-006 — Obfuscated PowerShell | IR-006 — Obfuscated PowerShell |
| UC-007 — RDP Lateral Movement | IR-007 — RDP Lateral Movement |
| UC-008 — Archive Collected Data | IR-008 — Archive Collected Data |
| UC-009 — HTTP Data Exfiltration | IR-009 — HTTP Data Exfiltration |

The two documentation layers serve different purposes:

### Detection Use Case

```text
What activity was simulated?
        ↓
What telemetry was generated?
        ↓
How was it detected?
        ↓
What SPL query was used?
        ↓
What evidence was collected?
```

### Incident Report

```text
What was detected?
        ↓
How should an analyst investigate it?
        ↓
How severe is the activity?
        ↓
How should it be contained?
        ↓
How should it be eradicated?
        ↓
How should the environment recover?
        ↓
What was learned?
```

Together, these components demonstrate both **detection engineering** and **incident response analysis**.

---

## 6. Severity Classification

The laboratory uses three primary incident severity levels.

### Medium

Suspicious activity requiring investigation but which may also have legitimate administrative explanations.

Examples:

- suspicious PowerShell execution;
- system information discovery.

### High

Activity associated with techniques that may enable persistence, defense evasion, lateral movement, or preparation for data theft.

Examples:

- encoded or obfuscated PowerShell;
- Registry persistence;
- RDP lateral movement;
- archive collection.

### Critical

Activity associated with significant compromise impact or access to sensitive security information.

Examples:

- credential dumping;
- data exfiltration.

Severity represents the potential security impact of the technique in a real environment.

The actual laboratory activity was controlled and intentionally generated for security testing.

---

## 7. Correlation Across Incidents

One of the objectives of the project is to demonstrate that SOC investigations should not rely only on isolated alerts.

Individual events may have legitimate explanations.

Their security significance can increase when multiple behaviors occur together.

For example:

```text
Suspicious PowerShell
        ↓
System Discovery
        ↓
Persistence
        ↓
Credential Access
        ↓
Lateral Movement
        ↓
Collection
        ↓
Exfiltration
```

An analyst observing several of these behaviors on related hosts or accounts would have significantly stronger evidence of a potential compromise than an analyst reviewing a single event in isolation.

The Splunk SIEM, detection rules, SOC dashboard, and Threat Intelligence enrichment implemented in this project provide the telemetry and context required to perform this type of investigation.

---

## 8. SOC Investigation Workflow

The general investigation workflow demonstrated by the incident reports is:

```text
Security Telemetry
       ↓
Splunk Detection
       ↓
Alert / Suspicious Event
       ↓
Initial Triage
       ↓
Endpoint & User Investigation
       ↓
Process / Authentication / Network Correlation
       ↓
Threat Intelligence Context
       ↓
Incident Classification
       ↓
PICERL Response
       ↓
Incident Closure
```

Not every incident requires every available data source.

The analyst selects the telemetry relevant to the detected technique.

For example:

- PowerShell incidents focus primarily on process and command-line telemetry.
- RDP investigations combine authentication and network telemetry.
- Exfiltration investigations focus on network activity, preceding collection behavior, and external destination context.

---

## 9. Supporting SOC Components

The incident response process is supported by several components implemented elsewhere in the project.

### Detection Engineering

```text
docs/use-cases/
```

Contains the technical detection scenarios, attack simulations, SPL queries, MITRE ATT&CK mapping, analysis, and evidence.

### Splunk Detection Content

```text
splunk/detections/
```

Contains detection-related Splunk content developed for the laboratory.

### Threat Intelligence

```text
scripts/threat-intel/
```

Provides automated public IP enrichment using VirusTotal, AbuseIPDB, and AlienVault OTX.

### SOC Dashboard

```text
splunk/dashboards/
```

Provides centralized visibility into endpoint activity, authentication, RDP, PowerShell, network connections, Threat Intelligence, and detection alerts.

### Evidence

```text
screenshots/
```

Contains screenshots collected throughout the implementation and validation of the SOC laboratory.

---

## 10. Final Result

The incident response section extends the project beyond simple attack detection.

For each implemented security scenario, the laboratory demonstrates a transition from:

```text
Attack Simulation
        ↓
Telemetry Generation
        ↓
SIEM Detection
        ↓
SOC Investigation
        ↓
Incident Response
```

The nine incident reports demonstrate how endpoint, authentication, network, detection, and Threat Intelligence data can support analyst decision-making throughout the incident response lifecycle.

Together with the detection use cases and SOC Security Overview dashboard, these reports provide a documented workflow from security telemetry generation to incident investigation and response.
