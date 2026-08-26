# IR-001 — Suspicious PowerShell Execution

## 1. Incident Summary

A suspicious PowerShell execution was detected on the Windows 11 endpoint `target-pc` during the SOC laboratory attack simulation.

The activity was identified through Sysmon process creation telemetry collected by the Splunk Universal Forwarder and forwarded to the central Splunk SIEM.

The detection focused on PowerShell execution containing suspicious command-line characteristics. The event was successfully collected, detected, and investigated through the SOC monitoring environment.

This incident corresponds to **UC-001 — Suspicious PowerShell**.

---

## 2. Incident Classification

| Field | Value |
|---|---|
| Incident ID | IR-001 |
| Related Use Case | UC-001 — Suspicious PowerShell |
| Affected Host | `target-pc` |
| Data Source | Sysmon |
| SIEM | Splunk |
| Primary Event | Sysmon Event ID 1 — Process Creation |
| Activity Type | Suspicious PowerShell Execution |
| Severity | Medium |
| Status | Detected / Investigated |
| Environment | Controlled SOC Laboratory |

The incident was classified as **Medium severity** because suspicious PowerShell execution can indicate malicious script execution or post-exploitation activity. However, the observed activity occurred inside the controlled laboratory environment and no real production system was affected.

---

## 3. Investigation Findings

The investigation confirmed that PowerShell was executed on `target-pc` and that the execution generated Sysmon process creation telemetry.

The collected event provided information useful to the analyst, including:

- execution timestamp;
- affected endpoint;
- user context;
- PowerShell process;
- parent process;
- command-line arguments.

Splunk successfully received the corresponding endpoint telemetry, allowing the analyst to investigate the execution centrally.

The activity matched the detection logic implemented in **UC-001**.

Detailed attack simulation steps, SPL detection logic, screenshots, MITRE ATT&CK mapping, and detection analysis are documented separately in:

`docs/use-cases/UC-001-Suspicious-PowerShell.md`

---

## 4. Incident Timeline

| Stage | Activity |
|---|---|
| Attack Simulation | Suspicious PowerShell activity was executed on `target-pc`. |
| Telemetry Generation | Sysmon generated process creation telemetry for the PowerShell execution. |
| Log Collection | Splunk Universal Forwarder collected and forwarded the event. |
| Detection | Splunk detection logic identified the suspicious PowerShell activity. |
| Investigation | The analyst reviewed the host, process, user context, parent process, and command line. |
| Assessment | The activity was confirmed as part of the controlled attack simulation. |
| Closure | The incident was documented and closed as a laboratory security incident. |

---

# 5. Incident Response — PICERL

## 5.1 Preparation

Before the incident occurred, the SOC laboratory had already been configured with:

- Sysmon endpoint monitoring;
- Splunk Universal Forwarder;
- centralized Splunk logging;
- process creation telemetry;
- PowerShell detection logic.

These controls provided the visibility required to detect and investigate the activity.

## 5.2 Identification

The suspicious PowerShell execution was identified using Sysmon Event ID 1 telemetry.

The analyst reviewed the process information and command-line activity in Splunk and confirmed that the event matched the suspicious PowerShell detection criteria defined in UC-001.

## 5.3 Containment

In a production environment, containment could include isolating the affected endpoint and terminating confirmed malicious PowerShell processes.

Because this incident was generated intentionally inside the isolated SOC laboratory, endpoint isolation was not required.

The analyst instead confirmed that the activity remained limited to the controlled lab environment.

## 5.4 Eradication

For a real malicious incident, eradication would include removing malicious scripts or payloads, eliminating persistence mechanisms if present, and verifying that no unauthorized processes remained active.

In this simulation, no production remediation was required because the PowerShell activity was intentionally generated for detection testing.

## 5.5 Recovery

The endpoint remained operational after the simulation.

The analyst verified that security telemetry continued to reach Splunk and that normal monitoring functionality remained available.

No system restoration was required.

## 5.6 Lessons Learned

The incident demonstrated the importance of collecting detailed process creation telemetry.

PowerShell itself is a legitimate administrative tool, meaning that detecting the executable alone is insufficient. Command-line arguments, parent processes, user context, and surrounding endpoint activity provide additional context required during investigation.

The test also confirmed that the SOC pipeline could successfully collect and investigate suspicious PowerShell execution from the monitored Windows endpoint.

---

## 6. Final Assessment

**IR-001 was successfully detected and investigated.**

The complete monitoring chain operated as expected:

`PowerShell Execution → Sysmon → Splunk Universal Forwarder → Splunk → Detection → SOC Investigation`

No real compromise occurred because the activity was intentionally generated inside the controlled SOC laboratory.

The incident validates the SOC environment's ability to provide visibility into suspicious PowerShell process execution and demonstrates how the collected telemetry can support an analyst during incident investigation.
