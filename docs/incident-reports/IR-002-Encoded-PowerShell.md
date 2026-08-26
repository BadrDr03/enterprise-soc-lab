# IR-002 — Encoded PowerShell Execution

## 1. Incident Summary

An encoded PowerShell command was detected on the Windows 11 endpoint `target-pc` during the SOC laboratory attack simulation.

Encoded PowerShell commands can be used to hide the actual content of commands from direct inspection. Although encoding itself is not necessarily malicious, its use can represent suspicious behavior when combined with PowerShell execution.

Sysmon captured the process execution and forwarded the telemetry through the Splunk Universal Forwarder to the central Splunk SIEM.

This incident corresponds to **UC-002 — Encoded PowerShell**.

---

## 2. Incident Classification

| Field | Value |
|---|---|
| Incident ID | IR-002 |
| Related Use Case | UC-002 — Encoded PowerShell |
| Affected Host | `target-pc` |
| Data Source | Sysmon |
| SIEM | Splunk |
| Primary Event | Sysmon Event ID 1 — Process Creation |
| Activity Type | Encoded PowerShell Execution |
| Severity | High |
| Status | Detected / Investigated |
| Environment | Controlled SOC Laboratory |

The incident was classified as **High severity** because encoded PowerShell can be used to obscure commands and make malicious execution more difficult to identify through simple command-line inspection.

---

## 3. Investigation Findings

The investigation confirmed that PowerShell was executed with encoded command-line content on `target-pc`.

Sysmon process creation telemetry provided the analyst with information including:

- execution timestamp;
- affected endpoint;
- user context;
- PowerShell executable;
- parent process;
- command-line arguments.

The command-line characteristics matched the detection logic implemented for encoded PowerShell activity.

Splunk successfully collected the telemetry and allowed the execution to be investigated centrally.

Detailed simulation steps, detection logic, screenshots, MITRE ATT&CK mapping, and technical detection analysis are documented in:

`docs/use-cases/UC-002-Encoded-PowerShell.md`

---

## 4. Incident Timeline

| Stage | Activity |
|---|---|
| Attack Simulation | Encoded PowerShell activity was executed on `target-pc`. |
| Telemetry Generation | Sysmon generated process creation telemetry. |
| Log Collection | Splunk Universal Forwarder forwarded the event to Splunk. |
| Detection | The encoded PowerShell characteristics matched the UC-002 detection logic. |
| Investigation | The analyst reviewed the process and command-line information. |
| Assessment | The activity was confirmed as part of the controlled attack simulation. |
| Closure | The incident was documented and closed as a laboratory security incident. |

---

# 5. Incident Response — PICERL

## 5.1 Preparation

The SOC environment was prepared with:

- Sysmon process monitoring;
- Splunk Universal Forwarder;
- centralized Splunk logging;
- PowerShell monitoring;
- encoded PowerShell detection logic.

These controls provided the telemetry required to identify the execution.

## 5.2 Identification

The incident was identified from Sysmon Event ID 1 process creation telemetry.

The analyst reviewed the PowerShell command line and identified characteristics associated with encoded command execution.

The event matched the detection criteria implemented in UC-002.

## 5.3 Containment

In a production environment, confirmed malicious encoded PowerShell activity could require isolating the affected endpoint and terminating the associated malicious process.

Because the activity occurred intentionally inside the isolated SOC laboratory, endpoint containment was not required.

The analyst confirmed that the execution was associated with the controlled simulation.

## 5.4 Eradication

For a real compromise, eradication could involve removing malicious scripts or payloads associated with the PowerShell execution and investigating the endpoint for additional malicious artifacts or persistence.

No production remediation was required during this simulation.

## 5.5 Recovery

The Windows endpoint remained operational following the simulation.

The analyst verified that Sysmon telemetry continued to be generated and forwarded to Splunk.

No restoration procedure was required.

## 5.6 Lessons Learned

The incident demonstrated that encoded command execution can reduce the readability of PowerShell activity and make manual investigation more difficult.

Monitoring complete process command lines therefore provides important visibility for identifying suspicious PowerShell behavior.

The test also confirmed that Sysmon and Splunk could provide sufficient telemetry to detect and investigate encoded PowerShell execution.

---

## 6. Final Assessment

**IR-002 was successfully detected and investigated.**

The monitoring chain operated as expected:

`Encoded PowerShell → Sysmon → Splunk Universal Forwarder → Splunk → Detection → SOC Investigation`

The activity occurred inside the controlled laboratory and did not represent a real compromise.

The incident validates the SOC environment's ability to identify PowerShell execution using encoded command-line characteristics.
