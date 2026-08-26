# IR-003 — System Information Discovery

## 1. Incident Summary

System information discovery activity was detected on the Windows 11 endpoint `target-pc` during the SOC laboratory attack simulation.

System discovery commands can be used by an attacker after gaining access to an endpoint to understand the compromised environment before performing additional actions.

Sysmon captured the process execution and the telemetry was forwarded through the Splunk Universal Forwarder to the central Splunk SIEM.

This incident corresponds to **UC-003 — System Information Discovery**.

---

## 2. Incident Classification

| Field | Value |
|---|---|
| Incident ID | IR-003 |
| Related Use Case | UC-003 — System Information Discovery |
| Affected Host | `target-pc` |
| Data Source | Sysmon |
| SIEM | Splunk |
| Primary Event | Sysmon Event ID 1 — Process Creation |
| Activity Type | System Information Discovery |
| Severity | Medium |
| Status | Detected / Investigated |
| Environment | Controlled SOC Laboratory |

The incident was classified as **Medium severity** because system discovery commands are legitimate administrative operations but can also indicate reconnaissance performed after an attacker gains access to a system.

---

## 3. Investigation Findings

The investigation confirmed execution of a system information discovery command on `target-pc`.

Sysmon process creation telemetry provided information including:

- execution timestamp;
- affected endpoint;
- user context;
- executed process;
- parent process;
- command-line arguments.

The observed activity matched the detection logic implemented for system information discovery.

Splunk successfully collected the telemetry and provided centralized visibility for the investigation.

Detailed simulation steps, SPL detection logic, screenshots, MITRE ATT&CK mapping, and technical analysis are documented in:

`docs/use-cases/UC-003-System-Information-Discovery.md`

---

## 4. Incident Timeline

| Stage | Activity |
|---|---|
| Attack Simulation | System information discovery activity was executed on `target-pc`. |
| Telemetry Generation | Sysmon generated process creation telemetry. |
| Log Collection | Splunk Universal Forwarder forwarded the telemetry to Splunk. |
| Detection | The activity matched the UC-003 discovery detection logic. |
| Investigation | The analyst reviewed the process, command line, host, and user context. |
| Assessment | The activity was confirmed as part of the controlled attack simulation. |
| Closure | The incident was documented and closed. |

---

# 5. Incident Response — PICERL

## 5.1 Preparation

The SOC laboratory was prepared with:

- Sysmon process monitoring;
- Splunk Universal Forwarder;
- centralized Splunk logging;
- process creation telemetry;
- system discovery detection logic.

These controls provided visibility into commands executed on the monitored endpoint.

## 5.2 Identification

The activity was identified through Sysmon Event ID 1 process creation telemetry.

The analyst reviewed the executed process and its command-line arguments and determined that the activity was associated with system information discovery.

The event matched the detection criteria implemented in UC-003.

## 5.3 Containment

In a production environment, system discovery activity would require additional investigation to determine whether it originated from an authorized administrator or an unauthorized user.

If malicious activity were confirmed, the affected endpoint could be isolated to prevent further attacker activity.

Because the observed execution was part of the controlled laboratory simulation, endpoint isolation was not required.

## 5.4 Eradication

For a real compromise, eradication would focus on identifying and removing the attacker's original access mechanism and any malicious artifacts discovered during the investigation.

The discovery command itself would not normally represent the root cause of the compromise.

No remediation was required during this controlled simulation.

## 5.5 Recovery

The endpoint remained operational after the simulation.

The analyst verified that endpoint telemetry continued to reach Splunk and that monitoring remained functional.

No system restoration was required.

## 5.6 Lessons Learned

System discovery commands can appear legitimate when analyzed individually.

Their security value increases when they are correlated with other suspicious activity such as PowerShell execution, credential access, persistence, or lateral movement.

The incident therefore demonstrated the importance of analyzing endpoint events as part of a broader sequence of attacker behavior rather than relying only on isolated events.

---

## 6. Final Assessment

**IR-003 was successfully detected and investigated.**

The monitoring chain operated as expected:

`System Discovery → Sysmon → Splunk Universal Forwarder → Splunk → Detection → SOC Investigation`

The activity was intentionally generated inside the controlled laboratory.

The incident confirms that the SOC environment can detect and investigate system information discovery activity and provide the telemetry required for further correlation with other attack stages.
