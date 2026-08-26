# IR-006 — Obfuscated PowerShell Execution

## 1. Incident Summary

Obfuscated PowerShell activity was detected on the Windows 11 endpoint `target-pc` during the SOC laboratory attack simulation.

PowerShell obfuscation can be used to make commands more difficult for analysts and security controls to interpret. Although obfuscation does not automatically indicate malicious activity, its presence can represent an attempt to hide the real purpose of executed commands.

Sysmon captured the PowerShell process execution and the telemetry was forwarded through the Splunk Universal Forwarder to the central Splunk SIEM.

This incident corresponds to **UC-006 — Obfuscated PowerShell**.

---

## 2. Incident Classification

| Field | Value |
|---|---|
| Incident ID | IR-006 |
| Related Use Case | UC-006 — Obfuscated PowerShell |
| Affected Host | `target-pc` |
| Data Source | Sysmon |
| SIEM | Splunk |
| Primary Event | Sysmon Event ID 1 — Process Creation |
| Activity Type | Obfuscated PowerShell Execution |
| Severity | High |
| Status | Detected / Investigated |
| Environment | Controlled SOC Laboratory |

The incident was classified as **High severity** because command obfuscation can be used as a defense-evasion technique to reduce visibility into attacker activity and make malicious commands more difficult to analyze.

---

## 3. Investigation Findings

The investigation confirmed execution of PowerShell with obfuscated command-line characteristics on `target-pc`.

Sysmon process creation telemetry provided relevant investigation fields including:

- execution timestamp;
- affected endpoint;
- user context;
- PowerShell executable;
- parent process;
- complete command line.

The command-line characteristics matched the detection logic implemented in UC-006.

The complete command line was particularly important because the PowerShell executable itself is legitimate and commonly used for system administration.

The suspicious context was therefore derived from **how PowerShell was executed**, rather than simply from the presence of `powershell.exe`.

Detailed simulation steps, SPL detection logic, screenshots, MITRE ATT&CK mapping, and technical analysis are documented in:

`docs/use-cases/UC-006-Obfuscated-PowerShell.md`

---

## 4. Incident Timeline

| Stage | Activity |
|---|---|
| Attack Simulation | Obfuscated PowerShell activity was executed on `target-pc`. |
| Telemetry Generation | Sysmon generated process creation telemetry containing the PowerShell command line. |
| Log Collection | Splunk Universal Forwarder forwarded the event to Splunk. |
| Detection | The command-line characteristics matched the UC-006 detection logic. |
| Investigation | The analyst reviewed the process, parent process, user context, and command line. |
| Assessment | The activity was confirmed as part of the controlled attack simulation. |
| Closure | The incident was documented and closed. |

---

# 5. Incident Response — PICERL

## 5.1 Preparation

The SOC laboratory was prepared with:

- Sysmon process creation monitoring;
- command-line logging;
- Splunk Universal Forwarder;
- centralized Splunk logging;
- PowerShell detection logic.

Command-line visibility was particularly important because obfuscation attempts to make executed instructions more difficult to interpret.

## 5.2 Identification

The incident was identified through Sysmon Event ID 1 telemetry.

The analyst reviewed the PowerShell process and its command-line arguments and identified characteristics associated with command obfuscation.

The event matched the detection criteria implemented in UC-006.

## 5.3 Containment

In a production environment, confirmed malicious obfuscated PowerShell activity could require isolation of the affected endpoint and termination of the associated malicious process.

The analyst would also investigate related process execution, network connections, downloaded files, and persistence activity.

Because the execution occurred intentionally inside the isolated SOC laboratory, endpoint containment was not required.

## 5.4 Eradication

For a real compromise, eradication would involve removing any malicious scripts, payloads, or artifacts associated with the PowerShell execution.

The analyst would also investigate whether the obfuscated command created additional persistence mechanisms or launched other malicious processes.

No production remediation was required during the controlled simulation.

## 5.5 Recovery

The monitored endpoint remained operational following the simulation.

The analyst verified that Sysmon continued generating telemetry and that events continued to reach Splunk.

No system restoration was required.

## 5.6 Lessons Learned

The incident demonstrated why monitoring only process names is insufficient for PowerShell investigations.

Both legitimate administrators and attackers can use `powershell.exe`.

Useful investigation context therefore includes:

- command-line arguments;
- parent process;
- user account;
- related process creation;
- network connections;
- surrounding endpoint activity.

The simulation also demonstrated how command-line telemetry can provide visibility into defense-evasion behavior.

---

## 6. Final Assessment

**IR-006 was successfully detected and investigated.**

The monitoring chain operated as expected:

`Obfuscated PowerShell → Sysmon → Splunk Universal Forwarder → Splunk → Detection → SOC Investigation`

The activity was intentionally generated inside the controlled SOC laboratory and did not represent a real compromise.

The incident validates the SOC environment's ability to identify suspicious PowerShell execution based on command-line characteristics and demonstrates the importance of detailed endpoint telemetry when investigating obfuscated activity.
