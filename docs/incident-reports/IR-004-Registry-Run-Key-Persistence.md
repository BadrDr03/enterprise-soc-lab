# IR-004 — Registry Run Key Persistence

## 1. Incident Summary

Registry-based persistence activity was detected on the Windows 11 endpoint `target-pc` during the SOC laboratory attack simulation.

Windows Registry Run keys can be used to automatically execute programs when a user logs on. Although this mechanism can be used legitimately by software, attackers may abuse it to maintain persistence on a compromised endpoint.

Sysmon captured the registry modification and the telemetry was forwarded through the Splunk Universal Forwarder to the central Splunk SIEM.

This incident corresponds to **UC-004 — Registry Run Key Persistence**.

---

## 2. Incident Classification

| Field | Value |
|---|---|
| Incident ID | IR-004 |
| Related Use Case | UC-004 — Registry Run Key Persistence |
| Affected Host | `target-pc` |
| Data Source | Sysmon |
| SIEM | Splunk |
| Primary Event | Sysmon Event ID 13 — Registry Value Set |
| Activity Type | Registry-Based Persistence |
| Severity | High |
| Status | Detected / Investigated |
| Environment | Controlled SOC Laboratory |

The incident was classified as **High severity** because unauthorized modification of Registry Run keys can allow malicious code to execute automatically after user logon and maintain attacker access across sessions.

---

## 3. Investigation Findings

The investigation confirmed that a Windows Registry value associated with automatic execution was modified on `target-pc`.

Sysmon registry telemetry provided information including:

- event timestamp;
- affected endpoint;
- user context;
- process responsible for the modification;
- registry target path;
- registry value data.

The registry modification matched the persistence detection logic implemented in UC-004.

The associated Splunk alert was also configured with a **Log Event** action, allowing the triggered detection to be persisted in Splunk.

This alert activity was later visible in the SOC dashboard as:

`Registry Run Key Persistence`

Detailed simulation steps, SPL detection logic, screenshots, MITRE ATT&CK mapping, and technical analysis are documented in:

`docs/use-cases/UC-004-Registry-Run-Key-Persistence.md`

---

## 4. Incident Timeline

| Stage | Activity |
|---|---|
| Attack Simulation | A Registry Run key persistence modification was generated on `target-pc`. |
| Telemetry Generation | Sysmon recorded the registry modification. |
| Log Collection | Splunk Universal Forwarder forwarded the event to Splunk. |
| Detection | The registry activity matched the UC-004 persistence detection logic. |
| Alerting | The Splunk alert generated a persisted Log Event. |
| Investigation | The analyst reviewed the registry path, process, user, and associated value. |
| Assessment | The modification was confirmed as part of the controlled attack simulation. |
| Closure | The incident was documented and closed. |

---

# 5. Incident Response — PICERL

## 5.1 Preparation

The SOC environment was prepared with:

- Sysmon registry monitoring;
- Splunk Universal Forwarder;
- centralized Splunk logging;
- registry modification detection logic;
- Splunk alerting.

These controls provided the visibility required to identify changes to persistence-related Registry locations.

## 5.2 Identification

The incident was identified through Sysmon registry telemetry.

The analyst reviewed the registry target and associated process and determined that the modification affected a location capable of automatically executing software during user logon.

The activity matched the persistence detection criteria implemented in UC-004.

## 5.3 Containment

In a production environment, confirmed malicious persistence would require containment of the affected endpoint to prevent continued attacker access or additional malicious activity.

The analyst would also investigate the process responsible for creating the persistence mechanism and determine whether other systems were affected.

Because the activity was intentionally generated inside the isolated SOC laboratory, endpoint isolation was not required.

## 5.4 Eradication

For a real incident, eradication would include removing the unauthorized Registry Run entry and any associated malicious executable, script, or payload.

The analyst would also search for additional persistence mechanisms that may have been created by the attacker.

In the laboratory simulation, the persistence artifact was part of the controlled test and no production remediation was required.

## 5.5 Recovery

After removal of malicious persistence in a production environment, the affected system should be monitored to confirm that the unauthorized Registry value does not reappear.

Normal endpoint operation and security telemetry should also be verified.

In the laboratory, the endpoint remained operational and continued forwarding telemetry to Splunk.

## 5.6 Lessons Learned

Registry persistence monitoring provides visibility into an important post-compromise technique.

However, Registry Run keys are also used by legitimate applications. Detection should therefore consider additional context such as:

- process responsible for the modification;
- user account;
- registry value data;
- associated executable;
- surrounding endpoint activity.

The simulation also confirmed that Splunk alert events can be persisted and displayed in the SOC Security Overview dashboard.

---

## 6. Final Assessment

**IR-004 was successfully detected, alerted, and investigated.**

The monitoring chain operated as expected:

`Registry Modification → Sysmon → Splunk Universal Forwarder → Splunk → Detection → Alert → SOC Investigation`

The activity was intentionally generated inside the controlled laboratory and did not represent a real compromise.

The incident validates the SOC environment's ability to detect Registry-based persistence and demonstrates the integration between endpoint telemetry, Splunk detection logic, alerting, and centralized dashboard visibility.
