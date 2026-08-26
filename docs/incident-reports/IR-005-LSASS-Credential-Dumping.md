# IR-005 — LSASS Credential Dumping

## 1. Incident Summary

Credential access activity targeting the Windows Local Security Authority Subsystem Service (LSASS) was detected on the Windows 11 endpoint `target-pc` during the SOC laboratory attack simulation.

LSASS is a security-sensitive Windows process involved in authentication and credential management. Attempts to access LSASS memory can be associated with credential dumping techniques used after an attacker obtains access to a system.

Sysmon captured the relevant endpoint activity and the telemetry was forwarded through the Splunk Universal Forwarder to the central Splunk SIEM.

This incident corresponds to **UC-005 — LSASS Credential Dumping**.

---

## 2. Incident Classification

| Field | Value |
|---|---|
| Incident ID | IR-005 |
| Related Use Case | UC-005 — LSASS Credential Dumping |
| Affected Host | `target-pc` |
| Data Source | Sysmon |
| SIEM | Splunk |
| Activity Type | Credential Access |
| Target Process | `lsass.exe` |
| Severity | Critical |
| Status | Detected / Investigated |
| Environment | Controlled SOC Laboratory |

The incident was classified as **Critical severity** because unauthorized access to LSASS can indicate an attempt to obtain credentials and may enable further attacker activity such as privilege escalation or lateral movement.

The observed activity was intentionally generated inside the controlled laboratory and therefore did not represent a real compromise.

---

## 3. Investigation Findings

The investigation identified activity associated with access to the LSASS process on `target-pc`.

The available endpoint telemetry allowed the analyst to identify relevant context including:

- event timestamp;
- affected endpoint;
- source process;
- target process;
- user context;
- activity involving `lsass.exe`.

The activity matched the credential access detection logic implemented in UC-005.

Because LSASS is a legitimate and continuously running Windows process, the existence of `lsass.exe` alone is not suspicious. The important security signal is the context of another process interacting with or attempting to access the LSASS process.

Detailed attack simulation steps, detection logic, screenshots, MITRE ATT&CK mapping, and technical analysis are documented in:

`docs/use-cases/UC-005-LSASS-Credential-Dumping.md`

---

## 4. Incident Timeline

| Stage | Activity |
|---|---|
| Attack Simulation | Credential access behavior targeting LSASS was generated on `target-pc`. |
| Telemetry Generation | Endpoint monitoring generated telemetry related to the LSASS activity. |
| Log Collection | Splunk Universal Forwarder forwarded the telemetry to Splunk. |
| Detection | The activity matched the UC-005 credential access detection logic. |
| Investigation | The analyst reviewed the source process, target process, host, and user context. |
| Assessment | The activity was confirmed as part of the controlled attack simulation. |
| Closure | The incident was documented and closed as a laboratory security incident. |

---

# 5. Incident Response — PICERL

## 5.1 Preparation

The SOC laboratory was prepared with:

- Sysmon endpoint monitoring;
- Splunk Universal Forwarder;
- centralized Splunk logging;
- process-level security telemetry;
- LSASS credential access detection logic.

These controls provided visibility into activity involving security-sensitive Windows processes.

## 5.2 Identification

The incident was identified from endpoint telemetry associated with access to `lsass.exe`.

The analyst reviewed the source and target process information and determined that the observed behavior matched the credential access detection criteria implemented in UC-005.

Because legitimate security and system software may interact with LSASS, the activity must be evaluated using process context and surrounding telemetry rather than relying only on the target process name.

## 5.3 Containment

In a production environment, confirmed malicious credential dumping would require rapid containment.

Possible response actions would include:

- isolating the affected endpoint;
- preventing further attacker movement;
- identifying the account associated with the activity;
- investigating whether credentials were exposed;
- searching other endpoints for related activity.

Because the event was intentionally generated in the isolated SOC laboratory, endpoint containment was not required.

## 5.4 Eradication

For a confirmed compromise, eradication would focus on removing the malicious process or tooling responsible for the credential access attempt and identifying the attacker's original access mechanism.

Additional persistence or malicious artifacts discovered during the investigation would also need to be removed.

No production remediation was required during the controlled simulation.

## 5.5 Recovery

In a real credential compromise, affected credentials should be considered potentially exposed and appropriate credential-reset procedures should be performed after the environment is secured.

The affected endpoint should also be monitored for additional suspicious authentication or lateral movement activity.

In the laboratory, the endpoint remained operational and continued forwarding telemetry to Splunk.

## 5.6 Lessons Learned

Credential access activity represents a significant escalation in an attack sequence.

An attacker who successfully obtains credentials may be able to move from a single compromised endpoint to additional systems.

For this reason, LSASS-related detections should be correlated with other telemetry such as:

- suspicious process execution;
- PowerShell activity;
- authentication events;
- RDP activity;
- lateral movement indicators.

The simulation demonstrated how endpoint telemetry can provide visibility into credential access behavior and support investigation before potential lateral movement occurs.

---

## 6. Final Assessment

**IR-005 was successfully detected and investigated.**

The monitoring chain operated as expected:

`LSASS Credential Access Activity → Endpoint Telemetry → Splunk Universal Forwarder → Splunk → Detection → SOC Investigation`

The activity was intentionally generated inside the controlled SOC laboratory.

The incident validates the environment's ability to identify security-sensitive activity involving LSASS and demonstrates how credential access detections can contribute to a broader investigation of post-compromise attacker behavior.
