# IR-008 — Archive Collected Data

## 1. Incident Summary

Archive creation activity associated with data collection was detected on the Windows 11 endpoint `target-pc` during the SOC laboratory attack simulation.

Attackers may collect files from a compromised system and combine them into an archive before exfiltration. Archiving reduces the number of files that must be transferred and can make collected information easier to move outside the compromised environment.

The activity generated endpoint telemetry that was collected by Sysmon and forwarded through the Splunk Universal Forwarder to the central Splunk SIEM.

This incident corresponds to **UC-008 — Archive Collected Data**.

---

## 2. Incident Classification

| Field | Value |
|---|---|
| Incident ID | IR-008 |
| Related Use Case | UC-008 — Archive Collected Data |
| Affected Host | `target-pc` |
| Data Source | Sysmon |
| SIEM | Splunk |
| Activity Type | Data Collection / Archive Creation |
| Attack Stage | Collection |
| Severity | High |
| Status | Detected / Investigated |
| Environment | Controlled SOC Laboratory |

The incident was classified as **High severity** because archive creation following suspicious activity can indicate that an attacker is preparing collected information for exfiltration.

Archive creation alone is not necessarily malicious. Legitimate users and applications regularly create compressed files, so the activity must be analyzed together with process, command-line, user, file, and surrounding endpoint context.

---

## 3. Investigation Findings

The investigation confirmed archive-related activity on `target-pc` during the controlled attack simulation.

The available endpoint telemetry provided relevant investigation context including:

- event timestamp;
- affected endpoint;
- user context;
- process responsible for the activity;
- process command line;
- archive-related activity;
- surrounding endpoint events.

The activity matched the detection logic implemented in **UC-008 — Archive Collected Data**.

From a SOC perspective, the archive itself represents only one part of the investigation.

The analyst must determine whether the archived information represents legitimate user activity or whether it forms part of a larger attack sequence.

For example, archive activity becomes more significant when correlated with earlier suspicious behavior such as:

```text
Suspicious Execution
        ↓
System Discovery
        ↓
Credential Access
        ↓
Data Collection
        ↓
Archive Creation
        ↓
Possible Exfiltration
```

This correlation helps distinguish normal archive creation from activity that may represent preparation for data theft.

Detailed attack simulation steps, SPL detection logic, screenshots, MITRE ATT&CK mapping, and technical analysis are documented in:

`docs/use-cases/UC-008-Archive-Collected-Data.md`

---

## 4. Incident Timeline

| Stage | Activity |
|---|---|
| Attack Simulation | Archive creation activity was intentionally generated on `target-pc`. |
| Telemetry Generation | Endpoint monitoring recorded the activity associated with the archive operation. |
| Log Collection | Splunk Universal Forwarder forwarded the relevant telemetry to Splunk. |
| Detection | The activity matched the UC-008 archive collection detection logic. |
| Investigation | The analyst reviewed the process, command line, host, user context, and surrounding activity. |
| Correlation | The archive activity was evaluated in the context of the broader simulated attack sequence. |
| Assessment | The activity was confirmed as part of the controlled data collection simulation. |
| Closure | The incident was documented and closed as a laboratory security incident. |

---

## 5. Incident Response — PICERL

### 5.1 Preparation

The SOC laboratory was prepared with:

- Sysmon endpoint monitoring;
- process creation telemetry;
- file-related endpoint visibility;
- Splunk Universal Forwarder;
- centralized Splunk logging;
- archive activity detection logic.

These controls provided the visibility required to identify archive-related behavior on the monitored endpoint.

### 5.2 Identification

The incident was identified from endpoint telemetry associated with archive creation activity.

The analyst reviewed the relevant process information and command-line context to determine how the archive was created and which endpoint generated the activity.

The observed behavior matched the detection criteria implemented in UC-008.

Because archive creation can occur during legitimate system activity, the event was not evaluated in isolation.

The analyst also considered the surrounding attack sequence and other endpoint telemetry collected during the simulation.

### 5.3 Containment

In a production environment, suspicious archive creation associated with possible data theft would require investigation before the collected information could leave the environment.

If malicious collection were confirmed, possible containment actions could include:

- isolating the affected endpoint;
- terminating confirmed malicious processes;
- restricting suspicious outbound communication;
- protecting sensitive files from additional access;
- investigating the user account responsible for the activity;
- searching other endpoints for similar archive creation behavior.

Because the activity occurred intentionally inside the isolated SOC laboratory, production containment was not required.

### 5.4 Eradication

For a confirmed compromise, eradication would focus on removing the malicious tooling or scripts responsible for collecting and archiving the information.

The analyst would also investigate and remove:

- malicious payloads;
- unauthorized persistence;
- temporary staging files;
- suspicious archives;
- other artifacts created during the attack.

The original compromise mechanism would also need to be identified and removed.

No production remediation was required during the controlled laboratory simulation.

### 5.5 Recovery

In a real incident, the affected endpoint would be returned to normal operation only after confirming that unauthorized collection activity had stopped.

The analyst would verify that:

- malicious artifacts had been removed;
- unauthorized archive files were no longer present;
- normal endpoint activity had resumed;
- security telemetry continued to reach the SIEM;
- no additional suspicious collection or exfiltration activity was occurring.

In the laboratory, the endpoint remained operational and continued forwarding telemetry to Splunk.

### 5.6 Lessons Learned

Archive creation is not inherently malicious.

The security value of this activity depends heavily on context.

A SOC analyst should therefore correlate archive activity with:

- the process creating the archive;
- command-line arguments;
- user context;
- files involved;
- previous suspicious execution;
- discovery activity;
- credential access;
- subsequent network or exfiltration behavior.

The simulation demonstrated that activity associated with data staging becomes significantly more meaningful when analyzed as part of a complete attack sequence rather than as an isolated event.

---

## 6. Final Assessment

**IR-008 was successfully detected and investigated.**

The monitoring workflow operated as expected:

```text
Data Collection
      ↓
Archive Activity
      ↓
Endpoint Telemetry
      ↓
Splunk Universal Forwarder
      ↓
Splunk
      ↓
Detection
      ↓
SOC Investigation
```

The activity was intentionally generated inside the controlled SOC laboratory and did not represent a real compromise.

The incident validates the environment's ability to identify archive-related collection activity and demonstrates the importance of correlating data staging behavior with earlier and later stages of an attack.

This incident also provides an important transition toward the next attack stage: **data exfiltration**, where collected information may be transferred outside the compromised environment.
