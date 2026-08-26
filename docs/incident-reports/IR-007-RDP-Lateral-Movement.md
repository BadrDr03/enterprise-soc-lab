# IR-007 — RDP Lateral Movement

## 1. Incident Summary

Remote Desktop Protocol (RDP) activity associated with lateral movement was detected during the SOC laboratory attack simulation.

RDP is a legitimate Windows remote administration protocol operating primarily over TCP port `3389`. However, attackers who obtain valid credentials may abuse RDP to remotely access additional systems and move through an environment.

The activity generated both authentication and network telemetry that was collected and analyzed in Splunk.

This incident corresponds to **UC-007 — RDP Lateral Movement**.

---

## 2. Incident Classification

| Field | Value |
|---|---|
| Incident ID | IR-007 |
| Related Use Case | UC-007 — RDP Lateral Movement |
| Data Sources | Windows Security Logs + Sysmon |
| SIEM | Splunk |
| Relevant Events | Windows 4624 / 4625 + Sysmon Event ID 3 |
| Network Protocol | RDP |
| Destination Port | TCP 3389 |
| Activity Type | Lateral Movement / Remote Access |
| Severity | High |
| Status | Detected / Investigated |
| Environment | Controlled SOC Laboratory |

The incident was classified as **High severity** because unauthorized RDP access can allow an attacker to establish an interactive session on another system and continue post-compromise activity using legitimate credentials.

---

## 3. Investigation Findings

The investigation combined authentication telemetry with network connection telemetry.

Relevant evidence included:

- RDP network connections over TCP port `3389`;
- source and destination information;
- successful authentication events;
- failed authentication attempts;
- affected host information;
- user authentication context.

Windows Security Event IDs provided authentication visibility:

```text
4624 → Successful Logon
4625 → Failed Logon
```

Sysmon Event ID 3 provided network connection visibility associated with RDP traffic.

Correlating these data sources provided stronger evidence than analyzing either authentication or network telemetry independently.

The SOC Security Overview dashboard also provides dedicated visibility through the **RDP Activity** and **Authentication Activity** panels.

Detailed attack simulation steps, SPL detection logic, screenshots, MITRE ATT&CK mapping, and technical analysis are documented in:

`docs/use-cases/UC-007-RDP-Lateral-Movement.md`

---

## 4. Incident Timeline

| Stage | Activity |
|---|---|
| Attack Simulation | RDP authentication and remote-access activity was generated in the laboratory. |
| Authentication Telemetry | Windows Security Logs recorded authentication attempts. |
| Network Telemetry | Sysmon recorded network connections associated with TCP port 3389. |
| Log Collection | The telemetry was forwarded to the central Splunk server. |
| Detection | Splunk detection logic identified RDP-related activity. |
| Correlation | Authentication and network events were reviewed together. |
| Investigation | The analyst reviewed hosts, authentication status, user context, and RDP network activity. |
| Assessment | The activity was confirmed as part of the controlled lateral movement simulation. |
| Closure | The incident was documented and closed. |

---

## 5. Incident Response — PICERL

### 5.1 Preparation

The SOC laboratory was prepared with:

- Windows Security Event collection;
- Sysmon network monitoring;
- Splunk Universal Forwarder;
- centralized Splunk logging;
- authentication monitoring;
- RDP detection logic;
- SOC dashboard visibility.

Collecting both authentication and network telemetry provided multiple sources of evidence for the investigation.

### 5.2 Identification

The activity was identified by reviewing RDP-related network connections and Windows authentication events.

The analyst correlated:

```text
Authentication Events
        +
RDP Network Activity
        +
Host and User Context
```

Successful and failed authentication events helped determine how authentication activity developed around the remote-access attempt.

Sysmon network telemetry confirmed communication associated with TCP port `3389`.

### 5.3 Containment

In a production environment, unauthorized RDP lateral movement would require rapid containment.

Possible response actions could include:

- isolating affected endpoints;
- disabling or restricting the compromised account;
- terminating unauthorized remote sessions;
- temporarily restricting RDP access where appropriate;
- investigating other systems for use of the same credentials.

Because the activity occurred inside the controlled SOC laboratory, production containment actions were not required.

### 5.4 Eradication

For a confirmed compromise, the analyst would investigate how the attacker obtained the credentials used for remote access.

Eradication could include:

- removing malicious tools or payloads;
- removing unauthorized persistence;
- securing the original compromised endpoint;
- resetting compromised credentials after containment;
- investigating additional lateral movement.

The RDP session itself may represent only one stage of a larger compromise, so remediation should address the attacker's original access and associated artifacts.

### 5.5 Recovery

In a production incident, affected systems would be returned to normal operation only after confirming that unauthorized access had been removed.

The analyst would continue monitoring:

- authentication events;
- RDP activity;
- account usage;
- endpoint process activity;
- network connections.

In the laboratory, the systems remained operational and telemetry continued to reach Splunk.

### 5.6 Lessons Learned

The incident demonstrated that RDP activity should not be evaluated using TCP port `3389` alone.

RDP is commonly used for legitimate administration.

A stronger investigation combines:

- source and destination systems;
- successful and failed authentication;
- user account;
- network connection;
- surrounding endpoint activity.

The simulation demonstrated the value of correlating multiple telemetry sources when investigating possible lateral movement.

---

## 6. Final Assessment

**IR-007 was successfully detected and investigated.**

The monitoring workflow combined multiple data sources:

```text
RDP Activity
      ↓
Windows Authentication + Sysmon Network Telemetry
      ↓
Splunk
      ↓
Correlation
      ↓
SOC Investigation
```

The activity occurred intentionally inside the controlled SOC laboratory and did not represent a real compromise.

The incident validates the SOC environment's ability to correlate authentication and network telemetry when investigating RDP-based lateral movement and demonstrates how multiple security events can provide stronger context than a single isolated indicator.
