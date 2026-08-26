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
