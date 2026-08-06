# UC-005 — LSASS Credential Dumping

## Objective

Detect LSASS memory dumping activity using Sysmon telemetry and Splunk SIEM.

---

## MITRE ATT&CK

| Tactic | Technique | ID |
|---------|-----------|----|
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |

Reference:
https://attack.mitre.org/techniques/T1003/001/

---

## Attack Description

An Atomic Red Team test (T1003.001-2) was executed in a controlled laboratory environment to simulate credential dumping from the LSASS process.

The attack used **rundll32.exe** together with **comsvcs.dll** to invoke the **MiniDump** function and create a memory dump of the LSASS process.

---

## Data Source

- Sysmon Event ID 1 (Process Creation)

---

## Detection Query

```spl
index=windows EventCode=1 Image="*rundll32.exe"
CommandLine="*comsvcs.dll*"
CommandLine="*MiniDump*"
CommandLine="*lsass*"
| table _time ComputerName User ParentImage Image CommandLine
```

---

## Detection Evidence

### Atomic Red Team Execution

![](../../screenshots/detections/UC-005-test-command.png)

---

### Splunk Detection

![](../../screenshots/detections/UC-005-query-result.png)

---

### Event Details

![](../../screenshots/detections/UC-005-event-details.png)

---

## Investigation

| Field | Value |
|--------|-------|
| Technique | T1003.001 |
| Event ID | 1 |
| Process | rundll32.exe |
| Parent Process | powershell.exe |
| DLL | comsvcs.dll |
| Function | MiniDump |
| Target Process | lsass.exe |
| Dump File | lsass-comsvcs.dmp |
| User | BADR\Administrator |
| Host | target-pc |

---

## Detection Logic

This detection is based on the behavior of LSASS memory dumping rather than the execution of **rundll32.exe** alone.

The rule correlates multiple indicators within the command line to identify credential dumping activity.

Detection Indicators:

- Process: rundll32.exe
- DLL: comsvcs.dll
- Function: MiniDump
- Target Process: lsass.exe

Using multiple indicators significantly reduces false positives because **rundll32.exe** is a legitimate Windows process that is frequently executed during normal system operation.

---

## 5 WHY Analysis

### Problem

Credential dumping activity targeting the LSASS process was detected.

### Why 1

Why was **rundll32.exe** executed?

Because it was used to invoke **comsvcs.dll**.

### Why 2

Why was **comsvcs.dll** used?

Because it exposes the **MiniDump** function capable of dumping process memory.

### Why 3

Why dump the LSASS process?

Because LSASS stores authentication material that may contain user credentials.

### Why 4

Why are credentials valuable?

Attackers can use them for privilege escalation and lateral movement.

### Why 5

Why should SOC analysts detect this behavior?

Credential dumping is one of the most common techniques used after initial access to compromise additional systems.

### Root Cause

A credential dumping technique attempted to access the memory of the LSASS process using **rundll32.exe** and **comsvcs.dll**.

---

## Analyst Conclusion

Splunk successfully detected execution of **rundll32.exe** with command-line arguments associated with LSASS credential dumping.

The command line clearly showed execution of **comsvcs.dll** using the **MiniDump** function targeting **lsass.exe**.

During this laboratory, the activity was intentionally generated using Atomic Red Team to validate credential dumping detection.

In a production environment, this behavior should be considered highly suspicious and immediately investigated because it may indicate an attempt to steal user credentials.

---

## Detection Status

| Item | Status |
|------|--------|
| Attack Executed | ✅ |
| Sysmon Logged Event | ✅ |
| Splunk Detection | ✅ |
| Investigation Completed | ✅ |
| MITRE Mapping | ✅ |
| Detection Logic | ✅ |
| 5 WHY Analysis | ✅ |
