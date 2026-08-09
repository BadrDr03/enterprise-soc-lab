# UC-006 — Obfuscated PowerShell Command

## Objective

Detect obfuscated PowerShell execution using Sysmon telemetry and Splunk SIEM.

---

## MITRE ATT&CK

| Tactic | Technique | ID |
|---------|-----------|----|
| Defense Evasion | Obfuscated Files or Information | T1027 |

Reference:  
https://attack.mitre.org/techniques/T1027/

---

## Attack Description

An Atomic Red Team test (`T1027-11`) was executed in a controlled laboratory environment to simulate PowerShell command obfuscation.

The test represented a PowerShell command as a character array and reconstructed it at runtime using PowerShell operations such as `[char[]]` and `-join`.

The reconstructed command launched Windows Calculator (`calc.exe`).

---

## Data Source

- Sysmon Event ID 1 — Process Creation

---

## Detection Query

```spl
index=windows EventCode=1 "*char[]*"
| table _time ComputerName User ParentImage Image ParentCommandLine CommandLine
| sort -_time
```

---

## Detection Evidence

### Atomic Red Team Execution

![](../../screenshots/detections/UC-006-test-command.png)

The Atomic Red Team test completed successfully with exit code `0`.

---

### Splunk Detection

![](../../screenshots/detections/UC-006-query-result.png)

Splunk identified process creation events containing the character-array pattern used during the test.

---

### Event Details

![](../../screenshots/detections/UC-006-event-details.png)

---

## Investigation

| Field | Value |
|-------|-------|
| Technique | T1027 |
| Atomic Test | T1027-11 |
| Event ID | 1 |
| Process | powershell.exe |
| Parent Process | powershell.exe |
| Obfuscation Pattern | `[char[]]` and `-join` |
| Executed Command | `Start-Process calc.exe` |
| User | BADR\Administrator |
| Host | target-pc |
| Integrity Level | High |

---

## Detection Logic

The detection focuses on PowerShell command-line behavior associated with character-array obfuscation.

Detecting `powershell.exe` alone would generate many false positives because PowerShell is a legitimate administrative tool.

Instead, the detection searches for patterns such as:

- PowerShell execution
- Character-array construction using `[char[]]`
- Runtime string reconstruction using `-join`

These indicators can reveal attempts to hide the real command from simple command-line inspection.

---

## 5 WHY Analysis

### Problem

Obfuscated PowerShell activity was detected on the endpoint.

### Why 1

Why was the PowerShell command difficult to read?

Because parts of the command were represented using a character array.

### Why 2

Why were characters used instead of a normal command?

To reconstruct the actual command dynamically during execution.

### Why 3

Why would an attacker reconstruct a command dynamically?

To make the original command less obvious during inspection and potentially evade simple detection mechanisms.

### Why 4

Why is command obfuscation relevant to a SOC?

Because attackers can use obfuscation to conceal suspicious commands inside otherwise legitimate tools such as PowerShell.

### Why 5

Why should the SOC detect obfuscation patterns?

Because unusual command construction can provide an early indicator of defense evasion or malicious script execution.

### Root Cause

A PowerShell command was intentionally obfuscated using character-array construction and runtime string reconstruction.

---

## Analyst Conclusion

Splunk successfully detected the obfuscated PowerShell activity through Sysmon Event ID 1.

The investigation showed a PowerShell parent command containing character-array and string reconstruction patterns, while the resulting PowerShell process executed `Start-Process calc.exe`.

During this laboratory, the activity was intentionally generated using Atomic Red Team to validate detection of command obfuscation.

In a production environment, this behavior should be investigated in context because PowerShell obfuscation may be used to conceal malicious commands and evade security monitoring.

---

## Detection Status

| Item | Status |
|------|--------|
| Attack Executed | ✅ |
| Sysmon Logged Event | ✅ |
| Splunk Detection | ✅ |
| Event Investigated | ✅ |
| MITRE Mapping | ✅ |
| Detection Logic | ✅ |
| 5 WHY Analysis | ✅ |
