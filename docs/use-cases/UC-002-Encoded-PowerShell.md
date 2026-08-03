# UC-002 — Encoded PowerShell Detection

## Objective

Detect PowerShell processes executed with an encoded command, a technique commonly used to hide command content and evade basic inspection.

---

## MITRE ATT&CK

| Tactic | Technique | ID |
|---|---|---|
| Execution | PowerShell | T1059.001 |
| Defense Evasion | Obfuscated/Compressed Files and Information | T1027 |

---

## Data Source

- Sysmon Event ID 1 — Process Creation

---

## Detection Logic

The detection searches for PowerShell process-creation events whose command line contains the `-EncodedCommand` or shortened `-enc` argument.

---

## SPL Query

```spl
index=windows EventCode=1 Image="*powershell.exe"
(CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*")
| table _time User ParentImage Image CommandLine ComputerName
```

### Detection Evidence

![](../../screenshots/detections/query-result.png)

---

## Test Performed

A harmless PowerShell command was encoded using UTF-16LE Base64 and executed with the `-EncodedCommand` argument.

```powershell
$cmd = "Write-Output 'Hello'"
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($cmd)
)
powershell.exe -EncodedCommand $encoded
```

### Test Evidence

![](../../screenshots/detections/test-command.png)

---

## Result

Sysmon recorded the PowerShell process creation, including the encoded command-line argument. The event was forwarded to Splunk, and the SPL query successfully returned the matching event.

---

## Investigation Summary

| Field | Finding |
|---|---|
| Process | `powershell.exe` |
| Suspicious argument | `-EncodedCommand` |
| Data source | Sysmon Event ID 1 |
| Environment | Controlled SOC laboratory |
| Classification | Benign test activity |

---

## Analyst Conclusion

Encoded PowerShell is not automatically malicious, but it reduces command visibility and is frequently associated with attacker activity.

This event was classified as **benign** because it was intentionally generated during controlled detection validation. In a production environment, the analyst should decode the Base64 content and examine the user, parent process, host, and related network activity.

---

## Detection Status

| Item | Status |
|---|---|
| Test executed | ✅ |
| Event collected | ✅ |
| SPL detection successful | ✅ |
| Investigation completed | ✅ |
