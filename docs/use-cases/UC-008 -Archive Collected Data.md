# UC-008 – Archive Collected Data

## Overview

This use case simulates the preparation of collected data for potential exfiltration by compressing multiple files into a single archive.

The activity maps to:

- **MITRE ATT&CK Technique:** T1560 – Archive Collected Data
- **Sub-technique:** T1560.001 – Archive via Utility
- **Target Host:** `target-pc`
- **Detection Source:** Sysmon
- **SIEM:** Splunk
- **Primary Event:** Sysmon Event ID 1 – Process Creation

The objective is to identify archive creation activity through process execution telemetry and command-line analysis.

---

## 1. Simulation Preparation

A dedicated directory was created on `target-pc` containing dummy files representing data that could potentially be collected by an attacker.

Directory:

```text
C:\SOC-Lab\Collection
```

The following test files were created:

```text
employees.txt
finance.txt
internal.txt
```

These files contain only dummy data created specifically for the isolated SOC lab.

### Evidence

![Dummy files prepared for collection](../../screenshots/detections/UC-008-dummy-files.png)

---

## 2. Archive Simulation

The collected files were archived using the native Windows `tar.exe` utility.

The following command was executed:

```powershell
tar.exe -a -c -f C:\SOC-Lab\collection.zip C:\SOC-Lab\Collection
```

The command creates a ZIP archive named:

```text
C:\SOC-Lab\collection.zip
```

from the files located in:

```text
C:\SOC-Lab\Collection
```

Using a standalone archive utility generated process creation telemetry that could be observed through Sysmon and forwarded to Splunk.

---

## 3. Initial SOC Investigation

Instead of searching directly for `tar.exe`, the investigation started with a broader review of process creation activity on the target endpoint.

The following Splunk query was used:

```spl
index=windows host="target-pc" EventCode=1 earliest=-4h
| stats count by Image
| sort +count
```

The search returned approximately **1,650 process creation events** representing **120 unique process images**.

Reviewing the process distribution revealed the execution of:

```text
C:\Windows\System32\tar.exe
```

This provided a lead for further investigation.

### Evidence

![Process execution narrowing](../../screenshots/detections/UC-008-process-narrowing.png)

---

## 4. Investigation of tar.exe

The investigation was then narrowed to Sysmon Process Creation events associated specifically with `tar.exe`.

The following Splunk query was used:

```spl
index=windows host="target-pc" EventCode=1 Image="*\\tar.exe" earliest=-4h
| table _time User Image CommandLine ParentImage
```

The search returned a single relevant process creation event.

The observed telemetry included:

```text
User:
BADR\Administrator

Image:
C:\Windows\System32\tar.exe

Parent Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Command Line:
"C:\WINDOWS\system32\tar.exe" -a -c -f C:\SOC-Lab\collection.zip C:\SOC-Lab\Collection
```

The command-line telemetry shows that `tar.exe` was launched from PowerShell and used to create `collection.zip` from the `C:\SOC-Lab\Collection` directory.

### Evidence

![tar.exe process creation detected in Splunk](../../screenshots/detections/UC-008-tar-process-creation.png)

---

## 5. Detection Logic

The activity can be identified by monitoring process creation events for archive utilities and analyzing their command-line arguments.

An example Splunk detection query is:

```spl
index=windows EventCode=1
(
    Image="*\\tar.exe"
    OR Image="*\\7z.exe"
    OR Image="*\\rar.exe"
)
| table _time host User Image ParentImage CommandLine
| sort -_time
```

The execution of an archive utility alone should not automatically be considered malicious.

Additional context such as the user, parent process, command line, execution time, source files, and surrounding activity should be investigated before determining whether the behavior is suspicious.

---

## 6. Detection Result

The archive activity was successfully captured by Sysmon and forwarded to Splunk.

Sysmon Event ID 1 provided the necessary telemetry to identify:

- The archive utility used: `tar.exe`
- The account executing the process: `BADR\Administrator`
- The parent process: `powershell.exe`
- The complete command line
- The archive destination: `C:\SOC-Lab\collection.zip`
- The source directory: `C:\SOC-Lab\Collection`
- The execution timestamp

The investigation demonstrated how broad process telemetry can be progressively narrowed until the relevant archive activity is identified.

---

## 7. MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Collection |
| Technique | Archive Collected Data |
| Technique ID | T1560 |
| Sub-technique | Archive via Utility |
| Sub-technique ID | T1560.001 |
| Data Source | Process Creation |
| Detection Source | Sysmon Event ID 1 |
| SIEM | Splunk |
| Host | `target-pc` |

---

## Conclusion

UC-008 successfully demonstrated the detection and investigation of archive creation activity on the Windows 11 endpoint.

The investigation started from a broad set of process creation events and progressively narrowed the results until the relevant `tar.exe` execution was identified.

The final Sysmon Event ID 1 provided the process, user, parent process, command-line, and timestamp context required to investigate the activity in Splunk.

The observed behavior is consistent with **MITRE ATT&CK T1560.001 – Archive via Utility** and demonstrates how archive creation can be detected as part of data collection and staging activity.
