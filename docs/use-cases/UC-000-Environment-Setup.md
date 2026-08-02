# UC-000 — Environment Setup

## Objective

Prepare the Enterprise SOC Lab by configuring the Splunk SIEM infrastructure and validating endpoint telemetry using Sysmon before integrating Windows endpoints into the monitoring platform.

---

# 1. Splunk Base Configuration

## 1.1 Dedicated Indexes

Five dedicated indexes were created to organize security data based on its source and purpose.

| Index | Purpose |
|--------|---------|
| windows | Windows Event Logs |
| sysmon | Sysmon telemetry |
| activedirectory | Active Directory events |
| threat_intel | Threat Intelligence data |
| atomic | Atomic Red Team events |

Using dedicated indexes improves data organization, search performance, and simplifies detection engineering.

### Screenshot

> Insert Screenshot: **splunk-indexes.png**

![](../../screenshots/infrastructure/splunk-indexes.png)

---

## 1.2 Receiving Port

Splunk was configured to listen on TCP port **9997**.

This port is used by the Splunk Universal Forwarder to securely transmit logs from monitored endpoints.

### Screenshot

> Insert Screenshot: **splunk-port-9997.png**

![](../../screenshots/infrastructure/splunk-port-9997.png)

---

## 1.3 Windows Sourcetypes Verification

The default Windows sourcetypes were verified to ensure that Splunk correctly parses Windows Event Logs and Sysmon telemetry.

Verified sourcetypes include:

- WinEventLog:Security
- WinEventLog:System
- WinEventLog:Application
- XmlWinEventLog

### Screenshot

> Insert Screenshot: **splunk-sourcetypes.png**

![](../../screenshots/infrastructure/splunk-sourcetypes.png)

---

## 1.4 Time Synchronization

The Splunk server, Windows Server, Windows 11 workstation, and Kali Linux attacker machine were configured to use the **Africa/Casablanca** timezone.

Time synchronization is essential for accurate event correlation during security investigations.

### Screenshot

> Insert Screenshot: **timezone.png**

![](../../screenshots/infrastructure/timezone.png)

---

## 1.5 Splunk Health Validation

The Splunk service was verified to ensure that the platform is operational.

License information:

- Splunk Enterprise Trial
- Daily ingestion limit: **500 MB**
- License status: Active

### Screenshot

> Insert Screenshot: **splunk-license.png**

![](../../screenshots/infrastructure/splunk-license.png)

---

# 2. Sysmon Validation

## 2.1 Service Status

The Sysmon service was verified to ensure that endpoint telemetry collection is active.

### Screenshot

> Insert Screenshot: **sysmon-service.png**

![](../../screenshots/infrastructure/sysmon-service.png)

---

## 2.2 Configuration Validation

The SwiftOnSecurity configuration was successfully applied.

This configuration enables detailed endpoint telemetry while reducing unnecessary events.

### Screenshot

> Insert Screenshot: **sysmon-config.png**

![](../../screenshots/infrastructure/sysmon-config.png)

---

## 2.3 Operational Log

Sysmon events were successfully generated inside:

```
Microsoft-Windows-Sysmon/Operational
```

### Screenshot

> Insert Screenshot: **sysmon-operational-log.png**

![](../../screenshots/infrastructure/sysmon-operational-log.png)

---

## 2.4 Verified Event IDs

The following Event IDs were successfully generated and verified.

| Event ID | Description |
|----------|-------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | Image Loaded |
| 11 | File Creation |
| 13 | Registry Modification |
| 22 | DNS Query |

---

### Event ID 1

> Insert Screenshot: **event-id-1.png**

![](../../screenshots/infrastructure/event-id-1.png)

---

### Event ID 3

> Insert Screenshot: **event-id-3.png**

![](../../screenshots/infrastructure/event-id-3.png)

---

### Event ID 22

> Insert Screenshot: **event-id-22.png**

![](../../screenshots/infrastructure/event-id-22.png)

---

# 3. Validation Summary

| Component | Status |
|----------|--------|
| Splunk Installed | ✅ |
| Splunk Service Running | ✅ |
| Dedicated Indexes Created | ✅ |
| TCP 9997 Enabled | ✅ |
| Windows Sourcetypes Verified | ✅ |
| Time Synchronization Verified | ✅ |
| Sysmon Installed | ✅ |
| SwiftOnSecurity Configuration Applied | ✅ |
| Sysmon Operational Logs Available | ✅ |
| Critical Event IDs Verified | ✅ |

---

# 4. Lessons Learned

- Splunk indexes should be separated according to the type of collected telemetry.
- TCP port 9997 is the standard receiving port for Splunk Universal Forwarders.
- Accurate time synchronization is critical for event correlation and incident timeline reconstruction.
- Sysmon significantly enhances Windows endpoint visibility compared to default Windows Event Logs.
- Verifying telemetry before forwarding logs simplifies troubleshooting during later deployment stages.
