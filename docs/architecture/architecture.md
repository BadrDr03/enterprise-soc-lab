# SOC Lab Architecture

## 1. Architecture Overview

This project implements a small enterprise-style Security Operations Center (SOC) validation environment designed to centralize security telemetry, detect suspicious activity, investigate security events, and document the incident response lifecycle.

The laboratory consists of a centralized Splunk SIEM server, an Active Directory Domain Controller, a Windows 11 endpoint, and a Kali Linux simulation machine connected through a VirtualBox NAT Network.

Windows telemetry is collected using Sysmon and native Windows event logs, then forwarded to Splunk through the Splunk Universal Forwarder. Controlled security scenarios are generated using Atomic Red Team and laboratory simulations. Threat Intelligence services are used to enrich public IP indicators during investigations.

The environment is designed as a lightweight validation platform rather than a production deployment. Its objective is to reproduce the main technical workflows of a SOC while remaining suitable for a virtual laboratory.

---

## 2. Design Objectives

The architecture was designed to achieve the following objectives:

- Simulate an enterprise-style SOC environment.
- Centralize Windows security telemetry using Splunk SIEM.
- Collect detailed endpoint telemetry using Sysmon.
- Forward endpoint events using Splunk Universal Forwarder.
- Generate controlled attack scenarios.
- Develop and validate detection searches.
- Map detection scenarios to MITRE ATT&CK techniques.
- Perform Threat Intelligence enrichment.
- Investigate security events and document incidents.
- Apply the Five Whys technique when relevant for root cause analysis.
- Produce professional technical documentation.

---

## 3. Network Topology

The laboratory uses a dedicated VirtualBox NAT Network:

| Asset | Role | IP Address |
|---|---|---|
| Splunk Server | SIEM / Log Analytics | `10.0.10.10` |
| ADDC01 | Active Directory / Domain Controller | `10.0.10.7` |
| target-pc | Windows 11 Target Endpoint | `10.0.10.20` |
| Kali Linux | Security Simulation Machine | `10.0.10.250` |
| Gateway | VirtualBox NAT Gateway | `10.0.10.1` |

**Network:** `10.0.10.0/24`  
**Domain:** `badr.local`  
**DNS Server:** `10.0.10.7`

![SOC Lab Network Architecture](../../architecture/network-diagram.png)

> The architecture diagram represents the logical organization of the validation laboratory. The exact image path may be adjusted according to the repository screenshot structure.

---

## 4. Design Decisions

### 4.1 Splunk SIEM

**Purpose**

Centralized Security Information and Event Management (SIEM).

**Why was it selected?**

Splunk provides log collection, indexing, SPL-based searches, dashboards, alerting, and investigation capabilities that are suitable for building and validating SOC monitoring workflows.

**Role**

- Receive security telemetry from monitored Windows systems.
- Index and normalize searchable events.
- Execute detection searches.
- Support investigation and correlation.
- Display operational dashboards.
- Integrate Threat Intelligence enrichment data.

**Main indexes**

- `windows`
- `sysmon`
- `activedirectory`
- `threat_intel`
- `atomic`

**Expected Output**

Centralized visibility across monitored systems and a single investigation point for the SOC analyst.

---

### 4.2 Windows Server – Active Directory Domain Controller

**Hostname:** `ADDC01`  
**IP Address:** `10.0.10.7`  
**Domain:** `badr.local`

**Purpose**

Provide a Windows Server environment representing centralized enterprise identity and authentication services.

**Role**

- Operate as the Active Directory Domain Controller.
- Provide DNS services for the laboratory domain.
- Generate Windows and Active Directory-related telemetry.
- Provide a second monitored Windows system in addition to the Windows 11 endpoint.
- Participate in authentication and RDP-related validation scenarios.

**Security Monitoring**

Sysmon and Splunk Universal Forwarder are installed on the server so relevant endpoint and Windows telemetry can be forwarded to the centralized Splunk server.

**Expected Output**

Visibility into server-side activity, authentication events, endpoint activity, and RDP-related telemetry.

---

### 4.3 Windows 11 Endpoint

**Hostname:** `target-pc`  
**IP Address:** `10.0.10.20`

**Purpose**

Represent a monitored enterprise workstation and the primary endpoint used for controlled detection validation.

**Role**

- Generate normal Windows endpoint activity.
- Execute controlled Atomic Red Team tests.
- Generate process, registry, network, and system telemetry.
- Validate Splunk detection searches.
- Support investigation of simulated security scenarios.

**Monitoring Components**

- Sysmon
- Splunk Universal Forwarder
- Native Windows event channels

**Expected Output**

Detailed endpoint telemetry forwarded to Splunk for detection and investigation.

---

### 4.4 Sysmon

**Purpose**

Provide detailed Windows endpoint telemetry beyond standard Windows logging.

**Why was it selected?**

Sysmon provides visibility into security-relevant endpoint activity such as process creation, network connections, registry changes, file creation, module loading, and DNS queries.

The laboratory uses a Sysmon configuration based on the SwiftOnSecurity configuration.

**Relevant Event IDs observed and used in the laboratory include:**

| Event ID | Description |
|---:|---|
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | Image Loaded |
| 11 | File Creation |
| 13 | Registry Value Set |
| 22 | DNS Query |

Not every event type is expected to appear in every simulation. Detection logic is based on the telemetry actually observed during each validation scenario.

**Role**

Sysmon acts as the main endpoint telemetry source for process and system-level detection use cases.

---

### 4.5 Splunk Universal Forwarder

**Purpose**

Forward Windows telemetry from monitored systems to the centralized Splunk server.

**Installed on**

- `ADDC01`
- `target-pc`

**Data Flow**

```text
Windows Event Logs / Sysmon
          |
          v
Splunk Universal Forwarder
          |
          | TCP 9997
          v
Splunk Server
10.0.10.10
