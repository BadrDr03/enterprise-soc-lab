# SOC Lab Architecture

## 1. Architecture Overview

This project simulates a small enterprise Security Operations Center (SOC) environment designed to monitor endpoint activity, detect cyber threats, investigate security incidents, and document the complete detection and response lifecycle.

The laboratory consists of a centralized Splunk SIEM server, an Active Directory Domain Controller, a Windows 11 endpoint, and a Kali Linux attacker machine connected through a VirtualBox NAT Network. Windows telemetry is collected using Sysmon and forwarded to Splunk through the Splunk Universal Forwarder. Controlled attack scenarios are generated using Kali Linux and Atomic Red Team, while Threat Intelligence services enrich indicators during investigations.

The architecture was intentionally designed to reproduce the workflow of a modern SOC while remaining lightweight enough to run in a virtual laboratory.

---

## 2. Design Objectives

The architecture was designed to achieve the following objectives:

- Simulate a realistic enterprise environment.
- Centralize endpoint telemetry using Splunk SIEM.
- Collect detailed Windows telemetry using Sysmon.
- Simulate real attack scenarios.
- Develop and validate detection rules.
- Perform Threat Hunting activities.
- Investigate security incidents.
- Apply the Five Whys technique for root cause analysis.
- Produce professional technical documentation.

---

## 3. Network Topology

![Import OVA](https://github.com/user-attachments/assets/48e179bd-e758-48b1-a41f-96969304741c)

---

## 4. Design Decisions

### 4.1 Splunk SIEM

**Purpose**

Centralized Security Information and Event Management (SIEM).

**Why was it selected?**

Splunk provides enterprise-grade log collection, indexing, search capabilities, dashboards, alerting, and SPL queries, making it suitable for SOC monitoring and detection engineering.

**Role**

Collects logs, indexes events, executes detection searches, generates alerts, and supports investigations.

**Expected Output**

Centralized visibility across all monitored endpoints.

---

### 4.2 Windows Server (Active Directory)

(To be completed later)

---

### 4.3 Windows 11 Endpoint

(To be completed later)

---

### 4.4 Sysmon

(To be completed later)

---

### 4.5 Splunk Universal Forwarder

(To be completed later)

---

### 4.6 Kali Linux

(To be completed later)

---

### 4.7 Atomic Red Team

(To be completed later)

---

### 4.8 Threat Intelligence

(To be completed later)

---

## 5. Security Data Flow

(To be completed later)

---

## 6. Network Ports

(To be completed later)

---

## 7. Design Limitations

(To be completed later)

---

## 8. Future Improvements

(To be completed later)
