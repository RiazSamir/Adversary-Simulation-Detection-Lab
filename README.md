# Adversary-Simulation-Detection-Lab
End-to-end detection lab using AD, pfSense, Zeek, Suricata, Sysmon and Splunk. Includes adversary simulation, network telemetry, and detection analysis
## Overview 
This project simulates a small enterprise network to develop SOC analysis Skills as well as Threat Hunting. This lab includes Active Directory, pfSense, Zeek, suricata, Splunk. Furthermore, it also includes adversary simulation with the use of kali linux, Atomic Red Team, Nmap, and malware execution. 
## Network Diagram 
<p align="center">
  <img width="562" height="694" alt="image" src="https://github.com/user-attachments/assets/080739ff-4dcf-4c49-a618-b8e0f2b91db5" />
</p>
<p align="center"><b>Figure 1: Diagram of Network Architecture</b></p>

## Lab Components 
- pfsense (Firewall & Gateway)
- Windows Server 2022 (Active Direcotry Domain Controller)
- Windows 10 Endpoint
- Zeek (Network Sensor)
- Suricata (IDS)
- Splunk (SIEM)
- Kali Linux (Attacker Machine)

## Network Layout
| Host / Service        | Role / Description             | IP Address     |
|-----------------------|--------------------------------|----------------|
| pfSense (WAN)         | Firewall WAN Interface         | 192.168.107.133 |
| pfSense (LAN)         | Firewall LAN Interface         | 192.168.1.1     |
| Active Directory DC   | Domain Controller + DNS        | 192.168.1.10    |
| Windows 10 Client     | Domain-Joined Workstation      | 192.168.1.100   |
| Kali Linux Attacker   | Attacker Machine               | 192.168.1.101   |
| Zeek & Suricata Sensor| Network IDS + Traffic Monitor  | 192.168.1.8     |
| Splunk Server         | SIEM + Log Aggregation         | 192.168.1.9     |

## Setup and Configuration 
### **pfSense**
**What is it:**
PfSense is an open source firewall/router copmuter based software based on FreeBSD. 

**Lab Use:** 
PfSense served as a firewall/gateway, isolating the internal network whilst allowing controlled outbound internet access. 

**Configuration:**
- Configuration involved assigning the LAN and WAN interfaces and validating connectivity. In the future, I plan to configure a web proxy using Squid on pfSense.

<p align="center">
  <img width="600" height="200" alt="image" src="https://github.com/user-attachments/assets/b13dd6bc-44a5-4ff8-a659-9b4632d78c7e" />
</p>
<p align="center"><b>Figure 2: pfSense Interface which shows the static IP Address of the LAN and WAN Interface</b></p>


### **Active Directory**
**What is it:**
On-Premise Active Directory is a Direcotry Service provided by microsoft to enable the centralizations of users, computers, and resources within a domain. 

**Lab Use:**
For this project Active Directory forms the core of the network. Allowing us to push out GPO to all machines joined on the network to produce realistic authentication logs, failed logon attempts, user activity, etc. 

**Configuration:**
  Setting up Active Direcotry involved the following:
  - Installed Windows Server and promoted it to a Domain Controller (*Figure 3*)
  - Domain created: SAM-AD.local
  - Configuring a static IP Address (192.168.1.10/24)
  - Default gateway: 192.168.1.1 (pfSense LAN)
  - Created three Organizational Units (OUs):
    - Finance
    - IT
    - Sales
  - Created three test users and assigned each to an OU (*Figure 4*):
    - Fin → Finance OU
    - Ian → IT OU
    - Sally → Sales OU
  - Created a dedicated GPO for auditing following [Microsoft’s best practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations?tabs=winclient). This is essential because a standard Windows system does not log key security events such as credential validation, Kerberos authentication, and account logon events by default.
    - Process Creation (Event ID 4688) is an important audit event. To make it useful, you must enable “Include command line in process creation events”, which adds command-line telemetry to Event 4688. This allows us to see exactly which commands were executed (*Figure 5*).
  - Besides the recommended audit policies I had also enabled "**PowerShell Script Block Logging**" (Event ID 4104) to log usage of powershell. 



**Active Direcotry Screenshots**

<p align="center">
  <img width="500" height="200" alt="image" src="https://github.com/user-attachments/assets/f0de671e-3f62-4686-b308-63cfc4ace9a0" />
</p>
<p align="center"><b>Figure 3: Domain Controller Deployment</b></p>

<p align="center">
  <img width="239" height="240" alt="image" src="https://github.com/user-attachments/assets/12f6996d-03f4-4066-b814-d3a085564e9f" />
</p>
<p align="center"><b>Figure 4: Organizational Units Created</b></p>

<p align="center">
  <img width="969" height="282" alt="image" src="https://github.com/user-attachments/assets/f62ed37c-f72a-48b0-ac47-accf57522e4f" />
</p>
<p align="center"><b>Figure 5: How to enable detailed process tracking</b></p>


### **Splunk**

**What is it:**
Splunk is a SIEM (Security Information Events Manager) platform which collects and indexes logs from multiple sources (e.g., Zeek, Suricata, Windows, etc) to enable search, correlation, and detection of security events.

**Lab Use:** 
Splunk will be used to collects events from all devices (except from the attacker machine) in the LAN via Splunk Universal Forwarder. By doing this we will be able to query security events within our SIEM. 

**Configuration:**
