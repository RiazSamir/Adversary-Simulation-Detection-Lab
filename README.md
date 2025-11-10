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
### pfSense
**What is it:**
PfSense is an open source firewall/router copmuter based software based on FreeBSD. 

**Lab Use:** 
PfSense served as a firewall/gateway, isolating the internal network whilst allowing controlled outbound internet access. 

**Configuration:**
Configuration involved assigning the LAN and WAN interfaces and validating connectivity. In the future, I plan to configure a web proxy using Squid on pfSense.

<p align="center">
  <img width="681" height="246" alt="image" src="https://github.com/user-attachments/assets/b13dd6bc-44a5-4ff8-a659-9b4632d78c7e" />
</p>
<p align="center"><b>Figure 2: pfSense Interface which shows the IP Address of the LAN and WAN Interface</b></p>


### Active Directory 
**What is it:**
On-Premise Active Directory is a Direcotry Service provided by microsoft to enable the centralizations of users, computers, and resources within a domain. 

**Lab Use:**
For this project Active Directory forms the core of the network. Allowing us to push out GPO to all machines joined on the network to produce realistic authentication logs, failed logon attempts, user activity, etc. 
