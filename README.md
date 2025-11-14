# Adversary-Simulation-Detection-Lab
End-to-end detection lab using AD, pfSense, Zeek, Suricata, Sysmon and Splunk. Includes adversary simulation, network telemetry, and detection analysis
## Overview 
This project simulates a small enterprise network to develop SOC analysis Skills as well as Threat Hunting. This lab includes Active Directory, pfSense, Zeek, Suricata, Splunk. Furthermore, it also includes adversary simulation with the use of kali linux, Atomic Red Team, Nmap, and malware execution. 
## Network Diagram 
<p align="center">
  <img width="562" height="694" alt="image" src="https://github.com/user-attachments/assets/080739ff-4dcf-4c49-a618-b8e0f2b91db5" />
</p>
<p align="center"><b>Figure 1: Diagram of Network Architecture</b></p>

## Lab Components 
- pfsense (Firewall & Gateway)
- Windows Server 2022 (Active Directory Domain Controller)
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
- Configuration involved assigning the LAN and WAN interfaces and validating connectivity.
  - The WAN interface was configured using Bridged mode in VMWare allowing for outbound internet access. 

<p align="center">
  <img width="600" height="200" alt="image" src="https://github.com/user-attachments/assets/b13dd6bc-44a5-4ff8-a659-9b4632d78c7e" />
</p>
<p align="center"><b>Figure 2: pfSense Interface which shows the static IP Address of the LAN and WAN Interface</b></p>


### **Active Directory**
**What is it:**
On-Premise Active Directory is a Directory Service provided by microsoft to enable the centralizations of users, computers, and resources within a domain. 

**Lab Use:**
For this project Active Directory forms the core of the network. Allowing us to push out GPO to all machines joined on the network to produce realistic authentication logs, failed logon attempts, user activity, etc. 

**Configuration:**
  Setting up Active Directory involved the following:
  - Installed Windows Server and promoted it to a Domain Controller (*Figure 3*).
  - Domain created: SAM-AD.local
  - Configuring a static IP Address (192.168.1.10/24)
  - Default gateway: 192.168.1.1 (pfSense LAN)
  - Created three Organizational Units (OUs):
    - Finance
    - IT
    - Sales
  - Created three test users and assigned each to an OU (*Figure 4*).:
    - Fin → Finance OU
    - Ian → IT OU
    - Sally → Sales OU
  - Created a dedicated GPO for auditing following [Microsoft’s best practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations?tabs=winclient). This is essential because a standard Windows system does not log key security events such as credential validation, Kerberos authentication, and account logon events by default.
    - Process Creation (Event ID 4688) is an important audit event. To make it useful, you must enable “Include command line in process creation events”, which adds command-line telemetry to Event 4688. This allows us to see exactly which commands were executed (*Figure 5*)..
  - Besides the recommended audit policies I had also enabled "**PowerShell Script Block Logging**" (Event ID 4104) to log usage of powershell. 



**Active Directory Screenshots**

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
- Installed Splunk enterprise on a machine with the static IP of **192.168.1.9** on Ubuntu 24.04.2 live server (*Figure 6*).
- Installed Splunk Add-on for Microsoft Windows
- Configured Universal Forwarders on
  - Active Directory Domain Controller
  - Windows 10 Client
  - Zeek and Suricata
  - pfSense
- Forwarders were configured to send logs to Splunk via tcp port 9997 to the Splunk Server (*Figure 7*).
- Created Indexes to store Logs for:
  - Windows Security Events and Sysmon 
  - pfSense
  - Zeek & Suricata
    

**Splunk Screenshots**

<p align="center">
  <img width="300" height="260" alt="image" src="https://github.com/user-attachments/assets/32f67152-c6fd-401f-8cc2-37c66b7119b6" />
</p>
<p align="center"><b>Figure 6: Static IP Configuration.</b></p>

<p align="center">
  <img width="1300" height="300" alt="image" src="https://github.com/user-attachments/assets/7fd48271-039f-4df0-b1b5-502f8bd54d89" />
</p>
<p align="center"><b>Figure 7: Configuring Splunk Receiving Indexer configured to listen on port 9997 for incoming logs from Universal Forwarders.</b></p>


### **Zeek & Suricata**

**What are they:**

**Zeek** is an Open Source monitoring tool used for network monitoring and providing deep protocol analysis of whats going on in the network. **Suricata** on the other hand is an open source Intrusion Detection/Prevention system (IDS/IPS) and it is used for monitoring the network for suspicious acitivty. It operates using signature-based detection rules, and when a rule is triggered, Suricata can either generate an alert or block the malicious activity. 

**Lab Use:**

- In this lab, Zeek and Suricata were deployed together on the same host (192.168.1.8)
- Zeek captured metadata from connections being made
- Suricata inspected packets in real time and generated alerts for malicious or suspicious patterns.
- Logs generated by both will be fowarded to Splunk and stored in the Index "Zeek-Suricata"

**Configuration**

Zeek: Configured the Node.cfg file tell Zeek which nodes exist and which interface to use for packet capture (*Figure 8*).
 - The Interface Zeek was running on was set to promiscuous mode which means that al network traffic will be captured even if its not addressed to that interface. 
 - Once you start "Zeekctl" you will see metadata produced by zeek in the "/opt/zeek/logs/current" directory (*Figure 9*).

Suricata: Configured the Suricata.yaml file to specify which interfaces Suricata should monitor (*Figure 10*). 
 - The suricata.yaml file is also important because it defines where the rule files are located. 
 - Once you start the Suricata Service via systemctl, you will be able to view the logs in "/var/log/suricata/" (*Figure 11*). 

**Zeek & Suricata Screenshots:**

<p align="center">
  <img width="650" height="500" alt="image" src="https://github.com/user-attachments/assets/4e6cb979-a53b-471c-aefa-dbfd0c07388a" />
</p>
<p align="center"><b>Figure 8: Zeek node configuration file (node.cfg).</b></p>

<p align="center">
  <img width="812" height="52" alt="image" src="https://github.com/user-attachments/assets/b307f24a-2beb-4ba0-9254-33d840341181" />
</p>
<p align="center"><b>Figure 9: Zeek deep protocol analysis logs.</b></p>

<p align="center">
  <img width="800" height="760" alt="image" src="https://github.com/user-attachments/assets/3d6543fd-a228-4c5e-b6b7-d53f6c8ce82f" />
</p>
<p align="center"><b>Figure 10: Suricata interface configuration (suricata.yaml).</b></p>

<p align="center">
  <img width="500" height="58" alt="image" src="https://github.com/user-attachments/assets/66f26250-3bba-4b54-8927-e902d3696528" />
</p>
<p align="center"><b>Figure 11: Suricata log directory (/var/log/suricata/).</b></p>


### **Windows 10 Endpoint**

**What is it:**

The windows 10 machine served as domain-joined endpoint and is used for generating user activity, authentication logs, and endpoint telemetry for monitoring and detection 

**Lab Use:**

- The machine had joined the AD domain (sam-ad.local), allowing for centralized authenticaiton and GPO management.
- Logs Generated from this endpoint were forwarded to the splunk serevr via tCP port 9997.
- This machine will forward windows security logs and Sysmon logs.

**Configuration:**

- Configured with a static IP address of 192.168.1.100
- Joined the domain sam-ad.local
- Installed Splunk Universal Forwarder
  - Configured forwarder to send Windows Security and Sysmon logs to the Splunk Indexer (192.168.1.9) via TCP port 9997
- Configured the "inputs.conf" file to specify which logs to forward and which index to send them to (*Figure 12*)
  - *Note:* this was done on all machines forwarding logs to splunk

**Windows 10 Endpoint Screenshots:**

<p align="center">
  <img width="499" height="378" alt="image" src="https://github.com/user-attachments/assets/a498d403-25c2-489c-b598-795e5f686ab7" />
</p>
<p align="center"><b>Figure 12: Inputs.conf configured to define log sources and destination Index.</b></p>


### **Attacker Machine**


**Lab Use:**

The attacker machine was used to simulate malicious activity within the lab network. This helped generate realistic network traffic and security events for detection and analysis. 


**Configuration**

- Operating System Used: Kali Linux
- Configured with a static IP of **192.168.1.101**


## **Adversary Simulation**

### **Objective:**

To simulate malicious Activity within the lab enviroment to generate telemetry upon viewing logs forwarded to splunk


### **Scenario** 

- Utilised the metasploit framework to create a basic malware which when executed on the Windows 10 endpoint will establish a C2 connection back to the kali Linux allowing to take control of the system and download files from the victims machine (*Figure 13*)
  -  The simulated payload was named'invoices.doc.exe' which was hosted via HTTP port 9999 so the victim machine can download and execute this (*Figure 14*)
 
- An Nmap scan was also conducted to scan the ports of all machines within the LAN which will generate tons of telemetry. 

- To generate further telemetry Atomic Red Team was to create a local account to allow for persistance (*Figure 15*).
  - This goes under MITRE ATT&CK Technique: [T1136.001: Create Local Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) 

 ### ⚠️ **Disclaimer:**  
All simulated activities were performed within an isolated virtual lab for defensive and educational purposes only.  
No offensive or exploitative actions were executed outside this controlled environment and should not be replicated unless given the permission to do so. 


### Attack Simulation Screenshots:

<p align="center">
  <img width="626" height="98" alt="image" src="https://github.com/user-attachments/assets/286d6be8-09a8-4356-8cac-9b762f39778c" />
</p>
<p align="center"><b>Figure 13: Sucessful Meterpreter reverse Shell from the Windows 10 Endpoint to the Kali Linux Machine</b></p>

<p align="center">
  <img width="300" height="550" alt="image" src="https://github.com/user-attachments/assets/a04eec8b-794a-472f-99cc-b23c50c8d649" />
</p>
<p align="center"><b>Figure 14: invoice.doc.exe hosted via http:9999</b></p>


<p align="center">
  <img width="650" height="650" alt="image" src="https://github.com/user-attachments/assets/3b993506-edcc-4d7c-8add-28a5794de2c6" />

</p>
<p align="center"><b>Figure 15: Execution of MITRE ATT&CK technique T1136.001 - Create Account: Local Account</b></p>

## Log Analysis

**Objective:**

To analyze the telemetry generated during the adversary attack simulation. 

**Analysis**

**Zeek:** Zeek http.log was able to log the HTTP GET request the client had made for Invoices.docx.exe, confirming the visibility into the file download activity between the client and attacker (*Figure 16*)

**Windows Security Event:** Event ID 4688 was generated upon execution on the malicious Invoices.doc.exe (*Figure 17*). We can also see the process command line field appears as we had enabled "include command line in process creation events" via GPO. (*Figure 5*)




### **Log Analysis Screenshots**

<p align="center">
  <img width="826" height="382" alt="image" src="https://github.com/user-attachments/assets/887d426f-7ddd-4694-b28b-0ca78e461cb9" />
</p>
<p align="center"><b>Figure 16: Zeek log showing the HTTP Get request of the malicious invoices.docx.exe file</b></p>


<p align="center">
  <img width="646" height="542" alt="image" src="https://github.com/user-attachments/assets/f735d58b-ac4e-44e3-80a8-71d89da266f7" />
</p>
<p align="center"><b>Figure 16: Windows Security Event ID 4688 capturing process Execution</b></p>

