## **Sudden Network Slowdowns Incident**

![ChatGPT Image Apr 5, 2025 at 03_34_34 AM](https://github.com/user-attachments/assets/4795ee45-6f2f-4785-b9d7-6b49bd0ed217)

# Incident Investigation Report

## **Scenario:**

The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

---

## **Timeline Summary and Findings**

`sa-mde-test-2` was found failing several connection requests against other hosts on the same network.

```kql
DeviceNetworkEvents
| where DeviceName == "sa-mde-test-2"
| where ActionType == "ConnectionFailed"
| summarize Connection = count() by DeviceName, ActionType, LocalIP, RemoteIP
```
<img width="869" alt="log1" src="https://github.com/user-attachments/assets/4a6f984c-c1b0-4a09-a609-4361f937fd50" />
___

I Observed total failed connections for a specific IP Address against other IPs.

```kql
let IPInQuestion = "10.0.1.30";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP
| order by FailedConnectionsAttempts desc
```
<img width="775" alt="log2" src="https://github.com/user-attachments/assets/6bcff571-4604-41c7-a49c-38a6b66d0ef5" />
___

After observing failed connection requests from a suspected host `10.0.1.30` in chronological
order, I noticed a port scan was taking place due to the sequential order of the ports. There
were several port scans being conducted:

```kql
let IPInQuestion = "10.0.1.30";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```
<img width="998" alt="log3" src="https://github.com/user-attachments/assets/aee1ec2c-d896-4b03-bf3e-64321d4a068f" />
___

I pivoted to the DeviceProcessEvents table to see if I can see anything suspicious around the time the port scan
started. I noticed a PowerShell script named portscan.ps1 launched at `2025-03-22T20:38:03.9009574Z`.

```kql
// Observe DeviceProcessEvents for the past 10 minutes of the unusual activity found
let VMName = "sa-mde-test-2";
let specificTime = datetime(2025-03-22T20:38:33.1087982Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == "sa-mde-test-2"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
<img width="1104" alt="log4" src="https://github.com/user-attachments/assets/625043ab-117c-4197-b693-4f095abd37b2" />
___

I logged into the suspect computer and observed the PowerShell script that was used to conduct the port scan. I observed the port scan script was launched by the SYSTEM account, this is abnormal behaviour as is not something that was setup by the admins. Therefore I isolated the device and ran a malware scan.

```kql
let VMName = "sa-mde-test-2";
let specificTime = datetime(2025-03-22T20:38:33.1087982Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == "sa-mde-test-2"
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```
<img width="714" alt="log5" src="https://github.com/user-attachments/assets/9a75ca8a-1b8b-4364-bd7a-511bad0a2ceb" />
<img width="1389" alt="log6" src="https://github.com/user-attachments/assets/8cfa5680-d06b-475c-9182-f7ac86c879ca" />

The malware scan produced no results, so out of caution I kept the device isolated and created a ticket to have it reimaged/rebuilt.

___

# MITRE ATT&CK Techniques for Incident Notes

| **Tactic**                | **Technique**                                                                                       | **ID**       | **Description**                                                                                                                                 |
|---------------------------|---------------------------------------------------------------------------------------------------|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| **Initial Access**         | [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)                     | T1210        | Failed connection attempts may indicate an attacker probing for open ports or exploitable services.                                            |
| **Discovery**              | [Network Service Scanning](https://attack.mitre.org/techniques/T1046/)                           | T1046        | Sequential port scans performed using a script (`portscan.ps1`) align with service discovery activity.                                         |
| **Execution**              | [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)  | T1059.001    | The use of PowerShell (`portscan.ps1`) for conducting network scanning demonstrates script-based execution.                                    |
| **Persistence**            | [Account Manipulation](https://attack.mitre.org/techniques/T1098/)                               | T1098        | Unauthorized use of the SYSTEM account to launch a script indicates potential persistence through credential manipulation.                     |
| **Privilege Escalation**   | [Valid Accounts](https://attack.mitre.org/techniques/T1078/)                                     | T1078        | SYSTEM account execution suggests privilege escalation by leveraging valid but unauthorized credentials.                                       |
| **Defense Evasion**        | [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)                    | T1027        | If `portscan.ps1` contained obfuscated commands, this technique may have been used to avoid detection.                                         |
| **Impact**                 | [Network Denial of Service](https://attack.mitre.org/techniques/T1498/)                          | T1498        | The significant network slowdown could be a side effect or an intentional impact of excessive scanning activity.                              |

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Created By:
- **Author Name**: Soroush Asadi
- **Author Contact**: [Linkedin](https://www.linkedin.com/in/soroush-asadi-881098178/)
- **Date**: April 2025

## Validated By:
- **Reviewer Name**: Josh Madakor
- **Reviewer Contact**: [Linkedin](https://www.linkedin.com/in/joshmadakor/)
- **Validation Date**: April 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 2025`  | `Soroush Asadi`   
