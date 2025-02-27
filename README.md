# 🚨 Insider Threat Investigation: Employee on PIP

---

## 📌 Scenario  
An employee named **John Doe**, working in a **sensitive department**, was recently placed on a **Performance Improvement Plan (PIP)**.  
After **displaying erratic behavior**, management raised concerns that John **may be attempting to steal proprietary information** before leaving the company.  

Your task: **Investigate John's corporate device (`windows-target-1`) using Microsoft Defender for Endpoint (MDE)** and determine if any **suspicious activities** occurred.  

---

## Description  
- **John has administrator privileges** on his device.  
- He can install **any software**, including tools for **data compression and transfer**.  
- **Potential risk:** Archiving and **exfiltrating sensitive company data**.  

---

## **Timeline & Findings**  

### ** Identifying Suspicious File Creation**  
I ran a **query against John's device** to check for **ZIP file creation events**:  

#### 📜 Query:  
```kusto
DeviceFileEvents
| where DeviceName contains "king"
| sort by ActionType == "FileCreated"
| where FileName contains ".zip"
//| order by Timestamp desc
```
![Image Alt](https://github.com/K-ING-TECH/Threat-Hunt_Insider-Threat/blob/main/img1.png?raw=true)

#### Findings:

File Created: employee-data-20250213161342.zip
Timestamp: 2025-02-13T16:13:56.6703466Z
File Renamed: employee-data-20250213161342.zip
File Moved To: C:\ProgramData\backup\employee-data-temp20250213161342.csv
Created By User: KING

### Investigating ZIP File Creation & Process Execution
I searched for processes running around the time the ZIP file was created and discovered that 7-Zip was silently installed via PowerShell.

📜 Query:
```kusto
let PIPDevice = "king-vm-final";
let SpecificTime = datetime(2025-02-13T16:13:56.6703466Z);
DeviceProcessEvents
| where Timestamp between ((SpecificTime -5m) .. (SpecificTime + 5m))
| where DeviceName == PIPDevice
| where AccountName contains "king"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
![Image Alt](https://github.com/K-ING-TECH/Threat-Hunt_Insider-Threat/blob/main/img2.png?raw=true)

#### Findings:

PowerShell was used to install 7-Zip silently.
7-Zip was then used to archive employee data into a ZIP file.

### Checking for Network Exfiltration
I searched for any outbound network connections from the device after the ZIP file was created to detect potential data exfiltration.

📜 Query:
```kusto
let PIPDevice = "king-vm-final";
DeviceNetworkEvents
| where DeviceName == PIPDevice
| where ActionType contains "OutboundConnection"
| order by Timestamp desc
```
![Image Alt](https://github.com/K-ING-TECH/Threat-Hunt_Insider-Threat/blob/main/img3.png?raw=true)

#### Findings:

- No outbound connections were detected.

- No evidence of data transfer to an external location.

### Investigating Remote Access & File System Modifications
Using Remote Monitoring & Management (RMM) tools, I accessed the device’s file system and retrieved a PowerShell script that was attempting to exfiltrate data.

#### Findings:

- The script was automating archive creation at regular intervals.

- No successful exfiltration was logged, but the attempt was clear.

## MITRE ATT&CK Framework - Identified TTPs

### Tactic	Technique (ID)	Description
**Initial Access	T1078 -** Valid Accounts	User KING had valid credentials to execute commands.

**Execution	T1059.001 -** PowerShell	PowerShell was used to silently install and execute 7-Zip.

**Defense Evasion	T1140 -** Deobfuscate/Decode Files	Renaming/moving files was used to evade detection.

**Defense Evasion	T1564.001 -** Hidden Files/Directories	Files were stored in C:\ProgramData\backup, a concealed location.

**Discovery	T1083 -** File Discovery	The script accessed and modified sensitive employee files.

**Collection	T1074.001 -** Local Data Staging	Data was first saved as CSV, then compressed into a ZIP.

**Collection	T1560.001 -** Archive via Utility	7-Zip was used to compress files before potential exfiltration.

**Impact	T1485 -** Data Destruction	Files were moved, possibly overwriting originals.

## Response Plan: Mitigation & Prevention
### Immediate Actions
- Isolated the machine after detecting unauthorized archiving.

- Disabled administrator access on the user's device to prevent PowerShell execution and unwanted software installations.

- Set alerts for suspicious PowerShell execution in Microsoft Defender.

## Future Improvements
- Correlate PowerShell execution with network activity to detect exfiltration attempts.

- Restrict PowerShell execution policy to signed scripts only.

📜 Query to Detect Execution Policy Bypass:
```kusto
DeviceProcessEvents
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "-ExecutionPolicy Bypass"
```

## 📌 Summary
John Doe, an employee under PIP, attempted to archive employee data using PowerShell & 7-Zip.

The data was stored in a hidden location (C:\ProgramData\backup), but no exfiltration was detected.

The device was isolated, admin privileges were removed, and PowerShell restrictions were enforced.

MITRE ATT&CK TTPs were mapped, and alerts were set up for future incidents.

## Lessons Learned
- Monitor file creation and modifications in sensitive areas (C:\ProgramData).

- Restrict PowerShell execution to prevent unauthorized scripts.

- Set up automatic alerts for unauthorized file compression and movement.

- Ensure logging and auditing of file activity for insider threats.
