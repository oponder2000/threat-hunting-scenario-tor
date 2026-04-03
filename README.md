# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/oponder2000/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that included the string “tor” or “firefox” and discovered multiple suspicious file creations and deletions, as well as indications that user: employee downloaded a tor installer and some tor-related files. The file “tor-shopping-list.txt.txt” was created on the desktop at 2026-04-02T00:03:34.4955525Z as well as other files from the query below. These events began at: 2026-04-01T23:53:05.2048077Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == 'oliver-threathu'
| where FileName contains 'tor' or FileName contains 'firefox'
| where InitiatingProcessAccountName != 'system'
| where Timestamp >= datetime('2026-04-01T23:53:05.2048077Z')
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.8.exe” Based on the logs returned: On April 1st, just before midnight (23:55 UTC), a user named “employee” on a device called “oliver-threathu” downloaded and launched a file from their Downloads folder a portable Tor Browser installer (version 15.0.8), running it directly after download. Additionally the silent flag was used.

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == 'oliver-threathu'
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.8.exe"
| project Timestamp, DeviceName,AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user “employee” actually opened the tor browser. There was evidence that they did open it at 2026-04-01T23:55:59.1053838Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == 'oliver-threathu'
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName,AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the tor browser was used to establish a connection using any of the known ports. At 2026-04-01T23:56:46.6800268Z, on the same device, the user “employee” successfully established a connection using the Tor browser, reaching out over the internet to a remote server (188.68.41.74) on port 9001 (an address associated with the site mk3rals.com) indicating the Tor network was actively in use from the desktop installation. There were other connections to sites over port 443 as well, spanning over one minute time period.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == 'oliver-threathu'
| where InitiatingProcessAccountName == "employee"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001","9030","9040", "9050", "9051", "9150", "80", "443")
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### Phase 1 — TOR Installer Download (23:53 UTC)

- The user 'employee' downloaded the TOR Browser portable installer (version 15.0.8) to their Downloads folder. The file rename event at 23:53:05 UTC marks the earliest observed activity, indicating the download was completed at this time.

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
