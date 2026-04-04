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
<img width="1966" height="609" alt="1" src="https://github.com/user-attachments/assets/7cab3084-cc9e-4298-98b7-6f588c14d88b" />

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
<img width="1745" height="99" alt="2" src="https://github.com/user-attachments/assets/715791fe-cc8c-416d-a033-6746a3a3e2ec" />

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
<img width="2746" height="662" alt="3" src="https://github.com/user-attachments/assets/dab61186-f43e-4f16-a075-2d392b52b67c" />

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
<img width="2089" height="771" alt="4" src="https://github.com/user-attachments/assets/ff94707e-a3a6-4c8e-96dd-5cd623bc4240" />

---

## Chronological Event Timeline 

### Phase 1 — TOR Installer Download (23:53 UTC)

The user 'employee' downloaded the TOR Browser portable installer (version 15.0.8) to their Downloads folder. The file rename event at 23:53:05 UTC marks the earliest observed activity, indicating the download was completed at this time.

### Phase 2 — Silent Installation (23:55 UTC)

The installer was launched directly from the Downloads folder using the /S (silent) flag, suppressing any installation prompts or user dialogs. This behavior indicates deliberate intent to install the application without drawing attention. Within approximately 19 seconds, all core TOR browser components — including firefox.exe (TOR's bundled browser) and tor.exe (the TOR routing daemon) — were extracted to the user's Desktop.

### Phase 3 — TOR Browser Launch & Process Spawning (23:55–23:57 UTC)

The TOR Browser was opened immediately after installation. The browser spawned multiple child processes consistent with standard TOR Browser operation: a GPU rendering process, a Remote Data Decoder process, several browser tab content processes, and the tor.exe routing daemon. The tor.exe process was configured to listen on localhost port 9150 (SOCKS proxy) and 9151 (control port), which are the standard TOR Browser proxy ports.

### Phase 4 — Active TOR Network Connections (23:56–23:57 UTC)

The following outbound connections were established by tor.exe and firefox.exe to TOR network nodes. Connections over ports 9001 and 9030 are characteristic of TOR relay traffic; port 443 connections are consistent with TOR bridges or guard nodes using HTTPS camouflage.

The TOR network was confirmed active and in use. A total of 26 successful outbound connections were logged over a roughly one-minute window. The firefox.exe process connected to the local SOCKS proxy (127.0.0.1:9150), routing all browser traffic through the TOR daemon. tor.exe simultaneously established connections to multiple TOR relay nodes across ports 9001, 9030, and 443, confirming full TOR circuit establishment and active browsing through the anonymization network.

### Phase 5 — Continued Browser Activity & Additional Tabs (23:57–00:01 UTC)

The user continued active browsing through the TOR browser, opening at least 18 browser tab processes over approximately 5 minutes. The volume and frequency of new tab processes is consistent with active web browsing through the TOR network.

### Phase 6 — Suspicious File Creation: tor-shopping-list.txt.txt (00:03 UTC)


---

## IOCs


---

---

## Summary

On April 1, 2026, at approximately 23:53 UTC, user 'employee' on device oliver-threathu deliberately downloaded the TOR Browser portable installer (version 15.0.8) directly to their Downloads folder. At 23:55 UTC, the installer was executed using the /S silent flag — a deliberate choice to suppress all installation dialogs and avoid detection. Within seconds, the TOR Browser components (firefox.exe and tor.exe) were extracted to the user's Desktop.

The TOR Browser was launched immediately following installation at 23:55:59 UTC. The tor.exe routing daemon was initialized and configured to proxy all browser traffic through the TOR network via localhost port 9150. By 23:56:25 UTC — less than 35 seconds after launch — the first successful outbound TOR connection was established. Over the following minute, 26 confirmed successful connections were made to TOR relay nodes across the globe, utilizing ports 9001, 9030, and 443 to establish and maintain an anonymized TOR circuit.

The user engaged in active browsing through the TOR network for approximately 5 minutes, opening at least 18 browser tab processes between 23:55 and 00:01 UTC. At 00:03 UTC, a file named tor-shopping-list.txt.txt was created and modified on the Desktop during the TOR session. The suspicious naming and double extension of this file, combined with its creation during active TOR usage, makes it a significant artifact warranting forensic content review.

The use of the /S silent install flag, installation to the Desktop, and the creation of a file explicitly named in connection with TOR browsing all suggest this was intentional, premeditated activity rather than an accidental installation. The TOR network was actively used to bypass organizational network security controls and browse anonymously, in violation of acceptable use policy.


---

## Response Taken

TOR usage was confirmed on the endpoint oliver-threathu by the user employee. The device was isolated and the user's direct manager was notified.


Recommended additional actions for management and security team consideration:
- Conduct forensic imaging of the device before further changes are made to preserve evidence.
- Review and analyze the contents of tor-shopping-list.txt.txt to determine the nature of activity conducted over the TOR network.
- Audit the user's browsing history, clipboard, and any additional files created or modified during the TOR session window (23:53–00:04 UTC).
- Search for any data exfiltration indicators, including large outbound transfers or sensitive file access in the same time window.
- Review other endpoints for similar TOR-related file and process events to determine if this is an isolated incident.
- Block TOR-related executables and known TOR entry node IPs at the network perimeter and endpoint via policy.


---
