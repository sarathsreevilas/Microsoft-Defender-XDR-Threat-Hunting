\# KQL Threat Hunting Queries



\*\*Project:\*\* Microsoft Defender XDR — Threat Hunting \& Incident Investigation



\*\*Environment:\*\* MYDFIR Simulated Enterprise Lab



\*\*Primary Endpoint:\*\* EA-WKS01



\## Overview



This document contains Kusto Query Language (KQL) queries used to investigate suspicious endpoint activity in a simulated enterprise environment.



The investigation focused on encoded PowerShell execution, suspicious executables, browser-cookie extraction tools, persistence mechanisms, and external network communications.



Queries are organized according to the investigative questions they help answer.



\*\*Note:\*\* The lab included Windows Sysmon telemetry stored in the `WindowsEvent` table. Queries using this table are specific to the lab's data schema and may require adaptation for other Microsoft Defender or Microsoft Sentinel environments.



\---



\## 1. Hunt for Encoded PowerShell Execution



\*\*Investigation question:\*\* Were encoded PowerShell commands executed on the affected endpoint?



```kusto

WindowsEvent

| where EventID == 1

| where Computer contains "EA-WKS01"

| extend ED = parse\_json(EventData)

| extend

&#x20;   CommandLine = tostring(ED.CommandLine),

&#x20;   ParentImage = tostring(ED.ParentImage)

| where CommandLine contains "EncodedCommand"

| project

&#x20;   TimeGenerated,

&#x20;   Computer,

&#x20;   CommandLine,

&#x20;   ParentImage

| order by TimeGenerated ascc

```



\### Investigation Logic



Sysmon Event ID 1 records process creation activity.



The query filters for encoded PowerShell execution on EA-WKS01 and retrieves the command line and parent executable.



Encoded PowerShell alone does not establish maliciousness. The command must be analyzed alongside the decoded script, process ancestry, and other endpoint activity.



\### Investigation Finding



Suspicious encoded PowerShell activity was identified on September 18 and September 20, 2026.



Related encoded browser-cookie theft instructions were observed again on October 25, 2026.



The decoded malicious instructions were associated with executable downloads, browser-cookie extraction tooling, and attempted upload of collected information.



\*\*Supporting Evidence:\*\* `../evidence/encodedbase64.png`





\---



\## 2. Investigate Suspicious RuntimeBroker.exe Execution



\*\*Investigation question:\*\* Was `RuntimeBroker.exe` executing from an unusual location, and what activity was associated with it?



\### KQL Query



```kusto

WindowsEvent

| where EventID == 1

| where Computer contains "EA-WKS01"

| extend ED = parse\_json(EventData)

| extend

&#x20;   Image = tostring(ED.Image),

&#x20;   CommandLine = tostring(ED.CommandLine),

&#x20;   ParentImage = tostring(ED.ParentImage),

&#x20;   ProcessGuid = tostring(ED.ProcessGuid)

| where Image endswith @"\\RuntimeBroker.exe"

| project

&#x20;   TimeGenerated,

&#x20;   Computer,

&#x20;   Image,

&#x20;   CommandLine,

&#x20;   ParentImage,

&#x20;   ProcessGuid

| order by TimeGenerated asc```



\### Investigation Logic



Sysmon Event ID 1 captures process creation events.



The query identifies processes named `RuntimeBroker.exe` and displays their executable paths, command lines, parent processes, and process identifiers.



The legitimate Windows Runtime Broker normally executes from:



`C:\\Windows\\System32\\RuntimeBroker.exe`



However, the suspicious executable identified during this investigation was located at:



`C:\\Users\\jennifer.martinez\\AppData\\Roaming\\RuntimeBroker.exe`



An executable using a legitimate Windows process name from a user-writable directory warrants investigation.



The executable path alone does not prove maliciousness. Its relationship to encoded PowerShell execution, browser-extraction tooling, and suspicious network communications provides stronger evidence.



\### Investigation Finding



The investigation identified an AppData-based `RuntimeBroker.exe` associated with malicious PowerShell activity.



Additional network telemetry showed the suspicious executable generating DNS queries for `discord.com` and establishing outbound HTTPS connections.



This combination supported the assessment that the executable was masquerading as a legitimate Windows component.



\*\*Supporting Evidence:\*\*



\- `../evidence/confirmed.png`

\- `../evidence/outbountNetwrk.png`



\### Analyst Conclusion



\*\*Verdict:\*\* Malicious executable activity, high confidence.



The classification was based on process location, execution context, and correlated malicious behavior rather than the filename alone.





\---



\## 3. Investigate Browser-Cookie Extraction Tools



\*\*Investigation question:\*\* Were browser-cookie extraction utilities created and executed on the affected endpoint?



\### Query 1 — Identify File Creation Events



```kusto

WindowsEvent

| where EventID == 11

| where Computer contains "EA-WKS01"

| extend ED = parse\_json(EventData)

| extend

&#x20;   FilePath = tostring(ED.TargetFilename),

&#x20;   ProcessImage = tostring(ED.Image)

| where FilePath contains "chromelevator"

&#x20;   or FilePath contains "encryptor.exe"

| project

&#x20;   TimeGenerated,

&#x20;   Computer,

&#x20;   FilePath,

&#x20;   ProcessImage

| order by TimeGenerated asc```



\### Investigation Logic



Sysmon Event ID 11 records file creation activity.



The query searches for artifacts associated with the browser-cookie extraction tooling identified during the investigation.



The results showed the creation of:



\- `chromelevator\_x64.exe`

\- `chromelevator\_arm64.exe`

\- `encryptor.exe`



The files appeared in temporary directories on September 20, 2026.



\*\*Important:\*\* File creation alone does not establish that an executable ran.



\### Query 2 — Confirm Tool Execution



```kusto

WindowsEvent

| where EventID == 1

| where Computer contains "EA-WKS01"

| extend ED = parse\_json(EventData)

| extend

&#x20;   Image = tostring(ED.Image),

&#x20;   CommandLine = tostring(ED.CommandLine),

&#x20;   ParentImage = tostring(ED.ParentImage),

&#x20;   ProcessGuid = tostring(ED.ProcessGuid)

| where Image contains "chromelevator\_x64.exe"

&#x20;   or CommandLine contains "chromelevator\_x64.exe"

| project

&#x20;   TimeGenerated,

&#x20;   Computer,

&#x20;   Image,

&#x20;   CommandLine,

&#x20;   ParentImage,

&#x20;   ProcessGuid

| order by TimeGenerated asc```



\### Investigation Logic



Sysmon Event ID 1 records process creation activity.



This query was used to identify whether the previously observed browser-cookie extraction utility was executed.



The investigation identified execution of `chromelevator\_x64.exe` on:



| Date (UTC) | Time (UTC) | Finding |

|---|---|---|

| September 18, 2026 | 23:16:20 | Tool execution observed |

| September 18, 2026 | 23:17:06 | Additional execution |

| September 20, 2026 | 14:05:58 | Tool execution observed |

| September 20, 2026 | 14:07:44 | Additional execution |



\### Correlation and Assessment



The investigation correlated:



1\. Decoded PowerShell instructions referencing browser-cookie extraction.

2\. Creation of browser-extraction utilities in temporary directories.

3\. Subsequent execution of `chromelevator\_x64.exe`.

4\. Suspicious DNS and network activity during the same investigation periods.



Together, these findings support an attempted browser-cookie theft operation.



However, the available telemetry did not independently confirm that cookies were successfully extracted or uploaded.



\### Supporting Evidence



!\[Browser extraction tool creation](../evidence/malwre.png)



\### Analyst Conclusion



\*\*Confirmed:\*\* Browser-cookie extraction tooling was executed.



\*\*High Confidence:\*\* The activity was associated with attempted browser-cookie theft.



\*\*Unconfirmed:\*\* Successful cookie extraction and data exfiltration.



\---



\## 4. Investigate Registry Run-Key Persistence



\*\*Investigation question:\*\* Was a Windows Registry Run key used to establish persistence on the affected endpoint?



\### KQL Query



```kusto

WindowsEvent

| where Computer contains "EA-WKS01"

| where EventID in (12, 13, 14)

| extend ED = parse\_json(EventData)

| extend

&#x20;   RegistryPath = tostring(ED.TargetObject),

&#x20;   RegistryValue = tostring(ED.Details),

&#x20;   ProcessImage = tostring(ED.Image)

| where RegistryPath contains @"\\CurrentVersion\\Run"

| project

&#x20;   TimeGenerated,

&#x20;   Computer,

&#x20;   EventID,

&#x20;   RegistryPath,

&#x20;   RegistryValue,

&#x20;   ProcessImage

| order by TimeGenerated asc```



\### Investigation Logic



Sysmon provides registry-related telemetry through several event types:



\- \*\*Event ID 12:\*\* Registry object creation or deletion.

\- \*\*Event ID 13:\*\* Registry value modification.

\- \*\*Event ID 14:\*\* Registry object renaming.



The query searches for registry activity associated with Windows startup locations.



The `CurrentVersion\\Run` registry path is significant because entries under this location can automatically execute programs when the associated user signs in.



\### Investigation Finding



The investigation identified a suspicious registry entry associated with the following location:



\*\*Registry path:\*\*



`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`



\*\*Value name:\*\* `UpdateService`



The entry referenced encoded PowerShell execution.



This behavior is consistent with a persistence mechanism intended to execute malicious commands during future user logons.



\### Supporting Evidence



!\[Registry persistence investigation](../evidence/registary.csv.png)



\### Analyst Assessment



\*\*Finding:\*\* Suspicious registry-based persistence mechanism identified.



\*\*Confidence:\*\* High, based on the observed registry entry and its association with encoded PowerShell.



\*\*Limitation:\*\* The registry evidence does not independently prove that the persistence mechanism successfully triggered during a subsequent logon.



\### MITRE ATT\&CK Mapping



\*\*T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder\*\*



This technique describes the use of registry startup locations to maintain execution across user sessions.


---



\## 5. Investigate Discord DNS Activity



\*\*Investigation question:\*\* Did suspicious processes resolve `discord.com` during the malicious activity?



\### KQL Query



```kusto

WindowsEvent

| where EventID == 22

| where Computer contains "EA-WKS01"

| extend ED = parse\_json(EventData)

| extend

&#x20;   QueryName = tostring(ED.QueryName),

&#x20;   QueryStatus = tostring(ED.QueryStatus),

&#x20;   Image = tostring(ED.Image),

&#x20;   ProcessId = tostring(ED.ProcessId),

&#x20;   ProcessGuid = tostring(ED.ProcessGuid)

| where QueryName contains "discord.com"

| project

&#x20;   TimeGenerated,

&#x20;   Computer,

&#x20;   Image,

&#x20;   ProcessId,

&#x20;   ProcessGuid,

&#x20;   QueryName,

&#x20;   QueryStatus

| order by TimeGenerated asc```



\### Investigation Logic



Sysmon Event ID 22 records DNS query activity.



The query identifies DNS events involving `discord.com` on the affected endpoint.



During the investigation, DNS activity was observed from suspicious PowerShell and AppData-based `RuntimeBroker.exe` processes.



\### Investigation Findings



| Timestamp (UTC) | Process | Finding |

|---|---|---|

| Sep 18, 23:16:10 | RuntimeBroker.exe | Discord DNS query |

| Sep 18, 23:17:04 | RuntimeBroker.exe | Additional Discord DNS query |

| Sep 20, 14:05:51 | powershell.exe | Discord DNS query |

| Sep 20, 14:07:41 | RuntimeBroker.exe | Discord DNS query |

| Oct 25, 23:13:18 | powershell.exe | Discord DNS query |



The observed DNS events had successful query status.



However, successful DNS resolution only confirms that the process resolved the domain. It does not establish that data was uploaded.



\### Supporting Evidence



!\[Discord DNS investigation](../evidence/Discord.png)



\### Analyst Assessment



\*\*Confirmed:\*\* Suspicious processes performed DNS queries for `discord.com`.



\*\*Not Confirmed:\*\* Successful data exfiltration.



\---



\## 6. Investigate Outbound Network Connections



\*\*Investigation question:\*\* Did the suspicious executable establish outbound network connections during the malicious activity?



\### KQL Query



```kusto

WindowsEvent

| where EventID == 3

| where Computer contains "EA-WKS01"

| extend ED = parse\_json(EventData)

| extend

&#x20;   Image = tostring(ED.Image),

&#x20;   DestinationIP = tostring(ED.DestinationIp),

&#x20;   DestinationPort = tostring(ED.DestinationPort),

&#x20;   ProcessGuid = tostring(ED.ProcessGuid)

| where Image endswith @"\\RuntimeBroker.exe"

| project

&#x20;   TimeGenerated,

&#x20;   Computer,

&#x20;   Image,

&#x20;   DestinationIP,

&#x20;   DestinationPort,

&#x20;   ProcessGuid

| order by TimeGenerated asc```



\### Investigation Logic



Sysmon Event ID 3 records network connection events.



This query searches for connections involving `RuntimeBroker.exe` and extracts the destination IP address, destination port, and process identifier.



The process path is important because legitimate Windows processes can share the same executable name.



\### Investigation Findings



Outbound TCP connections over port 443 were observed during the suspicious execution periods.



Destination addresses included:



\- `162.159.138.232`

\- `140.82.113.3`

\- `140.82.114.3`

\- `185.199.108.133`

\- `185.199.110.133`



Some addresses belong to shared infrastructure used by legitimate services.



The connections were suspicious because of their association with malicious process activity, not because the destination IP addresses were inherently malicious.



\### Supporting Evidence



!\[Outbound network activity](../evidence/outbountNetwrk.png)



\### Analyst Assessment



\*\*Confirmed:\*\* Outbound network connections from the suspicious executable.



\*\*Supported:\*\* Network activity consistent with the decoded payload's external communication functionality.



\*\*Unconfirmed:\*\* Successful upload of browser cookies or other collected information.



\---



\## 7. Correlate Process and Network Activity



\*\*Investigation question:\*\* How can DNS and network events be connected to the malicious process?



\### Correlation Method



The investigation used the following fields to associate related events:



\- `Computer` — Identifies the affected endpoint.

\- `TimeGenerated` — Establishes event sequence.

\- `Image` — Identifies the executable responsible for the event.

\- `ProcessId` — Helps associate events with a process instance.

\- `ProcessGuid` — Provides stronger correlation across Sysmon event types.



\### KQL Query



```kusto

WindowsEvent

| where Computer contains "EA-WKS01"

| where EventID in (1, 3, 22)

| extend ED = parse\_json(EventData)

| extend

&#x20;   Image = tostring(ED.Image),

&#x20;   ProcessGuid = tostring(ED.ProcessGuid),

&#x20;   ProcessId = tostring(ED.ProcessId),

&#x20;   QueryName = tostring(ED.QueryName),

&#x20;   DestinationIP = tostring(ED.DestinationIp),

&#x20;   DestinationPort = tostring(ED.DestinationPort)

| where Image contains "RuntimeBroker.exe"

&#x20;   or QueryName contains "discord.com"

| project

&#x20;   TimeGenerated,

&#x20;   EventID,

&#x20;   Image,

&#x20;   ProcessGuid,

&#x20;   ProcessId,

&#x20;   QueryName,

&#x20;   DestinationIP,

&#x20;   DestinationPort

| order by TimeGenerated asc```



\### Investigation Logic



The query combines:



\- Sysmon Event ID 1 — Process creation.

\- Sysmon Event ID 3 — Network connections.

\- Sysmon Event ID 22 — DNS queries.



The results can be reviewed using timestamps, executable paths, and process identifiers to reconstruct the relationship between execution and network activity.



\*\*Important:\*\* This query provides candidate events for correlation. A shared hostname or nearby timestamp alone is not proof that two events belong to the same process instance. Matching a nonempty `ProcessGuid` provides stronger evidence.



\### Supporting Evidence



!\[Suspicious process and network correlation](../evidence/suspiciousprocesws.png)



\### Analyst Conclusion



The combined evidence demonstrates suspicious process execution, DNS resolution, and outbound network connections associated with the malicious activity.



Decoded PowerShell instructions further support the assessment that the activity involved an attempted browser-cookie theft and exfiltration operation.



However, the available telemetry did not independently confirm successful data transfer.



\---



\## 8. Hunt for Recurring Encoded PowerShell Activity



\*\*Investigation question:\*\* Did the previously identified malicious PowerShell payload execute again after the initial investigation period?



\### KQL Query



```kusto

WindowsEvent

| where EventID == 1

| where Computer contains "EA-WKS01"

| extend ED = parse\_json(EventData)

| extend

&#x20;   CommandLine = tostring(ED.CommandLine),

&#x20;   ParentImage = tostring(ED.ParentImage),

&#x20;   ProcessGuid = tostring(ED.ProcessGuid)

| where CommandLine contains "EncodedCommand"

| where CommandLine contains "JAB3AGUAYgBoAG8AbwBrAFUAcgBs"

| project

&#x20;   TimeGenerated,

&#x20;   Computer,

&#x20;   ParentImage,

&#x20;   CommandLine,

&#x20;   ProcessGuid

| order by TimeGenerated asc```



\### Investigation Logic



This query searches Sysmon process creation events for an encoded PowerShell command containing a distinctive Base64 fragment identified during the investigation.



The fragment acts as a hunting indicator for the specific encoded payload, rather than a generic indicator of all malicious PowerShell activity.



The query helps determine whether the same suspicious command appeared at different times.



\### Investigation Findings



Two matching process creation events were identified:



| Timestamp (UTC) | Endpoint | Finding |

|---|---|---|

| September 20, 2026 — 14:05:44 | EA-WKS01 | Encoded PowerShell execution |

| October 25, 2026 — 23:13:00 | EA-WKS01 | Recurrence of the encoded PowerShell payload |



The decoded instructions contained browser-cookie extraction and Discord webhook upload functionality.



A DNS query for `discord.com` was also observed on October 25 at 23:13:18 UTC.



\### Analyst Assessment



\*\*Confirmed:\*\* The same distinctive encoded PowerShell payload was observed on September 20 and October 25.



\*\*Supported:\*\* Recurring malicious execution involving browser-cookie theft instructions.



\*\*Unconfirmed:\*\* Whether the October 25 execution was triggered by the previously identified registry persistence mechanism or another execution method.



\### Investigation Limitation



Matching encoded commands can establish recurring payload execution, but do not independently establish how the payload was launched.



Additional process ancestry, registry execution, or scheduled-task evidence would be required to attribute the recurrence to a specific persistence mechanism.



\### Analyst Conclusion



The recurrence demonstrated that the suspicious activity was not limited to the initial September investigation period.



This finding reinforced the need to investigate persistence mechanisms and monitor for repeated execution after remediation.

