\# SOC Threat Hunting Investigation Report



\*\*Case Title:\*\* Encoded PowerShell Execution, Browser Cookie Theft and Discord Exfiltration Attempt



| Field | Details |

|---|---|

| Investigation Type | Proactive Threat Hunting / Endpoint Investigation |

| Environment | MYDFIR Simulated Enterprise Lab |

| Security Platform | Microsoft Defender XDR / KQL / Windows Sysmon |

| Primary Endpoint | EA-WKS01.corp.elliniaaccounting.ca |

| Associated Endpoint | EA-WKS04 |

| User Account | jennifer.martinez@elliniaaccounting.ca |

| Investigation Period | September 18 – October 25, 2026 |

| Case Classification | Confirmed Malicious Activity |

| Exfiltration Status | Attempted / Successful Transfer Unconfirmed |



\---



\## 1. Executive Summary



During a hands-on threat-hunting exercise in a preconfigured MYDFIR enterprise lab, suspicious endpoint activity was investigated using Microsoft Defender security telemetry, Kusto Query Language (KQL), and Windows Sysmon events.



The investigation identified malicious PowerShell execution associated with a suspicious executable named `RuntimeBroker.exe`, located in the affected user's AppData directory rather than the legitimate Windows system directory.



Further investigation identified browser-cookie extraction tooling, including `chromelevator\_x64.exe`, and persistence through the Windows Registry Run key `UpdateService`.



Analysis of the encoded PowerShell payload revealed instructions to download and execute browser-cookie extraction tools, archive collected data, and attempt to upload the resulting archive to a Discord webhook.



DNS telemetry confirmed resolution of `discord.com`, while network telemetry showed outbound HTTPS connections during the suspicious activity.



Related encoded PowerShell activity was also observed on October 25, 2026, indicating recurrence of the malicious behavior.



\*\*Final Assessment:\*\* Malicious execution and persistence were confirmed. The evidence strongly supports attempted browser-cookie theft and data exfiltration; however, successful cookie extraction or transfer to the external destination could not be independently verified.



This investigation was conducted using historical telemetry in an authorized simulated lab. It was not initiated by a live production alert.



\---



\## 2. Investigation Scope



\### 2.1 Objectives



The investigation aimed to:



1\. Identify suspicious endpoint activity involving encoded PowerShell.

2\. Analyze potentially malicious executable behavior.

3\. Investigate browser-cookie extraction tools.

4\. Identify persistence mechanisms.

5\. Correlate process, file, registry, DNS, and network telemetry.

6\. Reconstruct the attack timeline.

7\. Determine which malicious actions were confirmed and which remained unverified.



\### 2.2 Investigated Systems



\*\*Primary Endpoint:\*\* `EA-WKS01.corp.elliniaaccounting.ca`



The main investigation focused on suspicious PowerShell execution, malware activity, persistence, and outbound communications associated with this endpoint.



\*\*Associated Endpoint:\*\* `EA-WKS04`



Additional telemetry showed the download and creation of a suspicious `.pdf.lnk` attachment on September 20, 2026.



The available evidence did not establish that the attachment on EA-WKS04 caused the earlier malicious execution on EA-WKS01. These observations were therefore treated as related investigative leads rather than a confirmed infection chain.



\### 2.3 Data Sources



The investigation used the following available telemetry:



\- Microsoft Defender security events and hunting data

\- Windows Sysmon process creation events (Event ID 1)

\- Windows Sysmon network connection events (Event ID 3)

\- Windows Sysmon file creation events (Event ID 11)

\- Windows Sysmon DNS query events (Event ID 22)

\- Registry-related security telemetry

\- PowerShell process command lines



\### 2.4 Investigation Limitations



The investigation relied on telemetry available within the preconfigured lab environment.



The following limitations were identified:



\- No confirmed evidence of successful browser-cookie extraction.

\- No independent confirmation that a cookie archive was successfully uploaded.

\- DNS resolution and outbound HTTPS connections alone do not establish successful data exfiltration.

\- The initial infection vector on EA-WKS01 was not conclusively established.

\- Historical telemetry may not capture every action performed by the malicious processes.



These limitations were considered when determining the final investigation verdict.



\---



\## 3. Attack Timeline



The following timeline was reconstructed by correlating process execution, file creation, DNS queries, and network events from the MYDFIR simulated enterprise environment.



All timestamps are in UTC.



| Date / Time (UTC) | Endpoint | Observed Activity |

|---|---|---|

| Sep 18, 2026 — 23:16:05 | EA-WKS01 | Suspicious encoded PowerShell execution associated with the download and launch of `RuntimeBroker.exe` from an external IP address. |

| Sep 18 — 23:16:10 | EA-WKS01 | Suspicious `RuntimeBroker.exe` process queried `discord.com`. |

| Sep 18 — 23:16:20 | EA-WKS01 | `chromelevator\_x64.exe` execution observed, supporting browser-cookie extraction activity. |

| Sep 18 — 23:17:04 | EA-WKS01 | Additional `discord.com` DNS query associated with the suspicious executable. |

| Sep 18 — 23:17:06 | EA-WKS01 | Additional execution of `chromelevator\_x64.exe`. |

| Sep 20 — 14:05:44 | EA-WKS01 | Hidden encoded PowerShell execution observed with `explorer.exe` as the parent process. |

| Sep 20 — 14:05:51 | EA-WKS01 | PowerShell queried `discord.com`. |

| Sep 20 — 14:05:54 | EA-WKS01 | Browser extraction tools, including `chromelevator\_x64.exe`, created in a temporary directory. |

| Sep 20 — 14:05:58 | EA-WKS01 | `chromelevator\_x64.exe` executed. |

| Sep 20 — 14:07:41 | EA-WKS01 | Additional extraction tools created; suspicious `RuntimeBroker.exe` queried `discord.com`. |

| Sep 20 — 14:07:44 | EA-WKS01 | Another execution of `chromelevator\_x64.exe`. |

| Sep 20 — 14:21:41 | EA-WKS04 | Suspicious ZIP attachment downloaded. |

| Sep 20 — 14:22:08 | EA-WKS04 | Deceptive `.pdf.lnk` shortcut created after ZIP extraction. No execution confirmed on this endpoint. |

| Oct 25 — 23:13:00 | EA-WKS01 | Recurrence of encoded PowerShell activity containing the previously identified browser-cookie theft instructions. |

| Oct 25 — 23:13:18 | EA-WKS01 | PowerShell DNS query for `discord.com` observed. |



\### Timeline Interpretation



The earliest confirmed malicious execution in the investigated endpoint telemetry occurred on September 18, 2026.



The September 20 events demonstrated repeated execution of browser-cookie extraction tooling and associated network activity.



Additional suspicious attachment activity was identified on EA-WKS04 later on September 20, but a direct causal connection to the earlier EA-WKS01 compromise could not be established.



The October 25 activity demonstrated recurrence of the encoded PowerShell behavior.



The combined timeline supports repeated malicious activity involving PowerShell execution, browser-cookie extraction attempts, and communications with external services.



\*\*Analyst Assessment:\*\* The sequence is consistent with an attempted browser-session theft operation. Successful extraction and exfiltration remain unconfirmed.



\---



\## 4. Technical Analysis



\### 4.1 Suspicious Encoded PowerShell Execution



\*\*Finding:\*\* Malicious PowerShell execution identified on EA-WKS01.



\*\*Evidence:\*\* Process creation telemetry, PowerShell command-line arguments, and decoded script content.



The investigation identified PowerShell processes executing with hidden windows and Base64-encoded commands.



The observed command-line arguments included:



\- `-WindowStyle Hidden`

\- `-EncodedCommand`



Although encoded PowerShell is not inherently malicious, decoding the associated commands revealed behavior consistent with malware execution and browser-cookie theft.



On September 18, 2026, suspicious PowerShell activity was associated with downloading and launching an executable named `RuntimeBroker.exe` from an external IP address.



On September 20, additional encoded PowerShell activity was observed with `explorer.exe` as the parent process.



The decoded September 20 payload contained instructions to download browser-cookie extraction utilities, execute the tools, create an archive of collected data, and attempt to upload the archive to a Discord webhook.



Related encoded PowerShell activity was observed again on October 25.



\*\*Analyst Assessment:\*\* Confirmed malicious PowerShell activity based on decoded command functionality and correlated endpoint telemetry.



\*\*Supporting Evidence:\*\* `evidence/encodedbase64.png`



\### 4.2 Suspicious RuntimeBroker.exe Execution



\*\*Finding:\*\* An executable masquerading as a legitimate Windows process was identified.



The suspicious executable was located at:



`C:\\Users\\jennifer.martinez\\AppData\\Roaming\\RuntimeBroker.exe`



The legitimate Windows Runtime Broker executable normally resides at:



`C:\\Windows\\System32\\RuntimeBroker.exe`



The executable's location, associated PowerShell activity, and subsequent network communications supported its classification as malicious.



Network telemetry showed the suspicious executable establishing outbound HTTPS connections during the investigated activity.



\*\*Analyst Assessment:\*\* Confirmed suspicious executable execution consistent with process masquerading. The filename alone was not used as evidence of maliciousness.



\*\*Supporting Evidence:\*\* `evidence/confirmed.png`, `evidence/outbountNetwrk.png`



\### 4.3 Browser-Cookie Extraction Activity



\*\*Finding:\*\* Browser-cookie extraction tools were created and executed on EA-WKS01.



File creation telemetry identified the following executables in temporary directories:



\- `chromelevator\_x64.exe`

\- `chromelevator\_arm64.exe`

\- `encryptor.exe`



Process creation telemetry confirmed repeated execution of `chromelevator\_x64.exe` on September 18 and September 20.



The decoded PowerShell script also contained instructions to download and execute browser-cookie extraction tooling.



These observations support an attempted browser-cookie theft operation.



However, the available telemetry did not independently confirm that browser cookies were successfully extracted or archived.



\*\*Analyst Assessment:\*\* Confirmed execution of cookie-extraction tooling; successful extraction unconfirmed.



\*\*Supporting Evidence:\*\* `evidence/malwre.png`



\### 4.4 Registry Persistence



\*\*Finding:\*\* Registry Run-key persistence was identified.



The investigation identified a suspicious registry entry under:



`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`



\*\*Value Name:\*\* `UpdateService`



The entry referenced encoded PowerShell execution, consistent with an attempt to maintain execution across user logons.



Registry Run keys are a common persistence mechanism because configured programs or commands can execute when the associated user signs in.



\*\*Analyst Assessment:\*\* Registry-based persistence mechanism identified.



\*\*Supporting Evidence:\*\* `evidence/registary.csv.png`



\### 4.5 Discord DNS and Outbound Network Activity



\*\*Finding:\*\* Suspicious processes communicated with external infrastructure during malicious activity.



Sysmon DNS query telemetry (Event ID 22) recorded successful resolution of `discord.com` by suspicious PowerShell and AppData-based `RuntimeBroker.exe` processes.



Sysmon network connection telemetry (Event ID 3) recorded outbound TCP connections over port 443 during the same periods.



Observed destination IP addresses included:



\- `162.159.138.232`

\- `140.82.113.3`

\- `140.82.114.3`

\- `185.199.108.133`

\- `185.199.110.133`



Several of these addresses are associated with shared infrastructure or legitimate services. Their presence alone does not establish malicious activity.



The significance of the network activity came from its correlation with malicious processes and decoded PowerShell instructions referencing a Discord webhook.



The decoded script contained functionality to upload a ZIP archive using an HTTP POST request.



However, the investigation did not establish that the POST request completed successfully or that the destination received the archive.



\*\*Analyst Assessment:\*\* External communications confirmed; attempted exfiltration supported by payload analysis; successful exfiltration unconfirmed.



\*\*Supporting Evidence:\*\* `evidence/Discord.png`, `evidence/outbountNetwrk.png`, `evidence/suspiciousprocesws.png`



\### 4.6 Recurring Malicious Activity



\*\*Finding:\*\* Related malicious PowerShell activity recurred on October 25, 2026.



The investigation identified an encoded PowerShell command containing the same browser-cookie theft instructions previously observed on September 20.



A subsequent DNS query for `discord.com` was also observed.



This recurrence suggests that the malicious behavior was not limited to a single execution event.



However, the available evidence did not conclusively establish whether the recurrence resulted from persistence, repeated user interaction, or another execution mechanism.



\*\*Analyst Assessment:\*\* Recurring malicious execution confirmed; exact re-execution mechanism unconfirmed.



\---



\## 5. MITRE ATT\&CK Mapping



The following MITRE ATT\&CK techniques were mapped to behaviors observed during the investigation. Mappings reflect the available evidence and do not imply that every attempted action succeeded.



| Technique ID | Technique | Supporting Evidence | Assessment |

|---|---|---|---|

| T1059.001 | Command and Scripting Interpreter: PowerShell | Encoded PowerShell execution and decoded malicious script | Confirmed |

| T1027 | Obfuscated Files or Information | Base64-encoded PowerShell commands used to conceal script functionality | Confirmed |

| T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Suspicious `RuntimeBroker.exe` executed from the user's AppData directory | Supported |

| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | `UpdateService` registry Run-key entry referencing PowerShell | Confirmed |

| T1539 | Steal Web Session Cookie | Chromelevator extraction tool execution and decoded cookie-theft instructions | Attempted; successful theft unconfirmed |

| T1105 | Ingress Tool Transfer | PowerShell instructions to download external executables and observed tool creation | Supported |

| T1567.004 | Exfiltration Over Webhook | Decoded PowerShell contained instructions to upload archived data to a Discord webhook | Attempted; successful transfer unconfirmed |



\### Mapping Interpretation



The strongest evidence supports PowerShell execution, encoded commands, registry persistence, and execution of browser-cookie extraction tooling.



The exfiltration-related mapping is less certain because successful data transfer was not established. The decoded script demonstrates exfiltration intent, not completion.



\---



\## 6. Indicators of Compromise (IOCs)



The following indicators were identified during the simulated investigation.



\### 6.1 Suspicious Executables and File Paths



| Indicator | Type | Significance |

|---|---|---|

| `C:\\Users\\jennifer.martinez\\AppData\\Roaming\\RuntimeBroker.exe` | File path | Suspicious executable masquerading as a Windows process |

| `chromelevator\_x64.exe` | Executable | Browser-cookie extraction utility observed executing |

| `chromelevator\_arm64.exe` | Executable | Related utility observed in temporary directory |

| `encryptor.exe` | Executable | Related utility created alongside extraction tooling |

| `Required\_Information\_Instructions.pdf.lnk` | Shortcut file | Deceptive attachment artifact identified on EA-WKS04 |



\### 6.2 Network Indicators



| Indicator | Type | Investigation Context |

|---|---|---|

| `174.138.28.77` | IPv4 | External host referenced in malicious PowerShell download instructions |

| `discord.com` | Domain | DNS queries associated with suspicious processes and webhook functionality |

| `162.159.138.232` | IPv4 | Outbound connection and DNS correlation during suspicious activity |

| `140.82.113.3` | IPv4 | Observed outbound HTTPS destination |

| `140.82.114.3` | IPv4 | Observed outbound HTTPS destination |

| `185.199.108.133` | IPv4 | Observed outbound HTTPS destination |

| `185.199.110.133` | IPv4 | Observed outbound HTTPS destination |



\*\*Indicator Caution:\*\* Several addresses and domains above belong to shared or legitimate service infrastructure. They should not be treated as universally malicious or blocked solely because they appeared in this investigation. Their significance depends on process context, timestamps, and correlated behavior.



\### 6.3 Registry Indicator



\*\*Registry Key:\*\*



`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`



\*\*Value Name:\*\* `UpdateService`



\*\*Significance:\*\* Suspicious logon persistence mechanism referencing encoded PowerShell execution.



\### 6.4 Behavioral Indicators



\- Hidden PowerShell execution using `-EncodedCommand`.

\- Unexpected execution of `RuntimeBroker.exe` from a user-writable directory.

\- Creation and execution of browser-cookie extraction utilities.

\- Suspicious Registry Run-key modification.

\- DNS requests to `discord.com` from processes associated with malicious activity.

\- Outbound HTTPS connections correlated with suspicious PowerShell and executable activity.

\- Recurrence of the same encoded browser-cookie theft instructions.



\### 6.5 IOC Handling Considerations



The behavioral indicators are more useful for threat hunting than indiscriminate blocking of shared service IP addresses.



The full Discord webhook URL and any embedded authentication tokens have been intentionally excluded from this public report to avoid exposing sensitive or potentially functional endpoints.



\---



\## 7. Evidence Assessment and Investigation Limitations



\### 7.1 Confirmed Findings



The following findings were supported by the available endpoint and security telemetry:



\- Suspicious encoded PowerShell commands executed on EA-WKS01.

\- A suspicious `RuntimeBroker.exe` executable was launched from the user's AppData directory.

\- Browser-cookie extraction utilities were created and `chromelevator\_x64.exe` was executed.

\- A suspicious `UpdateService` Registry Run-key entry was identified.

\- Suspicious processes generated DNS queries for `discord.com`.

\- Outbound HTTPS connections occurred during the malicious activity.

\- Related encoded PowerShell activity recurred on October 25, 2026.



\### 7.2 Findings Not Conclusively Established



The investigation did not independently confirm:



\- Successful extraction of browser cookies.

\- Creation of a completed `cookies\_\*.zip` archive.

\- Successful HTTP POST delivery to the Discord webhook.

\- Receipt of stolen information by an external party.

\- The exact initial infection mechanism on EA-WKS01.

\- A causal relationship between the suspicious shortcut on EA-WKS04 and the earlier compromise of EA-WKS01.

\- The precise mechanism responsible for the October 25 recurrence.



\### 7.3 Evidence Confidence



| Finding | Confidence | Rationale |

|---|---|---|

| Malicious PowerShell execution | High | Decoded payload functionality and correlated process telemetry |

| Suspicious RuntimeBroker.exe | High | Unexpected file location and malicious behavioral context |

| Cookie-extraction tool execution | High | Process creation telemetry |

| Registry persistence mechanism | High | Registry entry and associated command |

| External network communications | High | DNS and network connection telemetry |

| Attempted cookie theft | High | Payload instructions and tool execution |

| Successful data exfiltration | Unconfirmed | No independent evidence of completed transfer |



\*\*Evidence Interpretation:\*\* A malicious script containing a success message does not prove that the corresponding action succeeded. Likewise, successful DNS resolution and outbound TCP connections do not independently establish successful data exfiltration.



\---



\## 8. Recommended Incident Response Actions



The following actions represent recommended responses in a production SOC environment. They were not performed as part of this historical lab investigation.



\### 8.1 Containment



1\. Isolate EA-WKS01 from the network using the organization's approved endpoint response process.

2\. Investigate the affected user's account and revoke active sessions where appropriate.

3\. Preserve relevant endpoint evidence before remediation.

4\. Identify other systems exhibiting the same suspicious executable paths, commands, or persistence mechanisms.



\### 8.2 Eradication



1\. Remove the malicious AppData-based `RuntimeBroker.exe` after preserving necessary evidence.

2\. Remove the unauthorized `UpdateService` Registry Run-key entry.

3\. Remove malicious extraction tools and associated artifacts.

4\. Investigate additional persistence mechanisms and scheduled tasks before declaring the endpoint clean.

5\. Perform appropriate endpoint remediation or reimage the system if required.



\### 8.3 Recovery



1\. Reset affected credentials where compromise is suspected.

2\. Revoke potentially exposed authentication sessions.

3\. Validate endpoint integrity before reconnecting the system to production networks.

4\. Monitor for recurrence of encoded PowerShell execution and suspicious outbound communications.



\### 8.4 Detection Improvements



\- Detect unexpected `RuntimeBroker.exe` execution outside trusted Windows directories.

\- Monitor suspicious PowerShell execution involving hidden windows, encoded commands, and external downloads.

\- Alert on unauthorized Registry Run-key modifications.

\- Correlate browser-extraction tool execution with suspicious network activity.

\- Monitor outbound webhook activity in the context of unusual endpoint processes.

\- Develop behavioral detections rather than blocking shared service IP addresses indiscriminately.



9\. Final Analyst Verdict



Classification: Confirmed Malicious Activity



Primary Endpoint: EA-WKS01



Suspected Objective: Browser-session cookie theft and attempted exfiltration.



Confirmed Activity: Malicious PowerShell execution, suspicious executable activity, browser-extraction tool execution, Registry Run-key persistence, and outbound network communications.



Exfiltration Outcome: Unconfirmed.



Final Assessment



The investigation identified a sequence of malicious endpoint activities consistent with an attempted browser-session theft operation.



The attacker-controlled PowerShell instructions were designed to retrieve browser-cookie extraction tooling, execute the utilities, package collected information, and upload the resulting archive to an external Discord webhook.



Endpoint telemetry confirmed execution of associated tooling and network communications during the suspicious activity.



However, the available evidence did not independently establish that browser cookies were successfully extracted or transmitted.



The final classification is therefore confirmed malicious activity with high-confidence attempted cookie theft and exfiltration, but no confirmed successful data exfiltration.



Lessons Learned



This investigation reinforced the importance of:



Correlating multiple telemetry sources rather than relying on a single event.



Decoding suspicious commands to understand their actual functionality.



Distinguishing legitimate Windows executables from malicious files using the same names.



Using process identifiers, timestamps, and file paths to reconstruct related activity.



Separating attacker intent from actions independently verified through telemetry.



Communicating investigative uncertainty accurately.



10\. Lab Disclosure



This case study was completed in an authorized, preconfigured MYDFIR simulated enterprise environment using historical security telemetry.



The investigation demonstrates hands-on threat-hunting, KQL analysis, evidence correlation, and incident documentation skills.



It does not represent a live production incident, customer engagement, or independently verified real-world compromise.

