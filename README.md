\# Microsoft Defender XDR — Threat Hunting \& Incident Investigation



\*\*Hands-On SOC Investigation | MYDFIR Simulated Enterprise Lab\*\*



\*\*Technologies:\*\* Microsoft Defender XDR, KQL, Windows Sysmon, PowerShell, MITRE ATT\&CK



\## 1. Project Overview



This project documents a hands-on threat-hunting investigation conducted in a preconfigured simulated enterprise environment provided through MYDFIR.



Using Microsoft Defender security telemetry and Kusto Query Language (KQL), I investigated suspicious endpoint activity involving encoded PowerShell commands, masquerading executables, registry persistence, browser-cookie extraction tools, and potential data exfiltration through Discord.



The investigation focused on identifying malicious behavior, reconstructing the attack timeline, correlating evidence across multiple telemetry sources, and distinguishing confirmed findings from unverified outcomes.



\*\*Investigation Type:\*\* Threat Hunting / Endpoint Investigation



\*\*Environment:\*\* Simulated Enterprise SOC Lab



\*\*Primary Endpoint:\*\* EA-WKS01



\*\*Investigation Period:\*\* September–October 2026



\*\*Final Verdict:\*\* Confirmed malicious execution and persistence, with high-confidence attempted browser-cookie theft. Successful data exfiltration was not confirmed.



\## 2. Investigation Objectives



\- Identify suspicious PowerShell execution and decode malicious commands.

\- Investigate executables masquerading as legitimate Windows processes.

\- Identify persistence mechanisms.

\- Correlate process execution, file creation, DNS queries, and outbound network activity.

\- Reconstruct the sequence of suspicious events.

\- Assess whether browser-cookie theft and data exfiltration occurred.

\- Document evidence, investigative limitations, and recommended response actions.



\## 3. Key Findings



| Finding | Investigation Result |

|---|---|

| Encoded PowerShell | Hidden PowerShell commands associated with malicious activity |

| Process Masquerading | Suspicious RuntimeBroker.exe executed from the user's AppData directory |

| Persistence | UpdateService registry Run-key persistence |

| Browser Cookie Theft | Chromelevator extraction tools created and executed |

| Network Activity | Discord DNS resolution and outbound HTTPS connections |

| Recurring Activity | Related encoded PowerShell activity observed on October 25 |

| Exfiltration | Attempted exfiltration supported by script analysis; successful transfer unconfirmed |



\## 4. Investigation Evidence



The `evidence/` directory contains selected screenshots documenting process execution, file creation, registry persistence, DNS resolution, and outbound network activity.



Each finding is discussed in greater detail in the investigation report.



\## 5. Investigation Methodology



The investigation followed an evidence-driven threat-hunting workflow:



1\. Review suspicious endpoint processes and command lines.

2\. Investigate encoded PowerShell execution.

3\. Correlate related executable and file creation events.

4\. Identify persistence mechanisms.

5\. Investigate DNS and network activity.

6\. Reconstruct the attack timeline.

7\. Evaluate the evidence and establish a defensible verdict.



\## 6. MITRE ATT\&CK



The investigation identified behavior consistent with several MITRE ATT\&CK techniques, including:



\- \*\*T1059.001\*\* — PowerShell

\- \*\*T1027\*\* — Obfuscated Files or Information

\- \*\*T1547.001\*\* — Registry Run Keys / Startup Folder

\- \*\*T1036\*\* — Masquerading

\- \*\*T1539\*\* — Steal Web Session Cookie



These mappings describe observed or supported behaviors and do not imply that every attempted action succeeded.



\## 7. Documentation



\- `evidence/` — Investigation screenshots

\- `queries/` — KQL hunting queries

\- `reports/` — Detailed investigation report and timeline



\## 8. Skills Demonstrated



\- Security event analysis and threat hunting

\- KQL query development

\- Windows process and Sysmon telemetry investigation

\- PowerShell command-line analysis

\- Persistence detection

\- Network activity correlation

\- MITRE ATT\&CK mapping

\- Incident documentation and evidence-based decision-making



\## Disclaimer



This project was completed in an authorized, preconfigured MYDFIR training environment. All findings relate to simulated lab activity. This is not a production security incident or a live customer investigation.

