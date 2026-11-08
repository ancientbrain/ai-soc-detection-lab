# AI-Assisted SOC Detection Lab: Design, Implementation, and Evaluation of an Endpoint Detection Pipeline with LLM-Assisted Alert Triage

**Author:** Satwika Maddukuri
**Program:** M.S. Information Systems, Northeastern University (expected December 2026)
**Repository:** github.com/ancientbrain/ai-soc-detection-lab
**Document status:** Living report, version 0.5
**Last updated:** November 7, 2026 (Phase 2 in progress: technique 1 of 6 complete)

> This report is updated at the end of each work session. Sections marked *[Planned]* describe work that has not yet been carried out; they will be replaced with methods, evidence, and results as the project progresses.

---

## Abstract

*[Provisional; to be finalized at project completion.]*

Security Operations Centers (SOCs) depend on high-fidelity endpoint telemetry, well-engineered detections, and efficient alert triage. This project builds a self-contained SOC laboratory to study all three. A Windows 11 victim host is instrumented with Microsoft Sysinternals Sysmon and native Windows auditing, and its telemetry is forwarded to Splunk Enterprise. Adversary behavior is emulated with Atomic Red Team, and detections are written against the resulting data and mapped to MITRE ATT&CK. The project then evaluates a large language model (LLM) as a triage assistant, measuring its accuracy against the author's manual analysis and documenting failure modes such as hallucination. Finally, detections are re-expressed as vendor-neutral Sigma rules and managed as code. As of this version, the full telemetry pipeline is deployed and verified end to end, and adversary emulation has begun: the first technique (T1059.001, encoded PowerShell) has been executed, investigated across three log sources, and covered by a validated detection that closes a gap in a commonly cited search. LLM evaluation and Detection-as-Code are pending.

---

## 1. Introduction

### 1.1 Motivation

Entry-level SOC work centers on three skills: understanding what telemetry an endpoint produces, writing searches that reliably separate malicious from benign activity, and triaging alerts quickly and accurately. LLMs are increasingly proposed as triage aids, but their reliability on security data is not well established, and unverified AI output in a SOC carries real operational risk. A controlled lab allows each of these elements to be built, tested, and measured end to end, with known ground truth for every simulated attack.

### 1.2 Objectives

1. Build an isolated, reproducible lab producing rich Windows endpoint telemetry.
2. Emulate a defined set of MITRE ATT&CK techniques and write detections that identify each one.
3. Document an investigation of a multi-stage attack chain in a professional incident report.
4. Design an LLM-based triage assistant with structured prompting and mandatory human review, and evaluate its accuracy against manual analysis.
5. Re-implement detections as Sigma rules, convert them to Splunk SPL, and manage them under version control (Detection-as-Code).

### 1.3 Scope

The lab consists of a single Windows 11 victim virtual machine and a Splunk Enterprise instance on the host. All adversary emulation occurs inside the virtual machine. Only synthetic lab data is processed by the LLM. Network-based detection, multi-host lateral movement, and production deployment are out of scope.

### 1.4 Schedule

The project follows a 22-day plan at roughly two hours per day.

| Phase | Focus | Planned dates | Status |
|---|---|---|---|
| 1 | Build the lab | Nov 3 – Nov 7, 2026 | Complete (Nov 6; Day 5 available as buffer) |
| 2 | Attack, detect, investigate | Nov 8 – Nov 12 | In progress (started early, Nov 6; 1 of 6 techniques complete) |
| 3 | AI-assisted triage | Nov 13 – Nov 17 | Not started |
| 4 | Detection-as-Code and polish | Nov 18 – Nov 21 | Not started |
| Buffer | Contingency | Nov 22 – Nov 24 | Unused |

---

## 2. Background

### 2.1 Endpoint telemetry

Default Windows logging records limited detail about process behavior. **Sysmon** is a free Microsoft Sysinternals system service that writes detailed events to the Windows event log, including process creation with full command lines and file hashes (Event ID 1), network connections (3), process access (10), registry modifications (12–14), and DNS queries (22). Sysmon's value depends heavily on its configuration, which determines which events are recorded and which are filtered as noise.

Two native Windows sources complement Sysmon. **PowerShell Script Block Logging** (Event ID 4104) records the content of script blocks as PowerShell executes them, after any obfuscation such as Base64 encoding has been decoded. **Security log auditing** records process creation (4688), which can include the command line when enabled, and account management events such as user creation (4720).

### 2.2 MITRE ATT&CK

MITRE ATT&CK is a publicly maintained knowledge base of adversary tactics and techniques derived from real-world observations. It provides a common vocabulary for describing attacker behavior and for measuring detection coverage. This project maps every simulated technique and every detection to an ATT&CK technique ID.

### 2.3 Adversary emulation

**Atomic Red Team** is an open-source library of small, focused tests, each mapped to an ATT&CK technique, that reproduce attacker behavior in a controlled way. Because the timing and content of each test are known, the resulting telemetry serves as ground truth for detection development and for evaluating automated triage.

### 2.4 Detection-as-Code and Sigma

Detection-as-Code applies software engineering practices (version control, review, and automated testing) to detection logic. **Sigma** is a vendor-neutral, YAML-based rule format for log detections. Rules written once in Sigma can be converted to query languages such as Splunk SPL with the pySigma toolchain, making detections portable across SIEM platforms.

### 2.5 LLMs in alert triage

LLMs can summarize alerts, suggest likely techniques, and recommend next steps, potentially reducing analyst workload. Known risks include hallucination (asserting facts not supported by the input), overconfidence, and sensitivity to prompt wording. Any evaluation must therefore compare model output against verified ground truth and keep a human analyst responsible for every decision.

---

## 3. Lab Architecture

### 3.1 Overview

```mermaid
flowchart LR
    subgraph Host["Host PC (Windows 11, 16 GB RAM)"]
        SPL["Splunk Enterprise 10.6.1.1<br/>receiver on 192.168.38.1:9997<br/>index: sysmon"]
        PY["Python triage assistant<br/>(Phase 3)"]
    end
    subgraph VM["SOC-Win11 victim VM"]
        SYS["Sysmon 15.22<br/>sysmon-modular config"]
        WIN["Windows auditing<br/>4104 / 4688 / 4720"]
        UF["Splunk Universal Forwarder 10.6.1.1<br/>least-privilege virtual service account"]
        ART["Atomic Red Team<br/>(Phase 2)"]
    end
    ART -- generates activity --> SYS
    ART -- generates activity --> WIN
    SYS --> UF
    WIN --> UF
    UF -- "host-only network (VMnet1)" --> SPL
    SPL -- "REST API alerts" --> PY
    PY -- "lab data only" --> LLM["LLM API (Gemini)"]
    VM -. "NAT (VMnet8): downloads only" .-> NET["Internet"]
```

### 3.2 Components

| Component | Version / detail | Location | Role |
|---|---|---|---|
| Host operating system | Windows 11, 16 GB RAM | Host | Runs the hypervisor, Splunk, and analysis tooling |
| VMware Workstation Pro | 26.0.1 | Host | Hypervisor |
| Windows 11 Enterprise Evaluation | Build 26300.9457 (90-day evaluation) | VM `SOC-Win11` | Victim endpoint |
| Sysmon | 15.22 | VM | Primary endpoint telemetry |
| sysmon-modular config | Release `configs-a45dedb13a43`, default balanced config | VM | Defines Sysmon event filtering |
| Splunk Enterprise | 10.6.1.1 (60-day Enterprise trial, convertible to Free license) | Host | SIEM: indexing, search, alerting |
| Splunk Add-on for Sysmon | 5.0.1 (`Splunk_TA_microsoft_sysmon`) | Host | Field extraction for Sysmon events |
| Splunk Add-on for Microsoft Windows | 12.0.0 (`Splunk_TA_windows`) | Host | Field extraction for Security and PowerShell events |
| Splunk Universal Forwarder | 10.6.1.1 (build b2ae2962645c, matching the receiver) | VM | Log shipping |
| Invoke-AtomicRedTeam + atomics | Installed from the official installer (`master` branch) to `C:\AtomicRedTeam` | VM | Adversary emulation |
| Gemini API | *[Pending, Phase 3]* | External | LLM for triage experiments |
| sigma-cli / pySigma | *[Pending, Phase 4]* | Host | Sigma-to-SPL conversion |

### 3.3 Virtual machine specification

| Resource | Allocation |
|---|---|
| Memory | 4 GB |
| Processors | 2 |
| Disk | 80 GB NVMe, dynamically allocated, split files |
| Firmware | UEFI with virtual TPM 2.0 |
| Encryption | TPM-related files only (`.nvram`, `.vmss`, `.vmem`, `.vmx`, `.vmsn`) |
| Network adapters | Adapter 1: NAT; Adapter 2: host-only |
| Removed devices | Sound card |

### 3.4 Network design

| Network | Subnet | Host address | VM address | Purpose |
|---|---|---|---|---|
| VMnet8 (NAT) | 192.168.23.0/24 | — (gateway 192.168.23.2) | 192.168.23.133 (DHCP) | Internet access for tool downloads |
| VMnet1 (host-only) | 192.168.38.0/24 | 192.168.38.1 | 192.168.38.128 (DHCP) | Private telemetry path to Splunk |

The dual-adapter design separates two needs. Tool installation requires internet access, while telemetry should travel only over a private link. Before adversary emulation begins, the NAT adapter will be disconnected so that the victim can reach only the host.

### 3.5 Design decisions

| Decision | Alternatives considered | Rationale |
|---|---|---|
| VMware Workstation Pro as hypervisor | VirtualBox (original plan) | Already installed and free for personal use; avoids running two hypervisors with conflicting drivers; full snapshot support. |
| Splunk on the host rather than in a second VM | Dedicated Splunk VM | With 16 GB of host RAM, a second VM would compete for memory; a host install is lighter and simpler to reach over the host-only network. |
| Windows 11 Enterprise Evaluation | Windows 10 | Current, supported platform representative of enterprise endpoints; free for testing purposes. |
| 80 GB virtual disk | 50 GB (original plan) | Windows 11 requires at least 64 GB of storage; dynamic allocation means unused space costs nothing. |
| TPM-only encryption | Full VM encryption | Satisfies the Windows 11 TPM requirement without full-disk encryption overhead. |
| VM stored at `C:\VMs\` | Default OneDrive location | Cloud sync of active VM files risks corruption and file locking, and would upload attack-lab artifacts to cloud storage. |
| sysmon-modular configuration | SwiftOnSecurity sysmon-config | Rules are annotated with ATT&CK technique IDs, and the default configuration logs process access to `lsass.exe`, which credential-dumping detection requires. |

---

## 4. Implementation

### 4.1 Phase 1: Building the lab

#### 4.1.1 Repository initialization (Day 0, November 2)

A private GitHub repository was created with a structure mirroring the project phases (`configs/`, `detections/`, `rules/`, `triage/`, `reports/`, `docs/`, `screenshots/`). A `.gitignore` excludes secrets (`.env`, key files), virtual machine artifacts (`.vmdk`, `.vmx`, `.iso`), raw event log exports (`.evtx`), and Python build files. Commits use a GitHub no-reply address so that no personal email address is published when the repository is made public. A progress log (`docs/progress-log.md`) records each session.

#### 4.1.2 Victim virtual machine (Day 1, November 4)

The VM was created in VMware Workstation Pro with the specification in Section 3.3. Windows 11 Enterprise Evaluation was installed from an ISO downloaded directly from the Microsoft Evaluation Center. During setup, the "I don't have internet" path was used to create a local account rather than a Microsoft account, keeping the lab free of personal cloud identities. VMware Tools was installed for display and input integration. After networking was repaired (Section 6), Windows Update was applied and a baseline snapshot, **"Clean install,"** was taken.

**Verification evidence**

| Check | Expected | Observed |
|---|---|---|
| NAT address | 192.168.23.x | 192.168.23.133, gateway 192.168.23.2 |
| Host-only address | 192.168.38.x | 192.168.38.128 |
| Internet reachability | `TcpTestSucceeded: True` to 8.8.8.8:53 | True (interface Ethernet0) |
| Baseline snapshot | Present in Snapshot Manager | "Clean install" present |

#### 4.1.3 Endpoint instrumentation (Day 2, November 4)

**Sysmon.** Sysmon was downloaded from the official Sysinternals distribution point. The sysmon-modular repository no longer contains a prebuilt `sysmonconfig.xml`, so the configuration was located among the release assets through the GitHub API (Section 6). Its integrity was verified against the publisher's SHA256SUMS file before installation:

```
SHA256 (published):  64bec37ba849c5f2934a55d2a29e7ddfae46a30d56f7f2908d1f8a454898797e
SHA256 (computed):   64bec37ba849c5f2934a55d2a29e7ddfae46a30d56f7f2908d1f8a454898797e
```

Before installation, the configuration was inspected to confirm that it contains `ProcessAccess` rules targeting `C:\Windows\system32\lsass.exe`, annotated `technique_id=T1003, technique_name=OS Credential Dumping`. Sysmon was installed with:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

**Native Windows logging.** The following settings were applied through the registry keys that Group Policy writes, which is functionally equivalent to configuring them in `gpedit.msc`:

| Setting | Mechanism | Event produced |
|---|---|---|
| PowerShell Script Block Logging | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1` | 4104 |
| Command line in process creation events | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1` | 4688 (with command line) |
| Audit Process Creation | `auditpol /set /subcategory:"Process Creation" /success:enable` | 4688 |
| Audit User Account Management | `auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable` | 4720 and related |

**Verification evidence**

| Check | Observed |
|---|---|
| Sysmon service | `Sysmon64` running |
| Sysmon events generated | Event IDs 3, 13, and 22 observed within minutes of installation |
| Script block logging | 4104 events generated by a new PowerShell session |
| Process creation command lines | 4688 event with a populated `Process Command Line` field |
| Audit policy | Process Creation: Success; User Account Management: Success and Failure |

An observation worth recording: a 4104 event existed from before script block logging was enabled. Windows logs script blocks it classifies as suspicious even without the policy, but enabling the policy is necessary for complete coverage.

The 4688 evidence also illustrates a triage-relevant field. `TokenElevationTypeLimited (3)` indicates the process ran without administrative privileges, whereas Type 2 (elevated) would indicate administrative execution, a useful signal when assessing an alert's severity.

A second snapshot, **"Sysmon + logging,"** was taken, and the verified configuration was committed to `configs/sysmon/sysmonconfig.xml`, with a matching hash confirmed on the host.

#### 4.1.4 SIEM deployment (Day 3, November 5)

Splunk Enterprise 10.6.1.1 was installed on the host from the official Windows MSI with default options (installed to `C:\Program Files\Splunk`, running as a Windows service). The 60-day Enterprise trial converts to the Free license (500 MB/day), which comfortably exceeds the lab's expected volume. Configuration then proceeded as follows:

1. **Index.** An events index named `sysmon` was created to hold all lab telemetry. Every detection will be scoped to `index=sysmon`.
2. **Receiving.** A receiving input was enabled on TCP 9997, the conventional port for Splunk-to-Splunk forwarding.
3. **Host firewall.** An inbound rule was created that allows TCP 9997 **only** from the host-only subnet:

   ```powershell
   New-NetFirewallRule -DisplayName "Splunk receiver 9997 (lab host-only)" -Direction Inbound -Protocol TCP -LocalPort 9997 -RemoteAddress 192.168.38.0/24 -Action Allow -Profile Any
   ```

   This applies least privilege: the home network and other interfaces cannot reach the receiver.
4. **Add-ons.** The Splunk Add-on for Sysmon (5.0.1) and the Splunk Add-on for Microsoft Windows (12.0.0) were installed to provide search-time field extraction (for example `CommandLine`, `Image`, `TargetImage`). Because Splunk Web's in-product app browser returned errors (Section 6), both packages were downloaded from Splunkbase, their provenance was checked (official site, publisher Splunk), and they were installed with the Splunk CLI:

   ```powershell
   & "C:\Program Files\Splunk\bin\splunk.exe" install app <package>
   & "C:\Program Files\Splunk\bin\splunk.exe" restart
   ```

**Verification evidence**

| Check | Expected | Observed |
|---|---|---|
| Receiver listening | TCP 9997 in LISTENING state | `0.0.0.0:9997 LISTENING` |
| Firewall rule | Enabled, inbound, allow | `Splunk receiver 9997 (lab host-only)`: True, Inbound, Allow |
| Reachability from VM | `TcpTestSucceeded: True` from a 192.168.38.x source | True; source 192.168.38.128 via the VM's host-only adapter |
| Add-ons | Installed and enabled | `Splunk_TA_microsoft_sysmon` and `Splunk_TA_windows`: ENABLED |

The receiver-side Splunk configuration (`indexes.conf`, `inputs.conf`) is stored in `configs/splunk/indexer/`.

#### 4.1.5 Forwarder deployment and end-to-end validation (Day 4, November 6)

**Installation.** The Splunk Universal Forwarder 10.6.1.1 was downloaded on the host (keeping the author's Splunk account off the victim machine) and copied into the VM. Its build identifier (`b2ae2962645c`) matches the receiver, avoiding version-mismatch issues. The installer was run with default options, which create a dedicated local forwarder administrator account and run the service as the low-privilege virtual account `NT SERVICE\SplunkForwarder`. The receiving indexer was set to `192.168.38.1:9997`, producing this `outputs.conf`:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.38.1:9997

[tcpout-server://192.168.38.1:9997]
```

**Inputs.** Collection was defined in `etc\system\local\inputs.conf`. Sysmon events are sent in XML form (`renderXml = true`), the format the Sysmon add-on expects:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = sysmon
renderXml = true
disabled = 0

[WinEventLog://Security]
index = sysmon
disabled = 0

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
index = sysmon
disabled = 0
```

**Fault diagnosis: missing Sysmon telemetry.** After the forwarder restarted, `splunk list forward-server` reported an active connection, and Security and PowerShell events arrived in Splunk, but Sysmon events did not. A search across all indexes (`index=* source=*Sysmon*`) returned nothing, ruling out misrouting. The forwarder's internal log (`var\log\splunk\splunkd.log`) showed the cause:

```
ERROR ExecProcessor ... splunk-winevtlog - WinEventLogChannel::init: Init failed,
unable to subscribe to Windows Event Log channel 'Microsoft-Windows-Sysmon/Operational': errorCode=5
```

Error code 5 is Windows `ERROR_ACCESS_DENIED`. The Sysmon channel's access control list, read with `wevtutil gl`, granted read access to SYSTEM, Administrators, Backup Operators, Server Operators, and Event Log Readers, but not to the forwarder's virtual account:

```
O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)
```

Two remediations were considered: running the forwarder as LocalSystem, or granting the existing account read-only access to this one channel. The second preserves least privilege and was chosen. The account's SID was resolved and a single read-only access control entry (`0x1`) was appended:

```powershell
wevtutil sl Microsoft-Windows-Sysmon/Operational "/ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-80-972488765-139171986-783781252-3188962990-3730692313)"
```

After the forwarder restarted, no new access errors appeared and Sysmon events began arriving in Splunk. Whether a Sysmon reinstall or configuration update resets this channel ACL has not been tested; it is the first item to check if Sysmon ingestion stops after such a change.

**Time zone change.** The forwarder log revealed that the VM's time zone was Pacific (UTC−08:00). It was changed to Eastern (`Set-TimeZone -Id "Eastern Standard Time"`) to match the analyst's local time. This change later proved to have left the VM's underlying UTC clock three hours fast; the discovery and correction are described in Section 4.2.3.

**Verification evidence**

| Check | Expected | Observed |
|---|---|---|
| Forwarder service | Running | `SplunkForwarder` running as `NT SERVICE\SplunkForwarder` |
| Forwarding connection | Active | `Active forwards: 192.168.38.1:9997`; no inactive forwards |
| Sources in Splunk | Sysmon, Security, PowerShell | All three present after the ACL fix |
| Event volume | Non-zero | 20,495 events across 42 distinct event codes (Nov 5, 4:00 PM to Nov 6, 4:44 PM) |

A **"Logging ready"** snapshot was taken. It is the restore point for all adversary emulation in Phase 2.

#### 4.1.6 Baseline telemetry profile

The pre-attack event distribution, the 14 most frequent of 42 event codes, establishes a benign baseline against which emulated attacks will be compared:

| Event code | Source | Meaning | Count |
|---|---|---|---|
| 4907 | Security | Auditing settings on an object were changed | 9,849 |
| 11 | Sysmon | File created | 4,399 |
| 2 | Sysmon | File creation time changed | 2,113 |
| 13 | Sysmon | Registry value set | 1,413 |
| 4688 | Security | Process created | 818 |
| 7 | Sysmon | Image (DLL) loaded | 380 |
| 3 | Sysmon | Network connection | 353 |
| 12 | Sysmon | Registry object created or deleted | 289 |
| 10 | Sysmon | Process accessed | 196 |
| 4104 | PowerShell | Script block logged | 131 |
| 4624 | Security | Successful logon | 105 |
| 4672 | Security | Special privileges assigned to new logon | 99 |
| 1 | Sysmon | Process created | 95 |
| 5379 | Security | Credential Manager credentials read | 54 |

Three observations from the baseline shape the detection work ahead:

1. **4907 dominates the volume** (about 48% of events). It most likely reflects Windows servicing activity after updates. It has little detection value here and is a candidate for filtering if volume ever becomes a concern.
2. **Sysmon Event 1 (95) is far lower than Security 4688 (818)** because the sysmon-modular configuration filters out known-benign process launches, while 4688 records every process. Sysmon Event 1 is therefore the higher-signal source for process-based detections.
3. **Sysmon Event 10 already appears 196 times without any attack.** Benign processes access LSASS routinely, so the credential-dumping detection (T1003.001) must be tuned against this baseline to avoid false positives.

### 4.2 Phase 2: Adversary emulation and detection

#### 4.2.1 Emulation setup (November 6)

**Tooling.** Invoke-AtomicRedTeam and the Atomic test library were installed in the VM. Before installation, the repository's default branch was confirmed through the GitHub API, and the installer was downloaded to a file and reviewed rather than piped directly into `Invoke-Expression`. A Microsoft Defender exclusion was added for `C:\AtomicRedTeam` only; real-time protection otherwise remained enabled.

**Defender intervention.** One candidate test (T1059.001-15) required the AtomicTestHarnesses PowerShell module. Installing it from the PowerShell Gallery placed it outside the excluded folder, and Defender blocked several of its scripts as malicious (including an LSASS-dumping harness), leaving the module partially loaded. Rather than widen the Defender exclusion, the VM was restored to the "ART installed" snapshot and an alternative test without that dependency was selected. This is itself a meaningful result: default endpoint protection detected and blocked attack tooling on arrival.

**Test plan.** One test was chosen per technique, preferring built-in Windows binaries (so tests run offline after isolation), alignment with the planned detection, and the availability of cleanup commands:

| ATT&CK ID | Technique | Atomic test | Prerequisites | Status |
|---|---|---|---|---|
| T1059.001 | PowerShell | -17 PowerShell Command Execution (`powershell.exe -e <Base64>`) | Met | **Executed; detected; alert saved** |
| T1003.001 | LSASS memory | -2 Dump LSASS.exe memory using comsvcs.dll | Met | Pending |
| T1053.005 | Scheduled task | -2 Scheduled task Local (`schtasks /create`) | Met | Pending |
| T1547.001 | Registry Run keys | -1 Reg Key Run | Met | Pending |
| T1136.001 | Local account | -4 Create a new user in a command prompt | Met | Pending |
| T1087.001 | Local account discovery | -8 Enumerate all accounts on Windows (Local) | Met | Pending |

**Isolation procedure.** Before testing, the VM's NAT adapter was disconnected at the hypervisor level (both *Connected* and *Connect at power on* cleared), leaving only the host-only link. Isolation is verified before tests rather than assumed: `Test-NetConnection 8.8.8.8 -Port 53` must fail and `Test-NetConnection 192.168.38.1 -Port 9997` must succeed. The first verification attempt showed the NAT adapter still connected, which the check caught before any attack ran. The verified state was saved as the snapshot "Pre-attack v2 (isolated, clock synced)."

#### 4.2.2 Technique 1: T1059.001, encoded PowerShell

**Execution.** Atomic test T1059.001-17 runs a command used in real intrusions, reported in Red Canary's 2021 Threat Detection Report:

```
powershell.exe -e JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
```

The Base64 payload is itself obfuscated: `'ie{0}' -f 'x'` assembles the string `iex` (Invoke-Expression) at runtime, and the displayed message is split into concatenated fragments to evade keyword matching. The test was started at 20:31:41 VM time and printed "Hello, from PowerShell!" All VM timestamps in this subsection are three hours fast because of the clock skew described in Section 4.2.3; the relative order and spacing of events are unaffected.

**Investigation.** The activity was located in Sysmon and PowerShell logs, and the Security log was searched:

| Time (VM clock) | Source | Evidence |
|---|---|---|
| 20:31:50.592 | Sysmon 1 | `cmd.exe` started with `"cmd.exe" /c powershell.exe -e JgAg...` |
| 20:31:50.721 | Sysmon 1 | `powershell.exe` started by `cmd.exe` with `powershell.exe -e JgAg...` |
| 20:31:51.259 | PowerShell 4104 | Decoded script block: `& (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'H"+"el"+"lo, fr"+"om P"+"ow"+"erS"+"h"+"ell!'")`, ScriptBlock ID `3f9c6326-cfc3-46e3-8cf3-d40d7479f972`, empty `Path` |
| 20:31–20:33 | Security 4688 | Window searched; results were dominated by forwarder activity, and the attack's own 4688 record was not isolated in this session |

Three analytic points emerged. First, the **parent process** separates the attack from benign use: the analyst's own PowerShell session in the same window had `WindowsTerminal.exe` as its parent, while the attack's parent was `cmd.exe`. Second, Script Block Logging recovered the **decoded payload**, and its empty `Path` field shows the code ran from the command line rather than from a script on disk. Third, the forwarder's own helper process (`splunk-powershell.exe`, run by `NT SERVICE\SplunkForwarder`) appears in 4688 results for "powershell.exe," a source of noise that naive keyword searches must account for.

**Detection gap.** The detection proposed in the original project plan was:

```
index=sysmon EventCode=1 Image="*\\powershell.exe" CommandLine="*-enc*"
```

After confirming that the `CommandLine` field was populated for the attack event, this search returned **zero results**. PowerShell accepts any unambiguous prefix of `-EncodedCommand` (for example `-e`, `-en`, `-enc`, and the alias `-ec`), so a search for the literal substring `-enc` misses the `-e` form used here.

**Improved detection.**

```
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where match(CommandLine, "(?i)\s[-/](e|ec|en[a-z]*)\s+[A-Za-z0-9+/=]{20,}")
| table _time, host, User, ParentImage, Image, CommandLine
```

The regular expression matches a parameter introduced by `-` or `/` that is `e`, `ec`, or any word beginning with `en`, followed by a Base64-like string of at least 20 characters; the length requirement suppresses matches on short, benign arguments. Filtering on the PowerShell image produces one result per execution, with the `cmd.exe` launcher visible in `ParentImage`. An initial version written with SPL's `| regex` command returned no results even though the same pattern matched under `where match()`; the root cause was not determined, and `where match()` was adopted.

**Validation.** Run over all indexed data (more than 51,000 events at the time), the improved detection returned **exactly one result**, the attack, giving a true positive with no false positives against the baseline.

**Alerting.** The search was saved as the scheduled alert *T1059.001 - PowerShell Encoded Command* (hourly; trigger when results exceed zero, for each result; action: add to Triggered Alerts, severity High). Review of the saved object showed that the alert had initially captured an unrelated `stats` search open in the same session; the search was corrected and re-verified. Scheduled alerting is available during the Splunk Enterprise trial but not under the Free license.

#### 4.2.3 Clock skew discovery and correction

When the validated detection was run over "Last 24 hours," it returned nothing, although it matched over "All time." The search window ended at 5:48 PM, while the attack events were stamped 8:31 PM: the events were about three hours in the future relative to Splunk. Comparing clocks confirmed the cause:

| Machine | Local time | UTC |
|---|---|---|
| Host | 5:53 PM | 22:53 (Nov 6) |
| VM | 8:55 PM | 01:55 (Nov 7) |

Both machines displayed Eastern time, but the VM's UTC clock was three hours fast, exactly the Pacific-to-Eastern offset introduced by the Day 4 time zone change. The most likely mechanism is that the hypervisor presents a Windows guest's hardware clock in host local time, so changing the guest's time zone shifted its computed UTC; this explanation was not verified further. The fix was to enable VMware Tools time synchronization with the host and confirm that the VM's UTC matched the host's (23:43 on both after correction). The pre-attack snapshot was retaken afterward, because snapshots also capture VM settings and the earlier one would have reintroduced the problem.

**Data quality impact.** Events generated by the VM between the Day 4 time zone change and this correction carry timestamps about three hours fast. Their internal ordering is intact, but they overlap in Splunk's timeline with correctly stamped events produced after the fix. This is recorded as a known limitation of the dataset. The episode illustrates why time synchronization is a prerequisite for correlation and scheduled detection in any SOC.

### 4.3 Phase 3: LLM-assisted triage *[Planned]*

**Design.** A Python client will retrieve triggered alerts through the Splunk REST API and submit each one to the LLM with a structured prompt that specifies context, objective, constraints (use only the provided data, answer "insufficient data" when uncertain), and a JSON output schema (summary, likely ATT&CK technique, severity with rationale, recommended next steps, confidence). No alert is actioned without analyst approval.

**Evaluation method.** Each model response will be graded against the author's manual analysis on a four-level rubric: *correct*, *partially correct*, *wrong*, or *hallucinated* (asserting details absent from the input). Results will be reported per technique and in aggregate, with technique-mapping accuracy measured separately. Prompt revisions and their effects will be documented.

### 4.4 Phase 4: Detection-as-Code *[Planned]*

Four to six detections will be rewritten as Sigma rules in `rules/`, converted to SPL with sigma-cli using the Splunk backend, and re-validated against the original Atomic test data. Optionally, a GitHub Actions workflow will validate rule syntax on every push.

---

## 5. Telemetry Coverage

| Source | Event ID | Captures | Relevant ATT&CK techniques | Status |
|---|---|---|---|---|
| Sysmon | 1 | Process creation, command line, hashes, parent | T1059.001, T1053.005, T1087.001 | Ingested |
| Sysmon | 3 | Network connections | Command and control, exfiltration | Ingested |
| Sysmon | 10 | Process access (including LSASS) | T1003.001 | Ingested (benign baseline present) |
| Sysmon | 13 | Registry value set | T1547.001 | Ingested |
| Sysmon | 22 | DNS queries | Command and control | Verified locally |
| PowerShell | 4104 | Decoded script block content | T1059.001 | Ingested |
| Security | 4688 | Process creation with command line | Broad execution coverage | Ingested |
| Security | 4720 | User account created | T1136.001 | Auditing enabled |

"Ingested" means events were observed in Splunk (`index=sysmon`). "Verified locally" means events were seen in the VM's event log but did not appear among the most frequent codes in Splunk. "Auditing enabled" means the event will first be produced during adversary emulation.

---

## 6. Challenges and Resolutions

| # | Issue | Symptom | Root cause | Resolution | Lesson |
|---|---|---|---|---|---|
| 1 | Git authentication failure | `Invalid username or token. Password authentication is not supported` | A stale saved GitHub credential on the host | Cleared it with `git credential reject` and re-authenticated through Git Credential Manager's browser flow | Check for cached credentials before assuming an account problem. |
| 2 | VM default path inside OneDrive | Wizard defaulted to `OneDrive\Documents\Virtual Machines` | VMware default location | Relocated to `C:\VMs\SOC-Win11` | Review defaults; cloud sync is unsuitable for VM disks and attack-lab artifacts. |
| 3 | No network addresses in VM | Both adapters had APIPA addresses (169.254.x.x); no internet | The host's VMware DHCP service (`VMnetDHCP`) was stopped despite automatic start | Started the service and renewed the leases (`ipconfig /release`, `/renew`) | A 169.254.x.x address always means DHCP did not answer; check the DHCP source first. |
| 4 | Sysmon config download returned 404 | Raw GitHub URL for `sysmonconfig.xml` not found | sysmon-modular no longer commits the generated config to the repository | Queried the GitHub API, found the config among the release assets, and verified it against SHA256SUMS | Tutorials go stale; consult the authoritative source and verify integrity. |
| 5 | Push rejected | `remote: fatal error in commit_refs` | GitHub server-side error | Commit preserved locally; push succeeded unchanged the next day (Nov 5) once the service recovered | Distinguish server-side from client-side failures before troubleshooting locally; Git's local-first design means a failed push never loses work. |
| 6 | Splunk Web app browser unavailable | "Page not found" and generic error pages when opening the app browser and the Manage Apps URL | Not fully diagnosed; a Splunk Web issue in this 10.6.1.1 installation | Installed the add-ons from Splunkbase packages with the Splunk CLI | Keep a CLI fallback; file-based installation is also standard on production SIEMs without internet access. |
| 7 | Browser warning on add-on packages | `.tgz` downloads flagged as potentially harmful | Generic browser heuristic for uncommon archive types | Confirmed the official source and publisher before keeping the files | Base trust decisions on provenance, not on the warning alone. |
| 8 | CLI command appeared to hang | `splunk display app \| Select-String` printed nothing for minutes | The CLI's login prompt was hidden by the output filter | Authenticated first with `splunk login`, then reran the command | Authenticate before piping interactive CLI output. |
| 9 | Verification run on the wrong machine | Connectivity tests showed the host's own addresses | Commands entered in the host terminal instead of the VM | Reran in the VM after checking the prompt (`satu7` = host, `SOC-WIN11` = VM) | Always confirm which machine a terminal belongs to; critical once attack simulations begin. |
| 10 | Write to forwarder configuration denied | `Out-File: Access to the path ... inputs.conf is denied` | Terminal not elevated | Reopened Terminal as Administrator and confirmed the role before writing | Changes under `Program Files` require elevation; verify the role rather than assuming it. |
| 11 | Sysmon events missing from Splunk | Security and PowerShell arrived; Sysmon absent from all indexes | Forwarder virtual account lacked read access to the Sysmon channel (`errorCode=5`) | Appended a read-only ACE for the account's SID to the channel SDDL (Section 4.1.5) | Least-privilege agents need explicit access to each protected log source; check the agent's own logs first. |
| 12 | Attack-tooling dependency blocked | `Install-Module AtomicTestHarnesses`: "file contains a virus or potentially unwanted software" | Defender flagged the module, installed outside the excluded folder | Restored the "ART installed" snapshot and chose a test without the dependency | Prefer snapshot rollback and alternative tests over widening security exclusions. |
| 13 | Isolation not actually in effect | `Test-NetConnection 8.8.8.8` succeeded via the NAT adapter | Adapter setting not yet applied | Disconnected the NAT adapter in VM settings and re-verified | Verify isolation; do not assume it. |
| 14 | Improved detection returned nothing | `\| regex` version of the search had no results | Not determined; the same pattern worked with `where match()` | Rewrote using `where match()` and confirmed field contents first | Test detections against a known-true event; zero results may mean a broken search. |
| 15 | Real-time time range selected | "0 of 0 events matched" while running | "All time (real-time)" only shows newly arriving events | Selected the historical "All time" preset | Distinguish real-time from historical searches. |
| 16 | Detection missed in "Last 24 hours" | Matched over All time but not over recent windows | VM UTC clock three hours fast after the time zone change | Enabled VMware Tools time sync, verified UTC, retook the pre-attack snapshot | Clock skew silently breaks time-windowed searches and alerts. |
| 17 | Alert saved the wrong search | Saved alert contained `index=sysmon \| stats count by source` | Alert created while a different search was open | Edited the saved search and re-verified it in Settings | Review what a saved alert actually runs, not just its name. |

---

## 7. Security, Safety, and Ethical Controls

1. **Isolation.** Adversary emulation runs only inside the VM. The NAT adapter is disconnected at the hypervisor before testing, and isolation is verified (internet unreachable, Splunk reachable) before each test session.
2. **Least-privilege network access.** The host firewall admits TCP 9997 only from the host-only subnet 192.168.38.0/24.
   **Least-privilege agent.** The forwarder runs as a virtual service account with read-only access to exactly the channels it collects, rather than as LocalSystem.
3. **Recoverability.** Snapshots are taken before every change and every attack test; current snapshots are "Clean install," "Sysmon + logging," "Logging ready," "ART installed," and "Pre-attack v2 (isolated, clock synced)."
4. **Scoped security exclusions.** The only Defender exclusion is the Atomic Red Team folder in the VM; when tooling outside it was blocked, the exclusion was not widened.
5. **Hardware separation.** No host USB devices (webcam, fingerprint reader, storage) are passed through to the VM.
6. **Supply-chain integrity.** Software is obtained only from official sources (Microsoft, Sysinternals, Splunk and Splunkbase, the original project repositories), published hashes are verified where available, and installer scripts are reviewed before execution.
7. **Data handling.** Only synthetic lab telemetry is ever sent to the LLM; no real organizational or personal data enters the lab.
8. **Secrets hygiene.** API keys will be stored in environment variables and excluded by `.gitignore`; the repository stays private until the core project is complete.
9. **Licensing.** Windows 11 Enterprise is used under Microsoft's evaluation terms for non-production testing.
10. **Human oversight.** The triage assistant is advisory; every recommendation requires analyst approval.

---

## 8. Results

*[Partial; Phases 2–4 in progress.]*

| Technique | Executed | Observed in | Detection | True positives | False positives (all data) |
|---|---|---|---|---|---|
| T1059.001 | Yes | Sysmon 1, PowerShell 4104 | Improved encoded-command search (Section 4.2.2) | 1 of 1 | 0 |

The detection proposed in the original plan for T1059.001 produced 0 of 1 true positives against the same data. Remaining contents (other techniques, LLM triage accuracy, Sigma conversion fidelity) will be added as the work is completed.

---

## 9. Limitations and Future Work

*[Partially provisional.]* Known limitations include a single-host environment with no lateral movement or domain infrastructure; Atomic tests that approximate but do not fully reproduce real adversary tradecraft; and a small alert sample for LLM evaluation, which limits statistical generalization. Splunk runs with its default self-signed certificates, and CLI server-certificate hostname validation is disabled in this installation; both are acceptable for a local-only lab but would be hardened in production. The host runs Windows 11, while Splunk's download page for 10.6.1.1 listed Windows 10 and Windows Server 2019/2022/2025, so the host OS may fall outside the officially listed platforms; this has no practical effect in the lab. Splunk scheduled alerting is unavailable under the Free license, so alerts depend on the 60-day Enterprise trial. VM telemetry between the Day 4 time zone change and the November 6 clock correction is time-shifted by about three hours (Section 4.2.3). Future work may include forwarding the *Microsoft-Windows-Windows Defender/Operational* log so that endpoint-protection responses are captured alongside attacker activity, an Active Directory domain, network sensors, and detection of prompt-injection attempts against a lab LLM application.

---

## 10. Conclusion

*[Pending.]*

---

## References

1. Microsoft Sysinternals. *Sysmon*. https://learn.microsoft.com/sysinternals/downloads/sysmon
2. Hartong, O. *sysmon-modular*. https://github.com/olafhartong/sysmon-modular
3. The MITRE Corporation. *MITRE ATT&CK*. https://attack.mitre.org
4. Red Canary. *Atomic Red Team*. https://github.com/redcanaryco/atomic-red-team
5. SigmaHQ. *Sigma: Generic Signature Format for SIEM Systems*. https://github.com/SigmaHQ/sigma
6. Microsoft. *Windows 11 Enterprise Evaluation*. https://www.microsoft.com/evalcenter/evaluate-windows-11-enterprise

---

## Appendix A: Session Timeline

| Date | Session | Outcome |
|---|---|---|
| Nov 2, 2026 | Day 0: Preparation | Hardware confirmed (16 GB RAM, more than 200 GB free); VMware networks verified; repository initialized |
| Nov 4, 2026 | Day 1: Victim VM | VM built, networking repaired, updated, "Clean install" snapshot |
| Nov 4, 2026 | Day 2: Instrumentation | Sysmon and Windows auditing deployed and verified; "Sysmon + logging" snapshot |
| Nov 5, 2026 | Day 3: SIEM | Splunk Enterprise 10.6.1.1 installed; `sysmon` index; receiving on 9997 with a host-only firewall rule; Sysmon and Windows add-ons installed via CLI |
| Nov 6, 2026 | Day 4: Forwarding | Universal Forwarder deployed; Sysmon channel access fixed; all three sources ingested; time zone corrected; "Logging ready" snapshot |
| Nov 6, 2026 | Phase 2 start | Atomic Red Team installed; Defender blocked a test dependency; isolation verified; T1059.001 executed, investigated, and detected with an improved search; clock skew found and corrected; alert saved |

## Appendix B: Artifact Index

| Artifact | Repository path | Status |
|---|---|---|
| Sysmon configuration (verified) | `configs/sysmon/sysmonconfig.xml` | Committed and pushed |
| Splunk receiver configuration | `configs/splunk/indexer/` | Added Day 3 |
| Progress log | `docs/progress-log.md` | Current through Phase 2 start |
| Universal Forwarder configuration | `configs/splunk/forwarder/` | Added Day 4 |
| Detection searches | `detections/spl/` | T1059.001 added Nov 7 |
| Sigma rules | `rules/` | Pending |
| Triage assistant | `triage/` | Pending |
| Incident report and AI evaluation | `reports/` | Pending |
