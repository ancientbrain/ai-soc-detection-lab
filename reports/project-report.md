# AI-Assisted SOC Detection Lab: Design, Implementation, and Evaluation of an Endpoint Detection Pipeline with LLM-Assisted Alert Triage

**Author:** Satwika [Last Name]
**Program:** M.S. Information Systems, Northeastern University (expected December 2026)
**Repository:** github.com/ancientbrain/ai-soc-detection-lab
**Document status:** Living report, version 0.2
**Last updated:** November 5, 2026 (end of Phase 1, Day 2)

> This report is updated at the end of each work session. Sections marked *[Planned]* describe work that has not yet been carried out; they will be replaced with methods, evidence, and results as the project progresses.

---

## Abstract

*[Provisional; to be finalized at project completion.]*

Security Operations Centers (SOCs) depend on high-fidelity endpoint telemetry, well-engineered detections, and efficient alert triage. This project builds a self-contained SOC laboratory to study all three. A Windows 11 victim host is instrumented with Microsoft Sysinternals Sysmon and native Windows auditing, and its telemetry is forwarded to Splunk Enterprise. Adversary behavior is emulated with Atomic Red Team, and detections are written against the resulting data and mapped to MITRE ATT&CK. The project then evaluates a large language model (LLM) as a triage assistant, measuring its accuracy against the author's manual analysis and documenting failure modes such as hallucination. Finally, detections are re-expressed as vendor-neutral Sigma rules and managed as code. As of this version, the instrumented victim environment is complete and verified; detection, evaluation, and results are pending.

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
| 1 | Build the lab | Nov 3 – Nov 7, 2026 | In progress (Days 1–2 complete) |
| 2 | Attack, detect, investigate | Nov 8 – Nov 12 | Not started |
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
    subgraph Host["Host PC (Windows, 16 GB RAM)"]
        SPL["Splunk Enterprise<br/>receiver on 192.168.38.1:9997<br/>(Phase 1, Day 3)"]
        PY["Python triage assistant<br/>(Phase 3)"]
    end
    subgraph VM["SOC-Win11 victim VM"]
        SYS["Sysmon 15.22<br/>sysmon-modular config"]
        WIN["Windows auditing<br/>4104 / 4688 / 4720"]
        UF["Splunk Universal Forwarder<br/>(Phase 1, Day 4)"]
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
| VMware Workstation Pro | 26.0.1 | Host | Hypervisor |
| Windows 11 Enterprise Evaluation | Build 26300.9457 (90-day evaluation) | VM `SOC-Win11` | Victim endpoint |
| Sysmon | 15.22 | VM | Primary endpoint telemetry |
| sysmon-modular config | Release `configs-a45dedb13a43`, default balanced config | VM | Defines Sysmon event filtering |
| Splunk Enterprise | *[Pending, Day 3]* | Host | SIEM: indexing, search, alerting |
| Splunk Universal Forwarder | *[Pending, Day 4]* | VM | Log shipping |
| Atomic Red Team | *[Pending, Phase 2]* | VM | Adversary emulation |
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

#### 4.1.4 SIEM deployment (Days 3–5) *[Planned]*

Install Splunk Enterprise on the host, create the `sysmon` index, enable receiving on TCP 9997, install the Splunk Add-on for Sysmon, deploy the Universal Forwarder to the VM, configure inputs for the Sysmon, Security, and PowerShell Operational logs, permit inbound 9997 from 192.168.38.0/24 on the host firewall, and verify ingestion with `index=sysmon | stats count by EventCode`.

### 4.2 Phase 2: Adversary emulation and detection *[Planned]*

| ATT&CK ID | Technique | Primary data source | Detection status |
|---|---|---|---|
| T1059.001 | PowerShell (encoded commands) | Sysmon 1, PowerShell 4104 | Not started |
| T1003.001 | LSASS memory credential dumping | Sysmon 10 | Not started |
| T1053.005 | Scheduled task | Sysmon 1 | Not started |
| T1547.001 | Registry Run keys | Sysmon 13 | Not started |
| T1136.001 | Create local account | Security 4720 | Not started |
| T1087.001 | Local account discovery | Sysmon 1 | Not started |

For each technique this section will record the Atomic test executed and its timestamp, the detection logic, whether the detection fired, and false-positive observations from baseline activity. A dashboard and an incident report for the chain PowerShell → credential dumping → persistence will follow.

### 4.3 Phase 3: LLM-assisted triage *[Planned]*

**Design.** A Python client will retrieve triggered alerts through the Splunk REST API and submit each one to the LLM with a structured prompt that specifies context, objective, constraints (use only the provided data, answer "insufficient data" when uncertain), and a JSON output schema (summary, likely ATT&CK technique, severity with rationale, recommended next steps, confidence). No alert is actioned without analyst approval.

**Evaluation method.** Each model response will be graded against the author's manual analysis on a four-level rubric: *correct*, *partially correct*, *wrong*, or *hallucinated* (asserting details absent from the input). Results will be reported per technique and in aggregate, with technique-mapping accuracy measured separately. Prompt revisions and their effects will be documented.

### 4.4 Phase 4: Detection-as-Code *[Planned]*

Four to six detections will be rewritten as Sigma rules in `rules/`, converted to SPL with sigma-cli using the Splunk backend, and re-validated against the original Atomic test data. Optionally, a GitHub Actions workflow will validate rule syntax on every push.

---

## 5. Telemetry Coverage

| Source | Event ID | Captures | Relevant ATT&CK techniques | Status |
|---|---|---|---|---|
| Sysmon | 1 | Process creation, command line, hashes, parent | T1059.001, T1053.005, T1087.001 | Configured |
| Sysmon | 3 | Network connections | Command and control, exfiltration | Verified |
| Sysmon | 10 | Process access (including LSASS) | T1003.001 | Configured (rule confirmed in config) |
| Sysmon | 13 | Registry value set | T1547.001 | Verified |
| Sysmon | 22 | DNS queries | Command and control | Verified |
| PowerShell | 4104 | Decoded script block content | T1059.001 | Verified |
| Security | 4688 | Process creation with command line | Broad execution coverage | Verified |
| Security | 4720 | User account created | T1136.001 | Auditing enabled |

"Verified" means events were observed in the local event log. "Configured" means the logging rule is in place but the event will first be observed during adversary emulation.

---

## 6. Challenges and Resolutions

| # | Issue | Symptom | Root cause | Resolution | Lesson |
|---|---|---|---|---|---|
| 1 | Git authentication failure | `Invalid username or token. Password authentication is not supported` | A stale saved GitHub credential on the host | Cleared it with `git credential reject` and re-authenticated through Git Credential Manager's browser flow | Check for cached credentials before assuming an account problem. |
| 2 | VM default path inside OneDrive | Wizard defaulted to `OneDrive\Documents\Virtual Machines` | VMware default location | Relocated to `C:\VMs\SOC-Win11` | Review defaults; cloud sync is unsuitable for VM disks and attack-lab artifacts. |
| 3 | No network addresses in VM | Both adapters had APIPA addresses (169.254.x.x); no internet | The host's VMware DHCP service (`VMnetDHCP`) was stopped despite automatic start | Started the service and renewed the leases (`ipconfig /release`, `/renew`) | A 169.254.x.x address always means DHCP did not answer; check the DHCP source first. |
| 4 | Sysmon config download returned 404 | Raw GitHub URL for `sysmonconfig.xml` not found | sysmon-modular no longer commits the generated config to the repository | Queried the GitHub API, found the config among the release assets, and verified it against SHA256SUMS | Tutorials go stale; consult the authoritative source and verify integrity. |
| 5 | Push rejected | `remote: fatal error in commit_refs` | GitHub server-side error | Commit preserved locally; push succeeded unchanged the next day (Nov 5) once the service recovered | Distinguish server-side from client-side failures before troubleshooting locally; Git's local-first design means a failed push never loses work. |

---

## 7. Security, Safety, and Ethical Controls

1. **Isolation.** Adversary emulation runs only inside the VM. The NAT adapter will be disconnected before testing, leaving only the host-only link.
2. **Recoverability.** Snapshots are taken before every change and every attack test; current snapshots are "Clean install" and "Sysmon + logging."
3. **Hardware separation.** No host USB devices (webcam, fingerprint reader, storage) are passed through to the VM.
4. **Supply-chain integrity.** Software is obtained only from official sources (Microsoft, Sysinternals, the original project repositories), and published hashes are verified where available.
5. **Data handling.** Only synthetic lab telemetry is ever sent to the LLM; no real organizational or personal data enters the lab.
6. **Secrets hygiene.** API keys will be stored in environment variables and excluded by `.gitignore`; the repository stays private until the core project is complete.
7. **Licensing.** Windows 11 Enterprise is used under Microsoft's evaluation terms for non-production testing.
8. **Human oversight.** The triage assistant is advisory; every recommendation requires analyst approval.

---

## 8. Results

*[Pending; to be completed in Phases 2–4.]* Planned contents: detection outcomes per technique, baseline false-positive observations, LLM triage accuracy by rubric category, representative failure cases, and Sigma conversion fidelity.

---

## 9. Limitations and Future Work

*[Partially provisional.]* Known limitations include a single-host environment with no lateral movement or domain infrastructure; Atomic tests that approximate but do not fully reproduce real adversary tradecraft; and a small alert sample for LLM evaluation, which limits statistical generalization. Future work may include an Active Directory domain, network sensors, and detection of prompt-injection attempts against a lab LLM application.

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

## Appendix B: Artifact Index

| Artifact | Repository path | Status |
|---|---|---|
| Sysmon configuration (verified) | `configs/sysmon/sysmonconfig.xml` | Committed and pushed |
| Progress log | `docs/progress-log.md` | Current through Day 2 |
| Splunk inputs/outputs configuration | `configs/splunk/` | Pending |
| Detection searches | `detections/spl/` | Pending |
| Sigma rules | `rules/` | Pending |
| Triage assistant | `triage/` | Pending |
| Incident report and AI evaluation | `reports/` | Pending |
