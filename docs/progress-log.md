# Progress Log

## Lab network
- Host (Splunk receiver): 192.168.38.1
- Host-only subnet (VMnet1): 192.168.38.0/24
- NAT subnet (VMnet8): 192.168.23.0/24

## 2026-11-02 (Day 0)
- Repo created, folder structure and .gitignore added
- VMware Workstation Pro 26.0.1 confirmed; Windows 11 Enterprise Eval ISO downloading
- Next: create SOC-Win11 VM and install Windows

## 2026-11-04 (Day 1) - Victim VM built
- Created SOC-Win11 in VMware Workstation Pro 26.0.1 (4 GB RAM, 2 CPU, 80 GB, vTPM with TPM-only encryption)
- Installed Windows 11 Enterprise Evaluation with a local account, plus VMware Tools
- Networking: NAT 192.168.23.133 (internet), host-only 192.168.38.128 (link to host 192.168.38.1)
- Troubleshooting: both adapters had 169.254.x.x addresses because the VMware DHCP service (VMnetDHCP) was stopped on the host; started it and renewed the leases
- Windows Update completed; snapshot "Clean install" taken
- Next: Day 2 - install Sysmon with a community config, enable PowerShell and command-line logging

## 2026-11-04 (Day 2) - Sysmon and Windows logging
- Installed Sysmon 15.22 with the sysmon-modular default config (release configs-a45dedb13a43), SHA256 verified against the published SHA256SUMS
- Challenge: sysmon-modular no longer keeps a prebuilt sysmonconfig.xml in the repo (raw link returned 404); found it in the GitHub release assets via the API
- Confirmed the config logs LSASS process access (Event 10) tagged T1003, needed for credential-dumping detection
- Enabled PowerShell Script Block Logging (4104), command line in process creation (4688), and auditing for Process Creation and User Account Management (4720)
- Verified Sysmon events 3, 13, 22 plus 4104 and 4688 with command lines
- Snapshot "Sysmon + logging" taken
- Next: Day 3 - install Splunk Enterprise on the host, create index, enable receiving on 9997

## 2026-11-05 (Day 3) - Splunk Enterprise (SIEM)
- Installed Splunk Enterprise 10.6.1.1 on the host; created index "sysmon"; enabled receiving on TCP 9997
- Host firewall rule allows 9997 only from the host-only subnet 192.168.38.0/24; VM reachability verified (TcpTestSucceeded from 192.168.38.128)
- Installed Splunk Add-on for Sysmon 5.0.1 and Splunk Add-on for Microsoft Windows 12.0.0 via the Splunk CLI (in-app browser returned errors)
- Saved receiver configs to configs/splunk/indexer/; report updated to v0.3
- Next: Day 4 - install the Universal Forwarder in the VM, configure inputs, verify events in Splunk

## 2026-11-06 (Day 4) - Universal Forwarder, end-to-end pipeline
- Installed Splunk Universal Forwarder 10.6.1.1 in the VM (build matches receiver); outputs to 192.168.38.1:9997
- inputs.conf collects Sysmon (renderXml), Security, and PowerShell Operational into index=sysmon
- Challenge: Sysmon missing in Splunk; splunkd.log showed errorCode=5 (access denied) for NT SERVICE\SplunkForwarder; granted read-only access to the Sysmon channel via SDDL instead of running as LocalSystem
- Verified all three sources in Splunk: 20,495 events, 42 event codes (baseline recorded in report)
- VM time zone changed from Pacific to Eastern; snapshot "Logging ready" taken
- Saved forwarder configs to configs/splunk/forwarder/; report updated to v0.4 (Phase 1 complete)
- Next: Phase 2 - install Atomic Red Team, run techniques, write detections

## 2026-11-06 (Phase 2 start) - Atomic Red Team installed
- Defender exclusion added for C:\AtomicRedTeam only (VM); real-time protection otherwise left on
- Confirmed invoke-atomicredteam default branch via GitHub API; downloaded the installer, reviewed it, then ran Install-AtomicRedTeam -getAtomics
- Verified with Invoke-AtomicTest T1059.001 -ShowDetailsBrief (21 tests listed)
- Snapshot "ART installed" taken
- Next: choose one test per technique, check prerequisites, disconnect NAT, run first test and detect it in Splunk

## 2026-11-06 (Phase 2, session 1) - First technique: T1059.001
- Defender blocked the AtomicTestHarnesses module (needed by test -15); restored "ART installed" instead of widening exclusions; chose test -17
- Isolated the VM (NAT disconnected, verified: internet False, Splunk True)
- Ran T1059.001-17 (powershell.exe -e <Base64>); found it in Sysmon 1 (cmd.exe -> powershell.exe) and 4104 (decoded payload, empty Path)
- Plan's detection CommandLine="*-enc*" returned 0 results (misses -e); improved where match() detection: 1 TP, 0 FP over all data
- Found VM clock 3h fast after the time zone change; enabled VMware Tools time sync; retook snapshot "Pre-attack v2 (isolated, clock synced)"
- Saved alert "T1059.001 - PowerShell Encoded Command" (fixed: it had saved the wrong search)
- Report updated to v0.5; detection saved to detections/spl/
- Next: T1003.001 LSASS dump via comsvcs.dll

## 2026-11-07 (Phase 2, session 2) - T1003.001 LSASS dumping
- Ran T1003.001-2 (comsvcs.dll MiniDump); Defender blocked it (Trojan:Win32/RundllLolBin.AF, Severe)
- Sysmon missed attempt 1; Security 4688 caught it; detection: comsvcs + MiniDump in cmd line (1 TP, 0 FP)
- Alert saved: "T1003.001 - LSASS Dump via comsvcs.dll" (Critical, hourly)
- Option A: added Defender/Operational to forwarder inputs; alert "Defender - Threat Detected" (1116) saved
- Option B: turned off real-time protection (Defender logged Event 5001); rundll32 ran but LSA protection (RunAsPPL=2) stopped the dump; detection caught attempt 2 as well
- Disk ran full (2.65 GB); deleted ISO and old snapshots; now ~35 GB free; Splunk recovered
- Detection files added: T1003.001_lsass_dump_comsvcs.spl, Defender_threat_detected.spl
- Next: Event 5001 detection (T1562.001), then T1053.005, T1547.001, T1136.001, T1087.001

## 2026-11-09 (Phase 2, session 3) - Techniques 3-6 complete
- T1053.005: schtasks /create; detection saved (1 TP, 0 FP)
- T1547.001: reg.exe writing to CurrentVersion\Run; tuned filter for Edge and SYSTEM; detection saved (1 TP, 0 FP)
- T1136.001: net user /add; Security Event 4720; detection saved (1 TP, 0 FP)
- T1087.001: net user/localgroup enumeration; 10 events, excluded SYSTEM account; detection saved (0 FP)
- Phase 2 complete: all 6 techniques executed, investigated, and detected; 7 alerts saved in Splunk
- Next: Phase 3 - Python + Gemini triage assistant

## 2026-11-15 (Phase 3) - AI-assisted triage assistant
- Built Python + Gemini triage script (triage/triage.py); pulls events from Splunk REST API for all 7 detections
- Model selection: went through gemini-2.0-flash, gemini-2.0-flash-lite before landing on gemini-3.5-flash-lite
- Results: 3/7 correct, 2/7 partial, 2/7 wrong, 0 hallucinated
- Root cause of failures: 10-event samples with noise diluted attack rows; Gemini analyzed visible events accurately but focused on majority (benign) activity
- Key finding: alert quality determines triage quality; 1-event clean alerts got best results
- Human review step confirmed: nothing actioned without analyst approval
- Evaluation notes documented in triage/evaluation_notes.md
- Next: Phase 4 - Sigma rules (Detection-as-Code) and polish
