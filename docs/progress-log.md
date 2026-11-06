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
