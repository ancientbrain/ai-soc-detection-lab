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
