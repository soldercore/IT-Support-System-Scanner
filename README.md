# Sagene Data IT Support System Scanner

Read-only system scanner for quick first-line troubleshooting of Windows PCs.

The tool collects relevant support information, shows a clear health summary, and can export reports for documentation or escalation.

It is designed for IKT support, helpdesk, field support, troubleshooting, and basic device health checks.

---

## What it checks on Windows

- System information: hostname, user, domain, OS, build, uptime
- Hardware: CPU, RAM, GPU, BIOS, motherboard
- Disk: free space, usage percentage, physical disk health
- Network: adapters, IPv4, DNS, gateway
- Security: Microsoft Defender, antivirus registration, Firewall, BitLocker
- Windows Update: latest installed hotfixes
- Pending reboot status
- Device Manager problems
- Important Windows services
- Local administrators
- Battery status on laptops
- Recent critical/error events from System and Application logs

---

## Key features

- Read-only: does not change system settings
- GUI with terminal-style layout
- Health status and health score
- Actionable findings with recommended next steps
- Export to TXT, HTML, and JSON
- Anonymized export option
- CLI mode for scripted usage
- Works best when run as Administrator

---

## Quick run

Run this in PowerShell:

```powershell
irm https://raw.githubusercontent.com/soldercore/IT-Support-System-Scanner/main/main.ps1 | iex
Recommended run

For a more transparent workflow, download the script first and then run it:

irm https://raw.githubusercontent.com/soldercore/IT-Support-System-Scanner/main/main.ps1 -OutFile .\SageneData-SystemScanner.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File .\SageneData-SystemScanner.ps1

Best result: open PowerShell as Administrator.

CLI export mode

Export reports without opening the GUI:

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SageneData-SystemScanner.ps1 -NoGui -ExportDirectory .\reports -Formats TXT,HTML,JSON

Export anonymized reports:

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SageneData-SystemScanner.ps1 -NoGui -ExportDirectory .\reports -Formats TXT,HTML,JSON -Anonymized

Run self-test:

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SageneData-SystemScanner.ps1 -SelfTest -NoGui
Report formats

The scanner can export:

TXT: simple support report
HTML: presentable dashboard-style report
JSON: structured data for further processing
Anonymized TXT/HTML/JSON: removes or masks sensitive values such as hostname, username, domain, IP, MAC, SID, and GUID values
Safety

This scanner is read-only.

It does not:

change registry values
start or stop services
change Defender settings
change Firewall settings
change BitLocker settings
install software
send data externally

The only network call happens when you download the script from GitHub.

Requirements
Windows 10 or Windows 11
Windows PowerShell 5.1 or newer
Administrator rights recommended for complete results

Some checks may return UNKNOWN if the script is not run as Administrator or if required Windows modules are unavailable.
