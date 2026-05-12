#requires -Version 5.1
<#
.SYNOPSIS
    Sagene Data IT Support System Scanner

.DESCRIPTION
    Read-only Windows support scanner for IT consultants.
    Supports GUI mode, CLI mode, TXT/HTML/JSON export, anonymized export, health scoring,
    self-test, and structured support findings.

.EXAMPLES
    powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File .\SageneData-SystemScanner.ps1

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SageneData-SystemScanner.ps1 -NoGui -ExportDirectory .\reports -Formats TXT,HTML,JSON -Anonymized

.NOTES
    - Read-only
    - No external network calls
    - No system changes
    - Best results when run as Administrator
#>

[CmdletBinding()]
param(
    [switch]$NoGui,

    [string]$ExportDirectory,

    [ValidateSet("TXT", "HTML", "JSON")]
    [string[]]$Formats = @("TXT"),

    [switch]$Anonymized,

    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSEdition -eq "Core" -and -not $IsWindows) {
    throw "This scanner is Windows-only."
}

$Script:UseGui = -not $NoGui

if ($Script:UseGui -and [System.Threading.Thread]::CurrentThread.GetApartmentState() -ne "STA" -and $PSCommandPath) {
    $exe = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-STA",
        "-File", "`"$PSCommandPath`""
    )

    if ($Anonymized) { $arguments += "-Anonymized" }
    if ($SelfTest) { $arguments += "-SelfTest" }

    Start-Process -FilePath $exe -ArgumentList $arguments
    exit
}

if ($Script:UseGui) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
}

# ============================================================
# CONFIG
# ============================================================

$Script:ScannerConfig = [ordered]@{
    ProductName          = "Sagene Data IT Support System Scanner"
    Vendor               = "Sagene Data"
    Version              = "4.0.0"
    EventLookbackDays    = 3
    MaxEvents            = 20
    DiskWarningPercent   = 20
    DiskCriticalPercent  = 10
    UptimeWarningHours   = 168
    UpdateWarningDays    = 45
    OutputBaseName       = "SageneData-SystemReport"
    ImportantServices    = @(
        @{ Name = "EventLog"; Critical = $true;  Label = "Windows Event Log" },
        @{ Name = "Winmgmt"; Critical = $true;  Label = "Windows Management Instrumentation" },
        @{ Name = "Dhcp"; Critical = $true;  Label = "DHCP Client" },
        @{ Name = "Dnscache"; Critical = $true;  Label = "DNS Client" },
        @{ Name = "LanmanWorkstation"; Critical = $true; Label = "Workstation" },
        @{ Name = "W32Time"; Critical = $false; Label = "Windows Time" },
        @{ Name = "wuauserv"; Critical = $false; Label = "Windows Update" },
        @{ Name = "BITS"; Critical = $false; Label = "Background Intelligent Transfer Service" },
        @{ Name = "WinDefend"; Critical = $false; Label = "Microsoft Defender Antivirus Service" }
    )
}

# ============================================================
# CORE MODELS
# ============================================================

function New-Check {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet("OK", "INFO", "WARNING", "CRITICAL", "UNKNOWN")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Details,

        [string]$Recommendation = "",

        [string]$Category = "General"
    )

    [PSCustomObject]@{
        Category       = $Category
        Name           = $Name
        Status         = $Status
        Details        = $Details
        Recommendation = $Recommendation
    }
}

function Add-Check {
    param(
        [System.Collections.Generic.List[object]]$Checks,

        [Parameter(Mandatory)]
        [object]$Check
    )

    if ($null -eq $Checks) {
        throw "Checks list is null."
    }

    [void]$Checks.Add($Check)
}

function Invoke-SafeSection {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [System.Collections.Generic.List[object]]$Checks,

        [Parameter(Mandatory)]
        [scriptblock]$Script
    )

    if ($null -eq $Checks) {
        throw "Checks list is null."
    }

    try {
        & $Script
    }
    catch {
        Add-Check -Checks $Checks -Check (New-Check `
            -Category "Scanner" `
            -Name $Name `
            -Status "UNKNOWN" `
            -Details "Could not collect data: $($_.Exception.Message)" `
            -Recommendation "Run as Administrator and verify that required Windows modules are available.")

        [PSCustomObject]@{
            Error   = $true
            Section = $Name
            Message = $_.Exception.Message
        }
    }
}

# ============================================================
# UTILITY
# ============================================================

function Get-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-StatusRank {
    param([string]$Status)

    switch ($Status) {
        "CRITICAL" { 5 }
        "WARNING"  { 4 }
        "UNKNOWN"  { 3 }
        "INFO"     { 2 }
        "OK"       { 1 }
        default    { 0 }
    }
}

function Get-OverallStatus {
    param([object[]]$Checks)

    if (@($Checks | Where-Object { $_.Status -eq "CRITICAL" }).Count -gt 0) { return "CRITICAL" }
    if (@($Checks | Where-Object { $_.Status -eq "WARNING" }).Count -gt 0)  { return "WARNING" }
    if (@($Checks | Where-Object { $_.Status -eq "UNKNOWN" }).Count -gt 0)  { return "UNKNOWN" }
    return "OK"
}

function Get-HealthScore {
    param([object[]]$Checks)

    if ($Checks.Count -eq 0) { return 0 }

    $score = 100
    $score -= (@($Checks | Where-Object Status -eq "CRITICAL").Count * 25)
    $score -= (@($Checks | Where-Object Status -eq "WARNING").Count * 10)
    $score -= (@($Checks | Where-Object Status -eq "UNKNOWN").Count * 4)

    if ($score -lt 0) { return 0 }
    return $score
}

function Get-StatusPrefix {
    param([string]$Status)

    switch ($Status) {
        "OK"       { "[OK]" }
        "INFO"     { "[INFO]" }
        "WARNING"  { "[WARN]" }
        "CRITICAL" { "[CRIT]" }
        "UNKNOWN"  { "[UNKNOWN]" }
        default    { "[?]" }
    }
}

function ConvertTo-SafeText {
    param([object]$Value)

    if ($null -eq $Value) { return "" }

    $text = [string]$Value
    $text = $text -replace "`r|`n", " "
    $text = $text.Trim()

    if ($text.Length -gt 260) {
        return $text.Substring(0, 260) + "..."
    }

    return $text
}

function Protect-ReportText {
    param(
        [Parameter(Mandatory)]
        [string]$Text,

        [Parameter(Mandatory)]
        [object]$Report
    )

    $result = $Text

    $sensitiveValues = @(
        $Report.Meta.ComputerName,
        $Report.Meta.UserName,
        $Report.Meta.UserDomain,
        $Report.Meta.Domain
    ) | Where-Object { $null -ne $_ -and [string]$_ -ne "" } | Select-Object -Unique

    foreach ($value in $sensitiveValues) {
        $escaped = [regex]::Escape([string]$value)
        $result = $result -replace $escaped, "[ANONYMIZED]"
    }

    $result = $result -replace '\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP-ANONYMIZED]'
    $result = $result -replace '\b([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}\b', '[MAC-ANONYMIZED]'
    $result = $result -replace '\bS-\d-\d+-(\d+-){1,14}\d+\b', '[SID-ANONYMIZED]'
    $result = $result -replace '\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b', '[GUID-ANONYMIZED]'

    return $result
}

function Get-SageneDataAsciiLogo {
@"
   _____                              ____        __
  / ___/____ _____ ____  ____  ___   / __ \____ _/ /_____ _
  \__ \/ __ `/ __ `/ _ \/ __ \/ _ \ / / / / __ `/ __/ __ `/
 ___/ / /_/ / /_/ /  __/ / / /  __// /_/ / /_/ / /_/ /_/ /
/____/\__,_/\__, /\___/_/ /_/\___//_____/\__,_/\__/\__,_/
           /____/

        SAGENE DATA
        IT SUPPORT SYSTEM SCANNER
"@
}

function Get-PendingRebootEvidence {
    $evidence = [System.Collections.Generic.List[string]]::new()

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) { [void]$evidence.Add($path) }
    }

    $sessionManager = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $pendingRename = Get-ItemProperty -Path $sessionManager -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($pendingRename -and $pendingRename.PendingFileRenameOperations) {
        [void]$evidence.Add("$sessionManager\PendingFileRenameOperations")
    }

    $computerNamePath = "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName"
    $activeName = Get-ItemProperty -Path "$computerNamePath\ActiveComputerName" -ErrorAction SilentlyContinue
    $pendingName = Get-ItemProperty -Path "$computerNamePath\ComputerName" -ErrorAction SilentlyContinue

    if ($activeName -and $pendingName -and $activeName.ComputerName -ne $pendingName.ComputerName) {
        [void]$evidence.Add("Pending computer rename")
    }

    return $evidence
}

function Get-OutputPath {
    param(
        [Parameter(Mandatory)]
        [string]$Directory,

        [Parameter(Mandatory)]
        [string]$Format,

        [switch]$Anonymized
    )

    $suffix = if ($Anonymized) { "-Anonymized" } else { "" }
    $extension = switch ($Format) {
        "TXT"  { "txt" }
        "HTML" { "html" }
        "JSON" { "json" }
    }

    Join-Path $Directory "$($Script:ScannerConfig.OutputBaseName)$suffix.$extension"
}

# ============================================================
# COLLECTOR
# ============================================================

function Get-SystemScannerReport {
    $checks = [System.Collections.Generic.List[object]]::new()
    $sections = [ordered]@{}

    $isAdmin = Get-IsAdministrator

    $meta = [ordered]@{
        ProductName       = $Script:ScannerConfig.ProductName
        Vendor            = $Script:ScannerConfig.Vendor
        Version           = $Script:ScannerConfig.Version
        GeneratedAt       = Get-Date
        ReportId          = [guid]::NewGuid().ToString()
        ComputerName      = $env:COMPUTERNAME
        UserName          = $env:USERNAME
        UserDomain        = $env:USERDOMAIN
        Domain            = ""
        IsAdministrator   = $isAdmin
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition = $PSVersionTable.PSEdition
        ProcessBitness    = if ([Environment]::Is64BitProcess) { "64-bit" } else { "32-bit" }
    }

    if ($isAdmin) {
        Add-Check $checks (New-Check -Category "Privilege" -Name "Administrator rights" -Status "OK" -Details "Scanner is running with Administrator rights.")
    }
    else {
        Add-Check $checks (New-Check -Category "Privilege" -Name "Administrator rights" -Status "WARNING" -Details "Scanner is not running with Administrator rights." -Recommendation "Run as Administrator for complete BitLocker, device, security and event data.")
    }

    $sections["System"] = Invoke-SafeSection -Name "System" -Checks $checks -Script {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $bios = Get-CimInstance Win32_BIOS
        $board = Get-CimInstance Win32_BaseBoard

        $meta.Domain = $cs.Domain

        $uptime = New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)
        $uptimeHours = [math]::Round($uptime.TotalHours, 1)
        $ramGb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)

        if ($uptimeHours -gt $Script:ScannerConfig.UptimeWarningHours) {
            Add-Check $checks (New-Check -Category "System" -Name "Uptime" -Status "WARNING" -Details "$uptimeHours hours since last boot." -Recommendation "Restart before deeper troubleshooting, especially for update, driver or performance issues.")
        }
        else {
            Add-Check $checks (New-Check -Category "System" -Name "Uptime" -Status "OK" -Details "$uptimeHours hours since last boot.")
        }

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            UserName     = $env:USERNAME
            Domain       = $cs.Domain
            Manufacturer = $cs.Manufacturer
            Model        = $cs.Model
            ChassisType  = $cs.PCSystemTypeEx
            OS           = $os.Caption
            OSVersion    = $os.Version
            BuildNumber  = $os.BuildNumber
            Architecture = $os.OSArchitecture
            InstallDate  = $os.InstallDate
            LastBoot     = $os.LastBootUpTime
            UptimeHours  = $uptimeHours
            CPU          = $cpu.Name
            CPUCores     = $cpu.NumberOfCores
            CPULogical   = $cpu.NumberOfLogicalProcessors
            RAMGB        = $ramGb
            BIOSVersion  = $bios.SMBIOSBIOSVersion
            BIOSSerial   = $bios.SerialNumber
            Motherboard  = "$($board.Manufacturer) $($board.Product)"
        }
    }

    $sections["Pending Reboot"] = Invoke-SafeSection -Name "Pending Reboot" -Checks $checks -Script {
        $evidence = Get-PendingRebootEvidence

        if ($evidence.Count -gt 0) {
            Add-Check $checks (New-Check -Category "System" -Name "Pending reboot" -Status "WARNING" -Details "Windows has pending reboot evidence." -Recommendation "Restart machine before continuing troubleshooting.")
            [PSCustomObject]@{ PendingReboot = $true; Evidence = ($evidence -join "; ") }
        }
        else {
            Add-Check $checks (New-Check -Category "System" -Name "Pending reboot" -Status "OK" -Details "No pending reboot evidence found.")
            [PSCustomObject]@{ PendingReboot = $false; Evidence = "None" }
        }
    }

    $sections["Graphics"] = Invoke-SafeSection -Name "Graphics" -Checks $checks -Script {
        Get-CimInstance Win32_VideoController | ForEach-Object {
            $memory = if ($_.AdapterRAM) { [math]::Round($_.AdapterRAM / 1GB, 2) } else { $null }

            [PSCustomObject]@{
                Name          = $_.Name
                DriverVersion = $_.DriverVersion
                AdapterRAMGB  = if ($memory) { $memory } else { "Unknown" }
                Status        = $_.Status
                Resolution    = if ($_.CurrentHorizontalResolution -and $_.CurrentVerticalResolution) {
                    "$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution)"
                } else {
                    "Unknown"
                }
            }
        }
    }

    $sections["Logical Disks"] = Invoke-SafeSection -Name "Logical Disks" -Checks $checks -Script {
        Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
            Sort-Object DeviceID |
            ForEach-Object {
                $freeGb = [math]::Round($_.FreeSpace / 1GB, 1)
                $totalGb = [math]::Round($_.Size / 1GB, 1)
                $freePercent = if ($_.Size -gt 0) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 0) } else { 0 }

                if ($freePercent -lt $Script:ScannerConfig.DiskCriticalPercent) {
                    Add-Check $checks (New-Check -Category "Disk" -Name "Disk space $($_.DeviceID)" -Status "CRITICAL" -Details "$freePercent% free on $($_.DeviceID)." -Recommendation "Free disk space immediately. Low disk space can break updates, profiles, apps and logging.")
                }
                elseif ($freePercent -lt $Script:ScannerConfig.DiskWarningPercent) {
                    Add-Check $checks (New-Check -Category "Disk" -Name "Disk space $($_.DeviceID)" -Status "WARNING" -Details "$freePercent% free on $($_.DeviceID)." -Recommendation "Clean up disk space soon.")
                }
                else {
                    Add-Check $checks (New-Check -Category "Disk" -Name "Disk space $($_.DeviceID)" -Status "OK" -Details "$freePercent% free on $($_.DeviceID).")
                }

                [PSCustomObject]@{
                    Drive       = $_.DeviceID
                    Label       = $_.VolumeName
                    FileSystem  = $_.FileSystem
                    FreeGB      = $freeGb
                    TotalGB     = $totalGb
                    FreePercent = "$freePercent%"
                }
            }
    }

    $sections["Physical Disk Health"] = Invoke-SafeSection -Name "Physical Disk Health" -Checks $checks -Script {
        if (-not (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
            Add-Check $checks (New-Check -Category "Disk" -Name "Physical disk health" -Status "UNKNOWN" -Details "Get-PhysicalDisk is not available.")
            return "Get-PhysicalDisk is not available."
        }

        $physicalDisks = @(Get-PhysicalDisk)

        if ($physicalDisks.Count -eq 0) {
            Add-Check $checks (New-Check -Category "Disk" -Name "Physical disk health" -Status "UNKNOWN" -Details "No physical disk data returned.")
        }

        foreach ($disk in $physicalDisks) {
            if ([string]$disk.HealthStatus -ne "Healthy") {
                Add-Check $checks (New-Check -Category "Disk" -Name "Physical disk health" -Status "CRITICAL" -Details "$($disk.FriendlyName): $($disk.HealthStatus)." -Recommendation "Take backup and investigate disk health immediately.")
            }
            else {
                Add-Check $checks (New-Check -Category "Disk" -Name "Physical disk health" -Status "OK" -Details "$($disk.FriendlyName): Healthy.")
            }
        }

        $physicalDisks | ForEach-Object {
            [PSCustomObject]@{
                FriendlyName      = $_.FriendlyName
                MediaType         = $_.MediaType
                HealthStatus      = $_.HealthStatus
                OperationalStatus = ($_.OperationalStatus -join ", ")
                SizeGB            = [math]::Round($_.Size / 1GB, 1)
            }
        }
    }

    $sections["Network"] = Invoke-SafeSection -Name "Network" -Checks $checks -Script {
        if (-not (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {
            Add-Check $checks (New-Check -Category "Network" -Name "Network configuration" -Status "UNKNOWN" -Details "Get-NetIPConfiguration is not available.")
            return "Get-NetIPConfiguration is not available."
        }

        $configs = @(Get-NetIPConfiguration | Where-Object { $_.IPv4Address })

        if ($configs.Count -eq 0) {
            Add-Check $checks (New-Check -Category "Network" -Name "IPv4 configuration" -Status "WARNING" -Details "No active IPv4 configuration found." -Recommendation "Check adapter, DHCP and network connection.")
        }
        else {
            Add-Check $checks (New-Check -Category "Network" -Name "IPv4 configuration" -Status "OK" -Details "$($configs.Count) active IPv4 adapter(s) found.")
        }

        $configs | ForEach-Object {
            $gateway = ($_.IPv4DefaultGateway.NextHop -join ", ")
            $dns = ($_.DNSServer.ServerAddresses -join ", ")

            if (-not $gateway) {
                Add-Check $checks (New-Check -Category "Network" -Name "Gateway $($_.InterfaceAlias)" -Status "WARNING" -Details "No IPv4 default gateway found on $($_.InterfaceAlias)." -Recommendation "Verify DHCP/static IP configuration.")
            }

            if (-not $dns) {
                Add-Check $checks (New-Check -Category "Network" -Name "DNS $($_.InterfaceAlias)" -Status "WARNING" -Details "No DNS server found on $($_.InterfaceAlias)." -Recommendation "Verify DNS configuration.")
            }

            [PSCustomObject]@{
                Interface = $_.InterfaceAlias
                IPv4      = ($_.IPv4Address.IPAddress -join ", ")
                Prefix    = ($_.IPv4Address.PrefixLength -join ", ")
                Gateway   = $gateway
                DNS       = $dns
            }
        }
    }

    $sections["Network Adapters"] = Invoke-SafeSection -Name "Network Adapters" -Checks $checks -Script {
        if (-not (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue)) {
            return "Get-NetAdapter is not available."
        }

        Get-NetAdapter | Sort-Object Name | ForEach-Object {
            [PSCustomObject]@{
                Name       = $_.Name
                Status     = $_.Status
                LinkSpeed  = $_.LinkSpeed
                MacAddress = $_.MacAddress
                Driver     = $_.DriverInformation
            }
        }
    }

    $sections["Defender"] = Invoke-SafeSection -Name "Defender" -Checks $checks -Script {
        if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
            Add-Check $checks (New-Check -Category "Security" -Name "Microsoft Defender" -Status "UNKNOWN" -Details "Defender module is not available." -Recommendation "Verify antivirus/EDR from Security Center or management tool.")
            return "Defender module not available."
        }

        $mp = Get-MpComputerStatus

        if ($mp.RealTimeProtectionEnabled) {
            Add-Check $checks (New-Check -Category "Security" -Name "Defender realtime protection" -Status "OK" -Details "Real-time protection is enabled.")
        }
        else {
            Add-Check $checks (New-Check -Category "Security" -Name "Defender realtime protection" -Status "CRITICAL" -Details "Real-time protection is disabled." -Recommendation "Enable Defender or verify active third-party EDR/AV.")
        }

        if ($mp.AntivirusSignatureLastUpdated) {
            $sigAge = (New-TimeSpan -Start $mp.AntivirusSignatureLastUpdated -End (Get-Date)).TotalDays
            if ($sigAge -gt 7) {
                Add-Check $checks (New-Check -Category "Security" -Name "Defender signatures" -Status "WARNING" -Details "Signatures are older than 7 days." -Recommendation "Update Defender signatures.")
            }
            else {
                Add-Check $checks (New-Check -Category "Security" -Name "Defender signatures" -Status "OK" -Details "Signatures are recently updated.")
            }
        }

        [PSCustomObject]@{
            AMServiceEnabled           = $mp.AMServiceEnabled
            AntivirusEnabled          = $mp.AntivirusEnabled
            RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
            BehaviorMonitorEnabled    = $mp.BehaviorMonitorEnabled
            IoavProtectionEnabled     = $mp.IoavProtectionEnabled
            NISEnabled                = $mp.NISEnabled
            SignatureUpdated          = $mp.AntivirusSignatureLastUpdated
            QuickScanAge              = $mp.QuickScanAge
            FullScanAge               = $mp.FullScanAge
        }
    }

    $sections["Security Center Antivirus"] = Invoke-SafeSection -Name "Security Center Antivirus" -Checks $checks -Script {
        $products = @(Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop)

        if ($products.Count -eq 0) {
            Add-Check $checks (New-Check -Category "Security" -Name "Antivirus product" -Status "WARNING" -Details "No antivirus product found in Security Center." -Recommendation "Verify AV/EDR status.")
        }
        else {
            Add-Check $checks (New-Check -Category "Security" -Name "Antivirus product" -Status "OK" -Details "$($products.Count) antivirus product(s) found in Security Center.")
        }

        $products | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = $_.displayName
                Path        = $_.pathToSignedProductExe
                State       = $_.productState
            }
        }
    }

    $sections["Firewall"] = Invoke-SafeSection -Name "Firewall" -Checks $checks -Script {
        if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
            Add-Check $checks (New-Check -Category "Security" -Name "Windows Firewall" -Status "UNKNOWN" -Details "Firewall cmdlets are not available.")
            return "Firewall cmdlets are not available."
        }

        Get-NetFirewallProfile | Sort-Object Name | ForEach-Object {
            if ($_.Enabled) {
                Add-Check $checks (New-Check -Category "Security" -Name "Firewall $($_.Name)" -Status "OK" -Details "$($_.Name) profile is enabled.")
            }
            else {
                Add-Check $checks (New-Check -Category "Security" -Name "Firewall $($_.Name)" -Status "WARNING" -Details "$($_.Name) profile is disabled." -Recommendation "Verify this is intended by policy.")
            }

            [PSCustomObject]@{
                Profile               = $_.Name
                Enabled               = $_.Enabled
                DefaultInboundAction  = $_.DefaultInboundAction
                DefaultOutboundAction = $_.DefaultOutboundAction
            }
        }
    }

    $sections["BitLocker"] = Invoke-SafeSection -Name "BitLocker" -Checks $checks -Script {
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
            Add-Check $checks (New-Check -Category "Security" -Name "BitLocker" -Status "UNKNOWN" -Details "BitLocker cmdlet is not available.")
            return "BitLocker cmdlet is not available."
        }

        $volumes = @(Get-BitLockerVolume)

        foreach ($volume in $volumes) {
            $isOs = $volume.VolumeType -eq "OperatingSystem"

            if ($isOs -and $volume.ProtectionStatus -ne "On") {
                Add-Check $checks (New-Check -Category "Security" -Name "BitLocker OS volume" -Status "WARNING" -Details "BitLocker protection is not enabled on OS volume $($volume.MountPoint)." -Recommendation "Enable BitLocker if the machine handles work data.")
            }
            elseif ($isOs) {
                Add-Check $checks (New-Check -Category "Security" -Name "BitLocker OS volume" -Status "OK" -Details "BitLocker protection is enabled on OS volume $($volume.MountPoint).")
            }
        }

        $volumes | ForEach-Object {
            [PSCustomObject]@{
                MountPoint       = $_.MountPoint
                VolumeType       = $_.VolumeType
                ProtectionStatus = $_.ProtectionStatus
                VolumeStatus     = $_.VolumeStatus
                EncryptionMethod = $_.EncryptionMethod
                LockStatus       = $_.LockStatus
            }
        }
    }

    $sections["Windows Updates"] = Invoke-SafeSection -Name "Windows Updates" -Checks $checks -Script {
        $hotfixes = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10)
        $latest = $hotfixes | Select-Object -First 1

        if ($latest -and $latest.InstalledOn) {
            $days = (New-TimeSpan -Start $latest.InstalledOn -End (Get-Date)).TotalDays

            if ($days -gt $Script:ScannerConfig.UpdateWarningDays) {
                Add-Check $checks (New-Check -Category "Updates" -Name "Latest installed update" -Status "WARNING" -Details "Latest hotfix appears older than $($Script:ScannerConfig.UpdateWarningDays) days: $($latest.HotFixID), $($latest.InstalledOn)." -Recommendation "Check Windows Update or management platform.")
            }
            else {
                Add-Check $checks (New-Check -Category "Updates" -Name "Latest installed update" -Status "OK" -Details "Recent hotfix found: $($latest.HotFixID), $($latest.InstalledOn).")
            }
        }
        else {
            Add-Check $checks (New-Check -Category "Updates" -Name "Latest installed update" -Status "UNKNOWN" -Details "Could not determine latest hotfix.")
        }

        $hotfixes | ForEach-Object {
            [PSCustomObject]@{
                HotFixID    = $_.HotFixID
                Description = $_.Description
                InstalledOn = $_.InstalledOn
                InstalledBy = $_.InstalledBy
            }
        }
    }

    $sections["Devices With Problems"] = Invoke-SafeSection -Name "Devices With Problems" -Checks $checks -Script {
        if (-not (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue)) {
            Add-Check $checks (New-Check -Category "Devices" -Name "PnP devices" -Status "UNKNOWN" -Details "Get-PnpDevice is not available.")
            return "Get-PnpDevice is not available."
        }

        $badDevices = @(Get-PnpDevice | Where-Object { $_.Status -ne "OK" })

        if ($badDevices.Count -gt 0) {
            Add-Check $checks (New-Check -Category "Devices" -Name "Device errors" -Status "WARNING" -Details "$($badDevices.Count) device(s) have non-OK status." -Recommendation "Check Device Manager and driver status.")
            $badDevices | Select-Object FriendlyName, Class, Status, InstanceId
        }
        else {
            Add-Check $checks (New-Check -Category "Devices" -Name "Device errors" -Status "OK" -Details "No device errors found.")
            "No device errors found."
        }
    }

    $sections["Important Services"] = Invoke-SafeSection -Name "Important Services" -Checks $checks -Script {
        foreach ($entry in $Script:ScannerConfig.ImportantServices) {
            $svc = Get-Service -Name $entry.Name -ErrorAction SilentlyContinue

            if (-not $svc) {
                Add-Check $checks (New-Check -Category "Services" -Name "Service $($entry.Name)" -Status "UNKNOWN" -Details "Service not found.")
                [PSCustomObject]@{ Name = $entry.Name; DisplayName = $entry.Label; Status = "Unknown"; StartType = "Unknown" }
                continue
            }

            if ($entry.Critical -and $svc.Status -ne "Running") {
                Add-Check $checks (New-Check -Category "Services" -Name "Service $($svc.Name)" -Status "WARNING" -Details "$($svc.DisplayName) is not running." -Recommendation "Investigate service state.")
            }

            [PSCustomObject]@{
                Name        = $svc.Name
                DisplayName = $svc.DisplayName
                Status      = $svc.Status
                StartType   = $svc.StartType
            }
        }
    }

    $sections["Local Administrators"] = Invoke-SafeSection -Name "Local Administrators" -Checks $checks -Script {
        if (-not (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) {
            Add-Check $checks (New-Check -Category "Security" -Name "Local administrators" -Status "UNKNOWN" -Details "Get-LocalGroupMember is not available.")
            return "Get-LocalGroupMember is not available."
        }

        $members = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop)

        if ($members.Count -gt 5) {
            Add-Check $checks (New-Check -Category "Security" -Name "Local administrators" -Status "WARNING" -Details "$($members.Count) local administrator member(s) found." -Recommendation "Review local administrator membership.")
        }
        else {
            Add-Check $checks (New-Check -Category "Security" -Name "Local administrators" -Status "INFO" -Details "$($members.Count) local administrator member(s) found.")
        }

        $members | Select-Object Name, ObjectClass, PrincipalSource
    }

    $sections["Battery"] = Invoke-SafeSection -Name "Battery" -Checks $checks -Script {
        $battery = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)

        if ($battery.Count -eq 0) {
            "No battery found. Normal for desktop PCs."
        }
        else {
            $battery | ForEach-Object {
                if ($_.EstimatedChargeRemaining -lt 15) {
                    Add-Check $checks (New-Check -Category "Battery" -Name "Battery charge" -Status "WARNING" -Details "Battery charge is $($_.EstimatedChargeRemaining)%." -Recommendation "Connect charger.")
                }

                [PSCustomObject]@{
                    Name                     = $_.Name
                    StatusCode               = $_.BatteryStatus
                    EstimatedChargeRemaining = "$($_.EstimatedChargeRemaining)%"
                    EstimatedRunTime         = $_.EstimatedRunTime
                }
            }
        }
    }

    $sections["Recent System Events"] = Invoke-SafeSection -Name "Recent System Events" -Checks $checks -Script {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName   = "System"
            Level     = 1, 2
            StartTime = (Get-Date).AddDays(-1 * $Script:ScannerConfig.EventLookbackDays)
        } -MaxEvents $Script:ScannerConfig.MaxEvents -ErrorAction Stop)

        if ($events.Count -gt 0) {
            Add-Check $checks (New-Check -Category "Events" -Name "System event errors" -Status "WARNING" -Details "$($events.Count) critical/error system event(s) found in the last $($Script:ScannerConfig.EventLookbackDays) day(s)." -Recommendation "Review event source, event ID and recurring patterns.")
        }
        else {
            Add-Check $checks (New-Check -Category "Events" -Name "System event errors" -Status "OK" -Details "No critical/error system events found in lookback window.")
        }

        $events | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message
    }

    $sections["Recent Application Events"] = Invoke-SafeSection -Name "Recent Application Events" -Checks $checks -Script {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName   = "Application"
            Level     = 1, 2
            StartTime = (Get-Date).AddDays(-1 * $Script:ScannerConfig.EventLookbackDays)
        } -MaxEvents $Script:ScannerConfig.MaxEvents -ErrorAction Stop)

        if ($events.Count -gt 0) {
            Add-Check $checks (New-Check -Category "Events" -Name "Application event errors" -Status "INFO" -Details "$($events.Count) critical/error application event(s) found in the last $($Script:ScannerConfig.EventLookbackDays) day(s).")
        }
        else {
            Add-Check $checks (New-Check -Category "Events" -Name "Application event errors" -Status "OK" -Details "No critical/error application events found in lookback window.")
        }

        $events | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message
    }

    $checksArray = @($checks)
    $overall = Get-OverallStatus -Checks $checksArray
    $score = Get-HealthScore -Checks $checksArray

    $counts = [ordered]@{
        OK       = (@($checksArray | Where-Object Status -eq "OK")).Count
        INFO     = (@($checksArray | Where-Object Status -eq "INFO")).Count
        WARNING  = (@($checksArray | Where-Object Status -eq "WARNING")).Count
        CRITICAL = (@($checksArray | Where-Object Status -eq "CRITICAL")).Count
        UNKNOWN  = (@($checksArray | Where-Object Status -eq "UNKNOWN")).Count
        TOTAL    = $checksArray.Count
    }

    [PSCustomObject]@{
        Meta        = [PSCustomObject]$meta
        Overall     = $overall
        HealthScore = $score
        Counts      = [PSCustomObject]$counts
        Checks      = $checksArray | Sort-Object @{ Expression = { Get-StatusRank $_.Status }; Descending = $true }, Category, Name
        Sections    = $sections
    }
}

# ============================================================
# RENDERING
# ============================================================

function Convert-ReportToText {
    param(
        [Parameter(Mandatory)]
        [object]$Report,

        [switch]$Anonymized
    )

    $lines = [System.Collections.Generic.List[string]]::new()

    [void]$lines.Add((Get-SageneDataAsciiLogo))
    [void]$lines.Add("")
    [void]$lines.Add("============================================================")
    [void]$lines.Add(" REPORT")
    [void]$lines.Add("============================================================")
    [void]$lines.Add("Product          : $($Report.Meta.ProductName)")
    [void]$lines.Add("Version          : $($Report.Meta.Version)")
    [void]$lines.Add("Generated        : $($Report.Meta.GeneratedAt)")
    [void]$lines.Add("Report ID        : $($Report.Meta.ReportId)")
    [void]$lines.Add("Computer         : $($Report.Meta.ComputerName)")
    [void]$lines.Add("User             : $($Report.Meta.UserName)")
    [void]$lines.Add("Domain           : $($Report.Meta.Domain)")
    [void]$lines.Add("Administrator    : $($Report.Meta.IsAdministrator)")
    [void]$lines.Add("PowerShell       : $($Report.Meta.PowerShellVersion) $($Report.Meta.PowerShellEdition)")
    [void]$lines.Add("Process          : $($Report.Meta.ProcessBitness)")

    [void]$lines.Add("")
    [void]$lines.Add("============================================================")
    [void]$lines.Add(" HEALTH SUMMARY")
    [void]$lines.Add("============================================================")
    [void]$lines.Add("Overall status   : $($Report.Overall)")
    [void]$lines.Add("Health score     : $($Report.HealthScore)/100")
    [void]$lines.Add("Critical         : $($Report.Counts.CRITICAL)")
    [void]$lines.Add("Warnings         : $($Report.Counts.WARNING)")
    [void]$lines.Add("Unknown          : $($Report.Counts.UNKNOWN)")
    [void]$lines.Add("Info             : $($Report.Counts.INFO)")
    [void]$lines.Add("OK               : $($Report.Counts.OK)")
    [void]$lines.Add("Total checks     : $($Report.Counts.TOTAL)")

    [void]$lines.Add("")
    [void]$lines.Add("============================================================")
    [void]$lines.Add(" ACTIONABLE FINDINGS")
    [void]$lines.Add("============================================================")

    foreach ($check in $Report.Checks) {
        $prefix = Get-StatusPrefix -Status $check.Status
        [void]$lines.Add("$prefix [$($check.Category)] $($check.Name): $($check.Details)")

        if ($check.Recommendation) {
            [void]$lines.Add("      Action: $($check.Recommendation)")
        }
    }

    foreach ($sectionName in $Report.Sections.Keys) {
        [void]$lines.Add("")
        [void]$lines.Add("============================================================")
        [void]$lines.Add(" $($sectionName.ToUpper())")
        [void]$lines.Add("============================================================")

        $section = $Report.Sections[$sectionName]

        if ($null -eq $section) {
            [void]$lines.Add("No data.")
            continue
        }

        if ($section -is [string]) {
            [void]$lines.Add($section)
            continue
        }

        $items = @($section)

        foreach ($item in $items) {
            if ($item -is [string]) {
                [void]$lines.Add($item)
                continue
            }

            foreach ($prop in $item.PSObject.Properties) {
                $value = ConvertTo-SafeText -Value $prop.Value
                [void]$lines.Add(("{0,-26}: {1}" -f $prop.Name, $value))
            }

            [void]$lines.Add("")
        }
    }

    $text = $lines -join "`r`n"

    if ($Anonymized) {
        $text = Protect-ReportText -Text $text -Report $Report
    }

    return $text
}

function Convert-ReportToHtml {
    param(
        [Parameter(Mandatory)]
        [object]$Report,

        [switch]$Anonymized
    )

    $statusClass = switch ($Report.Overall) {
        "OK"       { "ok" }
        "WARNING"  { "warning" }
        "CRITICAL" { "critical" }
        default    { "unknown" }
    }

    $findingsRows = foreach ($check in $Report.Checks) {
        $status = [System.Net.WebUtility]::HtmlEncode($check.Status)
        $category = [System.Net.WebUtility]::HtmlEncode($check.Category)
        $name = [System.Net.WebUtility]::HtmlEncode($check.Name)
        $details = [System.Net.WebUtility]::HtmlEncode($check.Details)
        $action = [System.Net.WebUtility]::HtmlEncode($check.Recommendation)
        "<tr><td class='s-$($check.Status.ToLower())'>$status</td><td>$category</td><td>$name</td><td>$details</td><td>$action</td></tr>"
    }

    $sectionBlocks = foreach ($sectionName in $Report.Sections.Keys) {
        $section = $Report.Sections[$sectionName]
        $safeName = [System.Net.WebUtility]::HtmlEncode($sectionName)

        if ($null -eq $section) {
            "<section><h2>$safeName</h2><p>No data.</p></section>"
            continue
        }

        if ($section -is [string]) {
            $safeText = [System.Net.WebUtility]::HtmlEncode($section)
            "<section><h2>$safeName</h2><pre>$safeText</pre></section>"
            continue
        }

        $items = @($section)
        $rows = foreach ($item in $items) {
            if ($item -is [string]) {
                $safeText = [System.Net.WebUtility]::HtmlEncode($item)
                "<tr><td colspan='2'>$safeText</td></tr>"
                continue
            }

            foreach ($prop in $item.PSObject.Properties) {
                $key = [System.Net.WebUtility]::HtmlEncode($prop.Name)
                $value = [System.Net.WebUtility]::HtmlEncode((ConvertTo-SafeText -Value $prop.Value))
                "<tr><th>$key</th><td>$value</td></tr>"
            }
            "<tr class='spacer'><td colspan='2'></td></tr>"
        }

        "<section><h2>$safeName</h2><table class='kv'>$($rows -join "`n")</table></section>"
    }

    $computer = [System.Net.WebUtility]::HtmlEncode($Report.Meta.ComputerName)
    $user = [System.Net.WebUtility]::HtmlEncode($Report.Meta.UserName)
    $domain = [System.Net.WebUtility]::HtmlEncode($Report.Meta.Domain)

    if ($Anonymized) {
        $computer = "[ANONYMIZED]"
        $user = "[ANONYMIZED]"
        $domain = "[ANONYMIZED]"
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sagene Data System Report</title>
<style>
:root {
    --bg: #070707;
    --panel: #111111;
    --panel2: #171717;
    --text: #eeeeee;
    --muted: #a6a6a6;
    --line: #2c2c2c;
    --cyan: #00d9ff;
    --ok: #39d353;
    --info: #58a6ff;
    --warning: #f7b731;
    --critical: #ff4d4d;
    --unknown: #b0b0b0;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: "Segoe UI", Arial, sans-serif;
}
.header {
    padding: 28px 34px;
    background: linear-gradient(90deg, #101010, #181818);
    border-bottom: 1px solid var(--line);
}
.brand {
    font-size: 26px;
    font-weight: 800;
    letter-spacing: .12em;
}
.sub {
    margin-top: 6px;
    color: var(--muted);
}
.status {
    display: inline-block;
    margin-top: 16px;
    padding: 9px 13px;
    border-radius: 10px;
    font-weight: 800;
}
.status.ok { background: rgba(57, 211, 83, .14); color: var(--ok); }
.status.warning { background: rgba(247, 183, 49, .14); color: var(--warning); }
.status.critical { background: rgba(255, 77, 77, .14); color: var(--critical); }
.status.unknown { background: rgba(176, 176, 176, .14); color: var(--unknown); }
main { padding: 28px 34px; }
.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 14px;
    margin-bottom: 24px;
}
.card {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 16px;
}
.card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
.card .value { margin-top: 8px; font-size: 24px; font-weight: 800; }
section {
    margin-top: 22px;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 14px;
    overflow: hidden;
}
h2 {
    margin: 0;
    padding: 14px 16px;
    background: var(--panel2);
    border-bottom: 1px solid var(--line);
    font-size: 15px;
    letter-spacing: .08em;
    text-transform: uppercase;
}
table { width: 100%; border-collapse: collapse; }
th, td {
    padding: 10px 12px;
    border-bottom: 1px solid var(--line);
    vertical-align: top;
    font-size: 13px;
}
th { width: 240px; color: var(--muted); text-align: left; font-weight: 600; }
.findings th { width: auto; }
.spacer td { padding: 5px; background: #0b0b0b; }
.s-ok { color: var(--ok); font-weight: 800; }
.s-info { color: var(--info); font-weight: 800; }
.s-warning { color: var(--warning); font-weight: 800; }
.s-critical { color: var(--critical); font-weight: 800; }
.s-unknown { color: var(--unknown); font-weight: 800; }
pre { white-space: pre-wrap; padding: 14px 16px; margin: 0; color: var(--text); }
</style>
</head>
<body>
<div class="header">
    <div class="brand">SAGENE DATA</div>
    <div class="sub">IT Support System Scanner</div>
    <div class="status $statusClass">STATUS: $($Report.Overall) · SCORE: $($Report.HealthScore)/100</div>
</div>
<main>
    <div class="cards">
        <div class="card"><div class="label">Computer</div><div class="value">$computer</div></div>
        <div class="card"><div class="label">User</div><div class="value">$user</div></div>
        <div class="card"><div class="label">Domain</div><div class="value">$domain</div></div>
        <div class="card"><div class="label">Critical</div><div class="value">$($Report.Counts.CRITICAL)</div></div>
        <div class="card"><div class="label">Warnings</div><div class="value">$($Report.Counts.WARNING)</div></div>
        <div class="card"><div class="label">Unknown</div><div class="value">$($Report.Counts.UNKNOWN)</div></div>
    </div>

    <section>
        <h2>Actionable Findings</h2>
        <table class="findings">
            <tr><th>Status</th><th>Category</th><th>Name</th><th>Details</th><th>Action</th></tr>
            $($findingsRows -join "`n")
        </table>
    </section>

    $($sectionBlocks -join "`n")
</main>
</body>
</html>
"@

    if ($Anonymized) {
        return Protect-ReportText -Text $html -Report $Report
    }

    return $html
}

function Export-SystemScannerReport {
    param(
        [Parameter(Mandatory)]
        [object]$Report,

        [Parameter(Mandatory)]
        [string]$Directory,

        [Parameter(Mandatory)]
        [string[]]$Formats,

        [switch]$Anonymized
    )

    if (-not (Test-Path $Directory)) {
        New-Item -Path $Directory -ItemType Directory -Force | Out-Null
    }

    $written = [System.Collections.Generic.List[string]]::new()

    foreach ($format in $Formats) {
        $path = Get-OutputPath -Directory $Directory -Format $format -Anonymized:$Anonymized

        switch ($format) {
            "TXT" {
                Convert-ReportToText -Report $Report -Anonymized:$Anonymized | Out-File -FilePath $path -Encoding UTF8
            }
            "HTML" {
                Convert-ReportToHtml -Report $Report -Anonymized:$Anonymized | Out-File -FilePath $path -Encoding UTF8
            }
            "JSON" {
                if ($Anonymized) {
                    $text = $Report | ConvertTo-Json -Depth 12
                    Protect-ReportText -Text $text -Report $Report | Out-File -FilePath $path -Encoding UTF8
                }
                else {
                    $Report | ConvertTo-Json -Depth 12 | Out-File -FilePath $path -Encoding UTF8
                }
            }
        }

        [void]$written.Add($path)
    }

    return $written
}

# ============================================================
# GUI
# ============================================================

if ($Script:UseGui) {
    function Get-StatusColor {
        param([string]$Status)

        switch ($Status) {
            "OK"       { [System.Drawing.Color]::FromArgb(57, 211, 83) }
            "INFO"     { [System.Drawing.Color]::FromArgb(88, 166, 255) }
            "WARNING"  { [System.Drawing.Color]::FromArgb(247, 183, 49) }
            "CRITICAL" { [System.Drawing.Color]::FromArgb(255, 77, 77) }
            "UNKNOWN"  { [System.Drawing.Color]::FromArgb(176, 176, 176) }
            default    { [System.Drawing.Color]::Gainsboro }
        }
    }

    function Append-RichText {
        param(
            [Parameter(Mandatory)]
            [System.Windows.Forms.RichTextBox]$Box,

            [AllowEmptyString()]
            [AllowNull()]
            [string]$Text = "",

            [Parameter(Mandatory)]
            [System.Drawing.Color]$Color,

            [bool]$NewLine = $true,

            [System.Drawing.FontStyle]$Style = [System.Drawing.FontStyle]::Regular
        )

        if ($null -eq $Text) {
            $Text = ""
        }

        $start = $Box.TextLength
        $textToAdd = $Text + $(if ($NewLine) { "`r`n" } else { "" })

        $Box.AppendText($textToAdd)

        if ($Text.Length -gt 0) {
            $Box.Select($start, $Text.Length)
            $Box.SelectionColor = $Color
            $Box.SelectionFont = New-Object System.Drawing.Font($Box.Font, $Style)
        }

        $Box.SelectionStart = $Box.TextLength
        $Box.SelectionLength = 0
        $Box.SelectionColor = $Box.ForeColor
        $Box.SelectionFont = $Box.Font
    }

    function Render-ReportInBox {
        param(
            [Parameter(Mandatory)]
            [System.Windows.Forms.RichTextBox]$Box,

            [Parameter(Mandatory)]
            [object]$Report
        )

        $Box.Clear()
        $text = Convert-ReportToText -Report $Report
        $lines = $text -split "`r?`n"

        foreach ($line in $lines) {
            if ($line -match "SAGENE DATA|IT SUPPORT SYSTEM SCANNER|^   _____|^  /|^ ___|^/____|^\s+/____") {
                Append-RichText -Box $Box -Text $line -Color ([System.Drawing.Color]::FromArgb(0, 217, 255)) -Style ([System.Drawing.FontStyle]::Bold)
            }
            elseif ($line -match "^=+$") {
                Append-RichText -Box $Box -Text $line -Color ([System.Drawing.Color]::FromArgb(70, 70, 70))
            }
            elseif ($line -match "^\s[A-Z][A-Z ]+$") {
                Append-RichText -Box $Box -Text $line -Color ([System.Drawing.Color]::FromArgb(88, 166, 255)) -Style ([System.Drawing.FontStyle]::Bold)
            }
            elseif ($line -match "^\[OK\]") {
                Append-RichText -Box $Box -Text $line -Color (Get-StatusColor "OK")
            }
            elseif ($line -match "^\[INFO\]") {
                Append-RichText -Box $Box -Text $line -Color (Get-StatusColor "INFO")
            }
            elseif ($line -match "^\[WARN\]") {
                Append-RichText -Box $Box -Text $line -Color (Get-StatusColor "WARNING")
            }
            elseif ($line -match "^\[CRIT\]") {
                Append-RichText -Box $Box -Text $line -Color (Get-StatusColor "CRITICAL") -Style ([System.Drawing.FontStyle]::Bold)
            }
            elseif ($line -match "^\[UNKNOWN\]") {
                Append-RichText -Box $Box -Text $line -Color (Get-StatusColor "UNKNOWN")
            }
            elseif ($line -match "^\s+Action:") {
                Append-RichText -Box $Box -Text $line -Color ([System.Drawing.Color]::Khaki)
            }
            else {
                Append-RichText -Box $Box -Text $line -Color ([System.Drawing.Color]::Gainsboro)
            }
        }

        $Box.SelectionStart = 0
        $Box.ScrollToCaret()
    }

    function Save-ReportFileDialog {
        param(
            [Parameter(Mandatory)]
            [object]$Report,

            [Parameter(Mandatory)]
            [ValidateSet("TXT", "HTML", "JSON")]
            [string]$Format,

            [switch]$Anonymized
        )

        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
        $dialog.FileName = Split-Path -Leaf (Get-OutputPath -Directory $dialog.InitialDirectory -Format $Format -Anonymized:$Anonymized)

        switch ($Format) {
            "TXT"  { $dialog.Filter = "Text file (*.txt)|*.txt" }
            "HTML" { $dialog.Filter = "HTML file (*.html)|*.html" }
            "JSON" { $dialog.Filter = "JSON file (*.json)|*.json" }
        }

        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

        switch ($Format) {
            "TXT" {
                Convert-ReportToText -Report $Report -Anonymized:$Anonymized | Out-File -FilePath $dialog.FileName -Encoding UTF8
            }
            "HTML" {
                Convert-ReportToHtml -Report $Report -Anonymized:$Anonymized | Out-File -FilePath $dialog.FileName -Encoding UTF8
            }
            "JSON" {
                if ($Anonymized) {
                    $json = $Report | ConvertTo-Json -Depth 12
                    Protect-ReportText -Text $json -Report $Report | Out-File -FilePath $dialog.FileName -Encoding UTF8
                }
                else {
                    $Report | ConvertTo-Json -Depth 12 | Out-File -FilePath $dialog.FileName -Encoding UTF8
                }
            }
        }

        [System.Windows.Forms.MessageBox]::Show("Report saved:`n$($dialog.FileName)", "Sagene Data Scanner") | Out-Null
    }

    function Show-SystemScannerGui {
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Sagene Data — IT Support System Scanner"
        $form.Size = New-Object System.Drawing.Size(1220, 850)
        $form.MinimumSize = New-Object System.Drawing.Size(980, 650)
        $form.StartPosition = "CenterScreen"
        $form.BackColor = [System.Drawing.Color]::FromArgb(8, 8, 8)

        $header = New-Object System.Windows.Forms.Panel
        $header.Dock = "Top"
        $header.Height = 82
        $header.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 18)
        $form.Controls.Add($header)

        $title = New-Object System.Windows.Forms.Label
        $title.Text = "SAGENE DATA"
        $title.ForeColor = [System.Drawing.Color]::White
        $title.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
        $title.AutoSize = $true
        $title.Location = New-Object System.Drawing.Point(18, 12)
        $header.Controls.Add($title)

        $subtitle = New-Object System.Windows.Forms.Label
        $subtitle.Text = "IT Support System Scanner"
        $subtitle.ForeColor = [System.Drawing.Color]::Silver
        $subtitle.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Regular)
        $subtitle.AutoSize = $true
        $subtitle.Location = New-Object System.Drawing.Point(21, 48)
        $header.Controls.Add($subtitle)

        $statusLabel = New-Object System.Windows.Forms.Label
        $statusLabel.Text = "STATUS: SCANNING"
        $statusLabel.ForeColor = [System.Drawing.Color]::Khaki
        $statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
        $statusLabel.AutoSize = $true
        $statusLabel.Anchor = "Top,Right"
        $statusLabel.Location = New-Object System.Drawing.Point(930, 28)
        $header.Controls.Add($statusLabel)

        $buttonPanel = New-Object System.Windows.Forms.Panel
        $buttonPanel.Dock = "Bottom"
        $buttonPanel.Height = 56
        $buttonPanel.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 18)
        $form.Controls.Add($buttonPanel)

        $rich = New-Object System.Windows.Forms.RichTextBox
        $rich.Dock = "Fill"
        $rich.ReadOnly = $true
        $rich.BorderStyle = "None"
        $rich.BackColor = [System.Drawing.Color]::FromArgb(5, 5, 5)
        $rich.ForeColor = [System.Drawing.Color]::Gainsboro
        $rich.Font = New-Object System.Drawing.Font("Consolas", 10)
        $rich.WordWrap = $false
        $form.Controls.Add($rich)

        $script:CurrentReport = $null

        function New-ScannerButton {
            param(
                [string]$Text,
                [int]$X,
                [scriptblock]$OnClick,
                [int]$Width = 118
            )

            $button = New-Object System.Windows.Forms.Button
            $button.Text = $Text
            $button.Width = $Width
            $button.Height = 34
            $button.Location = New-Object System.Drawing.Point($X, 11)
            $button.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
            $button.ForeColor = [System.Drawing.Color]::White
            $button.FlatStyle = "Flat"
            $button.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(70, 70, 70)
            $button.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $button.Add_Click($OnClick)
            $buttonPanel.Controls.Add($button)
            return $button
        }

        New-ScannerButton -Text "Rescan" -X 12 -OnClick {
            $rich.Clear()
            Append-RichText -Box $rich -Text "Scanning..." -Color ([System.Drawing.Color]::Khaki)
            $form.Refresh()

            $script:CurrentReport = Get-SystemScannerReport
            $statusLabel.Text = "STATUS: $($script:CurrentReport.Overall) · SCORE: $($script:CurrentReport.HealthScore)/100"
            $statusLabel.ForeColor = Get-StatusColor $script:CurrentReport.Overall
            Render-ReportInBox -Box $rich -Report $script:CurrentReport
        } | Out-Null

        New-ScannerButton -Text "Save TXT" -X 140 -OnClick {
            if ($script:CurrentReport) { Save-ReportFileDialog -Report $script:CurrentReport -Format "TXT" }
        } | Out-Null

        New-ScannerButton -Text "Save HTML" -X 268 -OnClick {
            if ($script:CurrentReport) { Save-ReportFileDialog -Report $script:CurrentReport -Format "HTML" }
        } | Out-Null

        New-ScannerButton -Text "Save JSON" -X 396 -OnClick {
            if ($script:CurrentReport) { Save-ReportFileDialog -Report $script:CurrentReport -Format "JSON" }
        } | Out-Null

        New-ScannerButton -Text "Anon TXT" -X 524 -Width 110 -OnClick {
            if ($script:CurrentReport) { Save-ReportFileDialog -Report $script:CurrentReport -Format "TXT" -Anonymized }
        } | Out-Null

        New-ScannerButton -Text "Anon HTML" -X 644 -Width 115 -OnClick {
            if ($script:CurrentReport) { Save-ReportFileDialog -Report $script:CurrentReport -Format "HTML" -Anonymized }
        } | Out-Null

        New-ScannerButton -Text "Copy Summary" -X 769 -Width 130 -OnClick {
            if ($script:CurrentReport) {
                $summary = @()
                $summary += "Sagene Data System Scanner"
                $summary += "Status: $($script:CurrentReport.Overall)"
                $summary += "Health score: $($script:CurrentReport.HealthScore)/100"
                $summary += "Critical: $($script:CurrentReport.Counts.CRITICAL)"
                $summary += "Warnings: $($script:CurrentReport.Counts.WARNING)"
                $summary += "Unknown: $($script:CurrentReport.Counts.UNKNOWN)"
                $summary += ""
                $summary += "Findings:"
                $summary += $script:CurrentReport.Checks |
                    Where-Object { $_.Status -in @("CRITICAL", "WARNING", "UNKNOWN") } |
                    ForEach-Object { "$(Get-StatusPrefix $_.Status) $($_.Name): $($_.Details)" }

                [System.Windows.Forms.Clipboard]::SetText(($summary -join "`r`n"))
                [System.Windows.Forms.MessageBox]::Show("Summary copied to clipboard.", "Sagene Data Scanner") | Out-Null
            }
        } | Out-Null

        $form.Add_Shown({
            Append-RichText -Box $rich -Text "Scanning..." -Color ([System.Drawing.Color]::Khaki)
            $form.Refresh()

            $script:CurrentReport = Get-SystemScannerReport
            $statusLabel.Text = "STATUS: $($script:CurrentReport.Overall) · SCORE: $($script:CurrentReport.HealthScore)/100"
            $statusLabel.ForeColor = Get-StatusColor $script:CurrentReport.Overall
            Render-ReportInBox -Box $rich -Report $script:CurrentReport
        })

        [void]$form.ShowDialog()
    }
}

# ============================================================
# SELF TEST
# ============================================================

function Invoke-ScannerSelfTest {
    $failures = [System.Collections.Generic.List[string]]::new()

    foreach ($fn in @(
        "New-Check",
        "Add-Check",
        "Invoke-SafeSection",
        "Get-SystemScannerReport",
        "Convert-ReportToText",
        "Convert-ReportToHtml",
        "Export-SystemScannerReport"
    )) {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
            [void]$failures.Add("Missing function: $fn")
        }
    }

    $testChecks = [System.Collections.Generic.List[object]]::new()
    Add-Check -Checks $testChecks -Check (New-Check -Name "Self test" -Status "OK" -Details "Check collection works." -Category "SelfTest")

    if ($testChecks.Count -ne 1) {
        [void]$failures.Add("Add-Check failed.")
    }

    if ($failures.Count -gt 0) {
        throw "Self-test failed: $($failures -join '; ')"
    }

    return "Self-test OK."
}

# ============================================================
# ENTRYPOINT
# ============================================================

if ($SelfTest) {
    Invoke-ScannerSelfTest | Write-Host
}

if ($NoGui) {
    $report = Get-SystemScannerReport

    if (-not $ExportDirectory) {
        $ExportDirectory = Join-Path (Get-Location) "reports"
    }

    $paths = Export-SystemScannerReport -Report $report -Directory $ExportDirectory -Formats $Formats -Anonymized:$Anonymized

    Write-Host "Sagene Data System Scanner"
    Write-Host "Status: $($report.Overall)"
    Write-Host "Health score: $($report.HealthScore)/100"
    Write-Host "Critical: $($report.Counts.CRITICAL)"
    Write-Host "Warnings: $($report.Counts.WARNING)"
    Write-Host "Unknown: $($report.Counts.UNKNOWN)"
    Write-Host ""
    Write-Host "Written files:"
    foreach ($path in $paths) {
        Write-Host "- $path"
    }

    exit
}

Show-SystemScannerGui
