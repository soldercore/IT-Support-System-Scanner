#requires -Version 5.1
<#
.SYNOPSIS
    Sagene Data IT Support System Scanner

.DESCRIPTION
    Read-only Windows support scanner for IT consultants.
    Produces a structured health report with GUI, TXT, HTML, JSON and anonymized exports.

.NOTES
    - Read-only
    - No external network calls
    - No system changes
    - Best results when run as Administrator
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSEdition -eq "Core" -and -not $IsWindows) {
    throw "This scanner is Windows-only."
}

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne "STA" -and $PSCommandPath) {
    $exe = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
    Start-Process -FilePath $exe -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-STA",
        "-File", "`"$PSCommandPath`""
    )
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

# ============================================================
# CONFIG
# ============================================================

$Script:ScannerConfig = [ordered]@{
    ProductName        = "Sagene Data IT Support System Scanner"
    Vendor             = "Sagene Data"
    Version            = "3.0.0"
    EventLookbackDays  = 3
    MaxEvents          = 20
    DiskWarningPercent = 20
    DiskCriticalPercent = 10
    UptimeWarningHours = 168
    HtmlFileName       = "SageneData-SystemReport.html"
    TextFileName       = "SageneData-SystemReport.txt"
    JsonFileName       = "SageneData-SystemReport.json"
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
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[object]]$Checks,

        [Parameter(Mandatory)]
        [object]$Check
    )

    [void]$Checks.Add($Check)
}

function Invoke-SafeSection {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [System.Collections.Generic.List[object]]$Checks,

        [Parameter(Mandatory)]
        [scriptblock]$Script
    )

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
            Error = $true
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

    if ($Checks | Where-Object { $_.Status -eq "CRITICAL" }) { return "CRITICAL" }
    if ($Checks | Where-Object { $_.Status -eq "WARNING" })  { return "WARNING" }
    if ($Checks | Where-Object { $_.Status -eq "UNKNOWN" })  { return "UNKNOWN" }
    return "OK"
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

    if ($null -eq $Value) {
        return ""
    }

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
        [string]$Text,
        [object]$Report
    )

    $result = $Text

    $sensitiveValues = @(
        $Report.Meta.ComputerName,
        $Report.Meta.UserName,
        $Report.Meta.Domain
    ) | Where-Object { $_ -and $_ -ne "" } | Select-Object -Unique

    foreach ($value in $sensitiveValues) {
        $escaped = [regex]::Escape([string]$value)
        $result = $result -replace $escaped, "[ANONYMIZED]"
    }

    $result = $result -replace '\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP-ANONYMIZED]'
    $result = $result -replace '\b([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}\b', '[MAC-ANONYMIZED]'
    $result = $result -replace '\bS-\d-\d+-(\d+-){1,14}\d+\b', '[SID-ANONYMIZED]'

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
    $evidence = New-Object System.Collections.Generic.List[string]

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            [void]$evidence.Add($path)
        }
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

# ============================================================
# COLLECTORS
# ============================================================

function Get-SystemScannerReport {
    $checks = [System.Collections.Generic.List[object]]::new()
    $sections = [ordered]@{}

    $isAdmin = Get-IsAdministrator

    $meta = [ordered]@{
        ProductName        = $Script:ScannerConfig.ProductName
        Vendor             = $Script:ScannerConfig.Vendor
        Version            = $Script:ScannerConfig.Version
        GeneratedAt        = Get-Date
        ReportId           = [guid]::NewGuid().ToString()
        ComputerName       = $env:COMPUTERNAME
        UserName           = $env:USERNAME
        UserDomain         = $env:USERDOMAIN
        Domain             = ""
        IsAdministrator    = $isAdmin
        PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition  = $PSVersionTable.PSEdition
        ProcessBitness     = if ([Environment]::Is64BitProcess) { "64-bit" } else { "32-bit" }
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
            ComputerName   = $env:COMPUTERNAME
            UserName       = $env:USERNAME
            Domain         = $cs.Domain
            Manufacturer   = $cs.Manufacturer
            Model          = $cs.Model
            ChassisType    = ($cs.PCSystemTypeEx)
            OS             = $os.Caption
            OSVersion      = $os.Version
            BuildNumber    = $os.BuildNumber
            Architecture   = $os.OSArchitecture
            InstallDate    = $os.InstallDate
            LastBoot       = $os.LastBootUpTime
            UptimeHours    = $uptimeHours
            CPU            = $cpu.Name
            CPUCores       = $cpu.NumberOfCores
            CPULogical     = $cpu.NumberOfLogicalProcessors
            RAMGB          = $ramGb
            BIOSVersion    = $bios.SMBIOSBIOSVersion
            BIOSSerial     = $bios.SerialNumber
            Motherboard    = "$($board.Manufacturer) $($board.Product)"
        }
    }

    $sections["Pending Reboot"] = Invoke-SafeSection -Name "Pending Reboot" -Checks $checks -Script {
        $evidence = Get-PendingRebootEvidence

        if ($evidence.Count -gt 0) {
            Add-Check $checks (New-Check -Category "System" -Name "Pending reboot" -Status "WARNING" -Details "Windows has pending reboot evidence." -Recommendation "Restart machine before continuing troubleshooting.")
        }
        else {
            Add-Check $checks (New-Check -Category "System" -Name "Pending reboot" -Status "OK" -Details "No pending reboot evidence found.")
        }

        if ($evidence.Count -eq 0) {
            [PSCustomObject]@{ PendingReboot = $false; Evidence = "None" }
        }
        else {
            [PSCustomObject]@{ PendingReboot = $true; Evidence = ($evidence -join "; ") }
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
            AMServiceEnabled             = $mp.AMServiceEnabled
            AntivirusEnabled            = $mp.AntivirusEnabled
            RealTimeProtectionEnabled   = $mp.RealTimeProtectionEnabled
            BehaviorMonitorEnabled      = $mp.BehaviorMonitorEnabled
            IoavProtectionEnabled       = $mp.IoavProtectionEnabled
            NISEnabled                  = $mp.NISEnabled
            AntivirusSignatureUpdated   = $mp.AntivirusSignatureLastUpdated
            QuickScanAge                = $mp.QuickScanAge
            FullScanAge                 = $mp.FullScanAge
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
                Profile              = $_.Name
                Enabled              = $_.Enabled
                DefaultInboundAction = $_.DefaultInboundAction
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

            if ($days -gt 45) {
                Add-Check $checks (New-Check -Category "Updates" -Name "Latest installed update" -Status "WARNING" -Details "Latest hotfix appears older than 45 days: $($latest.HotFixID), $($latest.InstalledOn)." -Recommendation "Check Windows Update or management platform.")
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
        $importantServices = @(
            @{ Name = "EventLog"; Critical = $true },
            @{ Name = "Winmgmt"; Critical = $true },
            @{ Name = "Dhcp"; Critical = $true },
            @{ Name = "Dnscache"; Critical = $true },
            @{ Name = "LanmanWorkstation"; Critical = $true },
            @{ Name = "wuauserv"; Critical = $false },
            @{ Name = "BITS"; Critical = $false },
            @{ Name = "WinDefend"; Critical = $false }
        )

        foreach ($entry in $importantServices) {
            $svc = Get-Service -Name $entry.Name -ErrorAction SilentlyContinue

            if (-not $svc) {
                Add-Check $checks (New-Check -Category "Services" -Name "Service $($entry.Name)" -Status "UNKNOWN" -Details "Service not found.")
                [PSCustomObject]@{
                    Name        = $entry.Name
                    DisplayName = "Not found"
                    Status      = "Unknown"
                    StartType   = "Unknown"
                }
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
        try {
            $members = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop)

            if ($members.Count -gt 5) {
                Add-Check $checks (New-Check -Category "Security" -Name "Local administrators" -Status "WARNING" -Details "$($members.Count) local administrator member(s) found." -Recommendation "Review local administrator membership.")
            }
            else {
                Add-Check $checks (New-Check -Category "Security" -Name "Local administrators" -Status "INFO" -Details "$($members.Count) local administrator member(s) found.")
            }

            $members | Select-Object Name, ObjectClass, PrincipalSource
        }
        catch {
            Add-Check $checks (New-Check -Category "Security" -Name "Local administrators" -Status "UNKNOWN" -Details "Could not read local administrators: $($_.Exception.Message)")
            "Could not read local administrators."
        }
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

    $sections["Time Service"] = Invoke-SafeSection -Name "Time Service" -Checks $checks -Script {
        $svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue

        if (-not $svc) {
            Add-Check $checks (New-Check -Category "System" -Name "Windows Time" -Status "UNKNOWN" -Details "Windows Time service not found.")
            return "Windows Time service not found."
        }

        if ($svc.Status -ne "Running") {
            Add-Check $checks (New-Check -Category "System" -Name "Windows Time" -Status "WARNING" -Details "Windows Time service is not running." -Recommendation "Start Windows Time service if domain, Kerberos or certificate issues exist.")
        }
        else {
            Add-Check $checks (New-Check -Category "System" -Name "Windows Time" -Status "OK" -Details "Windows Time service is running.")
        }

        [PSCustomObject]@{
            ServiceName = $svc.Name
            Status      = $svc.Status
            StartType   = $svc.StartType
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

    $counts = [ordered]@{
        OK       = (@($checksArray | Where-Object Status -eq "OK")).Count
        INFO     = (@($checksArray | Where-Object Status -eq "INFO")).Count
        WARNING  = (@($checksArray | Where-Object Status -eq "WARNING")).Count
        CRITICAL = (@($checksArray | Where-Object Status -eq "CRITICAL")).Count
        UNKNOWN  = (@($checksArray | Where-Object Status -eq "UNKNOWN")).Count
        TOTAL    = $checksArray.Count
    }

    [PSCustomObject]@{
        Meta     = [PSCustomObject]$meta
        Overall  = $overall
        Counts   = [PSCustomObject]$counts
        Checks   = $checksArray | Sort-Object @{ Expression = { Get-StatusRank $_.Status }; Descending = $true }, Category, Name
        Sections = $sections
    }
}

# ============================================================
# TEXT RENDERING
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

    $text = Convert-ReportToText -Report $Report -Anonymized:$Anonymized
    $encoded = [System.Net.WebUtility]::HtmlEncode($text)

    $statusClass = switch ($Report.Overall) {
        "OK"       { "ok" }
        "WARNING"  { "warning" }
        "CRITICAL" { "critical" }
        default    { "unknown" }
    }

@"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sagene Data System Report</title>
<style>
:root {
    --bg: #080808;
    --panel: #121212;
    --text: #e8e8e8;
    --muted: #a0a0a0;
    --line: #2b2b2b;
    --cyan: #00d9ff;
    --ok: #39d353;
    --warning: #f7b731;
    --critical: #ff4d4d;
    --unknown: #b0b0b0;
}
body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: Consolas, "Cascadia Mono", "Courier New", monospace;
}
.header {
    padding: 24px 32px;
    background: linear-gradient(90deg, #0f0f0f, #161616);
    border-bottom: 1px solid var(--line);
}
.brand {
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 0.08em;
}
.sub {
    margin-top: 6px;
    color: var(--muted);
}
.status {
    display: inline-block;
    margin-top: 14px;
    padding: 8px 12px;
    border-radius: 8px;
    font-weight: 700;
}
.status.ok { background: rgba(57, 211, 83, .15); color: var(--ok); }
.status.warning { background: rgba(247, 183, 49, .15); color: var(--warning); }
.status.critical { background: rgba(255, 77, 77, .15); color: var(--critical); }
.status.unknown { background: rgba(176, 176, 176, .15); color: var(--unknown); }
main {
    padding: 28px 32px;
}
pre {
    white-space: pre-wrap;
    line-height: 1.45;
    font-size: 13px;
}
</style>
</head>
<body>
<div class="header">
    <div class="brand">SAGENE DATA</div>
    <div class="sub">IT Support System Scanner</div>
    <div class="status $statusClass">STATUS: $($Report.Overall)</div>
</div>
<main>
<pre>$encoded</pre>
</main>
</body>
</html>
"@
}

# ============================================================
# GUI HELPERS
# ============================================================

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

        [Parameter(Mandatory)]
        [string]$Text,

        [Parameter(Mandatory)]
        [System.Drawing.Color]$Color,

        [bool]$NewLine = $true,

        [System.Drawing.FontStyle]$Style = [System.Drawing.FontStyle]::Regular
    )

    $start = $Box.TextLength
    $textToAdd = $Text + $(if ($NewLine) { "`r`n" } else { "" })

    $Box.AppendText($textToAdd)
    $Box.Select($start, $Text.Length)
    $Box.SelectionColor = $Color
    $Box.SelectionFont = New-Object System.Drawing.Font($Box.Font, $Style)
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

function Save-ReportFile {
    param(
        [Parameter(Mandatory)]
        [object]$Report,

        [Parameter(Mandatory)]
        [ValidateSet("TXT", "HTML", "JSON", "ANON_TXT", "ANON_HTML")]
        [string]$Format
    )

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")

    switch ($Format) {
        "TXT" {
            $dialog.FileName = $Script:ScannerConfig.TextFileName
            $dialog.Filter = "Text file (*.txt)|*.txt"
        }
        "HTML" {
            $dialog.FileName = $Script:ScannerConfig.HtmlFileName
            $dialog.Filter = "HTML file (*.html)|*.html"
        }
        "JSON" {
            $dialog.FileName = $Script:ScannerConfig.JsonFileName
            $dialog.Filter = "JSON file (*.json)|*.json"
        }
        "ANON_TXT" {
            $dialog.FileName = "SageneData-SystemReport-Anonymized.txt"
            $dialog.Filter = "Text file (*.txt)|*.txt"
        }
        "ANON_HTML" {
            $dialog.FileName = "SageneData-SystemReport-Anonymized.html"
            $dialog.Filter = "HTML file (*.html)|*.html"
        }
    }

    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        return
    }

    switch ($Format) {
        "TXT" {
            Convert-ReportToText -Report $Report | Out-File -FilePath $dialog.FileName -Encoding UTF8
        }
        "HTML" {
            Convert-ReportToHtml -Report $Report | Out-File -FilePath $dialog.FileName -Encoding UTF8
        }
        "JSON" {
            $Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $dialog.FileName -Encoding UTF8
        }
        "ANON_TXT" {
            Convert-ReportToText -Report $Report -Anonymized | Out-File -FilePath $dialog.FileName -Encoding UTF8
        }
        "ANON_HTML" {
            Convert-ReportToHtml -Report $Report -Anonymized | Out-File -FilePath $dialog.FileName -Encoding UTF8
        }
    }

    [System.Windows.Forms.MessageBox]::Show(
        "Report saved:`n$($dialog.FileName)",
        "Sagene Data Scanner",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
}

# ============================================================
# GUI
# ============================================================

function Show-SystemScannerGui {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Sagene Data — IT Support System Scanner"
    $form.Size = New-Object System.Drawing.Size(1180, 820)
    $form.MinimumSize = New-Object System.Drawing.Size(980, 650)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::FromArgb(8, 8, 8)

    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = "Top"
    $header.Height = 78
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
    $subtitle.Location = New-Object System.Drawing.Point(21, 46)
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
    $buttonPanel.Height = 52
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

    function New-Button {
        param(
            [string]$Text,
            [int]$X,
            [scriptblock]$OnClick,
            [int]$Width = 118
        )

        $button = New-Object System.Windows.Forms.Button
        $button.Text = $Text
        $button.Width = $Width
        $button.Height = 32
        $button.Location = New-Object System.Drawing.Point($X, 10)
        $button.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
        $button.ForeColor = [System.Drawing.Color]::White
        $button.FlatStyle = "Flat"
        $button.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(70, 70, 70)
        $button.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $button.Add_Click($OnClick)
        $buttonPanel.Controls.Add($button)
        return $button
    }

    New-Button -Text "Rescan" -X 12 -OnClick {
        $rich.Clear()
        Append-RichText -Box $rich -Text "Scanning..." -Color ([System.Drawing.Color]::Khaki)
        $form.Refresh()

        $script:CurrentReport = Get-SystemScannerReport
        $statusLabel.Text = "STATUS: $($script:CurrentReport.Overall)"
        $statusLabel.ForeColor = Get-StatusColor $script:CurrentReport.Overall
        Render-ReportInBox -Box $rich -Report $script:CurrentReport
    } | Out-Null

    New-Button -Text "Save TXT" -X 140 -OnClick {
        if ($script:CurrentReport) { Save-ReportFile -Report $script:CurrentReport -Format "TXT" }
    } | Out-Null

    New-Button -Text "Save HTML" -X 268 -OnClick {
        if ($script:CurrentReport) { Save-ReportFile -Report $script:CurrentReport -Format "HTML" }
    } | Out-Null

    New-Button -Text "Save JSON" -X 396 -OnClick {
        if ($script:CurrentReport) { Save-ReportFile -Report $script:CurrentReport -Format "JSON" }
    } | Out-Null

    New-Button -Text "Save Anon TXT" -X 524 -Width 140 -OnClick {
        if ($script:CurrentReport) { Save-ReportFile -Report $script:CurrentReport -Format "ANON_TXT" }
    } | Out-Null

    New-Button -Text "Save Anon HTML" -X 674 -Width 150 -OnClick {
        if ($script:CurrentReport) { Save-ReportFile -Report $script:CurrentReport -Format "ANON_HTML" }
    } | Out-Null

    New-Button -Text "Copy Summary" -X 834 -Width 140 -OnClick {
        if ($script:CurrentReport) {
            $summary = @()
            $summary += "Sagene Data System Scanner"
            $summary += "Status: $($script:CurrentReport.Overall)"
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
        $statusLabel.Text = "STATUS: $($script:CurrentReport.Overall)"
        $statusLabel.ForeColor = Get-StatusColor $script:CurrentReport.Overall
        Render-ReportInBox -Box $rich -Report $script:CurrentReport
    })

    [void]$form.ShowDialog()
}

Show-SystemScannerGui
