Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Append-ColoredText {
    param (
        [System.Windows.Forms.RichTextBox]$box,
        [string]$text,
        [System.Drawing.Color]$color,
        [bool]$newline = $true
    )

    $box.SelectionStart = $box.TextLength
    $box.SelectionLength = 0
    $box.SelectionColor = $color
    $box.AppendText($text + ($(if ($newline) { "`r`n" } else { "" })))
    $box.SelectionColor = $box.ForeColor
}

function Get-SystemReport {
    $report = @()

    # Systeminfo
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor
    $gpu = Get-CimInstance Win32_VideoController
    $bios = Get-CimInstance Win32_BIOS
    $baseboard = Get-CimInstance Win32_BaseBoard
    $ram = "{0:N2}" -f ($cs.TotalPhysicalMemory / 1GB)

    $report += @("=== SYSTEMINFORMASJON ===",
        "Bruker: $env:USERNAME",
        "Maskinnavn: $env:COMPUTERNAME",
        "Operativsystem: $($os.Caption) ($($os.Version))",
        "Build: $($os.BuildNumber) | Systemtype: $($os.OSArchitecture)",
        "Oppetid: $([math]::Round((New-TimeSpan -Start $os.LastBootUpTime).TotalHours, 1)) timer",
        "Domene/Arbeidsgruppe: $($cs.Domain)",
        "Prosessor: $($cpu.Name)",
        "RAM: $ram GB",
        "GPU: $($gpu.Name) | Minne: {0:N1} MB" -f ($gpu.AdapterRAM / 1MB),
        "BIOS: $($bios.SMBIOSBIOSVersion)",
        "Hovedkort: $($baseboard.Manufacturer) $($baseboard.Product)")

    # Disker
    $report += "`n=== DISKER ==="
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Sort-Object DeviceID | ForEach-Object {
        $free = "{0:N1}" -f ($_.FreeSpace / 1GB)
        $total = "{0:N1}" -f ($_.Size / 1GB)
        $report += "$($_.DeviceID): $free GB ledig av $total GB"
    }

    # Nettverk
    $report += "`n=== NETTVERK ==="
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.*" } | ForEach-Object {
        $report += "$($_.InterfaceAlias): $($_.IPAddress)"
    }

    # Batteri
    $batt = Get-CimInstance Win32_Battery
    if ($batt) {
        $report += "`n=== BATTERI ==="
        $status = switch ($batt.BatteryStatus) {
            1 { "Ukjent" } 2 { "Lader" } 3 { "Ladet" } 4 { "Lav" } 5 { "Kritisk" }
            6 { "Lader ikke" } 7 { "Frakoblet" } 8 { "Lader og høy" }
            default { "Ukjent ($($batt.BatteryStatus))" }
        }
        $report += "Status: $status | Kapasitet: $($batt.EstimatedChargeRemaining)%"
    }

    # Tjenester
    $report += "`n=== VIKTIGE TJENESTER ==="
    $services = "wuauserv", "Spooler", "WinDefend"
    foreach ($s in $services) {
        $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($svc) {
            $report += "$($svc.DisplayName): $($svc.Status)"
        }
    }

    return $report
}

# === GUI-Vindu ===
function Show-SystemReport {
    $lines = Get-SystemReport

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "PC Systemrapport"
    $form.Size = New-Object System.Drawing.Size(850, 600)
    $form.StartPosition = "CenterScreen"

    $rich = New-Object System.Windows.Forms.RichTextBox
    $rich.Multiline = $true
    $rich.Dock = "Fill"
    $rich.ReadOnly = $true
    $rich.BackColor = 'Black'
    $rich.ForeColor = 'Lime'
    $rich.Font = New-Object System.Drawing.Font("Consolas", 10)

    $form.Controls.Add($rich)

    $saveButton = New-Object System.Windows.Forms.Button
    $saveButton.Text = "Lagre rapport"
    $saveButton.Dock = "Bottom"
    $saveButton.Add_Click({
        $path = "$env:USERPROFILE\Desktop\PC-Rapport.txt"
        ($lines -join "`r`n") | Out-File -FilePath $path -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Rapport lagret til: $path")
    })
    $form.Controls.Add($saveButton)

    foreach ($line in $lines) {
        if ($line -match "^=== ") {
            Append-ColoredText -box $rich -text $line -color ([System.Drawing.Color]::Cyan)
        }
        elseif ($line -match "^\s*$") {
            Append-ColoredText -box $rich -text "" -color ([System.Drawing.Color]::White)
        }
        else {
            Append-ColoredText -box $rich -text $line -color ([System.Drawing.Color]::Lime)
        }
    }

    $form.ShowDialog()
}

# Kjør GUI
Show-SystemReport
