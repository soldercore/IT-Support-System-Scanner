
Add-Type -AssemblyName System.Windows.Forms

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

    $report += "=== SYSTEMINFORMASJON ==="
    $report += "Bruker: $env:USERNAME"
    $report += "Maskinnavn: $env:COMPUTERNAME"
    $report += "Operativsystem: $($os.Caption) ($($os.Version))"
    $report += "Build: $($os.BuildNumber) | Systemtype: $($os.OSArchitecture)"
    $report += "Oppetid: $([math]::Round((New-TimeSpan -Start $os.LastBootUpTime).TotalHours, 1)) timer"
    $report += "Domene/Arbeidsgruppe: $($cs.Domain)"
    $report += "Prosessor: $($cpu.Name)"
    $report += "RAM: $ram GB"
    $report += "GPU: $($gpu.Name) | Minne: {0:N1} MB" -f ($gpu.AdapterRAM / 1MB)
    $report += "BIOS: $($bios.SMBIOSBIOSVersion)"
    $report += "Hovedkort: $($baseboard.Manufacturer) $($baseboard.Product)"

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

    return $report -join "`r`n"
}

# === GUI-Vindu ===
function Show-SystemReport {
    $reportText = Get-SystemReport

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "PC Systemrapport"
    $form.Size = New-Object System.Drawing.Size(800, 600)
    $form.StartPosition = "CenterScreen"

    $textbox = New-Object System.Windows.Forms.TextBox
    $textbox.Multiline = $true
    $textbox.ScrollBars = "Vertical"
    $textbox.ReadOnly = $true
    $textbox.Dock = "Fill"
    $textbox.Font = 'Consolas, 10pt'
    $textbox.BackColor = "Black"
    $textbox.ForeColor = "Lime"
    $textbox.Text = $reportText

    $form.Controls.Add($textbox)

    $saveButton = New-Object System.Windows.Forms.Button
    $saveButton.Text = "Lagre rapport"
    $saveButton.Dock = "Bottom"
    $saveButton.Add_Click({
        $path = "$env:USERPROFILE\Desktop\PC-Rapport.txt"
        $reportText | Out-File -FilePath $path -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Rapport lagret til: $path")
    })

    $form.Controls.Add($saveButton)
    $form.ShowDialog()
}

# Kjør GUI
Show-SystemReport
