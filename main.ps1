Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Append-ColoredText {
    param (
        [System.Windows.Forms.RichTextBox]$box,
        [string]$text,
        [System.Drawing.Color]$color,
        [bool]$newline = $true
    )
    $start = $box.TextLength
    $textToAdd = $text + ($(if ($newline) { "`r`n" } else { "" }))
    $box.AppendText($textToAdd)
    $box.Select($start, $text.Length)
    $box.SelectionColor = $color
    $box.SelectionStart = $box.TextLength
    $box.SelectionLength = 0
    $box.SelectionColor = $box.ForeColor
}

function Get-SystemReport {
    $report = @()

    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor
    $gpu = Get-CimInstance Win32_VideoController
    $bios = Get-CimInstance Win32_BIOS
    $baseboard = Get-CimInstance Win32_BaseBoard
    $ram = "{0:N2}" -f ($cs.TotalPhysicalMemory / 1GB)

    $report += "=== SYSTEMINFORMASJON ==="
    $report += ""
    $report += "Maskinnavn       : $($env:COMPUTERNAME)"
    $report += "Bruker           : $($env:USERNAME)"
    $report += "Domene           : $($cs.Domain)"
    $report += "Operativsystem   : $($os.Caption) ($($os.Version))"
    $report += "Systemtype       : $($os.OSArchitecture)"
    $report += "Oppetid          : $([math]::Round((New-TimeSpan -Start $os.LastBootUpTime).TotalHours, 1)) timer"
    $report += "Prosessor        : $($cpu.Name)"
    $report += "RAM              : $ram GB"
    $report += "GPU              : $($gpu.Name)"
    $report += "GPU Minne        : {0:N1} MB" -f ($gpu.AdapterRAM / 1MB)
    $report += "BIOS             : $($bios.SMBIOSBIOSVersion)"
    $report += "Hovedkort        : $($baseboard.Manufacturer) $($baseboard.Product)"

    $report += ""
    $report += "=== DISKER ==="
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Sort-Object DeviceID | ForEach-Object {
        $free = "{0:N1}" -f ($_.FreeSpace / 1GB)
        $total = "{0:N1}" -f ($_.Size / 1GB)
        $report += "$($_.DeviceID)            : $free GB ledig av $total GB"
    }

    $report += ""
    $report += "=== NETTVERK ==="
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.*" } | ForEach-Object {
        $report += "$($_.InterfaceAlias) : $($_.IPAddress)"
    }

    $batt = Get-CimInstance Win32_Battery
    if ($batt) {
        $report += ""
        $report += "=== BATTERI ==="
        $status = switch ($batt.BatteryStatus) {
            1 { "Ukjent" } 2 { "Lader" } 3 { "Ladet" } 4 { "Lav" } 5 { "Kritisk" }
            6 { "Lader ikke" } 7 { "Frakoblet" } 8 { "Lader og høy" }
            default { "Ukjent ($($batt.BatteryStatus))" }
        }
        $report += "Status           : $status"
        $report += "Kapasitet        : $($batt.EstimatedChargeRemaining)%"
    }

    $report += ""
    $report += "=== VIKTIGE TJENESTER ==="
    $services = "wuauserv", "Spooler", "WinDefend"
    foreach ($s in $services) {
        $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($svc) {
            $report += "$($svc.DisplayName) : $($svc.Status)"
        }
    }

    $report += ""
    $report += "Rapport generert : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $report += "Unik ID          : $(Get-Random -Minimum 1000 -Maximum 9999)"

    return $report
}

function Show-SystemReport {
    $lines = Get-SystemReport

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "🖥️ PC Systemrapport"
    $form.Size = New-Object System.Drawing.Size(900, 600)
    $form.StartPosition = "CenterScreen"

    $rich = New-Object System.Windows.Forms.RichTextBox
    $rich.Multiline = $true
    $rich.Dock = "Fill"
    $rich.ReadOnly = $true
    $rich.BackColor = 'Black'
    $rich.ForeColor = 'White'
    $rich.Font = New-Object System.Drawing.Font("Consolas", 10)
    $form.Controls.Add($rich)

    $saveButton = New-Object System.Windows.Forms.Button
    $saveButton.Text = "💾 Lagre rapport"
    $saveButton.Dock = "Bottom"
    $saveButton.Height = 30
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
        elseif ($line -match "^[^:]+:") {
            $parts = $line -split ":", 2
            if ($parts.Count -eq 2) {
                Append-ColoredText -box $rich -text ($parts[0] + ":") -color ([System.Drawing.Color]::White) -newline:$false
                Append-ColoredText -box $rich -text (" " + $parts[1].Trim()) -color ([System.Drawing.Color]::Lime)
            } else {
                Append-ColoredText -box $rich -text $line -color ([System.Drawing.Color]::Lime)
            }
        } else {
            Append-ColoredText -box $rich -text $line -color ([System.Drawing.Color]::Lime)
        }
    }

    $form.ShowDialog()
}

Show-SystemReport
