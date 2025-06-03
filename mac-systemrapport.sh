#!/bin/bash

# midlertidig fil for rapport
REPORT_FILE=$(mktemp)

echo "=== SYSTEMRAPPORT (macOS) ===" > "$REPORT_FILE"
echo "Tid: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
echo "Maskinnavn: $(scutil --get ComputerName)" >> "$REPORT_FILE"
echo "Bruker: $(whoami)" >> "$REPORT_FILE"
echo "macOS-versjon: $(sw_vers -productVersion)" >> "$REPORT_FILE"
echo "Systemtype: $(uname -m)" >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "=== MASKINVARE ===" >> "$REPORT_FILE"
system_profiler SPHardwareDataType | grep -E 'Model|Processor|Memory' >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "=== DISK ===" >> "$REPORT_FILE"
df -h / | tail -n 1 | awk '{print "Diskbruk: " $3 " brukt av " $2 " (" $5 " brukt)"}' >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "=== BATTERI ===" >> "$REPORT_FILE"
pmset -g batt | grep "%" | awk '{print "Batteristatus: " $3 " (" $2 ")"}' >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "=== NETTVERK ===" >> "$REPORT_FILE"
ipconfig getifaddr en0 &>/dev/null && echo "Wi-Fi IP: $(ipconfig getifaddr en0)" >> "$REPORT_FILE"
ipconfig getifaddr en1 &>/dev/null && echo "Ethernet IP: $(ipconfig getifaddr en1)" >> "$REPORT_FILE"
networksetup -getdnsservers Wi-Fi 2>/dev/null | grep -v "There aren't" | sed 's/^/DNS: /' >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "=== PROSESSORBRUK (TOP 3) ===" >> "$REPORT_FILE"
ps -Ao %cpu,command | sort -nr | head -n 4 >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "=== TJENESTER MED PROBLEM ===" >> "$REPORT_FILE"
launchctl list | grep -v "0" | grep -v "-" | head -n 5 | awk '{print "Feil: " $3}' >> "$REPORT_FILE"

# vis GUI med AppleScript (monospaced)
osascript <<EOF
tell application "Terminal"
    activate
    do script "cat $REPORT_FILE; echo; echo Rapporten er ferdig. Trykk ENTER for å lukke; read"
end tell
EOF

sleep 2
rm "$REPORT_FILE"
