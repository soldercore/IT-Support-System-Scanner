# 🛠️ PC Systemrapport

Et PowerShell-skript som samler inn viktig systeminformasjon og viser det i et brukervennlig GUI-vindu — perfekt for IKT-support, feilsøking og helse-sjekk av Windows-PCer.

## 📌 Funksjoner

- RAM, CPU, GPU, BIOS og hovedkortinfo
- Diskplass og status
- Nettverksadaptere og IP-adresser
- Batteristatus (ved bærbar PC)
- Antivirus-status og Windows-tjenester
- Systemfeil fra siste 24 timer (Event Log)
- Terminal-stil GUI med lett lesbar rapport

## 🚀 Kjør direkte (ingen nedlasting)

Åpne PowerShell og lim inn denne kommandoen:

```powershell
irm https://raw.githubusercontent.com/soldercore/IT-Support-System-Scanner/main/main.ps1 | iex

```bash
curl -s https://raw.githubusercontent.com/soldercore/IT-Support-System-Scanner/main/mac-systemrapport.sh | bash
