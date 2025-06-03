# 🖥️ PC & Mac Systemrapport

Et PowerShell- og Bash-skript som samler inn viktig systeminformasjon og viser det i et brukervennlig GUI-vindu — perfekt for IKT-support, feilsøking og helsesjekk av både Windows- og macOS-maskiner.

---

## 🪟 Windows-funksjoner

- 🧠 RAM, CPU, GPU, BIOS og hovedkortinfo  
- 💽 Diskplass og lagringsstatus med prosentvis bruk  
- 🌐 Nettverksadaptere, IP-adresser, DNS og gateway  
- 🔋 Batteristatus (ved bærbar PC)  
- 🛡️ Antivirus-status og Windows-tjenester  
- ❗ Tjenester som ikke kjører (men burde)  
- ⚠️ Maskinvare med feilstatus (PnpDevice)  
- 🧾 Systemfeil fra siste 24 timer (Event Viewer)  
- 🖥️ GUI i terminal-stil med farger (RichTextBox)  
- 💾 Mulighet for lagring som `.txt` på skrivebord
### 🚀 Kjør direkte i PowerShell (ingen nedlasting)

<pre> ```powershell irm https://raw.githubusercontent.com/soldercore/IT-Support-System-Scanner/main/main.ps1 | iex ``` </pre>

🍏 **macOS-funksjoner**  
💻 Maskinnavn, innlogget bruker, OS-versjon og build  
🧠 CPU, RAM, maskinmodell og systemtype  
💽 Diskbruk (bruk/ledig og prosent)  
🔋 Batteristatus og lading  
🌐 IP-adresser, DNS-servere (Wi-Fi og Ethernet)  
📊 Prosesser med høy CPU-bruk (topp 3)  
❗ Tjenester som har feilet (launchctl)  
🪟 Automatisk GUI-popup i nytt Terminal-vindu  
🧾 Rapport vises i monospace layout og slettes etterpå  
🚀 Kjør direkte i macOS-terminal (ingen nedlasting)

```bash
curl -s https://raw.githubusercontent.com/soldercore/IT-Support-System-Scanner/main/mac-systemrapport.sh | b
