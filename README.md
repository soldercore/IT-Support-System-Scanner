# Sagene Data IT Support System Scanner

> Read-only Windows system scanner for quick first-line troubleshooting, support documentation, and device health checks.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Windows](https://img.shields.io/badge/Platform-Windows-0078D4)
![Read Only](https://img.shields.io/badge/Mode-Read--Only-brightgreen)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## Overview

**Sagene Data IT Support System Scanner** collects relevant Windows support information and presents it in a clear report with health status, health score, and recommended next steps.

It is designed for:

- IKT support
- Helpdesk
- Field support
- First-line troubleshooting
- Device health checks
- Documentation before escalation

The scanner is **read-only** and does not change system settings.

---

## Quick Run

Run this in **PowerShell**:

```powershell
irm https://raw.githubusercontent.com/soldercore/IT-Support-System-Scanner/main/main.ps1 | iex
