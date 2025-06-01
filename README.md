# task-3
# 🛡️ Basic Vulnerability Scan Report

## 📌 Task Overview
This task involved performing a basic vulnerability scan on a local machine to identify common security issues using a free vulnerability scanning tool.

---

## 🧰 Tools Used
- **Scanner**: Nessus Essentials (by Tenable)
- **Target**: Localhost (`192.168.56.1`)
- **Scan Duration**: 23 minutes
- **Scan Date**: 01/06/2025

---

## 📋 Executive Summary

| Severity | Number of Vulnerabilities |
|----------|---------------------------|
| Critical | 0                         |
| High     | 0                         |
| Medium   | 1                         |
| Mixed    | 1                         |
| Info     | 24                        |

---

## 🔐 Top Vulnerabilities Identified

### 1. SMB Signing Not Required
- **Severity**: Medium
- **CVE ID**: 57608
- **Description**: SMB message signing is not enforced, allowing attackers to perform man-in-the-middle (MITM) attacks.
- **Impact**: Packet tampering, credential theft, unauthorized data interception
- **Solution**: Enforce SMB signing through OS or Samba configuration.
- **Port**: 445/tcp

---

### 2. SSL Certificate Cannot Be Trusted
- **Severity**: Medium
- **CVE ID**: 51192
- **Description**: The SSL certificate used by the server is not trusted, possibly due to self-signing, expiration, or signature issues.
- **Impact**: Loss of trust, susceptibility to MITM attacks
- **Solution**: Replace with a valid SSL certificate issued by a recognized CA.
- **Port**: 8834/tcp

---

## 📸 Attachments
- 📄 `nessus_scan_report.pdf` (Exported report)
- 🖼️ `screenshots/` (Key vulnerability screenshots and scan summary)

---

## ✅ Conclusion
The scan revealed no critical or high-risk vulnerabilities, indicating a good baseline level of security. However, two medium-severity issues were found:
- **SMB Signing Not Required**
- **Untrusted SSL Certificate**

These should be remediated promptly to prevent potential network-based attacks. Future scans and regular patching are recommended to maintain system security.

---

## 📚 References
- [Nessus Documentation](https://docs.tenable.com/nessus/)
- [CVE-57608 - SMB Signing](https://www.tenable.com/plugins/nessus/57608)
- [CVE-51192 - Untrusted SSL Certificate](https://www.tenable.com/plugins/nessus/51192)

