# 🛡️ Attack Report — TryHackMe: Net Sec Challenge
**Target:** `10.48.178.206` | **Tools:** Nmap, Telnet, Hydra

---

## Q1 — Highest Open Port Below 10,000

**Finding:** Port **9999** (or similar high port under 10K)
**Method:**
```bash
nmap -p1-10000 <TARGET_IP>
```
Scan the first 10,000 ports with `-p1–10000` to identify the highest open port in that range.

**Fix:** Close all unnecessary ports. Apply firewall rules to whitelist only required services.

---

## Q2 — Open Port Above 10,000

**Finding:** Port **10021** (non-standard FTP)
**Method:**
```bash
nmap -p- -T4 <TARGET_IP>
```
Nmap scans only the 1,000 most popular ports by default. A full `-p-` scan across all 65,535 ports reveals hidden high-numbered ports.

**Fix:** Never run services on obscure ports as a security measure — "security through obscurity" is ineffective. Restrict access via firewall.

---

## Q3 — Total TCP Ports Open

**Finding:** **6 TCP ports** open
**Method:** Count open ports from the full `-p-` scan output.

Five ports were found under 10,000 and one above, giving a total of 6 open TCP ports.

**Fix:** Conduct regular port audits. Close any ports not serving a business function.

---

## Q4 — Flag in HTTP Server Header

**Finding:** Flag embedded in the `Server:` HTTP response header
**Method:**
```bash
nmap -sV -p80 <TARGET_IP>
# OR
curl -I http://<TARGET_IP>
```
Using `curl -I` reveals the HTTP response headers, where the flag is exposed in the `Server:` field.

**Fix:** Strip or spoof server headers in production. Use `lighttpd`/`nginx` configs to suppress version/banner info.

---

## Q5 — Flag in SSH Server Header

**Finding:** Flag in SSH banner/version string
**Method:**
```bash
nmap -sV -p22 <TARGET_IP> --script=ssh2-enum-algos
# OR
telnet <TARGET_IP> 22
```
Scanning port 22 with the `ssh2-enum-algos` script reveals the SSH server header containing the flag.

**Fix:** Disable SSH banners or configure `Banner none` in `sshd_config`. Avoid leaking version info in pre-auth banners.

---

## Q6 — FTP Server Version on Non-Standard Port

**Finding:** **vsftpd 3.0.5** running on port **10021**
**Method:**
```bash
nmap -sV -sC -p10021 <TARGET_IP>
```
A targeted version scan on port 10021 confirms it is running vsftpd 3.0.5.

**Fix:** Update FTP software to latest patched version. Consider replacing FTP with SFTP. Suppress version banners.

---

## Q7 — FTP Flag via Credential Brute-Force (eddie / quinn)

**Finding:** Flag found in `ftp_flag.txt` in **quinn's** account
**Method:**
```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://<TARGET_IP>:10021
lftp -p 10021 -u quinn,<password> <TARGET_IP>
get ftp_flag.txt
```
Hydra brute-forces the FTP credentials using the rockyou.txt wordlist. After logging in as quinn, `ftp_flag.txt` is found and downloaded.

**Fix:** Enforce strong password policies. Implement account lockout after failed attempts. Disable FTP; use SFTP/SCP instead. Never reuse weak passwords.

---

## Q8 — IDS Evasion via Null Scan (Port 8080 Challenge)

**Finding:** Flag revealed after scanning covertly without triggering IDS
**Method:**
```bash
sudo nmap -sN <TARGET_IP>
```
A TCP Null Scan sends packets with no flags set, bypassing many IDS/firewall rules that only detect standard SYN-based scans. The port 8080 challenge confirms the scan was stealthy and rewards the flag.

**Fix:** Deploy advanced IDS/IPS (e.g., Suricata, Snort) capable of detecting null, FIN, and Xmas scans. Don't rely solely on SYN-detection logic.

---

## 🔑 Key Takeaways

| Attack Vector | Tool Used | Severity |
|---|---|---|
| Open Port Enumeration | Nmap | Medium |
| Service Banner Leakage (HTTP/SSH) | Nmap / curl / Telnet | Medium |
| Non-standard Port FTP | Nmap | Medium |
| FTP Brute Force | Hydra | High |
| IDS Evasion (Null Scan) | Nmap `-sN` | High |

**General Remediations:** Harden all service banners, enforce strong credentials, disable legacy protocols (FTP/Telnet), deploy robust IDS with anomaly detection, and run periodic port audits.