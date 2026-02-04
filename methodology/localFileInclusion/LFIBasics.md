# File Inclusion Vulnerabilities - Complete Notes

## Table of Contents
1. [What is File Inclusion?](#what-is-file-inclusion)
2. [Understanding URL Parameters](#understanding-url-parameters)
3. [How File Inclusion Works](#how-file-inclusion-works)
4. [Directory Traversal (Path Traversal)](#directory-traversal-path-traversal)
5. [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
6. [Common Target Files](#common-target-files)
7. [Root Causes and Prevention](#root-causes-and-prevention)

---

## What is File Inclusion?

### Definition

**File Inclusion** is a vulnerability that occurs when web applications use user-controllable input to determine which files to load or include, without proper validation or sanitization.

### Purpose in Web Applications

Web applications often need to request access to files on the server for legitimate purposes:
- 📄 Loading static text files
- 🖼️ Retrieving images
- 📋 Accessing documents
- 🌐 Including language files
- ⚙️ Loading configuration files

### The Problem

When applications allow users to specify files through parameters **without proper validation**, attackers can:
- Read sensitive system files
- Access configuration files containing credentials
- Execute arbitrary code (in some cases)
- Compromise the entire system

---

## Understanding URL Parameters

### URL Structure Breakdown

A typical URL with parameters looks like this:

```
http://webapp.thm/get.php?file=userCV.pdf
```

**Component Breakdown:**

```
http://webapp.thm/get.php?file=userCV.pdf
│    │           │         │    │
│    │           │         │    └─ Parameter Value (userCV.pdf)
│    │           │         └────── Parameter Name (file)
│    │           └──────────────── File/Endpoint (get.php)
│    └──────────────────────────── Domain Name (webapp.thm)
└───────────────────────────────── Protocol (http)
```

**Detailed Components:**

| Component | Example | Description |
|-----------|---------|-------------|
| **Protocol** | `http://` | Communication protocol (HTTP/HTTPS) |
| **Domain Name** | `webapp.thm` | Server address |
| **File/Endpoint** | `get.php` | Script that processes the request |
| **Query String Marker** | `?` | Indicates start of parameters |
| **Parameter Name** | `file` | Name of the parameter |
| **Parameter Value** | `userCV.pdf` | Value being passed to the parameter |

### How Parameters Work

**Query String Parameters** are:
- Attached to the URL after the `?` symbol
- Used to pass data to the server
- Can be used to retrieve data or perform actions
- Based on user input
- Visible in the browser's address bar

**Multiple Parameters:**
```
http://webapp.thm/page.php?param1=value1&param2=value2&param3=value3
                           └────┬────┘  └────┬────┘  └────┬────┘
                            Param 1      Param 2      Param 3
```

---

## How File Inclusion Works

### Normal Request Flow

```
┌──────────────────┐
│  User / Browser  │
└────────┬─────────┘
         │
         │ HTTP Request: http://webapp.thm/get.php?file=userCV.pdf
         │
         ▼
┌──────────────────┐
│   Web Server     │
│ (Apache/Nginx)   │
└────────┬─────────┘
         │
         │ Executes get.php
         │
         ▼
┌──────────────────┐
│    get.php       │
│  (PHP Script)    │
└────────┬─────────┘
         │
         │ Reads parameter: file = userCV.pdf
         │
         ▼
┌──────────────────┐
│  App Directory   │
│ /var/www/app     │
└────────┬─────────┘
         │
         │ Navigate to CVs folder
         │
         ▼
┌──────────────────┐
│   CVs/           │
│  userCV.pdf      │
└────────┬─────────┘
         │
         │ File retrieved and returned to user
         │
         ▼
┌──────────────────┐
│  User receives   │
│  userCV.pdf      │
└──────────────────┘
```

### Vulnerable Code Example

**Basic Vulnerable PHP Code:**
```php
<?php
// Get the filename from URL parameter
$file = $_GET['file'];

// Include/load the file
include($file);
?>
```

**What This Code Does:**
1. Takes user input from the `file` parameter
2. Directly uses it in the `include()` function
3. Loads and executes/displays the file
4. **No validation or sanitization!**

**Intended Use:**
```
http://webapp.thm/get.php?file=userCV.pdf
→ Loads: userCV.pdf (legitimate file)
```

**Malicious Use:**
```
http://webapp.thm/get.php?file=/etc/passwd
→ Loads: /etc/passwd (sensitive system file!)
```

---

## Directory Traversal (Path Traversal)

### What is Directory Traversal?

**Directory Traversal** (also called Path Traversal) is an attack technique that allows attackers to:
- Read operating system resources
- Access files outside the web application's root directory
- Navigate through the server's directory structure
- Read local files on the server

### How Directory Traversal Works

Attackers exploit this by:
- Manipulating the web application's URL
- Using special character sequences
- Locating and accessing files/directories outside the intended scope

### The Dot-Dot-Slash Mechanism

**Core Concept:** The `../` sequence means "go up one directory level"

#### Understanding Directory Navigation

**Single Level Up:**
```
../
└─ Move up ONE directory
```

**Two Levels Up:**
```
../../
└─ Move up TWO directories
```

**Three Levels Up:**
```
../../../
└─ Move up THREE directories
```

### Visual Example of Directory Traversal

**Directory Structure:**
```
/ (root)
└── var/
    └── www/
        └── app/
            ├── get.php (current location)
            └── CVs/
                └── userCV.pdf
```

**Current Location:** `/var/www/app/get.php`

**Traversal Examples:**

| Payload | Result | Explanation |
|---------|--------|-------------|
| `../CVs/file.pdf` | `/var/www/app/CVs/file.pdf` | Go up 1, then into CVs |
| `../../etc/passwd` | `/var/etc/passwd` | Go up 2 levels to /var/ |
| `../../../etc/passwd` | `/etc/passwd` | Go up 3 levels to root |
| `../../../../etc/passwd` | `/etc/passwd` | Extra ../ ignored once at root |

### Practical Attack Examples

#### Linux System Example

**Target File:** `/etc/passwd`

**Current Location:** `/var/www/app/`

**Attack URL:**
```
http://webapp.thm/get.php?file=../../../../etc/passwd
```

**Path Resolution:**
```
/var/www/app/ + ../../../../etc/passwd
     ↓
/var/www/ (up 1)
     ↓
/var/ (up 2)
     ↓
/ (up 3 - at root)
     ↓
/etc/passwd (navigate to target)
```

#### Windows System Example

**Target File:** `C:\boot.ini`

**Attack Payloads:**
```
http://webapp.thm/get.php?file=../../../../boot.ini

OR

http://webapp.thm/get.php?file=../../../../windows/win.ini
```

**Note:** The exact number of `../` may vary depending on:
- Application directory structure
- Operating system version
- Web server configuration

---

## Local File Inclusion (LFI)

### Definition

**Local File Inclusion (LFI)** is a specific type of file inclusion vulnerability where:
- Web application loads files from the **local server**
- File path is determined by **user input**
- **No proper validation** is performed
- Attacker can read sensitive files (and sometimes execute code)

### Vulnerable PHP Functions

PHP functions commonly vulnerable to LFI:

| Function | Description | Risk Level |
|----------|-------------|------------|
| `include()` | Loads and executes a file | ⚠️ High |
| `include_once()` | Includes file only once | ⚠️ High |
| `require()` | Like include, but fatal error if fails | ⚠️ High |
| `require_once()` | Requires file only once | ⚠️ High |
| `file_get_contents()` | Reads file into string | ⚠️ Medium |
| `fopen()` | Opens file for reading | ⚠️ Medium |

**Important Note:** These functions are **NOT inherently faulty**. The vulnerability exists in **how user input is validated** (or not validated) before being used in these functions.

### LFI Attack Examples

#### Example 1: Basic LFI (No Protection)

**Vulnerable Backend Code:**
```php
<?php
include("languages/" . $_GET['lang']);
?>
```

**What This Code Does:**
```php
$_GET["lang"]  // Gets user input from URL parameter
include()      // Loads the file specified by user
```

**Application Setup:**
- Website supports multiple languages
- Language files stored in `languages/` folder
- Files: `EN.php`, `HIN.php`, etc.

**Normal/Intended Usage:**
```
http://webapp.thm/index.php?lang=EN.php
→ Loads: languages/EN.php ✅

http://webapp.thm/index.php?lang=HIN.php
→ Loads: languages/HIN.php ✅
```

**Malicious Usage:**
```
http://webapp.thm/index.php?lang=/etc/passwd
→ Loads: languages//etc/passwd
→ Actual: /etc/passwd (path resolved)
→ Result: Sensitive system file exposed! ❌
```

#### Example 2: Restricted Path (Still Vulnerable)

**"Improved" Vulnerable Code:**
```php
<?php
include("languages/" . $_GET['lang']);
?>
```

**Developer's Thinking:**
> "I'm restricting files to the languages/ folder. Users can only load files from there!"

**Why This Doesn't Work:**
The developer forgot about **directory traversal**!

**Attack Using Path Traversal:**

**Payload:**
```
http://webapp.thm/index.php?lang=../../../../etc/passwd
```

**What Happens:**
```php
include("languages/" . "../../../../etc/passwd");
//      becomes:
include("languages/../../../../etc/passwd");
```

**Path Resolution:**
```
/var/www/html/
    └── languages/
        └── ../../../../etc/passwd
                ↓
        /var/www/html/languages/../../../etc/passwd
                ↓
        /var/www/html/../etc/passwd
                ↓
        /var/www/etc/passwd  (if exists)
                OR
        /etc/passwd (if traversal reaches root)
```

**Result:** ❌ Still vulnerable! The restriction is easily bypassed.

### Why LFI is Dangerous

**Direct Impacts:**

1. **Information Disclosure**
   - Read sensitive configuration files
   - Access database credentials
   - View source code
   - Read user data

2. **Credential Theft**
   - Password hashes from `/etc/shadow`
   - Database passwords from config files
   - API keys and tokens
   - SSH keys

3. **Source Code Exposure**
   - Understand application logic
   - Find other vulnerabilities
   - Identify security weaknesses

4. **Remote Code Execution (RCE)**
   - If attacker can write files to server
   - LFI can be used to execute uploaded files
   - Often leads to full system compromise
   - Complete control over the server

**Attack Chain Example:**
```
LFI Vulnerability
    ↓
Read config files
    ↓
Find database credentials
    ↓
Access database
    ↓
Steal user data / admin accounts
    ↓
System compromise
```

**LFI + File Upload = RCE:**
```
Upload malicious PHP file
    ↓
Use LFI to include uploaded file
    ↓
Malicious code executes
    ↓
Remote Code Execution achieved
    ↓
Full server control
```

---

## Common Target Files

### Linux/Unix Systems

#### System Information Files

| File | Description | Sensitivity |
|------|-------------|-------------|
| `/etc/issue` | System identification message (displayed before login) | Low |
| `/etc/profile` | System-wide default variables, export variables, umask, terminal types | Medium |
| `/proc/version` | Linux kernel version information | Low |
| `/etc/hostname` | System hostname | Low |
| `/etc/timezone` | System timezone | Low |

#### User and Authentication Files

| File | Description | Sensitivity |
|------|-------------|-------------|
| `/etc/passwd` | All registered users with system access | **High** |
| `/etc/shadow` | User password hashes (requires root) | **Critical** |
| `/etc/group` | User group information | Medium |
| `/etc/sudoers` | Sudo privileges configuration | **Critical** |

#### History and Log Files

| File | Description | Sensitivity |
|------|-------------|-------------|
| `/root/.bash_history` | Root user command history | **High** |
| `/home/user/.bash_history` | User command history | **High** |
| `/var/log/apache2/access.log` | Apache access requests | Medium |
| `/var/log/apache2/error.log` | Apache error messages | Medium |
| `/var/log/auth.log` | Authentication attempts | **High** |
| `/var/log/syslog` | System logs | Medium |
| `/var/mail/root` | Root user emails | **High** |

#### SSH and Keys

| File | Description | Sensitivity |
|------|-------------|-------------|
| `/root/.ssh/id_rsa` | Root user's private SSH key | **Critical** |
| `/home/user/.ssh/id_rsa` | User's private SSH key | **Critical** |
| `/home/user/.ssh/authorized_keys` | Authorized SSH keys | **High** |
| `/etc/ssh/sshd_config` | SSH server configuration | Medium |

#### Web Server and Application Files

| File | Description | Sensitivity |
|------|-------------|-------------|
| `/var/www/html/config.php` | Application configuration | **Critical** |
| `/var/www/html/.env` | Environment variables (credentials) | **Critical** |
| `/etc/apache2/apache2.conf` | Apache configuration | Medium |
| `/etc/nginx/nginx.conf` | Nginx configuration | Medium |
| `/etc/php/php.ini` | PHP configuration | Medium |

### Windows Systems

#### Boot and System Files

| File | Description | Sensitivity |
|------|-------------|-------------|
| `C:\boot.ini` | Boot options for BIOS firmware systems | Medium |
| `C:\Windows\System32\drivers\etc\hosts` | DNS host file | Medium |
| `C:\Windows\win.ini` | Windows configuration | Low |
| `C:\Windows\System.ini` | System configuration | Low |

#### Application Files

| File | Description | Sensitivity |
|------|-------------|-------------|
| `C:\inetpub\wwwroot\web.config` | IIS web application configuration | **High** |
| `C:\xampp\apache\conf\httpd.conf` | XAMPP Apache configuration | Medium |
| `C:\wamp\bin\apache\apache2.x.x\conf\httpd.conf` | WAMP configuration | Medium |

### Example Payloads for Each File

**Linux Examples:**
```
# User information
http://webapp.thm/get.php?file=../../../../etc/passwd

# System version
http://webapp.thm/get.php?file=../../../../proc/version

# Command history
http://webapp.thm/get.php?file=../../../../root/.bash_history

# Web server logs
http://webapp.thm/get.php?file=../../../../var/log/apache2/access.log

# Application config
http://webapp.thm/get.php?file=../../../../var/www/html/config.php
```

**Windows Examples:**
```
# Boot configuration
http://webapp.thm/get.php?file=../../../../boot.ini

# Windows configuration
http://webapp.thm/get.php?file=../../../../windows/win.ini

# Hosts file
http://webapp.thm/get.php?file=../../../../Windows/System32/drivers/etc/hosts
```

---

## Root Causes and Prevention

### Root Causes of File Inclusion Vulnerabilities

#### 1. Lack of Input Validation

**The Problem:**
```php
// No validation at all!
$file = $_GET['file'];
include($file);
```

**Why It's Dangerous:**
- User input is trusted blindly
- No checks for malicious patterns
- Any file path is accepted
- Direct path to exploitation

#### 2. Insufficient Input Sanitization

**The Problem:**
```php
// Weak sanitization
$file = str_replace('../', '', $_GET['file']);
include($file);
```

**Why It's Still Vulnerable:**
- Only removes `../` once
- Can be bypassed with `....//`
- Doesn't handle all edge cases
- False sense of security

#### 3. User-Controlled Input

**The Core Issue:**
When users can control file paths through parameters, they can:
- Specify arbitrary files
- Navigate through directories
- Access sensitive data
- Execute malicious code (in some cases)

#### 4. Predictable Application Structure

**Contributing Factors:**
- Hardcoded paths
- Consistent naming patterns
- Visible directory structure
- Error messages revealing paths

### Prevention Methods

#### Method 1: Input Validation (Whitelist Approach)

**Best Practice: Use Whitelisting**

```php
<?php
// Define allowed files explicitly
$allowed_files = [
    'EN' => 'languages/english.php',
    'FR' => 'languages/french.php',
    'ES' => 'languages/spanish.php',
    'HI' => 'languages/hindi.php'
];

$lang = $_GET['lang'];

// Only allow pre-approved files
if (isset($allowed_files[$lang])) {
    include($allowed_files[$lang]);
} else {
    // Reject all other inputs
    die("Invalid language selection");
}
?>
```

**Benefits:**
- ✅ Only allows known-good inputs
- ✅ Complete control over accessible files
- ✅ No path traversal possible
- ✅ Most secure approach

#### Method 2: Input Sanitization

**Remove Dangerous Patterns:**

```php
<?php
$file = $_GET['file'];

// Remove path traversal sequences
$file = str_replace(['../', '..\\', './'], '', $file);

// Remove NULL bytes
$file = str_replace(chr(0), '', $file);

// Only allow alphanumeric and specific characters
$file = preg_replace('/[^a-zA-Z0-9._-]/', '', $file);

include("languages/" . $file . ".php");
?>
```

**Note:** Sanitization alone is often insufficient and can be bypassed.

#### Method 3: Use basename()

**Strip Directory Paths:**

```php
<?php
// basename() removes directory path, keeping only filename
$file = basename($_GET['file']);

// This prevents directory traversal
include("languages/" . $file . ".php");
?>
```

**Example:**
```php
Input:  ../../../../etc/passwd
Output: passwd (directory path stripped)
```

#### Method 4: Restrict File System Access

**PHP Configuration (php.ini):**

```ini
; Restrict PHP to specific directory
open_basedir = /var/www/html/

; Disable dangerous functions
disable_functions = system,exec,shell_exec,passthru,popen,proc_open
```

**Effect:**
- PHP cannot access files outside specified directory
- Dangerous functions are disabled
- Additional layer of security

#### Method 5: Avoid User Input in File Operations

**Don't Do This:**
```php
<?php
// Bad - user controls file path
include($_GET['file']);
?>
```

**Do This Instead:**
```php
<?php
// Good - indirect reference
$page_id = $_GET['page'];
$pages = [
    1 => 'home.php',
    2 => 'about.php',
    3 => 'contact.php'
];

if (isset($pages[$page_id])) {
    include($pages[$page_id]);
}
?>
```

### Defense in Depth Strategy

**Layer Multiple Protections:**

```
1. Input Validation (Whitelist)
        ↓
2. Input Sanitization
        ↓
3. Use basename()
        ↓
4. open_basedir Restriction
        ↓
5. File Permissions
        ↓
6. Web Application Firewall (WAF)
```

### Key Principles

1. **Never Trust User Input**
   - All user input is potentially malicious
   - Always validate and sanitize
   - Use whitelists, not blacklists

2. **Principle of Least Privilege**
   - Grant minimum necessary permissions
   - Restrict file system access
   - Limit function availability

3. **Defense in Depth**
   - Use multiple security layers
   - One layer failing shouldn't break everything
   - Combine different security measures

4. **Fail Securely**
   - Default to deny
   - Show generic error messages
   - Log security events

---

## Summary

### What We Learned

**File Inclusion Vulnerabilities:**
- Occur when applications load files based on user input
- Can be exploited to read sensitive files
- May lead to remote code execution
- Are caused by lack of input validation

**Directory Traversal:**
- Uses `../` sequences to navigate directories
- Allows access to files outside intended scope
- Works on both Linux and Windows systems
- Can bypass weak protections

**Local File Inclusion (LFI):**
- Specific type of file inclusion
- Targets local server files
- Exploits PHP include functions
- Critical security risk

**Prevention:**
- Use whitelist validation
- Sanitize user input
- Restrict file system access
- Apply defense in depth
- Never trust user input

### Critical Takeaways

1. 🚨 **Input validation is crucial** - The root cause of these vulnerabilities
2. 🛡️ **Whitelisting > Blacklisting** - Only allow known-good inputs
3. 🔒 **Multiple layers of security** - Defense in depth approach
4. ⚠️ **Functions aren't the problem** - It's how they're used
5. 📚 **Knowledge is power** - Understanding attacks helps prevent them