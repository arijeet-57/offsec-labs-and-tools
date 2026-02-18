# Lab 10: Access Control - Unprotected Admin Panel with Unpredictable URL

## Objective
Exploit an access control vulnerability where an admin panel with an unpredictable URL is disclosed in the page's JavaScript source code. Delete user `carlos` to solve the lab.

## Lab Description
This lab demonstrates a security misconfiguration where:
- An admin panel exists with a seemingly "secure" unpredictable URL
- The URL is hardcoded in client-side JavaScript
- No authentication is required to access the admin panel
- Any user can find and access administrative functions by viewing source code

**Goal:** Find the hidden admin panel URL in the page source and delete user `carlos`

---

## Understanding the Vulnerability

### Security Through Obscurity - The Wrong Approach

**Developer's Flawed Logic:**
```
"If I use an unpredictable URL like /admin-b9enjm instead of /admin,
attackers won't find it!"
```

**Why This Fails:**
- 🚫 URL is embedded in client-side code
- 🚫 Client-side code is publicly accessible
- 🚫 Anyone can view page source
- 🚫 Obscurity is not security

### The Two Security Failures

```
┌─────────────────────────────────────────┐
│         Failure #1                       │
│   Information Disclosure                 │
├─────────────────────────────────────────┤
│  Admin URL hardcoded in JavaScript       │
│  Visible to anyone who views source      │
└─────────────────────────────────────────┘
                +
┌─────────────────────────────────────────┐
│         Failure #2                       │
│   Broken Access Control                  │
├─────────────────────────────────────────┤
│  No authentication on admin panel        │
│  Anyone with URL can access admin        │
└─────────────────────────────────────────┘
                =
┌─────────────────────────────────────────┐
│     Critical Security Breach             │
│  Complete Admin Access for Anyone        │
└─────────────────────────────────────────┘
```

---

## Background: Client-Side Code Security

### What is Client-Side Code?

**Client-Side Code** is code that runs in the user's browser:
- HTML
- JavaScript
- CSS

**Key Characteristic:** Everything is **visible** to the user.

### Common Misconception

**Wrong Belief:**
```
"If I hide something in JavaScript, users won't find it"
```

**Reality:**
```
Every single line of JavaScript is downloaded to the user's browser
and can be easily viewed, copied, and analyzed.
```

### How to View Page Source

**Method 1: Right-Click Menu**
```
1. Right-click anywhere on the page
2. Select "View Page Source" or "Inspect"
```

**Method 2: Keyboard Shortcut**
```
Chrome/Firefox: Ctrl+U (Windows/Linux) or Cmd+Option+U (Mac)
Inspect Element: Ctrl+Shift+I or F12
```

**Method 3: URL Bar**
```
view-source:https://example.com
```

### What You Can Find in Source Code

**Sensitive Information Often Exposed:**
- 🔍 Hidden URLs and endpoints
- 🔍 API keys and tokens
- 🔍 Internal comments
- 🔍 Debug information
- 🔍 Application logic
- 🔍 Database queries
- 🔍 File paths
- 🔍 Version information

---

## Analyzing the Vulnerable Code

### The JavaScript Code

Looking at the page source, we find this critical section:

```javascript
<script>
var isAdmin = false;
if (isAdmin) {
   var topLinksTag = document.getElementsByClassName("top-links")[0];
   var adminPanelTag = document.createElement('a');
   adminPanelTag.setAttribute('href', '/admin-b9enjm');
   adminPanelTag.innerText = 'Admin panel';
   topLinksTag.append(adminPanelTag);
   var pTag = document.createElement('p');
   pTag.innerText = '|';
   topLinksTag.appendChild(pTag);
}
</script>
```

### Code Breakdown

**Line-by-Line Analysis:**

```javascript
var isAdmin = false;
```
**Purpose:** Checks if current user is an admin  
**Problem:** Client-side check (easily bypassed)

```javascript
if (isAdmin) {
```
**Purpose:** Only show admin link if user is admin  
**Problem:** Code inside is still visible to everyone!

```javascript
adminPanelTag.setAttribute('href', '/admin-b9enjm');
```
**🚨 CRITICAL LINE:** This reveals the admin panel URL!  
**Admin URL:** `/admin-b9enjm`

```javascript
adminPanelTag.innerText = 'Admin panel';
topLinksTag.append(adminPanelTag);
```
**Purpose:** Create and add the admin link to navigation  
**Result:** Link only appears if `isAdmin = true`

### What the Developer Intended

```
┌─────────────────────────────┐
│   Regular User              │
│   isAdmin = false           │
├─────────────────────────────┤
│   Navigation Bar:           │
│   [Home] [My Account]       │
│                             │
│   Admin link: NOT shown     │
└─────────────────────────────┘

┌─────────────────────────────┐
│   Admin User                │
│   isAdmin = true            │
├─────────────────────────────┤
│   Navigation Bar:           │
│   [Home] [Admin] [Account]  │
│                             │
│   Admin link: Shown         │
└─────────────────────────────┘
```

### What Actually Happens

```
┌──────────────────────────────────┐
│   Any User                        │
│   (Checks page source)            │
├──────────────────────────────────┤
│   Finds in JavaScript:            │
│   href='/admin-b9enjm'           │
│                                   │
│   Navigates to:                   │
│   /admin-b9enjm                  │
│                                   │
│   Result:                         │
│   Full admin access! ❌           │
└──────────────────────────────────┘
```

---

## Lab Solution - Step by Step

### Step 1: Access the Lab

**Action:** Navigate to the lab URL

**URL Format:**
```
https://[LAB-ID].web-security-academy.net/
```

**Initial Observation:**
- ✅ E-commerce website loads
- ✅ Product catalog visible
- ✅ Navigation shows: Home | My Account
- ❌ No admin panel visible in navigation

---

### Step 2: View Page Source

**Method 1: Right-Click Method**
```
1. Right-click anywhere on the page
2. Select "View Page Source"
```

**Method 2: Keyboard Shortcut**
```
Press: Ctrl+U (Windows/Linux)
   or: Cmd+Option+U (Mac)
```

**Method 3: Developer Tools**
```
1. Press F12 to open Developer Tools
2. Click on "Sources" or "Debugger" tab
3. Browse to the main HTML file
```

**Expected Result:**
```
✅ New tab/window opens showing HTML source code
✅ You can now read all the HTML and JavaScript
```

---

### Step 3: Search for Admin References

**Action:** Search the source code for admin-related keywords

**Search Method:**
```
1. Press Ctrl+F (Cmd+F on Mac)
2. Type: "admin"
3. Press Enter to find matches
```

**What to Look For:**
- URLs containing "admin"
- Variables named "admin"
- Comments mentioning "admin"
- Function names with "admin"

**Alternative Search Terms:**
```
- "admin"
- "administrator"
- "panel"
- "dashboard"
- "/admin"
```

---

### Step 4: Locate the Admin URL

**Finding the JavaScript Code:**

Search for "admin" in the source and you'll find:

```javascript
<script>
var isAdmin = false;
if (isAdmin) {
   var topLinksTag = document.getElementsByClassName("top-links")[0];
   var adminPanelTag = document.createElement('a');
   adminPanelTag.setAttribute('href', '/admin-b9enjm');  // ← HERE!
   adminPanelTag.innerText = 'Admin panel';
   topLinksTag.append(adminPanelTag);
   var pTag = document.createElement('p');
   pTag.innerText = '|';
   topLinksTag.appendChild(pTag);
}
</script>
```

**Key Line:**
```javascript
adminPanelTag.setAttribute('href', '/admin-b9enjm');
```

**Admin URL Discovered:** `/admin-b9enjm`

**Visual in Source Code:**
```
Line 45:  <script>
Line 46:  var isAdmin = false;
Line 47:  if (isAdmin) {
Line 48:     var topLinksTag = document.getElementsByClassName("top-links")[0];
Line 49:     var adminPanelTag = document.createElement('a');
Line 50:     adminPanelTag.setAttribute('href', '/admin-b9enjm'); ← FOUND IT!
Line 51:     adminPanelTag.innerText = 'Admin panel';
```

---

### Step 5: Access the Admin Panel

**Action:** Navigate to the discovered admin URL

**Complete URL:**
```
https://[LAB-ID].web-security-academy.net/admin-b9enjm
```

**How to Navigate:**
```
Method 1: Type URL in address bar
1. Click on the browser's address bar
2. Replace everything after .net/ with: admin-b9enjm
3. Press Enter

Method 2: Direct navigation
1. Copy the admin URL from source: /admin-b9enjm
2. Append it to the base URL
3. Press Enter
```

**Expected Result:**
```
✅ Admin panel loads successfully
✅ No login page appears
✅ No authentication required
✅ Admin interface is fully accessible
```

**What You Should See:**
```
┌─────────────────────────────────────┐
│        Admin Panel                   │
├─────────────────────────────────────┤
│                                      │
│  User Management                     │
│                                      │
│  Users:                              │
│  ├─ administrator    [Delete]        │
│  ├─ carlos          [Delete] ← Click │
│  └─ wiener          [Delete]         │
│                                      │
└─────────────────────────────────────┘
```

---

### Step 6: Delete User Carlos

**Action:** Locate and delete the user `carlos`

**Steps:**
```
1. Look for the user list in the admin panel
2. Find the row for user "carlos"
3. Click the [Delete] button next to carlos
4. Confirm deletion if prompted
```

**Visual Guide:**
```
Admin Panel > User Management
├── User: administrator
│   └── [Delete] button
│
├── User: carlos        ← Target user
│   └── [Delete] button ← Click here!
│
└── User: wiener
    └── [Delete] button
```

**Expected Outcome:**
```
✅ Confirmation: "User carlos has been deleted"
✅ Carlos removed from user list
✅ Lab status changes to "Solved"
✅ Success banner appears
```

---

## Understanding Why This is Vulnerable

### Problem #1: Client-Side URL Storage

**The Code:**
```javascript
adminPanelTag.setAttribute('href', '/admin-b9enjm');
```

**Why It's Wrong:**
```
Location: Client-side JavaScript
Visibility: Public (anyone can view)
Security: ZERO (cannot hide client-side code)
Result: Admin URL leaked to everyone
```

**Secure Alternative:**
```javascript
// Server-side check (pseudo-code)
if (user.isAdmin()) {
    // Only send admin URL to actual admins
    echo '<a href="/admin-panel">Admin Panel</a>';
}
```

### Problem #2: Client-Side Authorization

**The Vulnerable Logic:**
```javascript
var isAdmin = false;
if (isAdmin) {
    // Show admin link
}
```

**Why It Fails:**
```
Check Location: Client-side (browser)
Controlled By: User
Can Be Modified: YES (easily)
Security Level: None
```

**Client-Side Bypass Example:**
```javascript
// Attacker in browser console:
isAdmin = true;  // Change variable
// Now the link appears!

// But in this lab, we don't even need to do this
// We can just use the URL directly
```

### Problem #3: No Server-Side Authentication

**What Happens:**
```
User requests: /admin-b9enjm
         ↓
Server checks: Nothing!
         ↓
Server returns: Admin panel
         ↓
Result: Anyone can access
```

**What Should Happen:**
```
User requests: /admin-b9enjm
         ↓
Server checks: Is user logged in?
         ↓
         NO → Redirect to login
         YES → Check: Is user admin?
                ↓
                NO → Show 403 Forbidden
                YES → Show admin panel
```

---

## Real-World Impact

### What Attackers Can Discover

**In Client-Side Code:**
```javascript
// API endpoints
fetch('https://api.internal.com/v2/secret-data');

// Hidden features
if (betaUser) { unlockFeature(); }

// Admin URLs
adminPanel.href = '/super-secret-admin-xyz123';

// API keys (yes, really!)
const API_KEY = 'sk-abc123-xyz789-secret';

// Internal paths
const CONFIG_PATH = '/internal/config.json';
```

### Common Sensitive Data Found in Source

**Real Examples:**

1. **API Keys**
   ```javascript
   const googleMapsKey = "AIzaSyDxvL2nKmH3jU...";
   const stripeKey = "pk_live_51Hxyz...";
   ```

2. **Database Connection Strings**
   ```javascript
   const dbUrl = "mongodb://admin:pass123@db.company.com";
   ```

3. **Internal Endpoints**
   ```javascript
   const adminAPI = "https://admin-api.internal.company.com";
   ```

4. **Debug Information**
   ```javascript
   console.log("User ID: " + userId);
   console.log("Session token: " + sessionToken);
   ```

5. **Hidden Features**
   ```javascript
   if (window.location.hash === '#debug') {
       enableDebugMode();
   }
   ```

---

## Testing Methodology

### How to Find This Vulnerability

#### Step 1: Always View Page Source

**On Every Application:**
```
1. View main page source
2. Check included JavaScript files
3. Examine inline <script> tags
4. Look at commented-out code
```

#### Step 2: Search for Keywords

**Search Terms:**
```
- admin
- administrator
- panel
- dashboard
- secret
- hidden
- internal
- dev
- debug
- test
- api
- key
- token
- password
- config
```

#### Step 3: Examine JavaScript Files

**Check External Scripts:**
```html
<script src="/js/main.js"></script>
<script src="/js/admin.js"></script>  ← Check this!
<script src="/js/config.js"></script> ← And this!
```

**How to Access:**
```
1. Find script src in page source
2. Copy the path
3. Navigate to: https://site.com/js/main.js
4. Read the JavaScript code
```

#### Step 4: Use Browser Developer Tools

**Network Tab:**
```
1. Open DevTools (F12)
2. Go to Network tab
3. Reload page
4. Examine all JavaScript files loaded
5. Click each to view source
```

**Sources Tab:**
```
1. Open DevTools (F12)
2. Go to Sources/Debugger tab
3. Browse file tree on left
4. Read all JavaScript files
```

---

## Using BurpSuite for Discovery

### Method 1: Proxy History

**Steps:**
```
1. Configure browser to use Burp proxy
2. Browse the target application
3. In Burp, go to Proxy > HTTP History
4. Look for JavaScript files
5. Right-click > Send to Repeater
6. Examine response in Repeater
```

### Method 2: Target Site Map

**Steps:**
```
1. In Burp, go to Target > Site map
2. Expand the target domain
3. Look for .js files
4. Right-click > View response
5. Search for sensitive data
```

### Method 3: Engagement Tools

**Spider/Crawler:**
```
1. Right-click on target in Site map
2. Select "Spider this host"
3. Burp will automatically find all JavaScript
4. Review discovered resources
```

**Content Discovery:**
```
1. Right-click on target
2. Select "Discover content"
3. Burp will find common paths
4. Check discovered JavaScript files
```

---

## Prevention and Mitigation

### For Developers

#### 1. Never Store Secrets Client-Side

**DON'T DO THIS:**
```javascript
// ❌ BAD - Visible to everyone
var adminUrl = '/admin-secret-panel';
var apiKey = 'abc123xyz789';
var dbPassword = 'superSecret123';
```

**DO THIS:**
```javascript
// ✅ GOOD - Server-side only
// These values never sent to client
```

#### 2. Server-Side Authorization

**Secure Implementation:**
```php
<?php
// admin-panel.php
session_start();

// Check authentication
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    header('Location: /login');
    exit;
}

// Check authorization
$user = get_user($_SESSION['user_id']);
if ($user['role'] !== 'admin') {
    http_response_code(403);
    die('Access Denied');
}

// Only now show admin panel
display_admin_panel();
?>
```

#### 3. Don't Use Obscure URLs for Security

**Wrong Approach:**
```
/admin              → Too obvious
/admin-b9enjm       → Obscure but not secure
/admin-xyz123-abc   → Still not secure
```

**Right Approach:**
```
Any URL + Proper authentication + Authorization checks = Secure
```

#### 4. Minimize Client-Side Logic

**Bad:**
```javascript
// Client decides what user can see
if (userRole === 'admin') {
    showAdminPanel();
}
```

**Good:**
```javascript
// Server decides, client just renders
fetch('/api/navigation')
    .then(r => r.json())
    .then(nav => renderNavigation(nav));

// Server only returns admin links to admins
```

#### 5. Remove Debug Code

**Before Production:**
```javascript
// ❌ Remove these before deploying!
console.log("Admin URL:", adminUrl);
console.log("User object:", user);
console.log("Session data:", session);

// Debug features
if (DEBUG_MODE) {
    enableAllFeatures();
}
```

**Production Code:**
```javascript
// ✅ Clean production code
// No debug logs
// No debug features
// No commented-out code
```

### Security Headers

**Content Security Policy:**
```
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' https://trusted-cdn.com;
```

**Benefits:**
- Controls what JavaScript can run
- Prevents inline script injection
- Reduces XSS risk

---

## Common Developer Mistakes

### Mistake #1: Security Through Obscurity

**Wrong Thinking:**
```
"If I use a random URL like /admin-xyz123,
hackers won't find it!"
```

**Reality:**
```
Obscurity ≠ Security
Random URLs ≠ Protection
Hidden ≠ Secure
```

### Mistake #2: Trusting Client-Side Checks

**Wrong Code:**
```javascript
// Client-side check
if (userRole === 'admin') {
    window.location.href = '/admin';
}
```

**Problem:**
```
User can:
- Modify userRole variable
- Directly navigate to /admin
- Bypass client-side logic
```

### Mistake #3: Hardcoding Sensitive Data

**Examples:**
```javascript
// ❌ All visible to attackers
const DB_HOST = "database.internal.com";
const API_SECRET = "abc123";
const ADMIN_PASSWORD = "temp123";
```

### Mistake #4: Leaving Debug Code

**Bad Practice:**
```javascript
// ❌ Debug code left in production
console.log("Current user:", currentUser);
console.log("All users:", allUsersArray);
if (location.hash === "#debug") {
    showAllData();
}
```

---

## Advanced Discovery Techniques

### Technique 1: JavaScript Beautification

**Minified Code:**
```javascript
var a=!1;if(a){var b=document.getElementsByClassName("top-links")[0],c=document.createElement("a");c.setAttribute("href","/admin-b9enjm")}
```

**Beautified (Readable):**
```javascript
var isAdmin = false;
if (isAdmin) {
    var topLinksTag = document.getElementsByClassName("top-links")[0];
    var adminPanelTag = document.createElement("a");
    adminPanelTag.setAttribute("href", "/admin-b9enjm");
}
```

**Tools:**
- [jsbeautifier.org](https://jsbeautifier.org/)
- Browser DevTools (Pretty Print button)
- Burp Decoder

### Technique 2: Regular Expression Searches

**Search Patterns:**
```regex
/admin[^"'\s]*/gi          # Admin URLs
/api[^"'\s]*/gi            # API endpoints
/[a-f0-9-]{36}/gi          # UUIDs
/sk_[a-zA-Z0-9]+/gi        # API keys
```

### Technique 3: Source Map Analysis

**If source maps exist:**
```
main.js.map  ← Original unminified source
```

**Contains:**
- Original variable names
- Original file structure
- Comments from development
- Potentially sensitive info

---

## Testing Checklist

- [x] View page source (Ctrl+U)
- [x] Search for "admin" keywords
- [x] Check all inline `<script>` tags
- [x] Examine external JavaScript files
- [x] Look for commented-out code
- [x] Search for API keys/tokens
- [x] Check for debug code
- [x] Test discovered URLs
- [x] Verify access control
- [x] Document findings

---

## Lab Summary

**Vulnerability Type:** Broken Access Control + Information Disclosure

**Discovery Method:**
1. View page source
2. Search for "admin"
3. Find admin URL in JavaScript: `/admin-b9enjm`

**Exploitation:**
1. Navigate to `/admin-b9enjm`
2. Access admin panel (no auth required)
3. Delete user `carlos`

**Root Causes:**
- Admin URL hardcoded in client-side JavaScript
- No authentication on admin panel
- Security through obscurity
- Client-side authorization logic

**Impact:**
- Complete admin access
- User deletion capability
- System compromise

**Prevention:**
- Server-side authentication required
- Server-side authorization checks
- Never store sensitive URLs client-side
- Remove debug code before production

---

## Key Takeaways

1. 🔍 **Always view page source** - Developers leave secrets everywhere
2. 🚫 **Client-side code is public** - Never trust client-side security
3. 🔐 **Authentication must be server-side** - Client checks mean nothing
4. 🎲 **Obscurity ≠ Security** - Random URLs without auth are useless
5. 🧹 **Clean your code** - Remove debug info, comments, and secrets
6. 📚 **Defense in depth** - Multiple security layers required
7. ⚠️ **Test your own apps** - Find vulnerabilities before attackers do

---

## Comparison: Lab 9 vs Lab 10

| Aspect | Lab 9 (robots.txt) | Lab 10 (Source Code) |
|--------|-------------------|---------------------|
| **Discovery** | robots.txt file | JavaScript source |
| **URL** | `/administrator-panel` | `/admin-b9enjm` |
| **Obscurity** | Obvious path | Random string |
| **Disclosure** | robots.txt | Inline script |
| **Access Control** | None | None |
| **Fix** | Don't list in robots.txt | Server-side auth |

---

## Status
✅ **Lab Completed** - Successfully discovered admin panel URL in JavaScript source code and deleted user carlos