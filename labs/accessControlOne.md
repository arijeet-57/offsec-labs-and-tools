# Lab 9: Access Control - Unprotected Admin Panel via robots.txt

## Objective
Exploit an access control vulnerability where an admin panel is unprotected and its location is disclosed in the `robots.txt` file. Delete the user `carlos` to solve the lab.

## Lab Description
This lab demonstrates a common security misconfiguration where:
- An administrative panel exists without proper authentication
- The admin panel's location is disclosed in `robots.txt`
- Any user can access administrative functions

**Goal:** Find and access the admin panel, then delete user `carlos`

---

## Background: What is robots.txt?

### Definition

**robots.txt** is a text file that webmasters create to instruct web robots (crawlers/bots) how to crawl and index pages on their website.

**Location:**
```
http://example.com/robots.txt
```

Always found in the **root directory** of a website.

### Purpose of robots.txt

**Intended Use:**
- Tell search engines which pages to index
- Prevent crawling of duplicate content
- Reduce server load from bot traffic
- Hide development/staging areas

**Common Directives:**

```
User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /temp/
Allow: /public/
```

**Breakdown:**
- `User-agent: *` - Applies to all bots
- `Disallow:` - Don't crawl these paths
- `Allow:` - Okay to crawl these paths

### Example robots.txt File

```
# Example robots.txt

User-agent: *
Disallow: /admin/
Disallow: /administrator-panel/
Disallow: /backup/
Disallow: /private/
Disallow: /temp/
Disallow: /cgi-bin/

User-agent: Googlebot
Allow: /

Sitemap: http://example.com/sitemap.xml
```

### The Security Problem

**⚠️ Critical Misconception:**

Many developers believe that listing a path in `robots.txt` **hides** it from users.

**Reality:**
- `robots.txt` is **publicly accessible**
- Anyone can read it
- It actually **advertises** sensitive paths
- It's like putting a "Don't Look Here" sign on a secret door

**What robots.txt Does:**
- ❌ Does NOT provide security
- ❌ Does NOT block human users
- ❌ Does NOT require authentication to view
- ✅ ONLY suggests to bots what not to crawl

**Security Implication:**
```
Developer thinks: "I'll hide /admin/ in robots.txt"
           ↓
Attacker reads: robots.txt and finds /admin/
           ↓
Attacker accesses: /admin/ directly
           ↓
Result: Security through obscurity FAILS
```

---

## What is Access Control?

### Definition

**Access Control** is a security technique that regulates who can view or use resources in a computing environment.

### Types of Access Control Issues

#### 1. Vertical Access Control
**What it is:** Controls access to different types of functions/resources

**Example:**
- Regular users: Can view products
- Admin users: Can add/delete products

**Vulnerability:** Regular user can access admin functions

#### 2. Horizontal Access Control
**What it is:** Controls access to resources at the same privilege level

**Example:**
- User A: Can view their own orders
- User B: Can view their own orders

**Vulnerability:** User A can view User B's orders

#### 3. Context-Dependent Access Control
**What it is:** Access depends on application state/workflow

**Example:**
- Users can edit their cart before checkout
- Users cannot edit cart after payment

**Vulnerability:** User edits cart after payment

---

## Understanding This Vulnerability

### The Two Problems

This lab demonstrates **two separate security failures**:

```
┌─────────────────────────────────────┐
│      Problem #1                      │
│  Information Disclosure              │
├─────────────────────────────────────┤
│  Admin panel path revealed in        │
│  robots.txt (publicly accessible)    │
└─────────────────────────────────────┘
              +
┌─────────────────────────────────────┐
│      Problem #2                      │
│  Broken Access Control               │
├─────────────────────────────────────┤
│  Admin panel has no authentication   │
│  Anyone can access admin functions   │
└─────────────────────────────────────┘
              =
┌─────────────────────────────────────┐
│      Critical Vulnerability          │
│  Complete Admin Access for Anyone    │
└─────────────────────────────────────┘
```

### Attack Scenario

**Step 1:** Attacker discovers the admin panel location
```
Method: Reading robots.txt
Result: /administrator-panel disclosed
```

**Step 2:** Attacker accesses the admin panel
```
No authentication required
No authorization checks
Full admin access granted
```

**Step 3:** Attacker performs admin actions
```
Delete users
Modify settings
Access sensitive data
```

---

## Lab Solution - Step by Step

### Step 1: Access the Lab

**Action:** Navigate to the lab URL in your browser

**Example:**
```
https://[LAB-ID].web-security-academy.net/
```

**Observation:**
- ✅ Normal website loads
- ✅ Appears to be a standard web application
- ✅ No obvious admin panel visible

---

### Step 2: Check robots.txt

**Action:** Append `/robots.txt` to the lab URL

**URL:**
```
https://[LAB-ID].web-security-academy.net/robots.txt
```

**How to Do This:**
1. Look at your browser's address bar
2. Add `/robots.txt` to the end
3. Press Enter

**Expected Response:**
```
User-agent: *
Disallow: /administrator-panel
```

**Analysis:**
- ✅ **robots.txt exists** and is accessible
- ✅ **Admin panel path revealed**: `/administrator-panel`
- ✅ **Security misconfiguration identified**: Sensitive path disclosed

**Why This is a Problem:**
```
Developer's Intent:
"Let's prevent search engines from indexing our admin panel"

Actual Result:
"Let's tell everyone where our admin panel is located"
```

---

### Step 3: Access the Admin Panel

**Action:** Navigate to the disclosed admin panel path

**URL:**
```
https://[LAB-ID].web-security-academy.net/administrator-panel
```

**How to Do This:**
1. In the address bar, replace `/robots.txt`
2. Type `/administrator-panel`
3. Press Enter

**Expected Result:**
```
✅ Admin panel loads successfully
✅ No login prompt appears
✅ No authentication required
✅ Full admin interface visible
```

**What You Should See:**
- Admin dashboard
- User management interface
- List of users including `carlos`
- Delete buttons next to each user

**Security Failure:**
```
Expected Behavior:
Access admin panel → Login required → Authentication check → Access granted

Actual Behavior:
Access admin panel → Direct access → No checks → Immediate access
```

---

### Step 4: Delete User Carlos

**Action:** Locate and delete the user `carlos`

**Steps:**
1. Look for the user list in the admin panel
2. Find the entry for user `carlos`
3. Click the "Delete" button next to `carlos`
4. Confirm deletion if prompted

**Visual Representation:**
```
Admin Panel
├── User Management
│   ├── User: administrator [Delete]
│   ├── User: carlos [Delete] ← Click here
│   ├── User: wiener [Delete]
│   └── ...
```

**Expected Result:**
```
✅ User carlos deleted successfully
✅ Lab marked as solved
✅ Confirmation message displayed
```

---

## Understanding the Vulnerability

### What Went Wrong?

#### Vulnerability #1: Information Disclosure

**The Mistake:**
```
robots.txt:
User-agent: *
Disallow: /administrator-panel
```

**Why It's Wrong:**
- Makes admin path **publicly known**
- No security benefit whatsoever
- Actively helps attackers
- False sense of security

**Correct Approach:**
- Don't disclose sensitive paths in robots.txt
- Use obscure, unpredictable URLs if relying on obscurity
- Better yet: Implement proper authentication

#### Vulnerability #2: Missing Access Control

**The Mistake:**
```php
// Vulnerable code (simplified)
if ($_SERVER['REQUEST_URI'] == '/administrator-panel') {
    // Show admin panel - NO AUTH CHECK!
    display_admin_panel();
}
```

**Why It's Wrong:**
- No authentication required
- No authorization check
- Anyone can access admin functions
- Complete security bypass

**Correct Approach:**
```php
// Secure code
if ($_SERVER['REQUEST_URI'] == '/administrator-panel') {
    // Check if user is logged in
    if (!is_logged_in()) {
        redirect_to_login();
        exit;
    }
    
    // Check if user is admin
    if (!is_admin($current_user)) {
        show_403_forbidden();
        exit;
    }
    
    // Only now show admin panel
    display_admin_panel();
}
```

---

## Real-World Impact

### What Attackers Can Do

With access to an unprotected admin panel, attackers can:

1. **User Management**
   - Delete user accounts
   - Create admin accounts
   - Modify user permissions
   - Lock out legitimate users

2. **Data Manipulation**
   - Modify content
   - Delete records
   - Export sensitive data
   - Plant backdoors

3. **System Control**
   - Change configurations
   - Install malware
   - Create persistent access
   - Compromise entire system

### Real-World Examples

**Common Scenarios:**

```
E-commerce Site:
- Access admin panel
- Modify product prices
- Process fraudulent refunds
- Steal customer data

Blog/CMS:
- Delete all posts
- Deface website
- Inject malicious scripts
- Create admin accounts

Banking Application:
- Modify account balances
- Transfer funds
- Access customer information
- Complete financial fraud
```

---

## Testing Methodology

### How to Find This Vulnerability

#### Step 1: Always Check robots.txt

**On Every Web Application:**
```
http://target.com/robots.txt
```

**Look For:**
- `/admin`, `/administrator`, `/admin-panel`
- `/dashboard`, `/control-panel`, `/management`
- `/backup`, `/old`, `/dev`, `/test`
- Any path that seems sensitive

#### Step 2: Test Disclosed Paths

**For Each Path Found:**
1. Navigate to the path
2. Check if accessible without login
3. Test admin functions
4. Document findings

#### Step 3: Enumerate Common Admin Paths

**Even if Not in robots.txt:**
```
/admin
/administrator
/admin-panel
/administrator-panel
/admin.php
/admin/login
/adminpanel
/control-panel
/dashboard
/management
/manager
/moderator
/webadmin
/sysadmin
/cpanel
```

### Using BurpSuite

**Automated Testing:**

1. **Spider the site**
   - Burp automatically checks robots.txt
   - Notes all disallowed paths

2. **Use Intruder**
   - Position: URL path
   - Payload: Common admin paths
   - Look for 200 OK responses

3. **Examine Responses**
   - Check for admin interfaces
   - Test functionality
   - Verify access control

---

## Prevention and Mitigation

### For Developers

#### 1. Implement Proper Authentication

```php
// Always check authentication
function require_login() {
    if (!isset($_SESSION['user_id'])) {
        http_response_code(401);
        header('Location: /login');
        exit;
    }
}
```

#### 2. Implement Authorization Checks

```php
// Check user roles/permissions
function require_admin() {
    require_login();
    
    $user = get_current_user();
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        die('Access Denied');
    }
}

// Use in admin pages
require_admin();
```

#### 3. Don't Disclose Sensitive Paths

**Bad robots.txt:**
```
User-agent: *
Disallow: /admin/          ← Reveals admin location
Disallow: /administrator/   ← Reveals another admin path
Disallow: /backup/          ← Reveals backup location
```

**Better robots.txt:**
```
User-agent: *
Disallow: /api/v1/internal/
Disallow: /temp/

# Don't mention admin paths at all!
```

#### 4. Use Unpredictable URLs (Defense in Depth)

**Instead of:**
```
/admin
/administrator-panel
```

**Consider:**
```
/dashboard/a8f3k2x9m1p5
/management/secure-portal-2f8a9c3b
```

**Note:** This is **NOT** a replacement for authentication, only an additional layer.

#### 5. Implement Multi-Factor Authentication (MFA)

```
Login → Password → MFA Code → Access Granted
```

**Benefits:**
- Even if password is compromised
- Attacker needs second factor
- Significantly increases security

#### 6. Use IP Whitelisting (When Applicable)

```apache
# Apache .htaccess
<Directory /admin>
    Order Deny,Allow
    Deny from all
    Allow from 192.168.1.0/24
    Allow from 10.0.0.50
</Directory>
```

**Limits admin access to:**
- Specific IP addresses
- Internal network only
- VPN connections

### For Organizations

#### 1. Security Audits

**Regular Checks:**
- Review robots.txt
- Test admin panel access
- Verify authentication
- Check authorization

#### 2. Penetration Testing

**Include Tests For:**
- Unprotected admin panels
- Information disclosure
- Access control bypasses
- Privilege escalation

#### 3. Security Training

**Educate Developers On:**
- Common vulnerabilities
- Secure coding practices
- Access control principles
- Security by design

---

## Key Concepts

### robots.txt Best Practices

**DO:**
- ✅ Use for SEO purposes only
- ✅ Block crawling of duplicate content
- ✅ Prevent indexing of search result pages
- ✅ Limit bot traffic on resource-intensive pages

**DON'T:**
- ❌ Use for security
- ❌ List sensitive paths
- ❌ Rely on it for access control
- ❌ Assume it hides anything

### Access Control Principles

**Three A's of Access Control:**

1. **Authentication**
   - Who are you?
   - Verify identity
   - Login required

2. **Authorization**
   - What can you do?
   - Check permissions
   - Role-based access

3. **Accounting**
   - What did you do?
   - Audit logs
   - Activity tracking

---

## Common Mistakes

### Mistake #1: Security Through Obscurity

**Wrong Thinking:**
```
"If I don't link to the admin panel, nobody will find it"
"If I hide it in robots.txt, it's protected"
"Using /admin123 instead of /admin is secure"
```

**Reality:**
- Attackers use scanners
- Common paths are well-known
- robots.txt is checked first
- Obscurity is not security

### Mistake #2: Client-Side Access Control

**Wrong Approach:**
```javascript
// JavaScript only - easily bypassed!
if (userRole === 'admin') {
    showAdminPanel();
}
```

**Bypass:**
```javascript
// Attacker in browser console
userRole = 'admin';
showAdminPanel(); // Admin panel displayed!
```

**Correct Approach:**
- Server-side checks
- Verify on every request
- Never trust client

### Mistake #3: Incomplete Authorization

**Wrong:**
```php
// Only checks on initial access
if (is_admin()) {
    $_SESSION['admin_panel_unlocked'] = true;
}

// Later actions don't re-check!
if ($_SESSION['admin_panel_unlocked']) {
    delete_user($_POST['user_id']);
}
```

**Correct:**
```php
// Check on every action
if (is_admin()) {
    delete_user($_POST['user_id']);
} else {
    die('Forbidden');
}
```

---

## Testing Checklist

- [x] Check if robots.txt exists
- [x] Review robots.txt for sensitive paths
- [x] Test each disclosed path
- [x] Verify authentication is required
- [x] Check authorization for admin functions
- [x] Test privilege escalation
- [x] Enumerate common admin paths
- [x] Document all findings
- [x] Report vulnerabilities

---

## Lab Summary

**Vulnerability Type:** Broken Access Control + Information Disclosure

**Steps to Exploit:**
1. Read `robots.txt`
2. Find admin panel path (`/administrator-panel`)
3. Access admin panel directly
4. Delete user `carlos`

**Root Causes:**
- Sensitive path disclosed in robots.txt
- No authentication on admin panel
- No authorization checks

**Impact:**
- Complete admin access
- User deletion capability
- Full system compromise potential

**Fix:**
- Implement authentication
- Add authorization checks
- Remove sensitive paths from robots.txt
- Apply defense in depth

---

## Key Takeaways

1. **robots.txt is NOT security** - It's publicly readable and helps attackers
2. **Always require authentication** - Especially for admin panels
3. **Check authorization on every action** - Not just on initial access
4. **Use defense in depth** - Multiple layers of security
5. **Security through obscurity fails** - Don't rely on hiding things
6. **Test your own applications** - Find vulnerabilities before attackers do

---

## Status
✅ **Lab Completed** - Successfully exploited unprotected admin panel disclosed in robots.txt to delete user carlos