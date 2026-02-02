# Lab 3: IDOR Vulnerability - Ticket System Exploitation

## Objective
Exploit an Insecure Direct Object Reference (IDOR) vulnerability in a support ticket system to access tickets belonging to other users and find a flag.

## Lab Description
After gaining access to a support system, we discover that tickets are accessed via predictable integer IDs in the URL. This lab demonstrates how to use Burp Suite's Intruder to fuzz endpoint parameters and discover IDOR vulnerabilities.

## What is IDOR?

**Insecure Direct Object References (IDOR)** is a vulnerability that occurs when an application exposes references to internal implementation objects (like database keys, filenames, or directory paths) without proper access control checks.

### IDOR Characteristics
- Uses predictable identifiers (sequential numbers, simple patterns)
- Lacks proper authorization checks
- Allows unauthorized access to other users' data

## Initial Observations

### The Support System Interface

Upon logging into the support system, you are presented with:
- A table displaying various support tickets
- Clicking any row redirects to a detailed ticket view

### URL Structure Analysis

The ticket detail pages follow this format:
```
http://10.48.163.111/support/ticket/NUMBER
```

**Key Observations:**
1. Tickets use **integer identifiers** (1, 2, 3, etc.)
2. IDs are **sequential and predictable**
3. No complex or hard-to-guess identifiers (like UUIDs)

### Security Implications

This URL structure suggests two possible scenarios:

#### Scenario 1: Proper Access Control ✅
- Endpoint correctly restricts access
- Users can only view their own tickets
- Authorization checks are in place

#### Scenario 2: IDOR Vulnerability ❌
- Endpoint lacks access controls
- Any authenticated user can view any ticket
- Just changing the number grants access

## Attack Strategy

We will use **Burp Suite Intruder** to fuzz the ticket endpoint and determine if an IDOR vulnerability exists.

## Solution

### Prerequisites
- Burp Suite running and configured
- Browser proxy settings pointed to Burp
- Valid login credentials for the support system

### Step 1: Capture a Valid Request

**Important:** You must capture a request while logged in to include valid session cookies.

1. Log into the support system
2. Navigate to any ticket (e.g., `/support/ticket/1`)
3. Ensure Burp Proxy intercept is ON
4. Click on a ticket to view its details
5. Burp will intercept the GET request

**Example Request:**
```http
GET /support/ticket/1 HTTP/1.1
Host: 10.48.163.111
Cookie: session=abc123xyz789
User-Agent: Mozilla/5.0...
Accept: text/html,application/xhtml+xml...
```

### Step 2: Send to Intruder

1. Right-click on the intercepted request
2. Select "Send to Intruder" (or press `Ctrl+I`)
3. Navigate to the Intruder tab

### Step 3: Configure Attack Positions

1. Click "Clear §" to remove default positions
2. Highlight the ticket number in the URL path
3. Click "Add §" to mark it as a position

**Before:**
```http
GET /support/ticket/1 HTTP/1.1
```

**After:**
```http
GET /support/ticket/§1§ HTTP/1.1
```

### Step 4: Select Attack Type

**Question:** Which attack type is best suited for this task?

**Answer:** `Sniper`

**Reasoning:**
- We have only ONE position to test (the ticket ID)
- We want to test different numbers sequentially
- Sniper is perfect for testing a single parameter with multiple values

### Step 5: Configure Payload

1. Go to the "Payloads" tab
2. Select payload type: "Numbers"
3. Configure number range:
   - **Type:** Sequential
   - **From:** 1
   - **To:** 100
   - **Step:** 1

**Alternative:** Use a simple list
```
1
2
3
...
100
```

### Step 6: Start the Attack

1. Click "Start Attack"
2. A new window will open showing real-time results
3. Intruder will send 100 requests, one for each ticket ID

### Step 7: Analyze Results

#### Sort by Status Code

1. Click on the "Status" column header to sort
2. Look for responses with status code `200`
3. These indicate tickets that exist and are accessible

**Expected Results:**
- **200 OK** - Ticket exists and was successfully retrieved
- **404 Not Found** - Ticket does not exist
- **403 Forbidden** - Ticket exists but access is denied (proper security)
- **302 Redirect** - May indicate various states

#### Count Successful Requests

You should find that **at least five tickets** return a status code of `200`, indicating they exist and are accessible.

**This confirms the IDOR vulnerability** - you can access tickets that don't belong to you!

### Step 8: Find the Flag

#### Method 1: Using the Response Tab

1. In the Attack Results window, select each request with status `200`
2. Click on the "Response" tab
3. Click "Render" to view the page as HTML
4. Look for the flag in the ticket content

#### Method 2: Manual Browser Inspection

1. Note which ticket IDs returned status `200`
2. Manually visit each URL in your browser:
   ```
   http://10.48.163.111/support/ticket/5
   http://10.48.163.111/support/ticket/12
   http://10.48.163.111/support/ticket/23
   ...
   ```
3. Read each ticket until you find the flag

#### Method 3: Grep - Extract

1. In Intruder's "Options" tab, scroll to "Grep - Extract"
2. Click "Add"
3. Load a response that contains typical ticket content
4. Select the area where the flag would appear
5. Re-run the attack to automatically extract matching content

## Understanding the Vulnerability

### Why This is Dangerous

IDOR vulnerabilities allow attackers to:
- Access other users' private data
- Modify or delete resources they shouldn't have access to
- Escalate privileges
- Enumerate all resources in the system

### The Attack Flow

```
1. User logs in legitimately
   ↓
2. Accesses their own ticket (e.g., ticket/5)
   ↓
3. Changes URL to ticket/1, ticket/2, ticket/3...
   ↓
4. No authorization check occurs
   ↓
5. User can read all tickets in the system
```

### What Should Happen (Secure Implementation)

```python
# Pseudocode for secure implementation
def get_ticket(ticket_id, current_user):
    ticket = database.get_ticket(ticket_id)
    
    # Authorization check
    if ticket.owner != current_user:
        return "403 Forbidden - Access Denied"
    
    return ticket.content
```

### What Actually Happens (Vulnerable Implementation)

```python
# Pseudocode for vulnerable implementation
def get_ticket(ticket_id):
    ticket = database.get_ticket(ticket_id)
    
    # No authorization check!
    return ticket.content
```

## Prevention Measures

### 1. Implement Access Control Checks

Always verify that the authenticated user has permission to access the requested resource:

```python
if not user.can_access(resource):
    return HTTP 403 Forbidden
```

### 2. Use Unpredictable Identifiers

Instead of sequential integers, use:
- **UUIDs** (e.g., `a7f3e8b2-4c9d-4e1a-8f5b-2c3d4e5f6a7b`)
- **Cryptographically random tokens**
- **Hash-based identifiers**

### 3. Indirect Reference Maps

Use an indirect reference map:
```python
# User 123's tickets mapped to abstract IDs
user_tickets = {
    "ref1": ticket_5,
    "ref2": ticket_12,
    "ref3": ticket_18
}
```

### 4. Server-Side Authorization

- Never rely on client-side checks
- Always validate on the server
- Check permissions for EVERY request

### 5. Logging and Monitoring

- Log access attempts
- Monitor for unusual patterns (rapid sequential access)
- Alert on potential IDOR attacks

## Key Takeaways

1. **Sequential IDs are dangerous** - They make it easy to enumerate resources
2. **Authentication ≠ Authorization** - Being logged in doesn't mean you should access everything
3. **Intruder is perfect for IDOR testing** - Sniper attack type with number payloads
4. **Status codes reveal vulnerabilities** - 200 OK when it should be 403 Forbidden
5. **Always implement access control** - Check permissions on every request

## Lab Completion Checklist

- [x] Capture a request while logged in
- [x] Send request to Intruder
- [x] Configure position on ticket ID
- [x] Select Sniper attack type
- [x] Set payload range 1-100
- [x] Start the attack
- [x] Identify requests with status 200
- [x] Find at least five accessible tickets
- [x] Locate and retrieve the flag

## Common IDOR Locations

Be aware of IDOR vulnerabilities in:
- User profile pages (`/user/123`)
- Document access (`/document/456`)
- Order history (`/order/789`)
- API endpoints (`/api/resource/ID`)
- File downloads (`/download?file=report.pdf`)
- Admin panels (`/admin/user/999`)

## Testing Tips

### Recognizing IDOR Candidates

Look for URLs with:
- Sequential numbers
- Predictable patterns
- Direct object references
- RESTful API endpoints with IDs

### Efficient Testing

1. **Try adjacent IDs first** - If you can access ID 5, try 4 and 6
2. **Test common IDs** - Try 1, 2, 3, 100, 999, 1000
3. **Use Intruder for scale** - Automate testing of large ranges
4. **Check different HTTP methods** - GET, POST, PUT, DELETE
5. **Test with different privilege levels** - Regular user, admin, guest

## Status
✅ **Lab Completed** - Successfully exploited IDOR vulnerability and retrieved the flag