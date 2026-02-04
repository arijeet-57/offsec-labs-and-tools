# Lab 5: Advanced Credential Stuffing with CSRF Protection Bypass

## Objective
Perform a credential stuffing attack against a login form that is protected by CSRF tokens and session cookies. Learn to use Burp Suite Macros to automatically handle dynamic security tokens.

## Lab Description
This is an advanced variant of a credential-stuffing attack where the application has implemented additional security measures:
- **Session cookies** that change with each request
- **CSRF tokens** (loginToken) that are unique per request

We'll use **Burp Macros** to automatically extract and inject these values into each login attempt.

## What Makes This Lab Challenging?

### Security Mechanisms in Place

1. **Dynamic Session Cookies**
   - Set with every page load
   - Required for authentication
   - Changes on each request

2. **CSRF Tokens**
   - Prevents Cross-Site Request Forgery attacks
   - Hidden field in the login form
   - Regenerated with each page load
   - Must match the server-side session

### Why Standard Brute-Force Won't Work

- Each login attempt needs a **fresh** CSRF token
- Each request needs a **valid** session cookie
- These values change continuously
- Manual extraction is impractical for thousands of attempts

## What are Burp Macros?

**Burp Macros** allow you to define a set of actions that are executed repeatedly before each request. 

### Use Cases for Macros
- Extracting dynamic tokens (CSRF, anti-CSRF)
- Handling session management
- Performing multi-step authentication
- Automating complex workflows

### How Macros Work in This Attack

```
For each login attempt:
1. Macro sends GET request to /admin/login/
2. Extract new session cookie from response
3. Extract new loginToken from HTML form
4. Insert both values into the login POST request
5. Send the login attempt with fresh values
6. Repeat for next credential pair
```

## Initial Reconnaissance

### Step 1: Capture and Analyze a Login Request

Navigate to:
```
http://10.49.165.11/admin/login/
```

### Example Response

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 20 Aug 2021 22:31:16 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Set-Cookie: session=eyJ0b2tlbklEIjoiMzUyNTQ5ZjgxZDRhOTM5YjVlMTNlMjIzNmI0ZDlkOGEifQ.YSA-mQ.ZaKKsUnNsIb47sjlyux_LN8Qst0; HttpOnly; Path=/
Vary: Cookie
Front-End-Https: on
Content-Length: 3922

<form method="POST">
    <div class="form-floating mb-3">
        <input class="form-control" type="text" name=username  placeholder="Username" required>
        <label for="username">Username</label>
    </div>
    <div class="form-floating mb-3">
        <input class="form-control" type="password" name=password  placeholder="Password" required>
        <label for="password">Password</label>
    </div>
    <input type="hidden" name="loginToken" value="84c6358bbf1bd8000b6b63ab1bd77c5e">
    <div class="d-grid"><button class="btn btn-warning btn-lg" type="submit">Login!</button></div>
</form>
```

### Key Observations

1. **Session Cookie**
   ```
   Set-Cookie: session=eyJ0b2tlbklEIjoiMzUyNTQ5ZjgxZDRhOTM5YjVlMTNlMjIzNmI0ZDlkOGEifQ.YSA-mQ...
   ```

2. **CSRF Token (Hidden Field)**
   ```html
   <input type="hidden" name="loginToken" value="84c6358bbf1bd8000b6b63ab1bd77c5e">
   ```

3. **Dynamic Values Test**
   - Refresh the page multiple times
   - Notice both `session` cookie and `loginToken` change each time
   - This confirms we need dynamic extraction

## Solution - Complete Walkthrough

### Part 1: Configure Intruder (Standard Setup)

#### Step 1: Capture the Login Request

1. Navigate to `http://10.49.165.11/admin/login/`
2. Enable **Intercept** in Burp Proxy
3. Enter any username and password
4. Click **Login** to submit the form
5. Burp intercepts the POST request

**Example POST Request:**
```http
POST /admin/login/ HTTP/1.1
Host: 10.49.165.11
Cookie: session=eyJ0b2tlbklEIjoiMzUyNTQ5...
Content-Type: application/x-www-form-urlencoded
Content-Length: 89

username=admin&password=password&loginToken=84c6358bbf1bd8000b6b63ab1bd77c5e
```

#### Step 2: Send to Intruder

1. Right-click on the intercepted request
2. Select **"Send to Intruder"** (or press `Ctrl+I`)

#### Step 3: Configure Attack Type

1. Navigate to the **Intruder** tab
2. Go to the **Positions** sub-tab
3. Select attack type: **"Pitchfork"**

**Why Pitchfork?**
- We have paired username-password combinations
- Each username corresponds to a specific password
- Pitchfork tests pairs simultaneously

#### Step 4: Set Attack Positions

1. Click **"Clear §"** to remove all default positions
2. Highlight the **username** value in the request body
3. Click **"Add §"** to mark it as a position
4. Highlight the **password** value
5. Click **"Add §"** to mark it as a position

**Do NOT mark** `loginToken` or `session` as positions – the macro will handle these!

**After Configuration:**
```http
POST /admin/login/ HTTP/1.1
Host: 10.49.165.11
Cookie: session=eyJ0b2tlbklEIjoiMzUyNTQ5...
Content-Type: application/x-www-form-urlencoded

username=§admin§&password=§password§&loginToken=84c6358bbf1bd8000b6b63ab1bd77c5e
```

#### Step 5: Load Payloads

1. Switch to the **Payloads** tab
2. **Payload Set 1** (Usernames):
   - Select "Simple list"
   - Load your username wordlist
   - Or manually add usernames: `admin`, `user`, `root`, etc.

3. **Payload Set 2** (Passwords):
   - Select "Simple list"  
   - Load your password wordlist
   - Or manually add passwords: `password123`, `admin`, etc.

**Important:** Ensure both wordlists have the same number of entries for Pitchfork attack!

### Part 2: Create a Macro (Advanced Setup)

This is where the magic happens – we'll create a macro to automatically grab fresh tokens.

#### Step 1: Access Settings

1. Click on **Settings** (top-right of Burp Suite)
2. Navigate to **"Sessions"** category on the left sidebar

#### Step 2: Create the Macro

1. Scroll down to the **"Macros"** section at the bottom
2. Click the **"Add"** button
3. A new window shows your request history

**If you don't see a GET request to `/admin/login/`:**
- Open your browser
- Navigate to `http://10.49.165.11/admin/login/`
- Return to Burp and refresh the macro window

4. Select the **GET request** to `/admin/login/`
5. Click **"OK"**
6. Give your macro a descriptive name: `"Extract Login Tokens"`
7. Click **"OK"** to save

**Visual Reference:**
```
Request History → Select GET /admin/login/ → OK → Name it → OK
```

#### Step 3: Create Session Handling Rule

Now we need to tell Burp **when** and **how** to use this macro.

1. Still in the **"Sessions"** category
2. Scroll to **"Session Handling Rules"** at the top
3. Click **"Add"** to create a new rule

#### Step 4: Configure Rule Details

A new window appears with two tabs: **"Details"** and **"Scope"**

**In the Details Tab:**
1. Enter a description: `"Use Macro for Intruder Attacks"`

**Switch to the Scope Tab:**
1. **Tools Scope** section:
   - ✅ Check **"Intruder"** only
   - ❌ Uncheck all other tools (Proxy, Repeater, etc.)
   - This ensures the macro only runs during Intruder attacks

2. **URL Scope** section:
   - Option A: Select **"Use suite scope"** (if you've set a global scope)
   - Option B: Select **"Use custom scope"** and add `http://10.49.165.11/`

#### Step 5: Add Rule Action

**Switch back to the Details Tab:**

1. In the **"Rule Actions"** section, click **"Add"**
2. From the dropdown, select **"Run a Macro"**
3. In the new window, select your macro: `"Extract Login Tokens"`
4. Click **"OK"**

#### Step 6: Restrict Parameter Updates (Critical!)

By default, the macro will overwrite **ALL** parameters. We only want it to update specific ones.

**Configure Parameter Updates:**

1. Select **"Update only the following parameters and headers"**
2. Click the **"Edit"** button next to it
3. In "Enter a new item": type `loginToken`
4. Click **"Add"**
5. Click **"Close"**

**Configure Cookie Updates:**

1. Select **"Update only the following cookies"**
2. Click the **"Edit"** button next to it
3. In "Enter a new item": type `session`
4. Click **"Add"**
5. Click **"Close"**

7. Click **"OK"** to confirm the action
8. Click **"OK"** to save the session handling rule

### Macro Configuration Summary

```
┌─────────────────────────────────────┐
│         Macro Created               │
├─────────────────────────────────────┤
│ Name: Extract Login Tokens          │
│ Action: GET /admin/login/           │
│ Extracts: session cookie, loginToken│
└─────────────────────────────────────┘
           ↓
┌─────────────────────────────────────┐
│    Session Handling Rule            │
├─────────────────────────────────────┤
│ Scope: Intruder only                │
│ URL: http://10.49.165.11/           │
│ Action: Run macro before each req   │
│ Update: loginToken parameter        │
│ Update: session cookie              │
└─────────────────────────────────────┘
```

### Part 3: Execute the Attack

#### Step 1: Return to Intruder

1. Navigate back to the **Intruder** tab
2. Verify your positions are set correctly
3. Verify your payloads are loaded

#### Step 2: Start the Attack

1. Click **"Start Attack"**
2. A new window opens showing real-time results

#### Step 3: Monitor for Errors

**✅ Success Indicator:** All responses show `302` status code

**❌ Error Indicator:** You see `403 Forbidden` errors

**If you see 403 errors:**
- Your macro is NOT working properly
- Double-check the session handling rule configuration
- Verify the macro is extracting the correct values
- Ensure "Intruder" is checked in the Tools Scope

### Part 4: Identify Successful Login

#### Analyzing Results

Unlike simple login forms, this attack returns all `302` responses (redirects), making it harder to identify the successful login.

**Method: Sort by Response Length**

1. Click on the **"Length"** column header to sort by size
2. Look for responses with **significantly different lengths**
3. The successful login will typically be **shorter** or **longer** than failed attempts

**Why Different Lengths?**
- Failed login: Redirects to login page with error message
- Successful login: Redirects to admin dashboard (different content)

#### Expected Results

You'll see various response lengths:
```
302 - 1250 bytes (failed)
302 - 1248 bytes (failed)
302 - 1251 bytes (failed)
302 - 875 bytes  (SUCCESS - significantly different!)
302 - 1249 bytes (failed)
```

The outlier is your successful login!

#### Step 5: Extract Credentials

1. Click on the request with the unusual length
2. Check the **"Request"** tab to see which credentials were used
3. Note the username and password

#### Step 6: Manual Login

1. **Refresh** the login page in your browser (to get a new CSRF token)
2. Enter the credentials you discovered
3. Click **"Login"**
4. You should successfully access the admin area!

**Why refresh?** The old CSRF token from the attack is now invalid.

## Understanding the Attack Flow

### Without Macro (Won't Work)

```
1. Intruder sends: username=admin&password=pass1&loginToken=OLD_TOKEN
   ↓
2. Server validates CSRF token
   ↓
3. Token is expired/invalid
   ↓
4. Returns 403 Forbidden
   ❌ Attack fails
```

### With Macro (Works!)

```
1. Macro executes: GET /admin/login/
   ↓
2. Server responds with NEW session cookie and loginToken
   ↓
3. Macro extracts both values
   ↓
4. Intruder sends: username=admin&password=pass1&loginToken=NEW_TOKEN
   (with fresh session cookie)
   ↓
5. Server validates CSRF token
   ↓
6. Token is valid!
   ↓
7. Server checks credentials
   ↓
8. Returns 302 redirect (success or failure based on credentials)
   ✅ Attack proceeds correctly
```

## How the Macro Works Behind the Scenes

### Macro Execution Sequence

```
For each Intruder request:

Step 1: Macro Request
GET /admin/login/ HTTP/1.1
Host: 10.49.165.11

Step 2: Macro Response
HTTP/1.1 200 OK
Set-Cookie: session=NEW_SESSION_VALUE
...
<input type="hidden" name="loginToken" value="NEW_TOKEN_VALUE">

Step 3: Extract Values
- session cookie: NEW_SESSION_VALUE
- loginToken: NEW_TOKEN_VALUE

Step 4: Update Intruder Request
POST /admin/login/ HTTP/1.1
Host: 10.49.165.11
Cookie: session=NEW_SESSION_VALUE
...
username=test&password=test123&loginToken=NEW_TOKEN_VALUE

Step 5: Send Modified Request
(This happens automatically for each payload pair)
```

## Troubleshooting Guide

### Issue 1: Getting 403 Forbidden Errors

**Cause:** Macro is not running or not updating values correctly

**Solutions:**
- Verify macro exists in Settings → Sessions → Macros
- Check session handling rule is active
- Ensure "Intruder" is checked in Tools Scope
- Verify parameter names are correct: `loginToken` and `session`
- Make sure URL scope includes your target

### Issue 2: Macro Not Appearing in Dropdown

**Cause:** Macro wasn't saved properly

**Solution:**
- Recreate the macro
- Ensure you clicked "OK" at each step
- Verify it appears in the Macros list

### Issue 3: All Responses Same Length

**Cause:** May not have found the correct credentials yet

**Solutions:**
- Try a larger wordlist
- Verify wordlists are properly formatted
- Check that Pitchfork attack type is selected
- Ensure wordlists have matching entry counts

### Issue 4: Macro Updating Wrong Parameters

**Cause:** Parameter restriction not configured

**Solution:**
- Edit session handling rule
- Ensure "Update only the following parameters" is selected
- Verify `loginToken` is in the parameter list
- Verify `session` is in the cookie list

## Key Concepts Explained

### CSRF (Cross-Site Request Forgery)

**What it is:**
An attack that tricks a user into executing unwanted actions on a web application where they're authenticated.

**How tokens prevent it:**
- Server generates unique token for each session/request
- Token must be included in state-changing requests
- Attacker cannot predict or obtain valid token
- Request without valid token is rejected

**Why this makes brute-forcing harder:**
- Each attempt needs a fresh, valid token
- Tokens expire quickly
- Cannot reuse tokens from previous requests

### Session Cookies

**Purpose:**
- Maintain user state across HTTP requests
- Identify returning users
- Store session-specific data

**Why they change:**
- Security best practice
- Prevents session fixation attacks
- Ensures each interaction is fresh

### Why Recursive Grep Won't Work Here

**Recursive Grep** can extract values from responses and use them in subsequent requests, but it has limitations:

**Problem in this lab:**
- Server returns `302 Redirect` responses
- The redirect doesn't contain the new token/session
- Need to follow redirect to get the login page
- Recursive grep can't handle multi-step extraction

**Macros solve this:**
- Make a separate request to get fresh tokens
- Extract from that dedicated request
- Insert into the actual attack request

## Best Practices for Using Macros

### 1. Keep Macros Simple
- One macro = one specific task
- Don't overcomplicate the logic
- Test macros before full attacks

### 2. Proper Scoping
- Limit to specific tools (only Intruder if needed)
- Restrict to specific URLs
- Avoid unintended macro execution

### 3. Parameter Restriction
- Always specify which parameters to update
- Prevents overwriting usernames/passwords
- Maintains control over the attack

### 4. Testing
- Run a small attack first (5-10 requests)
- Verify all responses are `302`, not `403`
- Check that tokens are being updated

### 5. Documentation
- Name macros descriptively
- Document session handling rules
- Save configurations for future reference

## Prevention Measures (For Developers)

### 1. CSRF Protection
✅ **What's Working in This Lab:**
- Unique tokens per request
- Server-side validation
- Hidden form fields

✅ **Additional Improvements:**
- Rate limiting on login attempts
- Account lockout after X failed attempts
- CAPTCHA after multiple failures
- Two-factor authentication

### 2. Session Management
✅ **What's Working:**
- Session cookies regenerate
- HttpOnly flag set
- Secure session identifiers

✅ **Additional Improvements:**
- Short session timeout
- Session invalidation on logout
- Bind sessions to IP addresses

### 3. Login Protection
❌ **What Could Be Better:**
- No rate limiting (allows rapid attempts)
- No CAPTCHA
- No account lockout
- No login attempt monitoring

## Real-World Applications

### When You'll Use Macros

1. **Multi-step Authentication**
   - OAuth flows
   - SSO (Single Sign-On)
   - MFA challenges

2. **Dynamic Token Extraction**
   - CSRF tokens
   - Anti-automation tokens
   - Nonce values

3. **Session Management**
   - Refreshing expired sessions
   - Maintaining authentication
   - Handling token rotation

4. **Complex Workflows**
   - Shopping carts
   - Multi-page forms
   - Stateful applications

## Attack Summary Checklist

- [x] Capture login POST request
- [x] Send to Intruder
- [x] Set attack type to Pitchfork
- [x] Configure positions (username, password only)
- [x] Load username wordlist (Payload Set 1)
- [x] Load password wordlist (Payload Set 2)
- [x] Create macro to GET /admin/login/
- [x] Create session handling rule
- [x] Configure rule scope (Intruder only)
- [x] Add "Run a Macro" action
- [x] Restrict to update only loginToken parameter
- [x] Restrict to update only session cookie
- [x] Start attack
- [x] Verify all responses are 302 (not 403)
- [x] Sort by response length
- [x] Identify successful login (different length)
- [x] Extract credentials from successful request
- [x] Refresh login page
- [x] Manually login with discovered credentials

## Key Takeaways

1. **CSRF tokens complicate brute-forcing** - But macros provide a solution
2. **Macros automate multi-step processes** - Essential for complex attacks
3. **Session handling rules control macro behavior** - Proper scoping is critical
4. **Response length analysis** - Often more reliable than status codes
5. **Parameter restriction** - Prevents macros from breaking your attack
6. **Testing is essential** - Verify macro works before full-scale attack
7. **302 vs 403** - Status code indicates macro health

## Status
✅ **Lab Completed** - Successfully bypassed CSRF protection and performed credential stuffing using Burp Macros