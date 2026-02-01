# Burp Suite - Complete Notes

## Table of Contents
1. [Burp Suite Overview](#burp-suite-overview)
2. [Dashboard Components](#dashboard-components)
3. [Settings](#settings)
4. [Proxy Module](#proxy-module)
5. [Target Module](#target-module)
6. [Repeater Module](#repeater-module)
7. [Inspector Module](#inspector-module)
8. [Workflow & Best Practices](#workflow--best-practices)

---

## Burp Suite Overview

### What is Burp Suite?
- **Purpose**: Integrated platform for web application security testing
- **Foundation**: Java-based framework
- **Focus**: API-based applications
- **Core Function**: Manipulates HTTP/HTTPS traffic between browser and web server

### Key Capabilities
- Scanning web applications for vulnerabilities
- Fuzzing inputs
- Intercepting HTTP/HTTPS traffic
- Analyzing web traffic
- Manipulating requests and responses

---

## Editions

### Burp Suite Community
- Free version
- Basic functionality
- Limited features
- Good for learning and basic testing

### Burp Suite Professional

**Features**:
- ✅ **Automated vulnerability scanner**
- ✅ **Unlimited fuzzer/brute-forcer** (no rate limiting)
- ✅ **Save projects** for future use
- ✅ **Report generation**
- ✅ **Built-in API** for tool integration
- ✅ **Unrestricted extension support**
- ✅ **Burp Collaborator** (request catcher - self-hosted or Portswigger-owned server)
- ✅ **BApp Store** (third-party modules)

---

## Dashboard Components

### Tasks Menu
**Purpose**: Define background tasks that Burp Suite performs while you use the application

**Community Edition**:
- Default: "Live Passive Crawl" task
- Automatically logs pages visited
- Sufficient for basic use

**Professional Edition**:
- All Community features
- On-demand scans
- Scheduled scans
- Custom task configuration

---

### Event Log
**What it shows**:
- Actions performed by Burp Suite
- Proxy startup information
- Connection details
- Error messages
- Extension loading status

**Use cases**:
- Troubleshooting connection issues
- Verifying proxy status
- Monitoring Burp Suite activities

---

### Issue Activity (Professional Only)
**Displays**:
- Vulnerabilities identified by automated scanner
- Ranked by severity (Critical, High, Medium, Low, Info)
- Filterable by certainty level

**Severity Levels**:
- Critical
- High
- Medium
- Low
- Informational

---

### Advisory (Professional)
**Provides**:
- Detailed vulnerability information
- References to security standards (OWASP, CWE, etc.)
- Suggested remediation steps
- Proof of concept
- Exportable reports

**Note**: May be empty in Community edition as it lacks automated scanning

---

## Settings

### User Settings
**Scope**: Entire Burp Suite installation

**Includes**:
- Display settings
- HTTP settings
- SSL/TLS settings
- Performance settings
- Hotkeys
- Extension settings

---

### Project Settings
**Scope**: Current project only

**Includes**:
- Target scope
- Session handling rules
- Macro configurations
- Task scheduler (Professional)
- Project-specific configurations

---

## Proxy Module

### Core Functionality

#### Intercepting Requests
**How it works**:
1. Requests are captured before reaching target server
2. Held in Proxy tab for review
3. Can be modified before forwarding

**Available Actions**:
- **Forward**: Send request to server
- **Drop**: Cancel request
- **Edit**: Modify request parameters
- **Send to**: Other Burp modules (Repeater, Intruder, etc.)

**Toggle Intercept**: 
- Click "Intercept is on" button to enable/disable
- Shortcut available in settings

---

### Match and Replace

**Purpose**: Automatically modify requests/responses using regex

**Use Cases**:
- Modify user agent strings
- Manipulate cookies
- Add/remove headers
- Change parameter values
- Test different input variations

**Configuration**:
1. Go to Proxy → Options
2. Scroll to "Match and Replace"
3. Add rules with:
   - Type (Request/Response header/body)
   - Match (regex pattern)
   - Replace (replacement string)

---

### Important Warnings

⚠️ **Critical: When Intercept is ON**
- Browser will hang on EVERY request
- No requests can complete without manual action
- Must forward or drop each request
- Can prevent all browsing if left on accidentally

**Best Practices**:
- Turn off intercept when not actively testing
- Use hotkey for quick toggle
- Check intercept status before browsing
- Only enable when needed

---

### Right-Click Menu Options

**Available Actions**:
- Forward request
- Drop request
- Send to Repeater (`Ctrl + R`)
- Send to Intruder (`Ctrl + I`)
- Send to Organizer
- Do intercept → Response to this request
- Don't intercept requests to this host
- Copy URL
- Copy as curl command
- Engagement tools (Discover content, Schedule task, etc.)

---

## Target Module

### Site Map

**Function**: Visual tree structure of tested web application

**Features**:
- **Auto-mapping**: Every visited page appears automatically
- **Tree structure**: Organized by domain/path
- **Color coding**: Different colors for different response codes
- **Request/Response view**: Click any item to see details

**Benefits**:
- Understand application structure
- Identify hidden pages
- Track testing progress
- Export site map

---

### Issue Definitions

**Contains**:
- Extensive list of web vulnerabilities
- Complete descriptions
- Technical details
- References (OWASP, CWE, CAPEC)
- Remediation guidance

**Use Cases**:
- Report writing
- Vulnerability research
- Learning about security issues
- Reference during manual testing
- Client communication

---

### Scope Settings

**Purpose**: Control what Burp captures and logs

**How to Set Scope**:

1. **Method 1 - From Target Tab**:
   - Switch to Target tab
   - Right-click target from list
   - Select "Add To Scope"
   - Choose to stop logging out-of-scope traffic (usually YES)

2. **Method 2 - Manual Entry**:
   - Target → Scope
   - Add protocol, host, and file
   - Use regex for advanced matching

---

### Additional Proxy Configuration for Scope

**Location**: Proxy settings → "Intercept Client Requests"

**Setting**: Enable "And URL Is in target scope"

**Result**: 
- Proxy completely ignores out-of-scope traffic
- Cleaner traffic view
- Better performance
- Focus on target application

**Benefits**:
- Reduced noise
- Faster testing
- Easier analysis
- Better organization

---

## Bypassing Client-Side Filters

### Scenario: Email Field Restrictions
**Problem**: Client-side filters prevent script elements in input fields

### Bypass Method

**Step 1**: Enable Burp Proxy + Intercept ON
```
Proxy → Intercept → Intercept is on
```

**Step 2**: Enter legitimate data
- Email: `pentester@example.thm`
- Query: `Test Attack`
- Or any valid-looking data

**Step 3**: Submit form
- Request will be intercepted
- Appears in Proxy → Intercept tab

**Step 4**: Modify captured request
- Find the email parameter
- Change email field to payload:
  ```html
  <script>alert("Succ3ssful XSS")</script>
  ```

**Step 5**: URL encode payload
- Select the payload
- Press `Ctrl + U`
- Makes special characters safe to send
- Bypasses filters

**Step 6**: Forward request
- Click "Forward" button
- Request sent to server with modified payload

**Key Insight**: 
- Client-side filters only validate in browser
- Server may not validate properly
- Burp bypasses browser validation
- Always test server-side validation

---

## Repeater Module

### Purpose
- Modify and resend intercepted requests
- Manual request crafting
- Iterative testing
- Similar to command-line tools (cURL, wget)

---

### Workflow

#### Method 1: From Proxy (Most Common)
1. Capture request in Proxy
2. Right-click → "Send to Repeater"
3. **Shortcut**: `Ctrl + R`

#### Method 2: Manual Creation
- Create requests from scratch
- Useful for testing API endpoints
- Full control over all parameters

---

### Key Features

#### Show Non-Printable Characters
**Button**: `\n` button in toolbar

**Purpose**: Display invisible characters

**Shows**:
- `\r\n` (carriage return + newline)
- Null bytes
- Tabs
- Other control characters

**Important for**:
- HTTP header interpretation
- Debugging request issues
- Understanding response structure

---

#### Response Views

**Pretty View**:
- Formatted/beautified
- Syntax highlighting
- Easy to read
- Best for JSON, XML, HTML

**Raw View**:
- Unformatted original
- Shows exact bytes
- Best for debugging
- Reveals hidden characters

**Hex View**:
- Hexadecimal representation
- Useful for binary data
- Detecting encoding issues
- Finding hidden data

**Render View** (HTML responses):
- Renders HTML in browser-like view
- Shows how page would appear
- Useful for XSS testing

---

### Request Tabs
- Multiple requests in tabs
- Easy switching between tests
- Organize testing workflow
- Compare different requests

---

### Send/Cancel Buttons
- **Send**: Execute request
- **Cancel**: Stop ongoing request
- Shows response time
- Displays status code

---

## Inspector Module

### Purpose
- **Visually organized breakdown** of requests/responses
- **Experiment with changes**
- **See real-time effects** on raw versions
- **Simplify complex edits**

---

### Request Attributes Section

**Modifiable Elements**:
- **Location** (resource path)
  - Change requested URL path
  - Example: `/api/v1/users` → `/api/v2/users`

- **Method** (GET, POST, PUT, DELETE, etc.)
  - Switch HTTP methods
  - Example: GET → POST

- **Protocol** (HTTP/1, HTTP/1.1, HTTP/2)
  - Change protocol version
  - Test protocol-specific features

**Example Modifications**:
```
Original: GET /api/users HTTP/1.1
Modified: POST /api/admin HTTP/2
```

---

### Request Query Parameters

**Definition**: Data sent via URL

**Example**:
```
https://admin.thm/?redirect=false&user=admin
```

**Parameters**:
- `redirect` = `false`
- `user` = `admin`

**Capabilities**:
- Add new parameters
- Edit existing values
- Remove parameters
- URL encode/decode values

**Use Cases**:
- Testing parameter manipulation
- SQL injection
- XSS testing
- Access control bypass

---

### Request Body Parameters

**Specific to**: POST, PUT, PATCH requests

**Contains**: Data sent in request body

**Common Formats**:
- Form data (application/x-www-form-urlencoded)
- JSON (application/json)
- XML (application/xml)
- Multipart (multipart/form-data)

**Capabilities**:
- Edit parameter values
- Add new parameters
- Remove parameters
- Change parameter order

**Example**:
```
Original:
username=admin&password=pass123

Modified:
username=admin' OR 1=1--&password=anything
```

---

### Request Cookies

**Contains**: Modifiable list of cookies

**Sent**: With each request to matching domain

**Capabilities**:
- View all cookies
- Edit cookie values
- Add new cookies
- Delete cookies
- URL encode/decode

**Use Cases**:
- Session manipulation
- Authentication bypass
- Cookie injection
- Testing cookie security

**Example**:
```
Original: session=abc123; role=user
Modified: session=abc123; role=admin
```

---

### Request Headers

**Capabilities**:
- **View** all headers
- **Modify** existing headers
- **Add** new headers
- **Remove** headers

**Common Headers**:
- User-Agent
- Authorization
- Content-Type
- Accept
- Referer
- Cookie
- Custom headers

**Use Cases**:
- Test server response to unexpected headers
- Bypass security controls
- Header injection
- Test input validation

**Example Modifications**:
```
Add:    X-Forwarded-For: 127.0.0.1
Modify: User-Agent: CustomBot/1.0
Remove: Authorization header
```

---

### Response Headers (Read-Only)

**Contains**: Headers returned by server

**Cannot Modify**: No control over server responses

**Visibility**: Only appears after sending request and receiving response

**Useful Information**:
- Server type and version
- Security headers (CSP, HSTS, X-Frame-Options)
- Content-Type
- Set-Cookie
- Cache control
- CORS headers

**Use Cases**:
- Identify server technology
- Check security configurations
- Analyze caching behavior
- Find security misconfigurations

---

## Workflow & Best Practices

### Burp Suite Workflow

```
1. Configure Proxy
   - Set browser proxy settings
   - Import Burp CA certificate
        ↓
2. Set Target Scope
   - Add target to scope
   - Configure logging
        ↓
3. Browse Application
   - Proxy captures all traffic
   - Site map builds automatically
        ↓
4. Intercept & Modify Requests
   - Enable intercept when needed
   - Modify suspicious requests
        ↓
5. Send to Repeater for Testing
   - Test different payloads
   - Analyze responses
        ↓
6. Use Inspector to Analyze
   - Visual parameter editing
   - Structured view of data
        ↓
7. Test for Vulnerabilities
   - SQLi, XSS, IDOR, etc.
   - Document findings
```

---

### Best Practices

#### General
- ✅ **Set proper scope** to avoid noise
- ✅ **Turn off intercept** when not actively testing
- ✅ **Use Repeater** for iterative testing
- ✅ **Leverage Inspector** for detailed analysis
- ✅ **Save projects** (Professional) for future reference
- ✅ **Combine tools** (Proxy → Repeater → Intruder)

#### Proxy Usage
- ✅ Always check intercept status
- ✅ Use scope to filter traffic
- ✅ Enable "Match and Replace" for common modifications
- ✅ Right-click for quick actions
- ✅ Use history to review past requests

#### Repeater Usage
- ✅ Organize tabs logically
- ✅ Name tabs descriptively
- ✅ Use Inspector for complex edits
- ✅ Compare requests side-by-side
- ✅ Document successful payloads

#### Target Usage
- ✅ Review site map regularly
- ✅ Identify untested areas
- ✅ Use scope to focus testing
- ✅ Check issue definitions for reference
- ✅ Export site map for documentation

---

### Keyboard Shortcuts

**Essential Shortcuts**:
- `Ctrl + R` - Send to Repeater
- `Ctrl + I` - Send to Intruder
- `Ctrl + U` - URL encode
- `Ctrl + Shift + U` - URL decode
- `Ctrl + F` - Find in current view
- `Ctrl + T` - New tab in Repeater

---

### Common Use Cases

#### SQL Injection Testing
1. Capture request in Proxy
2. Send to Repeater
3. Modify parameter with SQLi payload
4. Analyze response for errors
5. Refine payload iteratively

#### XSS Testing
1. Identify input fields
2. Capture request in Proxy
3. Modify with XSS payload
4. URL encode if needed
5. Check response rendering

#### Authentication Testing
1. Capture login request
2. Send to Repeater
3. Test different credentials
4. Analyze session tokens
5. Test session fixation

#### API Testing
1. Browse API documentation
2. Capture API requests
3. Modify in Repeater
4. Test different methods
5. Check authorization

---

### Troubleshooting

#### Browser Hangs
**Cause**: Intercept is ON
**Solution**: Turn off intercept or forward requests

#### Certificate Errors
**Cause**: Burp CA not installed
**Solution**: Import Burp CA certificate in browser

#### No Traffic Captured
**Cause**: Proxy not configured properly
**Solution**: Check browser proxy settings (127.0.0.1:8080)

#### Scope Issues
**Cause**: Target not in scope
**Solution**: Add target to scope or disable scope filter

---

## Advanced Features

### Extensions (BApp Store)
- Logger++
- Autorize
- ActiveScan++
- Additional scanners
- Custom tools

### Intruder (Professional)
- Automated attacks
- Fuzzing
- Brute forcing
- Parameter enumeration

### Scanner (Professional)
- Automated vulnerability scanning
- Active and passive scanning
- Custom scan configurations
- Report generation

### Collaborator (Professional)
- Out-of-band interaction detection
- Blind vulnerability detection
- Self-hosted or cloud-based

---