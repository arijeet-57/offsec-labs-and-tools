# Burp Suite Intruder - Comprehensive Guide

## Overview

Burp Suite's Intruder module is a powerful tool for automated and customizable attacks. It allows you to modify specific parts of a request and perform repetitive tests with variations of input data. Intruder is particularly useful for:

- **Fuzzing**: Testing various inputs to discover vulnerabilities
- **Brute-forcing**: Testing multiple credentials or values systematically
- **Parameter testing**: Identifying how different values affect application behavior

## What is Intruder?

Intruder is Burp Suite's built-in fuzzing tool that enables:
- Automated request modification
- Repetitive testing with input variations
- Systematic vulnerability discovery

### Common Use Cases

1. **Brute-forcing login forms** - Substituting username/password fields with wordlist values
2. **Fuzzing attacks** - Testing subdirectories, endpoints, or virtual hosts using wordlists
3. **Parameter enumeration** - Testing various parameter values to identify vulnerabilities
4. **Session testing** - Validating session tokens and authentication mechanisms

### Comparison to CLI Tools

Intruder's functionality is comparable to command-line tools like:
- **Wfuzz**
- **ffuf**
- **Burp Intruder** (GUI-based advantage)

## Accessing Intruder

### How to Send Requests to Intruder

**Method 1: Keyboard Shortcut**
```
Ctrl + I
```

**Method 2: Right-click Menu**
1. Right-click on any request in Proxy, Repeater, or other modules
2. Select "Send to Intruder"

## Understanding Positions

### What are Positions?

Positions are the parts of a request where payloads will be inserted. They are marked with section marks: `§`

**Example:**
```http
POST /login HTTP/1.1
Host: example.com

username=§admin§&password=§password123§
```

### Position Control Buttons

The Intruder interface provides three key buttons for managing positions:

| Button | Function |
|--------|----------|
| **Add §** | Manually define new positions by highlighting text and clicking the button |
| **Clear §** | Remove all defined positions for a clean slate |
| **Auto §** | Automatically identify likely positions based on the request |

### How to Use Positions

1. **Clear default positions** - Click "Clear §" to start fresh
2. **Highlight target text** - Select the part of the request you want to fuzz
3. **Add position** - Click "Add §" to mark it as a position
4. **Verify** - Ensure section marks (§) appear at start and end of each position

## Attack Types

Intruder offers four attack types, each with specific use cases:

### 1. Sniper Attack

**Description:** The default and most commonly used attack type.

**How it Works:**
- Cycles through payloads one at a time
- Inserts one payload at a time into each position
- Iterates through all payloads linearly

**Use Case:** Precise and focused testing of individual parameters

**Formula:**
```
Total Requests = numberOfWords × numberOfPositions
```

**Example:**
- Positions: 2 (username, password)
- Payloads: 100 words
- Total Requests: 200

**Request Pattern:**
```
Position 1: admin     | Position 2: password
Position 1: user      | Position 2: password
Position 1: root      | Position 2: password
...
Position 1: admin     | Position 2: 123456
Position 1: admin     | Position 2: letmein
```

### 2. Battering Ram Attack

**Description:** Sends all payloads simultaneously.

**How it Works:**
- Same payload inserted into ALL positions at once
- Useful for testing race conditions
- All positions receive identical values

**Use Case:** Testing when all parameters should have the same value

**Example:**
```
Request 1: username=admin&password=admin
Request 2: username=user&password=user
Request 3: username=test&password=test
```

### 3. Pitchfork Attack

**Description:** Tests multiple positions with different payload sets simultaneously.

**How it Works:**
- Uses one payload set per position (up to 20 maximum)
- Iterates through payload sets in parallel
- Stops when the shortest list is exhausted

**Important:** Payload sets should ideally have the same length. If lengths differ, Intruder stops when the shortest list completes.

**Formula:**
```
Total Requests = Length of shortest payload set
```

**Example:**

**Payload Set 1 (Usernames):**
- joel
- harriet
- alex

**Payload Set 2 (Passwords):**
- J03l
- Emma1815
- Sk1ll

**Request Pattern:**

| Request # | Request Body |
|-----------|--------------|
| 1 | `username=joel&password=J03l` |
| 2 | `username=harriet&password=Emma1815` |
| 3 | `username=alex&password=Sk1ll` |

**Use Case:** Testing known username-password pairs or correlated data

### 4. Cluster Bomb Attack

**Description:** Tests every possible combination of payloads across all positions.

**How it Works:**
- Iterates through each payload set individually
- Tests every possible combination
- Generates significant traffic

**Formula:**
```
Total Requests = Product of payload counts in each set
```

**Example:**

**Payload Set 1 (Usernames):** 3 items
**Payload Set 2 (Passwords):** 3 items
**Total Requests:** 3 × 3 = 9

**Request Pattern:**
```
username=joel&password=J03l
username=joel&password=Emma1815
username=joel&password=Sk1ll
username=harriet&password=J03l
username=harriet&password=Emma1815
username=harriet&password=Sk1ll
username=alex&password=J03l
username=alex&password=Emma1815
username=alex&password=Sk1ll
```

**Use Case:** Credential brute-forcing when username-password mapping is unknown

## Configuring Payloads

### Payload Sets

- Each position can have its own payload set (in Pitchfork and Cluster Bomb)
- Payloads can be loaded from:
  - Wordlists (files)
  - Built-in lists
  - Runtime file
  - Custom lists (manual entry)

### Payload Types

Common payload types include:
- **Simple list** - Basic wordlist
- **Runtime file** - Read from file during attack
- **Numbers** - Sequential or random numbers
- **Character substitution** - Modify base word with variations
- **Case modification** - Test different cases

## Analyzing Results

### The Results Window

When the attack starts, a new window displays:
- Request number
- Payload values
- Status code
- Error messages
- Length (bytes)
- Response times

### Identifying Successful Requests

Since many applications return the same status code for both successful and failed attempts, use alternative indicators:

#### 1. Response Length
- Click the "Length" column header to sort by byte size
- Look for anomalies (shorter or longer responses)
- Failed attempts often include extra error messages, headers, or session reset logic

#### 2. Status Codes
- Look for different status codes (200 vs 302, 401, etc.)
- Note: Not always reliable for authentication

#### 3. Response Content
- Examine the "Response" tab for successful requests
- Look for success messages, redirects, or different page content

#### 4. Grep - Match
- Define custom patterns to identify successful responses
- Set up in "Options" tab before starting the attack

### Sorting and Filtering

- **Sort by column** - Click column headers
- **Filter results** - Use the filter bar to show/hide specific responses
- **Compare responses** - Select multiple requests to compare side-by-side

## Best Practices

### 1. Start Small
- Test with a small payload set first
- Verify the attack is working correctly
- Then scale up to full wordlists

### 2. Use Appropriate Attack Types
- **Sniper** - Single parameter testing
- **Pitchfork** - Known pairs of data
- **Cluster Bomb** - Unknown combinations

### 3. Monitor Response Indicators
- Don't rely solely on status codes
- Use length, timing, and content analysis
- Set up Grep patterns for automated detection

### 4. Respect Rate Limits
- Configure thread count appropriately
- Add delays between requests if needed
- Avoid overwhelming the target server

### 5. Save Your Work
- Save attack configurations for reuse
- Export results for documentation
- Keep track of successful payloads

## Common Pitfalls

1. **Not clearing default positions** - Always clear and set your own positions
2. **Wrong attack type** - Cluster Bomb when Sniper would suffice (wastes time)
3. **Ignoring response length** - Often more reliable than status codes
4. **Too many threads** - Can crash the application or get you blocked
5. **Not URL encoding** - Some payloads need proper encoding

## Attack Type Selection Flowchart

```
Do you need to test combinations?
├─ No → Use Sniper
└─ Yes
    ├─ Do you have paired data? (username→password)
    │   └─ Yes → Use Pitchfork
    └─ No → Do you need ALL combinations?
        ├─ Yes → Use Cluster Bomb
        └─ No → Use Sniper or Battering Ram
```

## Key Takeaways

- **Intruder** is a powerful fuzzing and brute-forcing tool
- **Four attack types** serve different purposes
- **Positions** define where payloads are inserted (marked with §)
- **Response analysis** is crucial - don't just rely on status codes
- **Choose the right attack type** to avoid wasting time and resources

## Related Tools

- **Repeater** - Manual request modification and testing
- **Decoder** - Encode/decode payloads
- **Comparer** - Compare responses to identify differences
- **Proxy** - Capture requests to send to Intruder