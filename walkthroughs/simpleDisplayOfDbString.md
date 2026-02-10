# SQL Injection UNION Attack Lab Report

**Lab Title:** Retrieving Database Data Using SQL Injection UNION Attack  
**Date:** February 11, 2026  
**Objective:** Perform a SQL injection UNION attack to make a specific value appear in query results

---

## Executive Summary

This lab demonstrates the exploitation of SQL injection vulnerabilities using UNION-based attacks. The goal was to inject a specific value into the database query results by crafting a UNION SELECT statement that matches the column structure of the original query.

**Result:** Successfully injected the target value `'ab57jskd'` into the query results.

---

## Lab Objectives

- Identify the number of columns in the original SQL query
- Determine which columns contain text/string data
- Construct a UNION SELECT statement to inject a specific value into the results
- Make the provided value (`'ab57jskd'`) appear in the query output

---

## Methodology

### Phase 1: Determining the Number of Columns

**Technique:** Incremental NULL injection

The first step in a UNION attack is to determine how many columns the original query returns. This is accomplished by using UNION SELECT with varying numbers of NULL values.

**Payload Used:**
```sql
' UNION SELECT NULL,NULL,NULL--
```

**Result:** This payload executed successfully without errors, indicating the original query returns **3 columns**.

**Explanation:**
- The single quote `'` closes the original query's string parameter
- `UNION SELECT NULL,NULL,NULL` attempts to combine results with a query returning 3 NULL values
- `--` comments out the remainder of the original query
- Success means the column count matches; an error would indicate a mismatch

---

### Phase 2: Identifying Text-Compatible Columns

**Technique:** Systematic string injection

After determining the column count, the next step is to identify which columns accept string/text data. This is done by replacing NULL values one at a time with a test string.

**Payload Used:**
```sql
' UNION SELECT NULL,'abc',NULL--
```

**Result:** This payload executed successfully, confirming that **column 2 accepts string data**.

**Testing Process:**
- Column 1: `' UNION SELECT 'abc',NULL,NULL--` (likely failed or column 2 was tested first)
- **Column 2: `' UNION SELECT NULL,'abc',NULL--` ✓ Success**
- Column 3: Would test with `' UNION SELECT NULL,NULL,'abc'--` (not needed after finding column 2)

---

### Phase 3: Injecting the Target Value

**Technique:** UNION-based data injection

With the column structure identified (3 columns, column 2 accepts strings), the final step was to inject the specific target value provided by the lab.

**Target Value:** `'ab57jskd'`

**Final Payload:**
```sql
' UNION SELECT NULL,'ab57jskd',NULL--
```

**Result:** ✓ **Successfully injected** - The value `'ab57jskd'` appeared in the query results, solving the lab.

---

## Technical Analysis

### SQL Injection Breakdown

Original (vulnerable) query structure:
```sql
SELECT column1, column2, column3 FROM table WHERE condition = 'USER_INPUT'
```

After injection:
```sql
SELECT column1, column2, column3 FROM table WHERE condition = '' 
UNION SELECT NULL,'ab57jskd',NULL--'
```

### Why This Works

1. **Empty First Query:** The initial single quote creates an empty condition, potentially returning no results or minimal results from the original query

2. **UNION Operator:** Combines the results of two SELECT statements, requiring:
   - Same number of columns
   - Compatible data types in corresponding columns

3. **NULL Values:** Act as universal placeholders compatible with any data type

4. **String Injection:** The value `'ab57jskd'` is placed in column 2, which accepts text data

5. **Comment Sequence:** The `--` comment marker neutralizes any remaining SQL code from the original query

---

## Vulnerabilities Identified

### Root Cause
The application fails to properly sanitize user input before incorporating it into SQL queries, allowing attackers to inject arbitrary SQL code.

### Attack Vector
- **Input Field:** Likely a search parameter, filter, or product category selector
- **Vulnerability Type:** SQL Injection (CWE-89)
- **Severity:** Critical

---

## Security Implications

### Potential Impact

1. **Data Exfiltration:** Attackers can extract sensitive data from any table in the database
2. **Data Manipulation:** Possibility to modify or delete database records
3. **Authentication Bypass:** Potential to bypass login mechanisms
4. **Privilege Escalation:** Access to administrative data or functions
5. **Complete Database Compromise:** With sufficient permissions, full database access is possible

### Real-World Scenarios

In a production environment, instead of `'ab57jskd'`, an attacker could inject:
- `UNION SELECT username, password, email FROM users--`
- `UNION SELECT credit_card, cvv, expiry FROM payments--`
- `UNION SELECT NULL, version(), database()--` (to gather system information)

---

## Remediation Recommendations

### Immediate Actions

1. **Parameterized Queries (Prepared Statements):**
   ```python
   # Vulnerable
   query = "SELECT * FROM products WHERE category = '" + user_input + "'"
   
   # Secure
   query = "SELECT * FROM products WHERE category = ?"
   cursor.execute(query, (user_input,))
   ```

2. **Input Validation:**
   - Whitelist acceptable characters
   - Reject input containing SQL keywords or special characters
   - Implement strict type checking

3. **Stored Procedures:**
   - Use stored procedures with parameterized inputs
   - Limit database permissions for application accounts

### Long-Term Solutions

1. **Web Application Firewall (WAF):** Deploy WAF rules to detect and block SQL injection attempts

2. **Least Privilege Principle:** Database users should have minimal necessary permissions

3. **Regular Security Audits:** Conduct penetration testing and code reviews

4. **Security Training:** Educate developers on secure coding practices

5. **Error Handling:** Avoid displaying detailed database errors to users

---

## Lessons Learned

1. **UNION attacks require knowledge of:**
   - The number of columns in the original query
   - Compatible data types for each column position

2. **Systematic enumeration is key:**
   - Start with column counting
   - Identify data type compatibility
   - Construct targeted injection payloads

3. **NULL is a powerful tool:**
   - Compatible with all data types
   - Allows flexible column matching

4. **Simple vulnerabilities have severe consequences:**
   - Basic input validation failures can lead to complete database compromise

---

## Conclusion

This lab successfully demonstrated a SQL injection UNION attack by:
- Determining the query returns 3 columns
- Identifying column 2 accepts string data
- Injecting the target value `'ab57jskd'` into the results

The vulnerability highlights the critical importance of input sanitization and the use of parameterized queries in all database interactions. Organizations must prioritize secure coding practices to prevent such fundamental yet devastating security flaws.

---

## Appendix: Command Reference

| Step | Payload | Purpose | Result |
|------|---------|---------|--------|
| 1 | `' UNION SELECT NULL,NULL,NULL--` | Determine column count | Success (3 columns) |
| 2 | `' UNION SELECT NULL,'abc',NULL--` | Identify string column | Success (column 2) |
| 3 | `' UNION SELECT NULL,'ab57jskd',NULL--` | Inject target value | Lab solved ✓ |

---

**Lab Status:** ✓ COMPLETED  
**Attack Success Rate:** 100%  
**Remediation Priority:** CRITICAL