# Lab 1: SQL Injection Vulnerability Allowing Login Bypass

## Objective
Login as the administrator user by exploiting an SQL injection vulnerability in the login page.

## Lab Description
This lab contains a login page with username and password fields. The goal is to bypass the authentication mechanism and login as the administrator without knowing the actual password.

## Solution

### Tools Required
- No BurpSuite needed
- Can be performed directly in the browser

### Attack Steps

1. **Navigate to the login page**
   - Locate the username and password fields

2. **Inject SQL payload in the username field**
   ```sql
   administrator'--
   ```

3. **Enter any value in the password field**
   - The password field is required by frontend JavaScript validation
   - Enter any random value (e.g., "password123")

4. **Submit the form**

## How It Works

### The SQL Injection Payload
```sql
administrator'--
```

**Breakdown:**
- `administrator` - The username we want to login as
- `'` - Single quote to close the username string in the SQL query
- `--` - SQL comment syntax that comments out everything after it

### Behind the Scenes

**Original SQL Query (likely):**
```sql
SELECT * FROM users WHERE username='[INPUT]' AND password='[INPUT]'
```

**After Injection:**
```sql
SELECT * FROM users WHERE username='administrator'--' AND password='anything'
```

**Effective Query:**
```sql
SELECT * FROM users WHERE username='administrator'
```

The `--` comments out the password check, allowing us to bypass authentication.

### Why We Need to Enter a Password
- The password field has a `required` attribute in the HTML
- This is a **frontend validation** (JavaScript)
- The backend doesn't actually check the password due to our SQL injection
- Any value will work since it gets commented out in the SQL query

## Key Takeaways

1. **SQL Comments**: The `--` operator in SQL comments out everything after it
2. **String Termination**: The single quote `'` closes the string in the SQL query
3. **Frontend vs Backend Validation**: Frontend validation (required fields) doesn't protect against SQL injection
4. **Authentication Bypass**: By commenting out the password check, we bypass the authentication mechanism

## Prevention

To prevent this vulnerability:
- Use **parameterized queries** (prepared statements)
- Implement **input validation** and sanitization
- Use an **ORM** (Object-Relational Mapping) framework
- Apply the **principle of least privilege** for database users
- Implement **Web Application Firewall (WAF)** rules

## Status
✅ **Lab Completed** - Successfully logged in as administrator