# Lab— IDOR via Masked Password Field

## Overview

| Field | Detail |
|---|---|
| **Vulnerability** | Insecure Direct Object Reference (IDOR) |
| **Category** | Broken Access Control (OWASP A01:2021) |
| **Escalation Type** | Horizontal → Vertical (user → admin) |
| **Tool Used** | Burp Suite (Proxy + Repeater) |
| **Credentials** | `wiener:peter` |
| **Goal** | Retrieve administrator password → delete user `carlos` |

---

## Background

The application has an **account settings page** that displays the user's current password pre-filled inside a masked `<input type="password">` field. This is a UX pattern meant to show users their saved password without making them retype it.

The critical mistake: the password value is embedded directly in the **server's HTML response**. Masking an input field only hides it visually in the browser — the underlying value is fully accessible in the DOM and in the raw HTTP response. Any tool that bypasses the browser UI (Burp, curl, DevTools) can read it instantly.

Compound this with the fact that the account page accepts a user-controlled `id` parameter to determine **whose** account to render — and you have a direct path to any user's password.

---

## Vulnerability Deep Dive

### What the server does

When you visit the account page, a request is made similar to:

```
GET /my-account?id=wiener HTTP/1.1
Cookie: session=<your_session_token>
```

The server uses the `id` parameter to fetch account data from the database and renders it into HTML, including:

```html
<input type="password" name="password" value="peter">
```

### What the server should do but doesn't

The server should verify:

> "Does the `id` in the request match the user who owns the session cookie?"

Instead, it trusts the client-supplied `id` parameter unconditionally. This means any authenticated user can request any other user's account page simply by changing the `id` value.

---

## Exploitation — Step by Step

### Step 1 — Inspect the masked field via DevTools

Log in as `wiener:peter`. Navigate to the account/profile page. Open browser DevTools (`F12`) → Elements tab. Find the password input:

```html
<input type="password" value="peter" name="password">
```

The plaintext value is right there. This confirms the server is embedding passwords in HTML responses.

### Step 2 — Trigger a request and capture it in Burp

Enable Burp Proxy intercept. Perform any account action — changing the email address works well because it triggers a clean GET request to reload the account page. Burp captures:

```
GET /my-account?id=wiener HTTP/1.1
Host: <lab-host>
Cookie: session=<wiener_session>
```

### Step 3 — Send to Repeater and change the ID

Right-click → **Send to Repeater**. In the Repeater tab, modify the request:

```
GET /my-account?id=administrator HTTP/1.1
Host: <lab-host>
Cookie: session=<wiener_session>
```

Note: **wiener's session cookie is still being used.** We are not logging in as admin — we are simply telling the server to fetch the admin's account data while authenticated as wiener.

### Step 4 — Read the password from the response

Hit **Send**. The server returns `200 OK` with the administrator's account page, including:

```html
<input type="password" value="ugodv1bs9fj5gvp35o19" name="password">
```

**Administrator password recovered: `ugodv1bs9fj5gvp35o19`**

### Step 5 — Log in as administrator and delete carlos

1. Log out of `wiener`.
2. Log in with `administrator:ugodv1bs9fj5gvp35o19`.
3. Navigate to the **Admin Panel**.
4. Delete user `carlos`. ✅

---

## Why This Works — The Authorization Gap

The server performs **authentication** (it checks that you have a valid session) but fails at **authorization** (it never checks that your session is allowed to access the requested user's data).

```
Authentication:  "Are you logged in?"           → ✅ checked
Authorization:   "Are you allowed to see this?" → ❌ NOT checked
```

This is one of the most common and impactful bugs in web applications. The distinction between these two concepts is fundamental:

- **Authentication** = proving who you are.
- **Authorization** = proving you're allowed to do what you're trying to do.

A valid session proves identity — it does not automatically grant access to every resource on the server.

---

## Impact

- Any authenticated user can read any other user's **plaintext password**.
- Since the admin account is reachable the same way, this is a full **vertical privilege escalation** — regular user → administrator.
- From admin, an attacker can take over the entire application: create/delete accounts, access all data, modify application settings.

---

## How to Fix

**1. Ignore the client-supplied `id` — derive identity from the session.**

Instead of:
```python
# INSECURE — trusts user input
user_id = request.params["id"]
account = db.get_account(user_id)
```

Do:
```python
# SECURE — identity derived from server-controlled session
user_id = session["authenticated_user_id"]
account = db.get_account(user_id)
```

**2. Never return passwords in HTTP responses — ever.**

Passwords should only travel one way: from the user into the server during login or password change. They should never be echoed back to the client, masked or otherwise. Use a static placeholder if you need visual feedback:

```html
<!-- Never do this -->
<input type="password" value="actualpassword123">

<!-- Do this instead -->
<input type="password" placeholder="••••••••">
```

**3. If you must accept user IDs from the client, enforce ownership.**

```python
requested_id = request.params["id"]
if requested_id != session["authenticated_user_id"] and not session["is_admin"]:
    abort(403)
```

---

## Key Takeaway

> A masked input field is a UI trick, not a security control. The browser is fully controlled by the user — anything the server sends to it can be read. Security must be enforced on the **server side**, never delegated to the client.