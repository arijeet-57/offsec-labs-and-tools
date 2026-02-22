# Lab: Admin Panel Access via Forgeable Cookie

## Objective
Access the admin panel at `/admin` by manipulating a client-side cookie, then delete the user `carlos`.

**Credentials provided:** `wiener:peter`

---

## Vulnerability
The application uses a client-side cookie to determine whether a user is an administrator. Because this cookie is stored in the browser and not validated server-side, it can be freely modified by any user — making it a classic example of **insecure client-side authorization**.

---

## Steps

### 1. Log In
Log in using the provided credentials (`wiener` / `peter`).

### 2. Inspect the Cookie
Open browser DevTools → **Application** tab → **Cookies** → select the site.

Locate the `Admin` (or similarly named) cookie. Its value is set to `false` for a regular user.

### 3. Modify the Cookie
Change the cookie value from `false` to `true` directly in the DevTools panel.

### 4. Refresh the Page
Reload the page. The application now reads the modified cookie and treats the session as an admin.

### 5. Navigate to the Admin Panel
Go to `/admin` in the URL bar. Access is granted.

### 6. Delete User Carlos
Use the admin panel interface to delete the user `carlos`. Lab solved. ✓

---

## Root Cause
The server trusts the client-supplied `Admin` cookie without any cryptographic signature or server-side session validation. An attacker can set this value arbitrarily to escalate privileges.

## Remediation
- Never store authorization roles in unprotected client-side cookies.
- Use server-side sessions or cryptographically signed tokens (e.g., JWT with HMAC) to determine user roles.
- Treat all client-supplied data as untrusted.