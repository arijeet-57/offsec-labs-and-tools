# Lab: Privilege Escalation via JSON Role Manipulation

## Objective
Access `/admin` and delete user `carlos` by escalating privileges through a mass assignment vulnerability.

**Credentials:** `wiener:peter`

---

## Vulnerability
The API endpoint that updates user account data accepts a `roleid` field in the JSON body — and blindly applies it. An attacker can inject a higher-privileged role ID directly into the request.

---

## Steps

1. **Log in** as `wiener:peter` and navigate to the account page.
2. **Update your email** using the provided form and intercept the request in Burp Suite.
3. **Observe the response** — it contains your current `roleid` (e.g., `1`).
4. **Send the request to Repeater.** Add `"roleid": 2` to the JSON body and resend.
5. **Confirm** the response shows `roleid` is now `2`.
6. **Navigate to `/admin`** — access granted.
7. **Delete carlos.** Lab solved. ✓

---

## Root Cause
The server accepts client-controlled fields like `roleid` in update requests without stripping or validating them. This is a **mass assignment** vulnerability — the API applies all supplied fields indiscriminately.

## Remediation
- Whitelist only the fields the server should accept from clients (e.g., only `email`).
- Never derive authorization roles from user-supplied request data.
- Enforce role checks server-side based on authenticated session state only.