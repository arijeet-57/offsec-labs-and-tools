# Lab: Horizontal Privilege Escalation via IDOR on Account Page

## Objective
Obtain the API key for user `carlos` by exploiting a horizontal privilege escalation vulnerability.

**Credentials:** `wiener:peter`

---

## Vulnerability
The account page uses a predictable, user-supplied `id` parameter in the URL to fetch user data. No server-side check verifies that the logged-in user matches the requested `id` — allowing any user to access another's data.

> **Horizontal Privilege Escalation** — accessing resources belonging to another user *at the same privilege level*, rather than escalating to a higher role.
>**Insecure Direct Object Reference (IDOR)**

---

## Steps

1. **Log in** as `wiener:peter`.
2. **Navigate to your account page** — note the URL contains `?id=wiener` and your API key is displayed.
3. **Change the `id` parameter** in the URL from `wiener` to `carlos`.
4. **Press Enter** — the server returns carlos's account page, including his API key.
5. **Submit the API key** as the solution. ✓

---

## Root Cause
The application trusts the `id` parameter directly from the URL without verifying it matches the authenticated session. Any user can enumerate or guess another username and retrieve their data.

## Remediation
- Derive the user identity exclusively from the server-side session, not from URL parameters.
- Enforce ownership checks: confirm the requested resource belongs to the authenticated user before returning data.