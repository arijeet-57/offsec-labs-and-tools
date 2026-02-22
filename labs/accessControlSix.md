# Lab: Horizontal Privilege Escalation via GUID Enumeration

## Objective
Find carlos's GUID, use it to access his account page, and retrieve his API key.

**Credentials:** `wiener:peter`

---

## Vulnerability
Users are identified by GUIDs instead of plain usernames — which adds obscurity, but not real security. GUIDs are exposed in publicly accessible parts of the application (blog posts), making them discoverable.

> **GUID (Globally Unique Identifier)** — a 128-bit identifier used to uniquely reference resources. It cannot be reversed or brute-forced, but if leaked elsewhere in the app, it can be harvested.

---

## Steps

1. **Log in** as `wiener:peter`.
2. **Browse to the blog section** and find a post authored by `carlos`.
3. **Inspect the page source** — the author link contains carlos's GUID in the href.
4. **Navigate to the account page** and replace your GUID in the URL with carlos's.
5. **Carlos's account page loads**, revealing his API key.
6. **Submit the API key** as the solution. ✓

---

## Root Cause
Using GUIDs instead of usernames is security through obscurity. The GUIDs are still leaked through public-facing content (blog post author links), making them just as exploitable as predictable IDs.

## Remediation
- Never expose internal user identifiers in public-facing content unnecessarily.
- Enforce server-side ownership validation regardless of the ID format used.
- GUIDs alone are not an access control mechanism.