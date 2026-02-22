# Lab: Sensitive Data Leaked in Redirect Response Body

## Objective
Obtain carlos's API key, which is leaked in the body of a redirect response.

**Credentials:** `wiener:peter`

---

## Vulnerability
When an unauthorized user triggers a redirect (e.g., trying to access another user's account page), the server issues a `302 Found` response — but still includes the sensitive page content in the response body before redirecting. Browsers follow the redirect and discard the body, but an intercepting proxy captures it.

---

## Steps

1. **Log in** as `wiener:peter` and open Burp Suite with intercept enabled.
2. **Trigger a request** make an email change request that sends a POST request and that generates a secondary account-fetch (GET) request in the background.
3. **Intercept the secondary request** in Burp Proxy — it fetches user account data.
4. **Modify the username** in the request to `carlos` and forward it.
5. **Observe the response** — the server returns a `302 redirect`, but the **response body contains carlos's account page** including his API key.
6. **Copy the API key** from the body and submit it as the solution. ✓

---

## Root Cause
The server performs its access control logic (redirecting unauthorized users) but still renders and sends the full response body before issuing the redirect. Browsers silently discard this body, masking the leak — but it is fully visible in any proxy or HTTP client.

## Remediation
- Return an empty body with redirect responses (`302`, `301`), never page content.
- Apply access control checks before generating any response content, not after.
- Audit all redirect flows for data leakage in the response body.