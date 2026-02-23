# Lab— IDOR via Predictable Chat Transcript Filenames

## Overview

| Field | Detail |
|---|---|
| **Vulnerability** | Insecure Direct Object Reference (IDOR) |
| **Category** | Broken Access Control (OWASP A01:2021) |
| **Escalation Type** | Horizontal (user → user) |
| **Tool Used** | Burp Suite (Proxy + Repeater) |
| **Goal** | Find Carlos's password from his chat log → log in as `carlos` |

---

## Background

The application includes a **live chat feature**. After a conversation ends, users can download a transcript of their chat. The developer implemented this by saving each conversation as a plain `.txt` file on the server's filesystem, then serving it via a direct URL.

This shortcut introduced two compounding mistakes:

1. **Files are named using a predictable incrementing counter** — `1.txt`, `2.txt`, `3.txt`, and so on. Any user can guess valid filenames trivially.
2. **The download endpoint performs no authorization check** — it verifies that you're logged in, but never verifies that the transcript you're requesting actually belongs to you.

Together, these mistakes mean any authenticated user can download any other user's private chat history.

---

## How the Application Works Internally

When a chat session ends and the user clicks **View Transcript**, the browser sends:

```
GET /download-transcript/12.txt HTTP/1.1
Cookie: session=<your_session>
```

The server-side logic is roughly:

```python
def download_transcript(filename):
    filepath = "/chat_transcripts/" + filename
    return open(filepath).read()
```

Notice what's missing:

- ❌ No check that `filename` belongs to the requesting user
- ❌ No ownership mapping in the database
- ❌ No permission validation of any kind

The server's only implicit check is whether the file exists. If it does, it gets served — to anyone.

The filesystem looks something like this:

```
/chat_transcripts/
    1.txt   ← Carlos's conversation (contains his password)
    2.txt
    3.txt
    ...
    12.txt  ← Your conversation
```

---

## Vulnerability Deep Dive

### Why the filenames are guessable

The developer chose **sequential integers** as file identifiers. This is called **predictable object identification** and is a well-known anti-pattern. The moment a user can see their own filename (e.g., `12.txt`) they can immediately infer that files `1.txt` through `11.txt` exist and belong to other users.

Compare this to a secure approach — using a UUID:

```
/download-transcript/f47ac10b-58cc-4372-a567-0e02b2c3d479.txt
```

Even without authorization checks, a UUID is practically impossible to guess. Sequential integers take seconds to enumerate.

### Why authorization checks matter more than obscurity

Even UUIDs are not a substitute for proper authorization. A developer who uses UUIDs and thinks "they can't guess this" is relying on **security through obscurity** — a fundamentally fragile approach. If the UUID leaks anywhere (logs, referrer headers, shared links), the protection collapses entirely.

The correct fix is always an **explicit server-side ownership check**, regardless of how the file is named.

---

## Exploitation — Step by Step

### Step 1 — Use the chat feature and intercept the transcript request

Log in to the application. Open the chat and have a brief conversation. When finished, click **View Transcript** or **Download Transcript**. Intercept the request in Burp Suite:

```
GET /download-transcript/12.txt HTTP/1.1
Host: <lab-host>
Cookie: session=<your_session>
```

Note the filename — in this case `12.txt`. This tells you the incrementing counter is currently at 12, meaning files `1.txt` through `11.txt` likely exist and belong to other users.

### Step 2 — Send to Repeater and enumerate

Right-click → **Send to Repeater**. Start changing the filename to lower numbers:

```
GET /download-transcript/1.txt HTTP/1.1
```

Send the request. The server responds with `200 OK` and returns the full contents of Carlos's chat transcript.

### Step 3 — Extract the password

Read through the transcript. Carlos has asked the chat support bot about his credentials, and the bot has responded with his password. Extract it from the response.

### Step 4 — Log in as Carlos

Log out of your account. Log in using `carlos:<extracted_password>`. ✅

---

## Why This Works — Authentication vs. Authorization (Again)

Just like Lab 1, the server draws the wrong security boundary:

```
Authentication:  "Is there a valid session cookie?"   → ✅ checked
Authorization:   "Does this session own this file?"   → ❌ NOT checked
```

This is **horizontal privilege escalation** — both you and Carlos are regular users. You didn't gain admin access; you accessed a peer's private data. Horizontal privilege escalation is often underestimated in severity, but it can be devastating — in a real application this pattern could expose private messages, financial records, medical data, or PII for every user in the system.

---

## How Burp Suite Was Essential

Your browser's UI would never show you a link to `1.txt` — it only renders links to your own transcripts. But the browser is just a convenient interface; the actual communication happens over HTTP, which Burp sits in the middle of.

Burp let you:
1. **See the raw request** — revealing the filename pattern.
2. **Modify the request** before it reached the server — changing `12.txt` to `1.txt`.
3. **Bypass any UI restrictions** — the frontend never had to "know" about other users' files.

This is the core lesson of client-side security controls: **they can always be bypassed**. Only the server can enforce real security.

---

## How to Automate This (Real-World Breach Pattern)

In a real engagement, an attacker wouldn't manually try each number. They'd use **Burp Intruder**:

1. Send the request to Intruder.
2. Mark the filename number as the payload position: `§12§.txt`
3. Set payload type to **Numbers**, range `1` to `500`, step `1`.
4. Start the attack — Intruder sends 500 requests in seconds.
5. Filter responses by status `200` and non-zero content length.
6. Every hit is another user's private chat log.

This is exactly how real data breaches involving IDOR happen — automated enumeration dumps thousands of records in minutes.

---

## Impact

- Every user's private chat history is accessible to any other logged-in user.
- If chat logs contain sensitive information (passwords, personal details, support tickets), the entire user base is exposed.
- No special privileges required — a newly registered account can enumerate all transcripts.

---

## How to Fix

**1. Bind transcripts to user IDs, not filenames.**

Store transcript ownership in the database:

```sql
CREATE TABLE transcripts (
    id UUID PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    content TEXT,
    created_at TIMESTAMP
);
```

**2. Enforce ownership on every request.**

```python
def download_transcript(transcript_id):
    transcript = db.get_transcript(transcript_id)

    if transcript is None:
        abort(404)

    if transcript.user_id != session["authenticated_user_id"]:
        abort(403)  # Forbidden — not your transcript

    return transcript.content
```

**3. Use non-sequential, non-guessable identifiers.**

Even with authorization checks in place, replace sequential integers with UUIDs to eliminate enumeration as an attack vector entirely:

```python
import uuid
transcript_id = str(uuid.uuid4())
# e.g., "3d6f4e2a-91bc-4f3d-b8e7-5c2a1f0d9e83"
```

---

## Key Takeaway

> The server must never trust the client to request only what it's allowed to access. Every resource access must be validated server-side against the authenticated user's identity. "Users won't know the filename" is not a security control — it's wishful thinking.