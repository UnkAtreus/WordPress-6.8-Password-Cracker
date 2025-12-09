# WordPress 6.8 Password Cracker

A password cracker for WordPress's new bcrypt-based password hashing system.

## What's This About?

Starting with WordPress 6.8 (February 2025), WordPress switched from their old phpass hashing to a custom bcrypt implementation. This tool lets you test password security for the new system.

### The New WordPress Password System

On February 17, 2025, [WordPress announced](https://make.wordpress.org/core/2025/02/17/wordpress-6-8-will-use-bcrypt-for-password-hashing/) they're finally moving to bcrypt after years of using phpass. But they didn't just implement vanilla bcrypt - they made it their own:

```
bcrypt(base64(hmac-sha384(key="wp-sha384", password)))
```

**Hash format:** `$wp$2y$cost$salthash`

**Why the weird format?** They prehash with SHA-384 to get around bcrypt's 72-byte limit. The `$wp$` prefix distinguishes their hashes from regular bcrypt hashes you might see from plugins.

## Installation

```bash
pip3 install bcrypt tqdm
```

## Quick Test

```bash
python3 wp-hash-cracker.py -H '$wp$2y$10$607XKVrBjPEqujeOXNwbYuOJ.gPMd2TelMMknmeV70Kap1E81Ovo6' -w wordlist.txt
```

## How To Use

**Single hash:**
```bash
python3 wp-hash-cracker.py -H '$wp$2y$10$hash...' -w wordlist.txt
```

**Multiple hashes from a file:**
```bash
python3 wp-hash-cracker.py -f hashes.txt -w wordlist.txt -t 8
```

**Save results:**
```bash
python3 wp-hash-cracker.py -f hashes.txt -w wordlist.txt -o cracked.txt
```

**having issues?** Try single-threaded mode:
```bash
python3 wp-hash-cracker.py -H '$wp$2y$10$hash...' -w wordlist.txt --single
```

## Options

```
-H, --hash          Single hash to crack
-f, --hashfile      File with multiple hashes
-w, --wordlist      Wordlist (required)
-t, --threads       Worker threads (default: your CPU cores)
--single            Single-threaded mode
-o, --output        Save results to file
```

## Features

- Parallel processing that actually works
- Real-time progress bars
- Handles large wordlists (shows loading progress for files >10MB)
- Multiple hash formats supported
- Saves results to file
- Early exit when password is found
- Works on Linux, Windows, and MacOS

## Technical Details

### How WordPress Hashes Work

1. **Prehash:** `h = HMAC-SHA384(key="wp-sha384", msg=password)`
2. **Encode:** `b = base64(h)`
3. **Hash:** `bcrypt(b, salt, cost)`
4. **Format:** Add `$wp$` prefix to distinguish from vanilla bcrypt

### Why Prehash?

Bcrypt has a 72-byte password limit. By prehashing with SHA-384 first, WordPress can handle longer passwords without truncation.
