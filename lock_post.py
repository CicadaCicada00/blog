#!/usr/bin/env python3
"""
lock_post.py
Encrypts, unlocks, or re-keys blog HTML files using PBKDF2 + AES-GCM (256-bit).
Compatible with Web Crypto API and lock.js.
Supports single-file or batch rekey operations:
  python lock_post.py lock <day> <passcode>
  python lock_post.py unlock <day> <passcode>
  python lock_post.py rekey-all <old_passcode> <new_passcode>
  python lock_post.py list
"""

import sys
import os
import re
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_text(password: str, text: str) -> dict:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, text.encode('utf-8'), None)
    return {
        "salt": base64.b64encode(salt).decode('ascii'),
        "iv": base64.b64encode(iv).decode('ascii'),
        "data": base64.b64encode(ciphertext).decode('ascii')
    }

def decrypt_payload(password: str, payload: dict) -> str:
    salt = base64.b64decode(payload["salt"])
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["data"])
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(iv, ciphertext, None)
    return decrypted.decode('utf-8')

def find_file(day_arg: str, repo_dir: Path) -> Path:
    blogs_dir = repo_dir / "blogs"
    clean = str(day_arg).strip().lower()
    
    if clean.isdigit():
        target = blogs_dir / f"day{clean}.html"
    elif clean.startswith("day") and clean.endswith(".html"):
        target = blogs_dir / clean
    elif clean.startswith("day"):
        target = blogs_dir / f"{clean}.html"
    else:
        target = Path(day_arg)
        if not target.is_absolute():
            target = blogs_dir / day_arg
    
    return target

def extract_main_content(html: str) -> str:
    m = re.search(r'<main>(.*?)</main>', html, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    
    m2 = re.search(r'<main>(.*?)(?=<footer>|</body>)', html, re.DOTALL | re.IGNORECASE)
    if m2:
        return m2.group(1).strip()

    return ""

def lock_file(target_file: Path, password: str, quiet=False):
    if not target_file.exists():
        print(f"Error: File not found: {target_file}")
        sys.exit(1)

    html = target_file.read_text(encoding='utf-8')

    if "window.LOCKED_POST" in html:
        print(f"Note: {target_file.name} is already locked. If changing password, use 'rekey' or 'unlock' first.")
        return False

    title_match = re.search(r'<h1>(.*?)</h1>', html, re.DOTALL | re.IGNORECASE)
    title = title_match.group(1).strip() if title_match else target_file.stem

    main_content = extract_main_content(html)
    if not main_content:
        print(f"Error: Could not locate content inside <main> tag in {target_file.name}")
        sys.exit(1)

    main_content = re.sub(r'<p>&copy;.*?</p>', '', main_content, flags=re.IGNORECASE).strip()
    payload = encrypt_text(password, main_content)

    locked_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} (Locked)</title>
    <link rel="stylesheet" href="../style.css">
</head>
<body>
    <header>
        <h1>{title}</h1>
        <nav>
            <a href="../index.html">Home</a>
        </nav>
    </header>

    <main>
        <div id="lock-box" class="lock-card">
            <span class="lock-badge">&#128274; RESTRICTED ACCESS</span>
            <h3>This entry is private</h3>
            <p>This entry contains personal reflections restricted to approved readers. Enter the secret access code below to unlock.</p>
            
            <form class="lock-form" onsubmit="event.preventDefault(); unlockPost();">
                <input type="password" id="post-passcode" class="lock-input" placeholder="Enter access code..." autocomplete="off">
                <button type="submit" class="lock-btn">Unlock</button>
            </form>
            <div id="lock-error" class="lock-error"></div>

            <div class="lock-request">
                <span>Don't have the code? Reach out on </span>
                <a href="https://www.instagram.com/vandalised_wall/" target="_blank">Instagram (@vandalised_wall)</a>
                <span> to request access.</span>
            </div>
        </div>

        <div id="decrypted-content" style="display: none;"></div>

        <p style="margin-top: 30px;">follow my everyday blogs, youre going to witness my life ramming and unfolding infront of your eyes!!</p>
    </main>

    <footer>
        <p>&copy; 2026 My Simple Blog</p>
    </footer>

    <script>
        window.LOCKED_POST = {json.dumps(payload)};
    </script>
    <script src="../lock.js"></script>
</body>
</html>
"""

    target_file.write_text(locked_html, encoding='utf-8')
    if not quiet:
        print(f"[OK] {target_file.name} is now encrypted and locked with passcode '{password}'.")
    return True

def unlock_file(target_file: Path, password: str, quiet=False):
    if not target_file.exists():
        print(f"Error: File not found: {target_file}")
        sys.exit(1)

    html = target_file.read_text(encoding='utf-8')
    if "window.LOCKED_POST" not in html:
        if not quiet:
            print(f"{target_file.name} is already plain HTML (not locked).")
        return False

    title_match = re.search(r'<h1>(.*?)</h1>', html, re.DOTALL | re.IGNORECASE)
    title = title_match.group(1).strip() if title_match else target_file.stem

    payload_match = re.search(r'window\.LOCKED_POST\s*=\s*(\{.*?\});', html, re.DOTALL)
    if not payload_match:
        print("Error: Could not extract encryption payload from file.")
        sys.exit(1)

    payload = json.loads(payload_match.group(1))

    try:
        decrypted_content = decrypt_payload(password, payload)
    except Exception:
        if not quiet:
            print(f"Error: Incorrect passcode for {target_file.name}. Could not unlock.")
        return False

    unlocked_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="stylesheet" href="../style.css">
</head>
<body>
    <header>
        <h1>{title}</h1>
        <nav>
            <a href="../index.html">Home</a>
        </nav>
    </header>

    <main>
        {decrypted_content}
    </main>

    <footer>
        <p>&copy; 2026 My Simple Blog</p>
    </footer>
</body>
</html>
"""
    target_file.write_text(unlocked_html, encoding='utf-8')
    if not quiet:
        print(f"[OK] {target_file.name} is now restored to plain HTML.")
    return True

def list_locked_posts(repo_dir: Path):
    blogs_dir = repo_dir / "blogs"
    files = sorted(blogs_dir.glob("*.html"))
    locked = []
    plain = []
    for f in files:
        txt = f.read_text(encoding='utf-8')
        if "window.LOCKED_POST" in txt:
            locked.append(f.name)
        else:
            plain.append(f.name)

    print("\n--- Current Blog Post Status ---")
    print(f"Locked ({len(locked)}):   " + (", ".join(locked) if locked else "None"))
    print(f"Public ({len(plain)}):   " + (", ".join(plain) if plain else "None"))
    print("--------------------------------\n")

def rekey_all(repo_dir: Path, old_password: str, new_password: str):
    blogs_dir = repo_dir / "blogs"
    files = sorted(blogs_dir.glob("*.html"))
    
    locked_count = 0
    updated_count = 0
    failed_count = 0

    print(f"Scanning {len(files)} blog posts for locked entries...\n")

    for f in files:
        txt = f.read_text(encoding='utf-8')
        if "window.LOCKED_POST" in txt:
            locked_count += 1
            # Step 1: Unlock with old password
            success = unlock_file(f, old_password, quiet=True)
            if not success:
                print(f"[FAIL] {f.name}: Old passcode was incorrect. Skipped.")
                failed_count += 1
                continue
            
            # Step 2: Lock with new password
            lock_file(f, new_password, quiet=True)
            print(f"[UPDATED] {f.name}: Re-encrypted with new passcode.")
            updated_count += 1

    print(f"\nFinished! Rekeyed {updated_count}/{locked_count} locked posts.")
    if failed_count > 0:
        print(f"{failed_count} posts could not be rekeyed because the old passcode did not match.")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  lock <dayNumber> <passcode>                     # Lock a single post")
        print("  unlock <dayNumber> <passcode>                   # Unlock a single post")
        print("  rekey-all <old_passcode> <new_passcode>          # Change passcode on ALL locked posts")
        print("  list                                            # List which posts are locked vs public")
        sys.exit(1)

    action = sys.argv[1].lower()
    repo_dir = Path(__file__).resolve().parent

    if action in ("list", "status"):
        list_locked_posts(repo_dir)
        return

    if action in ("rekey-all", "change-pass", "change-password"):
        if len(sys.argv) < 4:
            print("Usage: rekey-all <old_passcode> <new_passcode>")
            sys.exit(1)
        old_pass = sys.argv[2]
        new_pass = sys.argv[3]
        rekey_all(repo_dir, old_pass, new_pass)
        return

    if len(sys.argv) < 4:
        print(f"Usage: {action} <dayNumber> <passcode>")
        sys.exit(1)

    day_arg = sys.argv[2]
    password = sys.argv[3]
    target_file = find_file(day_arg, repo_dir)

    if action == "lock":
        lock_file(target_file, password)
    elif action == "unlock":
        unlock_file(target_file, password)
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)

if __name__ == "__main__":
    main()
