#!/usr/bin/env python3
"""
WordPress Custom Bcrypt Password Cracker (Parallel Version)
Based on: bcrypt(base64(hmac-sha384(key="wp-sha384", password)))

MacOS Note: If multiprocessing hangs on MacOS, use --single flag or set:
  export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
"""

import hmac
import base64
import bcrypt
import sys
import argparse
from multiprocessing import Pool, Manager, cpu_count
from tqdm import tqdm

WORDPRESS_KEY = b"wp-sha384"  # fixed key used by WP for HMAC-SHA384


def wp_prehash(password: str) -> bytes:
    """
    Compute: base64( HMAC-SHA384("wp-sha384", password) )
    Returns bytes ready for bcrypt().
    """
    h = hmac.digest(WORDPRESS_KEY, password.encode('utf-8', errors='ignore'), "sha384")
    return base64.b64encode(h)


def worker_init(shared_dict, target_bcrypt_hash):
    """Initialize worker process with shared data"""
    global found_flag, bcrypt_hash_global
    found_flag = shared_dict
    bcrypt_hash_global = target_bcrypt_hash


def check_password_batch(batch_data):
    """
    Worker function to check a batch of passwords
    Returns tuple: (found_password, passwords_checked)
    """
    passwords, batch_size = batch_data
    checked = 0
    
    for password in passwords:
        # Check if another process found it
        if found_flag.get('found', False):
            return (None, checked)
        
        checked += 1
        
        try:
            prehash = wp_prehash(password)
            if bcrypt.checkpw(prehash, bcrypt_hash_global):
                found_flag['found'] = True
                found_flag['password'] = password
                return (password, checked)
        except Exception:
            continue
    
    return (None, checked)


def chunk_wordlist(wordlist, num_chunks):
    """Split wordlist into roughly equal chunks"""
    chunk_size = max(1, len(wordlist) // num_chunks)
    chunks = []
    
    for i in range(0, len(wordlist), chunk_size):
        chunks.append(wordlist[i:i + chunk_size])
    
    return chunks


def crack_wp_hash_parallel(target_hash: str, wordlist_path: str, num_workers: int = None):
    """
    Crack WordPress hash using parallel processing
    """
    if not target_hash.startswith("$wp$2y$"):
        print("[!] Not a valid WordPress bcrypt(sha384→base64) hash.")
        print("[!] Hash must start with $wp$2y$")
        return None

    # Convert WP format → real bcrypt hash for python
    # $wp$2y$10$salt22charrest.........  →  $2y$10$salt22charrest.........
    bcrypt_hash = target_hash.replace("$wp$", "$").encode()

    if num_workers is None:
        num_workers = cpu_count()

    print(f"[*] Target hash: {target_hash}")
    print(f"[*] Converted bcrypt: {bcrypt_hash.decode()}")
    print(f"[*] Loading wordlist: {wordlist_path}")

    # Load wordlist into memory with progress indicator
    try:
        # Check file size first
        import os
        file_size = os.path.getsize(wordlist_path)
        
        if file_size > 10 * 1024 * 1024:  # > 10MB
            print(f"[*] Large wordlist detected ({file_size / (1024*1024):.1f}MB), loading...")
            
        wordlist = []
        with open(wordlist_path, "r", encoding='utf-8', errors="ignore") as f:
            if file_size > 10 * 1024 * 1024:
                # Show progress for large files
                from tqdm import tqdm as tqdm_load
                for line in tqdm_load(f, desc="Loading", unit=" lines", unit_scale=True):
                    stripped = line.strip()
                    if stripped:
                        wordlist.append(stripped)
            else:
                # Fast load for small files
                wordlist = [line.strip() for line in f if line.strip()]
                
    except FileNotFoundError:
        print(f"[!] Could not open wordlist: {wordlist_path}")
        return None

    total_passwords = len(wordlist)
    print(f"[+] Loaded {total_passwords:,} passwords")
    print(f"[*] Using {num_workers} parallel workers")
    print(f"[*] Initializing workers...")
    print()

    # Create chunks for parallel processing
    # For small wordlists, use fewer chunks. For large ones, use more for better progress updates
    if total_passwords < 1000:
        # Small wordlist: use simple chunking (workers * 2)
        num_chunks = min(num_workers * 2, total_passwords)
    else:
        # Large wordlist: aim for 100-500 passwords per chunk for better progress
        chunk_target_size = max(100, min(500, total_passwords // (num_workers * 20)))
        num_chunks = max(num_workers * 4, total_passwords // chunk_target_size)
    
    num_chunks = max(1, min(num_chunks, total_passwords))  # Ensure at least 1 chunk, no more than passwords
    
    # Split wordlist into chunks for parallel processing
    chunks = chunk_wordlist(wordlist, num_chunks)
    
    # Add chunk size to each chunk for progress tracking
    chunk_data = [(chunk, len(chunk)) for chunk in chunks]
    
    # Create shared dictionary for inter-process communication
    manager = Manager()
    shared_dict = manager.dict()
    shared_dict['found'] = False
    shared_dict['password'] = None

    # Create progress bar
    pbar = tqdm(total=total_passwords, desc="Cracking", unit="pwd",
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]')

    found_password = None

    # Start parallel cracking
    with Pool(processes=num_workers, initializer=worker_init, 
              initargs=(shared_dict, bcrypt_hash)) as pool:
        
        try:
            for result, checked in pool.imap_unordered(check_password_batch, chunk_data, chunksize=1):
                # Update progress with actual passwords checked
                pbar.update(checked)
                
                if result:
                    found_password = result
                    pbar.close()
                    pool.terminate()
                    pool.join()
                    break
                    
                # Check if another worker found it
                if shared_dict.get('found', False):
                    if found_password is None:
                        found_password = shared_dict.get('password')
                    pbar.close()
                    pool.terminate()
                    pool.join()
                    break
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            pbar.close()
            pool.terminate()
            pool.join()
            return None
    
    pbar.close()
    
    if found_password:
        print(f"\n[+] PASSWORD FOUND: {found_password}")
        return found_password
    else:
        print("\n[!] Password not found in wordlist.")
        return None


def crack_wp_hash_single(target_hash: str, wordlist_path: str):
    """
    Single-threaded version for comparison
    """
    if not target_hash.startswith("$wp$2y$"):
        print("[!] Not a valid WordPress bcrypt(sha384→base64) hash.")
        return None

    bcrypt_hash = target_hash.replace("$wp$", "$").encode()

    print(f"[*] Target hash: {target_hash}")
    print(f"[*] Converted bcrypt: {bcrypt_hash.decode()}")
    print(f"[*] Loading wordlist: {wordlist_path}")

    try:
        # Check file size first
        import os
        file_size = os.path.getsize(wordlist_path)
        
        if file_size > 10 * 1024 * 1024:  # > 10MB
            print(f"[*] Large wordlist detected ({file_size / (1024*1024):.1f}MB), loading...")
            
        wordlist = []
        with open(wordlist_path, "r", encoding='utf-8', errors="ignore") as f:
            if file_size > 10 * 1024 * 1024:
                # Show progress for large files
                from tqdm import tqdm as tqdm_load
                for line in tqdm_load(f, desc="Loading", unit=" lines", unit_scale=True):
                    stripped = line.strip()
                    if stripped:
                        wordlist.append(stripped)
            else:
                # Fast load for small files
                wordlist = [line.strip() for line in f if line.strip()]
                
    except FileNotFoundError:
        print(f"[!] Could not open wordlist: {wordlist_path}")
        return None

    print(f"[+] Loaded {len(wordlist):,} passwords")
    print()

    for password in tqdm(wordlist, desc="Cracking", unit="pwd"):
        try:
            prehash = wp_prehash(password)
            if bcrypt.checkpw(prehash, bcrypt_hash):
                print(f"\n[+] PASSWORD FOUND: {password}")
                return password
        except Exception:
            continue

    print("\n[!] Password not found in wordlist.")
    return None


def main():
    parser = argparse.ArgumentParser(
        description='WordPress Custom Bcrypt Password Cracker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -H '$wp$2y$10$hash...' -w wordlist.txt
  %(prog)s -H '$wp$2y$10$hash...' -w rockyou.txt -t 8
  %(prog)s -H '$wp$2y$10$hash...' -w wordlist.txt --single
  %(prog)s -f hashes.txt -w wordlist.txt -t 8
        """
    )
    
    hash_group = parser.add_mutually_exclusive_group(required=True)
    hash_group.add_argument('-H', '--hash',
                           help='Single WordPress hash to crack (must start with $wp$2y$)')
    hash_group.add_argument('-f', '--hashfile',
                           help='File containing multiple hashes (one per line, format: hash or hash:username)')
    
    parser.add_argument('-w', '--wordlist', required=True,
                       help='Path to wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=None,
                       help=f'Number of parallel workers (default: {cpu_count()} CPU cores)')
    parser.add_argument('--single', action='store_true',
                       help='Use single-threaded mode (slower, for testing)')
    parser.add_argument('-o', '--output',
                       help='Output file to save cracked passwords')
    
    args = parser.parse_args()
    
    # Determine threading mode
    use_single = args.single
    threads = args.threads if args.threads else cpu_count()
    
    # Handle single hash
    if args.hash:
        if use_single:
            result = crack_wp_hash_single(args.hash, args.wordlist)
        else:
            result = crack_wp_hash_parallel(args.hash, args.wordlist, threads)
        
        if result and args.output:
            with open(args.output, 'w') as f:
                f.write(f"{args.hash}:{result}\n")
            print(f"[+] Result saved to {args.output}")
    
    # Handle hash file
    elif args.hashfile:
        print(f"[*] Loading hashes from: {args.hashfile}")
        
        try:
            with open(args.hashfile, 'r') as f:
                hash_lines = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Hash file not found: {args.hashfile}")
            return
        
        print(f"[+] Loaded {len(hash_lines)} hash(es)")
        print()
        
        results = []
        for idx, line in enumerate(hash_lines, 1):
            # Parse line: can be "hash" or "hash:username" or "username:hash"
            if ':' in line:
                parts = line.split(':', 1)
                # Check which part is the hash (starts with $wp$2y$)
                if parts[0].startswith('$wp$2y$'):
                    hash_val = parts[0]
                    identifier = parts[1] if len(parts) > 1 else f"hash_{idx}"
                else:
                    hash_val = parts[1] if len(parts) > 1 else parts[0]
                    identifier = parts[0]
            else:
                hash_val = line
                identifier = f"hash_{idx}"
            
            print(f"{'='*70}")
            print(f"[*] Cracking {idx}/{len(hash_lines)}: {identifier}")
            print(f"{'='*70}")
            
            if use_single:
                result = crack_wp_hash_single(hash_val, args.wordlist)
            else:
                result = crack_wp_hash_parallel(hash_val, args.wordlist, threads)
            
            results.append({
                'hash': hash_val,
                'identifier': identifier,
                'password': result,
                'line': line
            })
            
            print()
        
        # Summary
        print(f"{'='*70}")
        print("SUMMARY")
        print(f"{'='*70}")
        
        cracked = 0
        for r in results:
            if r['password']:
                print(f"[+] {r['identifier']}: {r['password']}")
                cracked += 1
            else:
                print(f"[-] {r['identifier']}: NOT FOUND")
        
        print()
        print(f"[*] Cracked: {cracked}/{len(results)} ({cracked*100//len(results) if results else 0}%)")
        
        # Save results if output specified
        if args.output:
            with open(args.output, 'w') as f:
                for r in results:
                    if r['password']:
                        f.write(f"{r['identifier']}:{r['password']}\n")
            print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Show help if no arguments
        sys.argv.append('-h')
    main()