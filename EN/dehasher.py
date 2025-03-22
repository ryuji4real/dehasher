import sys
import os
import requests
import hashlib
import itertools
import logging
import time
import shutil
from datetime import datetime
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
import argparse
import re
import subprocess

init()

DEFAULT_WORDLIST = "rockyou.txt"
LOG_FILE = f"dehasher_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def info_text(text): print(f" {Style.RESET_ALL}{Fore.BLUE}[i] {text}{Style.RESET_ALL}")
def success_text(text): print(f" {Style.RESET_ALL}{Style.BRIGHT}{Fore.GREEN}[+] {text}{Style.RESET_ALL}")
def error_text(text): print(f" {Style.RESET_ALL}{Style.BRIGHT}{Fore.RED}[!] {text}{Style.RESET_ALL}")
def warning_text(text): print(f" {Style.RESET_ALL}{Style.BRIGHT}{Fore.YELLOW}[!] {text}{Style.RESET_ALL}")
def input_text(text): return input(f" {Style.RESET_ALL}{Style.BRIGHT}{Fore.BLUE}[*] {text} >>{Fore.RESET} ")

def find_hashcat():
    possible_paths = ["hashcat", "hashcat.exe", "/usr/bin/hashcat"]
    for path in possible_paths:
        if os.path.isfile(path) or shutil.which(path):
            return path
    return None

HASHCAT_PATH = find_hashcat()

def calculate_hash(text, algorithm="md5"):
    hash_funcs = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}
    try:
        return hash_funcs[algorithm](text.encode('utf-8')).hexdigest()
    except KeyError:
        error_text("Unsupported algorithm (md5, sha1, sha256)")
        return None

def detect_hash_type(hash_value):
    patterns = {
        "MD5": (r'^[a-fA-F0-9]{32}$', "0"),
        "SHA1": (r'^[a-fA-F0-9]{40}$', "100"),
        "SHA256": (r'^[a-fA-F0-9]{64}$', "1400")
    }
    for hash_type, (pattern, code) in patterns.items():
        if re.match(pattern, hash_value):
            return hash_type, code
    return "Unknown", None

def crack_with_hashcat(hash_value, hash_type, wordlist):
    if not HASHCAT_PATH:
        error_text("Hashcat not found. Install it or check the path.")
        return None
    if not os.path.isfile(wordlist):
        error_text(f"Wordlist not found: {wordlist}")
        return None
    cmd = [HASHCAT_PATH, "-m", hash_type, "-a", "0", hash_value, wordlist, "--potfile-disable"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    show_cmd = [HASHCAT_PATH, "-m", hash_type, "-a", "0", hash_value, wordlist, "--show"]
    show_result = subprocess.run(show_cmd, capture_output=True, text=True)
    return show_result.stdout

def simple_bruteforce(hash_value, algorithm, max_length=4, charset="abcdefghijklmnopqrstuvwxyz"):
    for length in range(1, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            word = ''.join(attempt)
            if calculate_hash(word, algorithm) == hash_value:
                return word
    return None

def save_results(content, filename=f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"):
    with open(filename, "w") as f:
        f.write(content)
    success_text(f"Results saved to {filename}")

def hash_text(target, algorithm="md5"):
    if os.path.isfile(target):
        results = []
        with open(target, "r") as f:
            for line in f:
                text = line.strip()
                hashed = calculate_hash(text, algorithm)
                if hashed:
                    results.append(f"{text}:{hashed}")
        save_results("\n".join(results))
    else:
        hashed = calculate_hash(target, algorithm)
        if hashed:
            success_text(f"Text '{target}' hashed ({algorithm}): {hashed}")

def check_hash(text_hash):
    try:
        text, hash_value = text_hash.split(":", 1)
        detected_type, _ = detect_hash_type(hash_value)
        if detected_type == "Unknown":
            error_text("Invalid or unsupported hash")
            return
        calculated = calculate_hash(text, detected_type.lower())
        if calculated == hash_value:
            success_text("The hash matches the text!")
        else:
            error_text("The hash does not match the text.")
    except ValueError:
        error_text("Invalid format. Use 'text:hash'")

def crack_with_api(hash_value, email, code):
    url = f"https://md5decrypt.net/en/Api/api.php?hash={hash_value}&hash_type=md5&email={email}&code={code}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers)
        result = BeautifulSoup(response.content, "html.parser").get_text().strip()
        if "ERROR" in result:
            error_text(f"API error: {result}")
            return None
        elif result:
            return result
        else:
            return None
    except Exception as e:
        error_text(f"API connection error: {e}")
        return None

def cli_mode(args):
    if args.single:
        hash_type, code = detect_hash_type(args.single)
        info_text(f"Detected type: {hash_type}")
        email = input_text("Email for API (or Enter for Hashcat)")
        if email:
            code = input_text("API code")
            if result := crack_with_api(args.single, email, code):
                success_text(f"Hash found: {args.single}:{result}")
            else:
                warning_text("Not found via API, switching to Hashcat")
                wordlist = input_text(f"Wordlist path (default {DEFAULT_WORDLIST})") or DEFAULT_WORDLIST
                if result := crack_with_hashcat(args.single, code or "0", wordlist):
                    save_results(result)
        else:
            wordlist = input_text(f"Wordlist path (default {DEFAULT_WORDLIST})") or DEFAULT_WORDLIST
            if result := crack_with_hashcat(args.single, code or "0", wordlist):
                save_results(result)
    elif args.dehash:
        with open(args.dehash, "r") as f:
            hashes = [line.strip() for line in f if line.strip()]
        if len(hashes) > 400:
            warning_text("Too many hashes (>400), using Hashcat")
            wordlist = input_text(f"Wordlist path (default {DEFAULT_WORDLIST})") or DEFAULT_WORDLIST
            results = []
            for h in hashes:
                if result := crack_with_hashcat(h, detect_hash_type(h)[1] or "0", wordlist):
                    results.append(result)
            save_results("\n".join(results))
        else:
            email = input_text("Email for API")
            code = input_text("API code")
            results = []
            for h in hashes:
                if result := crack_with_api(h, email, code):
                    results.append(f"{h}:{result}")
            save_results("\n".join(results))
    elif args.email:
        with open(args.email, "r") as f:
            hashes = [line.strip().split(":", 1)[1] for line in f if ":" in line]
        cli_mode(argparse.Namespace(dehash=hashes, single=None, email=None, hash=None, check=None))
    elif args.hash:
        hash_text(args.hash)
    elif args.check:
        check_hash(args.check)

def interactive_menu():
    while True:
        print(f"{Fore.GREEN}=== Enhanced Dehasher ==={Style.RESET_ALL}")
        print("1. Crack a single hash")
        print("2. Crack a list of hashes")
        print("3. Convert email:hash to hashes")
        print("4. Hash a text/file")
        print("5. Verify a hash")
        print("6. Quit")
        choice = input_text("Choice").strip()

        if choice == "1":
            hash_value = input_text("Hash")
            cli_mode(argparse.Namespace(single=hash_value, dehash=None, email=None, hash=None, check=None))
        elif choice == "2":
            file = input_text("Hash file")
            cli_mode(argparse.Namespace(dehash=file, single=None, email=None, hash=None, check=None))
        elif choice == "3":
            file = input_text("Email:hash file")
            cli_mode(argparse.Namespace(email=file, dehash=None, single=None, hash=None, check=None))
        elif choice == "4":
            target = input_text("Text or file")
            cli_mode(argparse.Namespace(hash=target, single=None, dehash=None, email=None, check=None))
        elif choice == "5":
            text_hash = input_text("Text:hash")
            cli_mode(argparse.Namespace(check=text_hash, single=None, dehash=None, email=None, hash=None))
        elif choice == "6":
            success_text("See you soon!")
            break

def main():
    parser = argparse.ArgumentParser(description="Enhanced Dehasher - MD5/SHA1/SHA256")
    parser.add_argument("-s", "--single", help="Crack a single hash")
    parser.add_argument("-d", "--dehash", help="Crack a list of hashes (file)")
    parser.add_argument("-e", "--email", help="Convert email:hash to hashes (file)")
    parser.add_argument("-h", "--hash", help="Hash a text or file")
    parser.add_argument("-c", "--check", help="Verify text:hash")
    
    args = parser.parse_args()
    if any([args.single, args.dehash, args.email, args.hash, args.check]):
        cli_mode(args)
    else:
        interactive_menu()

if __name__ == "__main__":
    if not HASHCAT_PATH:
        warning_text("Hashcat not detected, some features will be limited")
    main()
