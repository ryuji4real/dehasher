import sys
import os
import requests
import hashlib
import itertools
import logging
import time
from datetime import datetime
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
import argparse
import re

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
        error_text("Algorithme non supporté (md5, sha1, sha256)")
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
    return "Inconnu", None

def crack_with_hashcat(hash_value, hash_type, wordlist):
    if not HASHCAT_PATH:
        error_text("Hashcat non trouvé. Installez-le ou vérifiez le chemin.")
        return None
    if not os.path.isfile(wordlist):
        error_text(f"Wordlist introuvable : {wordlist}")
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
    success_text(f"Résultats sauvegardés dans {filename}")

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
            success_text(f"Texte '{target}' hashé ({algorithm}) : {hashed}")

def check_hash(text_hash):
    try:
        text, hash_value = text_hash.split(":", 1)
        detected_type, _ = detect_hash_type(hash_value)
        if detected_type == "Inconnu":
            error_text("Hash invalide ou non supporté")
            return
        calculated = calculate_hash(text, detected_type.lower())
        if calculated == hash_value:
            success_text("Le hash correspond au texte !")
        else:
            error_text("Le hash ne correspond pas au texte.")
    except ValueError:
        error_text("Format invalide. Utilisez 'texte:hash'")

def crack_with_api(hash_value, email, code):
    url = f"https://md5decrypt.net/en/Api/api.php?hash={hash_value}&hash_type=md5&email={email}&code={code}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers)
        result = BeautifulSoup(response.content, "html.parser").get_text().strip()
        if "ERROR" in result:
            error_text(f"Erreur API : {result}")
            return None
        elif result:
            return result
        else:
            return None
    except Exception as e:
        error_text(f"Erreur connexion API : {e}")
        return None

def cli_mode(args):
    if args.single:
        hash_type, code = detect_hash_type(args.single)
        info_text(f"Type détecté : {hash_type}")
        email = input_text("Email pour l'API (ou Enter pour Hashcat)")
        if email:
            code = input_text("Code API")
            if result := crack_with_api(args.single, email, code):
                success_text(f"Hash trouvé : {args.single}:{result}")
            else:
                warning_text("Non trouvé via API, passage à Hashcat")
                wordlist = input_text(f"Chemin wordlist (défaut {DEFAULT_WORDLIST})") or DEFAULT_WORDLIST
                if result := crack_with_hashcat(args.single, code or "0", wordlist):
                    save_results(result)
        else:
            wordlist = input_text(f"Chemin wordlist (défaut {DEFAULT_WORDLIST})") or DEFAULT_WORDLIST
            if result := crack_with_hashcat(args.single, code or "0", wordlist):
                save_results(result)
    elif args.dehash:
        with open(args.dehash, "r") as f:
            hashes = [line.strip() for line in f if line.strip()]
        if len(hashes) > 400:
            warning_text("Trop de hashes (>400), utilisation de Hashcat")
            wordlist = input_text(f"Chemin wordlist (défaut {DEFAULT_WORDLIST})") or DEFAULT_WORDLIST
            results = []
            for h in hashes:
                if result := crack_with_hashcat(h, detect_hash_type(h)[1] or "0", wordlist):
                    results.append(result)
            save_results("\n".join(results))
        else:
            email = input_text("Email pour l'API")
            code = input_text("Code API")
            results = []
            for h in hashes:
                if result := crack_with_api(h, email, code):
                    results.append(f"{h}:{result}")
            save_results("\n".join(results))
    elif args.email:
        with open(args.email, "r") as f:
            hashes = [line.strip().split(":", 1)[1] for line in f if ":" in line]
        cli_mode(argparse.Namespace(dehash=None, single=None, email=None, hash=None, check=None, dehash=hashes))
    elif args.hash:
        hash_text(args.hash)
    elif args.check:
        check_hash(args.check)

def interactive_menu():
    while True:
        print(f"{Fore.GREEN}=== Dehasher Amélioré ==={Style.RESET_ALL}")
        print("1. Craquer un hash unique")
        print("2. Craquer une liste de hashes")
        print("3. Convertir email:hash en hashes")
        print("4. Hasher un texte/fichier")
        print("5. Vérifier un hash")
        print("6. Quitter")
        choice = input_text("Choix").strip()

        if choice == "1":
            hash_value = input_text("Hash")
            cli_mode(argparse.Namespace(single=hash_value, dehash=None, email=None, hash=None, check=None))
        elif choice == "2":
            file = input_text("Fichier de hashes")
            cli_mode(argparse.Namespace(dehash=file, single=None, email=None, hash=None, check=None))
        elif choice == "3":
            file = input_text("Fichier email:hash")
            cli_mode(argparse.Namespace(email=file, dehash=None, single=None, hash=None, check=None))
        elif choice == "4":
            target = input_text("Texte ou fichier")
            cli_mode(argparse.Namespace(hash=target, single=None, dehash=None, email=None, check=None))
        elif choice == "5":
            text_hash = input_text("Texte:hash")
            cli_mode(argparse.Namespace(check=text_hash, single=None, dehash=None, email=None, hash=None))
        elif choice == "6":
            success_text("À bientôt !")
            break

def main():
    parser = argparse.ArgumentParser(description="Dehasher Amélioré - MD5/SHA1/SHA256")
    parser.add_argument("-s", "--single", help="Craquer un hash unique")
    parser.add_argument("-d", "--dehash", help="Craquer une liste de hashes (fichier)")
    parser.add_argument("-e", "--email", help="Convertir email:hash en hashes (fichier)")
    parser.add_argument("-h", "--hash", help="Hasher un texte ou fichier")
    parser.add_argument("-c", "--check", help="Vérifier texte:hash")
    
    args = parser.parse_args()
    if any([args.single, args.dehash, args.email, args.hash, args.check]):
        cli_mode(args)
    else:
        interactive_menu()

if __name__ == "__main__":
    if not HASHCAT_PATH:
        warning_text("Hashcat non détecté, certaines fonctionnalités seront limitées")
    main()
