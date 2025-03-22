## 🔓 Dehasher – A Powerful Hash Cracking & Analysis Tool

This repository contains a versatile Python-based **Dehasher**, designed to crack, generate, and analyze hashes with ease. Whether you're a cybersecurity enthusiast, a pentester, or just curious about hash cracking, this tool offers a robust and user-friendly solution! 🔧💾

### ✨ Features

✅ **Hash Cracking**: Crack MD5, SHA1, and SHA256 hashes using Hashcat, a built-in brute force option, or an optional external API  
✅ **Hash Generation**: Compute hashes from text or files (MD5, SHA1, SHA256)  
✅ **Hash Detection**: Automatically detect hash types based on length and format  
✅ **Batch Processing**: Crack lists of hashes or process email:hash files  
✅ **Verification**: Compare text to hash for validation  
✅ **Custom Wordlists**: Generate random wordlists for cracking (optional)  
✅ **Logging**: Track actions with detailed logs  
✅ **Interface**: Interactive menu and command-line interface (CLI)  

---

## 🚀 Installation

### Prerequisites
This tool was developed and tested on **Windows** and **Linux**. It requires Python 3 and some dependencies:

1️⃣ **Install Python 3**  
- Download Python from [python.org](https://www.python.org/downloads/).  
- Ensure `pip` is installed (usually included with Python).

2️⃣ **Install Dependencies**  
Open a terminal and run:  
```bash
pip install requests beautifulsoup4 colorama
```

3️⃣ **Install Hashcat (Optional)**  
For advanced cracking:  
- Download Hashcat from [hashcat.net](https://hashcat.net/hashcat/).  
- Add it to your system PATH or place it in the project folder.  
- Verify:  
  ```bash
  hashcat --version
  ```

4️⃣ **Optional Wordlist**  
Download a wordlist like `rockyou.txt` (e.g., from [SecLists](https://github.com/danielmiessler/SecLists)) and place it in the project folder for cracking.

### Clone and Setup

1️⃣ **Clone the Repository**  
```bash
git clone https://github.com/ryuji4real/dehasher.git
```

2️⃣ **Navigate to the Project Folder**  
```bash
cd dehasher
```

3️⃣ **Verify Setup**  
Ensure Python and dependencies are working:  
```bash
python3 -c "import requests, bs4, colorama"
```

---

## 🌐 Execution

### Option 1: Interactive Mode (Recommended)  
Launch the interactive menu:  
```bash
python3 dehasher.py
```
Choose an option (1–6) from the menu.  
- Example: Crack a single hash → Option 1 → Enter `1a79a4d60de6718e8e5b326e338ae533` → Follow prompts.

### Option 2: Command-Line Mode  
Run specific tasks directly:  
- **Crack a single hash**:  
  ```bash
  python3 dehasher.py -s 1a79a4d60de6718e8e5b326e338ae533
  ```  
  Expected: Prompts for email/API or wordlist, then outputs the result (e.g., `example`).  
- **Crack a hash list**:  
  ```bash
  python3 dehasher.py -d hashes.txt
  ```  
- **Hash a text**:  
  ```bash
  python3 dehasher.py -h "password"
  ```  
  Result: `5f4dcc3b5aa765d61d8327deb882cf99` (MD5)

### Notes
- If Hashcat isn’t found, the tool falls back to a simple brute force mode or skips Hashcat-specific features.  
- Results are saved in files like `results_20250322_123456.txt` to avoid overwriting.

---

## 💡 Usage Examples

- **Interactive Mode**  
  ```bash
  python3 dehasher.py
  ```  
  - Option 1: Crack `d41d8cd98f00b204e9800998ecf8427e` (MD5 of empty string).  
  - Result: `Found: ""`.

- **CLI Mode**  
  ```bash
  python3 dehasher.py -s d41d8cd98f00b204e9800998ecf8427e
  ```  
  - Follow prompts (e.g., skip API, use `rockyou.txt`).  
  - Result: `Found: ""`.

- **Verify a hash**:  
  ```bash
  python3 dehasher.py -c "test:098f6bcd4621d373cade4e832627b4f6"
  ```  
  - Result: `The hash matches the text!`

---

💡 **Fast, flexible, and powerful – your go-to tool for hash cracking and analysis!** 🚀
