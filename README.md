# 🕷️ InterSploit

<p align="center">
  <b>Fast, smart, and automated CVE & PoC hunter for the terminal.</b><br>
  <i>Stop Googling. Start exploiting.</i>
</p>

<img width="854" height="480" alt="axaxxaxa" src="https://github.com/user-attachments/assets/0dbbfbf9-70e8-4ff6-82d8-a49e96bf3d69" />


**InterSploit** is a powerful CLI tool designed for penetration testers, bug bounty hunters, and security researchers. Instead of manually searching for CVE IDs and then hunting down Proof-of-Concept (PoC) scripts, InterSploit does it all in one go.

Just give it a software name (e.g., `ProFTPD 1.3.5`, `PwnKit`, or `Log4j`), and it will automatically resolve the CVE, find public PoCs, and even check if there is a ready-to-use Metasploit module.

---

## ✨ Features

*   **🧠 Smart CVE Resolution:** Uses DuckDuckGo and Webless to translate software names into accurate CVE IDs.
*   **⚡ Multi-Source Search:** Parallel scanning across **GitHub**, **Sploitus**, and local **SearchSploit** (Exploit-DB).
*   **💀 Metasploit Integration:** Checks if a working MSF module exists (`--msf`) and displays the exact module path.
*   **🖥️ Interactive Shell:** A built-in REPL mode with command history (arrow keys) and the ability to open links directly in your browser (`.open <num>`).
*   **📊 Export Options:** Save your findings in **TXT**, **CSV**, **JSON**, or a beautifully formatted **Markdown** report.
*   **🛠️ Pipeline Friendly:** Use the `--raw` flag to output only URLs, making it perfect for Bash pipelines.
*   **📱 Cross-Platform:** Fully compatible with Linux, macOS, Windows, and Termux (Android).

---

## 📦 Installation

### Quick Install (Linux / macOS / Termux)
```bash
url -sL https://raw.githubusercontent.com/ex6p/InterKrot/main/install.sh -o install.sh
chmod +x install.sh
./install.sh
