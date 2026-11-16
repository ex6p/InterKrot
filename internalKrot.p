#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import csv
import json
import os
import re
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set

import httpx
from bs4 import BeautifulSoup
from webless import search

try:
    import readline
except ImportError:
    pass

R = "\033[0m"
B = "\033[1m"
D = "\033[2m"
C = "\033[36m"
G = "\033[32m"
Y = "\033[33m"
M = "\033[35m"
RED = "\033[31m"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}
CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
JUNK_WORDS = re.compile(r"\b(check|patch|fix|hardening|remediation|scanner|detector|mitigation|defender)\b", re.IGNORECASE)

LAST_RESULTS: Dict[int, str] = {}

def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

def open_url(url: str) -> None:
    try:
        if os.path.exists("/data/data/com.termux"):
            subprocess.run(["termux-open", url], check=True)
        elif sys.platform == "darwin":
            subprocess.run(["open", url], check=True)
        elif os.name == "nt":
            os.startfile(url)
        else:
            subprocess.run(["xdg-open", url], check=True)
        print(f"{G}[+]{R} Opened in browser.")
    except Exception as e:
        print(f"{RED}[!]{R} Failed to open URL: {e}")

class Spinner:
    def __init__(self, text: str = "Loading...", color: str = C):
        self.text = text
        self.color = color
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        with self.lock:
            self.running = False
        if self.thread:
            self.thread.join()
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    def _animate(self) -> None:
        chars = r"|\-/|"
        i = 0
        while self.running:
            with self.lock:
                sys.stdout.write(f"\r{self.color}{chars[i % len(chars)]}{R} {D}{self.text}{R}")
                sys.stdout.flush()
            i += 1
            time.sleep(0.08)

def fetch_http(url: str, method: str = "GET", data: Optional[Dict] = None, params: Optional[Dict] = None, headers: Optional[Dict] = None, text: str = "Searching...", timeout: int = 20, no_spinner: bool = False, custom_headers: Optional[Dict] = None) -> Optional[httpx.Response]:
    req_headers = custom_headers or headers or HEADERS.copy()
    spinner = None
    if not no_spinner:
        spinner = Spinner(text)
        spinner.start()
    
    try:
        with httpx.Client(headers=req_headers, timeout=timeout, follow_redirects=True) as client:
            if method.upper() == "POST":
                r = client.post(url, data=data, params=params)
            else:
                r = client.get(url, params=params)
            r.raise_for_status()
            return r
    except Exception:
        return None
    finally:
        if spinner:
            spinner.stop()

def find_cve_ddg(name: str, no_spinner: bool = False, timeout: int = 10) -> List[str]:
    found: Set[str] = set()
    r = fetch_http("https://html.duckduckgo.com/html/", method="POST", data={"q": f"{name} CVE"}, text=f"DDG: {name}", timeout=timeout, no_spinner=no_spinner)
    if r:
        soup = BeautifulSoup(r.text, "html.parser")
        for result in soup.find_all("div", class_="result"):
            for m in CVE_REGEX.findall(result.get_text(" ", strip=True)):
                found.add(m.upper())
    return sorted(found)

async def find_cve_webless_async(name: str, timeout: int = 20) -> List[str]:
    found: Set[str] = set()
    try:
        result = await search(f"{name} CVE", limit=10, timeout=timeout)
        if result.ok:
            for hit in result.hits:
                text = f"{hit.title} {hit.snippet}"
                for m in CVE_REGEX.findall(text):
                    found.add(m.upper())
    except Exception:
        pass
    return sorted(found)

def find_cve(name: str, no_spinner: bool = False, timeout: int = 20) -> List[str]:
    cves = find_cve_ddg(name, no_spinner=no_spinner, timeout=10)
    if cves:
        return cves

    spinner = None
    if not no_spinner:
        spinner = Spinner(text=f"Webless fallback: {name}")
        spinner.start()
    try:
        cves = asyncio.run(find_cve_webless_async(name, timeout))
    finally:
        if spinner:
            spinner.stop()
    return cves

def check_msf(cve: str) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["msfconsole", "-qx", f"search cve:{cve}; exit"],
            capture_output=True, text=True, timeout=30
        )
        output = proc.stdout + proc.stderr
        if "Matching Modules" in output:
            lines = [l.strip() for l in output.splitlines() if "exploit/" in l or "auxiliary/" in l]
            if lines:
                parts = lines[0].split()
                if len(parts) >= 2:
                    return f"MSF: {parts[1]}"
            return "MSF Module Found"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return None

def search_searchsploit(cve: str) -> List[Dict[str, Any]]:
    results = []
    try:
        proc = subprocess.run(
            ["searchsploit", "--json", cve],
            capture_output=True, text=True, timeout=15
        )
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                for item in data.get("RESULTS_EXPLOIT", []):
                    eid = item.get("EDB-ID", "")
                    title = item.get("Title", "")
                    path = item.get("Path", "")
                    if eid:
                        results.append({
                            "source": "SearchSploit",
                            "title": f"{title} (Local: {path})",
                            "url": f"https://www.exploit-db.com/exploits/{eid}",
                            "stars": 0,
                            "date": "",
                        })
            except json.JSONDecodeError:
                pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return results

def search_github(cve: str, no_spinner: bool = False, timeout: int = 20, custom_headers: Optional[Dict] = None) -> List[Dict[str, Any]]:
    results = []
    q = f'"{cve}" (poc OR exploit OR rce) in:name,description fork:false archived:false'
        
    headers = custom_headers or HEADERS.copy()
    token = os.environ.get("GITHUB_TOKEN")
    if token and not custom_headers:
        headers["Authorization"] = f"Bearer {token}"
    
    r = fetch_http("https://api.github.com/search/repositories", params={"q": q, "per_page": 20, "sort": "stars", "order": "desc"}, headers=headers, text=f"GitHub: {cve}", timeout=timeout, no_spinner=no_spinner)
    if r:
        try:
            for it in r.json().get("items", []):
                results.append({
                    "source": "GitHub",
                    "title": f"{it.get('full_name', '')} — {it.get('description') or ''}"[:200],
                    "url": it.get("html_url", ""),
                    "stars": it.get("stargazers_count", 0),
                    "date": it.get("updated_at", ""),
                })
        except Exception:
            pass
    return results

def search_sploitus(cve: str, no_spinner: bool = False, timeout: int = 20, custom_headers: Optional[Dict] = None) -> List[Dict[str, Any]]:
    results = []
    headers = custom_headers or HEADERS.copy()
    r = fetch_http("https://sploitus.com/", params={"query": cve, "type": "exploits"}, headers=headers, text=f"Sploitus: {cve}", timeout=timeout, no_spinner=no_spinner)
    if r:
        try:
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=re.compile(r"/exploit\?id=")):
                title = link.get_text(strip=True)
                href = link.get("href", "")
                if not title or not href:
                    continue
                
                title = re.sub(r"\d{4}-\d{2}-\d{2}", "", title)
                title = re.sub(r"KitPloit|KITPLOIT|GITHUB|1DAYEXPLOIT|UNKNOWN|PACKETSTORM|EXPLOITDB|EXPLOIT-DB", "", title, flags=re.IGNORECASE)
                title = re.sub(r"\s+", " ", title).strip()
                
                if title:
                    results.append({
                        "source": "Sploitus",
                        "title": title[:200],
                        "url": f"https://sploitus.com{href}" if href.startswith("/") else href,
                        "stars": 0,
                        "date": "",
                    })
        except Exception:
            pass
    return results

def save_results(all_results: Dict[str, List[Dict[str, Any]]], cves: List[str], args: argparse.Namespace, query_name: str) -> None:
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for cve, items in all_results.items():
                f.write(f"# {cve}\n")
                for item in items:
                    f.write(f"{item['url']}\n")
        print(f"{G}[+]{R} Saved list to {args.output}")

    if args.output_csv:
        with open(args.output_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["CVE", "Source", "Title", "URL", "Stars", "Date"])
            for cve, items in all_results.items():
                for item in items:
                    writer.writerow([cve, item["source"], item["title"], item["url"], item.get("stars", 0), item.get("date", "")])
        print(f"{G}[+]{R} Saved CSV to {args.output_csv}")

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump({"keyword": query_name, "cves": cves, "results": all_results}, f, indent=2, ensure_ascii=False)
        print(f"{G}[+]{R} Saved JSON to {args.output_json}")

    if args.output_md:
        with open(args.output_md, "w", encoding="utf-8") as f:
            f.write(f"# InterSploit Report: {query_name}\n\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Found CVEs:** {', '.join(cves)}\n\n")
            f.write("---\n\n")
            
            for cve, items in all_results.items():
                f.write(f"## {cve}\n\n")
                f.write("| Source | Title | URL | Stars |\n")
                f.write("|--------|-------|-----|-------|\n")
                for item in items:
                    title = item['title'].replace('|', '-')
                    url = item['url'] if item['url'] else "N/A"
                    stars = item.get('stars', 0)
                    f.write(f"| {item['source']} | {title} | [Link]({url}) | {stars} |\n")
                f.write("\n")
        print(f"{G}[+]{R} Saved Markdown to {args.output_md}")

def run_hunt(name: str, args: argparse.Namespace, is_interactive: bool = False) -> int:
    global LAST_RESULTS
    LAST_RESULTS = {}

    name = name.strip()
    if not name:
        return 1

    sources = [s.strip().lower() for s in args.sources.split(",")]
    
    if args.exclude:
        excludes = [s.strip().lower() for s in args.exclude.split(",")]
        sources = [s for s in sources if s not in excludes]

    if not args.no_spinner and not args.raw:
        print(f"{D}────────────────────────────────────────────────────────────{R}")
        print(f"{B}Target:{R} {Y}{name}{R}")

    cves = find_cve(name, no_spinner=args.no_spinner or args.raw, timeout=args.timeout)
    if not cves:
        if not args.raw:
            print(f"{RED}[!] No CVE found for '{name}'{R}")
        return 1

    all_results: Dict[str, List[Dict[str, Any]]] = {}
    stats = {s: 0 for s in sources}
    global_seen: Set[str] = set()
    limit = 999 if args.all else args.limit

    for cve in cves:
        if args.days:
            year = cve.split("-")[1]
            current_year = str(time.localtime().tm_year)
            if int(current_year) - int(year) > args.days // 365:
                continue

        results = []
        if "github" in sources:
            results.extend(search_github(cve, no_spinner=args.no_spinner or args.raw, timeout=args.timeout, custom_headers=args.headers))
        if "sploitus" in sources:
            results.extend(search_sploitus(cve, no_spinner=args.no_spinner or args.raw, timeout=args.timeout, custom_headers=args.headers))
        if "searchsploit" in sources:
            results.extend(search_searchsploit(cve))

        msf_status = None
        if args.msf:
            msf_status = check_msf(cve)

        unique = []
        for item in results:
            url = item.get("url", "").lower()
            title = item.get("title", "").lower()
            
            if JUNK_WORDS.search(title) or ".github.io" in url:
                continue

            repo = ""
            if "github.com/" in url:
                repo = url.rstrip("/").split("/")[-1]
            elif "sploitus.com" in url:
                m = re.search(r"github[-_]([a-z0-9-]+)", url)
                if m:
                    repo = m.group(1).replace("-", "")

            if url in global_seen or (repo and repo in global_seen):
                continue
                
            if item.get("stars", 0) >= args.min_stars:
                global_seen.add(url)
                if repo:
                    global_seen.add(repo)
                unique.append(item)
                stats[item["source"].lower()] += 1

        if unique or msf_status:
            if unique:
                all_results[cve] = unique[:limit]
            else:
                all_results[cve] = []

    if args.raw:
        for cve, items in all_results.items():
            for item in items:
                if item.get("url"):
                    print(item["url"])
        return 0

    if not args.no_spinner and not args.json:
        print(f"\n{B}Scan results:{R}")
        for s in sources:
            if stats.get(s, 0) > 0:
                print(f"  {G}[+]{R} {s.capitalize()}: {stats[s]} found")
            else:
                print(f"  {RED}[-]{R} {s.capitalize()}: none")

    if args.json:
        print(json.dumps({"keyword": name, "cves": cves, "results": all_results}, indent=2, ensure_ascii=False))
        return 0

    if not all_results:
        if not args.no_spinner:
            print(f"\n{RED}[!] No exploits found for: {', '.join(cves)}{R}")
        return 0

    idx = 1
    print(f"\n{B}Found CVEs:{R} {G}{', '.join(cves)}{R}")
    print(f"{D}────────────────────────────────────────────────────────────{R}\n")

    for cve, items in all_results.items():
        if args.sort == "stars":
            items.sort(key=lambda x: -x.get("stars", 0))
        elif args.sort == "date":
            items.sort(key=lambda x: x.get("date", ""), reverse=True)
        else:
            items.sort(key=lambda x: (0 if x["source"] == "GitHub" else (1 if x["source"] == "Sploitus" else 2), -x.get("stars", 0)))

        msf_line = ""
        if args.msf:
            msf_res = check_msf(cve)
            if msf_res:
                msf_line = f" {Y}[{msf_res}]{R}"
            else:
                msf_line = f" {D}[No MSF module]{R}"

        print(f"{B}{C}╭─ {cve}{R}{msf_line}")
        
        if not items:
            print(f"{C}│{R} {D}(no public PoC links found){R}")
        
        for item in items:
            stars = f" {M}★{item['stars']}{R}" if item.get("stars") else ""
            date = f" {D}({item['date'][:10]}){R}" if item.get("date") else ""
            
            if item["source"] == "GitHub":
                src = f"{G}[GitHub]{R}"
            elif item["source"] == "Sploitus":
                src = f"{Y}[Sploitus]{R}"
            else:
                src = f"{C}[SearchSploit]{R}"
                
            print(f"{C}│{R} {B}{idx}.{R} {src}{stars}{date} {item['title']}")
            if item["url"]:
                print(f"{C}│{R}    {D}{item['url']}{R}")
                LAST_RESULTS[idx] = item["url"]
            idx += 1
        print(f"{C}╰─{R}")

    print(f"\n{B}Total:{R} {G}{idx-1}{R} links found.")
    if is_interactive:
        print(f"{D}Use 'open <number>' to open a link in browser.{R}\n")
    else:
        print()
    
    save_results(all_results, cves, args, name)
    
    return 0

def interactive_shell(args: argparse.Namespace) -> None:
    global LAST_RESULTS
    clear_screen()
    print(r'''   ____     __          ____   
  /  _/__  / /____ ____/ __/__ 
 _/ // _ \/ __/ -_) __/\ \/ _ \
/___/_//_/\__/\__/_/ /___/ .__/
                        /_/    ''') 
    print(f"{D}Commands: <keyword> | open <num> | clear | quit{R}\n")
    
    while True:
        try:
            raw = input(f"{B}{C}→{R} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            break
        if not raw:
            continue
            
        parts = raw.split()
        cmd = parts[0].lower()
        
        if cmd in (".quit", ".exit", ".q"):
            break
        if cmd == ".clear":
            clear_screen()
            continue
            
        if cmd == ".open":
            if len(parts) < 2 or not parts[1].isdigit():
                print(f"{RED}[!]{R} Usage: open <number>")
                continue
            num = int(parts[1])
            if num in LAST_RESULTS:
                open_url(LAST_RESULTS[num])
            else:
                print(f"{RED}[!]{R} Link {num} not found in the last search.")
            continue
            
        run_hunt(raw, args, is_interactive=True)

def main() -> None:
    known_flags = {
        "-h", "--help",
        "-i", "--interactive", "-s", "--sources", "-e", "--exclude", 
        "--min-stars", "--days", "-l", "--limit", "-a", "--all", 
        "--sort", "-j", "--json", "-o", "--output", "-oc", "--output-csv", 
        "-oj", "--output-json", "-om", "--output-md", "--headers", 
        "--no-spinner", "-t", "--timeout", "--raw", "--msf"
    }
    flags_with_value = {
        "-s", "--sources", "-e", "--exclude", "--min-stars", "--days",
        "-l", "--limit", "--sort", "-o", "--output", "-oc", "--output-csv",
        "-oj", "--output-json", "-om", "--output-md", "--headers", "-t", "--timeout"
    }

    flags = []
    keywords = []
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in known_flags:
            flags.append(arg)
            if arg in flags_with_value and i + 1 < len(sys.argv):
                flags.append(sys.argv[i+1])
                i += 1
        else:
            keywords.append(arg)
        i += 1

    p = argparse.ArgumentParser(description="InterSploit - Advanced Exploit Hunter")
    p.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    p.add_argument("-s", "--sources", default="github,sploitus,searchsploit", help="Comma-separated sources")
    p.add_argument("-e", "--exclude", help="Exclude specific sources (comma-separated)")
    p.add_argument("--min-stars", type=int, default=0, help="Minimum stars for GitHub")
    p.add_argument("--days", type=int, help="Filter CVEs by age (in days)")
    p.add_argument("-l", "--limit", type=int, default=5, help="Max results per CVE")
    p.add_argument("-a", "--all", action="store_true", help="Show all results (disable limit)")
    p.add_argument("--sort", choices=["default", "stars", "date"], default="default", help="Sort results by")
    p.add_argument("-j", "--json", action="store_true", help="Print JSON output to stdout")
    p.add_argument("-o", "--output", help="Save URLs to text file")
    p.add_argument("-oc", "--output-csv", help="Save results to CSV file")
    p.add_argument("-oj", "--output-json", help="Save results to JSON file")
    p.add_argument("-om", "--output-md", help="Save results to Markdown file")
    p.add_argument("--headers", type=json.loads, help="Custom headers in JSON format")
    p.add_argument("--no-spinner", action="store_true", help="Disable animation")
    p.add_argument("-t", "--timeout", type=int, default=20, help="Request timeout in seconds")
    p.add_argument("--raw", action="store_true", help="Print only URLs (for pipelines)")
    p.add_argument("--msf", action="store_true", help="Check Metasploit module availability")
    
    if not flags and not keywords:
        p.print_help()
        sys.exit(0)

    args = p.parse_args(flags)

    keyword = " ".join(keywords) if keywords else None

    if keyword and keyword.lower() == "interactive":
        args.interactive = True
        keyword = None

    if args.interactive or not keyword:
        interactive_shell(args)
    else:
        sys.exit(run_hunt(keyword, args, is_interactive=False))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Interrupted by user. Exiting.{R}")
        sys.exit(0)
