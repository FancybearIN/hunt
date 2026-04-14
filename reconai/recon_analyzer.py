import os
import re
import json
import requests
from tqdm import tqdm
from rich import print

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3"  # change if needed


# -------------------------------
# FILE PARSING / SIGNAL EXTRACTION
# -------------------------------

def extract_urls(content):
    return re.findall(r'https?://[^\s"\']+', content)


def extract_ips(content):
    return re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)


def extract_ports(content):
    return re.findall(r'(\d{2,5})/tcp', content)


def extract_interesting(content):
    keywords = [
        "admin", "dev", "test", "staging", "internal",
        "api", "graphql", "auth", "login", "debug",
        "backup", "old", "v1", "v2"
    ]
    found = []
    for k in keywords:
        if k in content.lower():
            found.append(k)
    return list(set(found))


def parse_file(filepath):
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()

        return {
            "file": filepath,
            "urls": list(set(extract_urls(content))),
            "ips": list(set(extract_ips(content))),
            "ports": list(set(extract_ports(content))),
            "keywords": extract_interesting(content)
        }

    except Exception:
        return None


# -------------------------------
# DIRECTORY WALKER
# -------------------------------

def scan_directory(path):
    results = []

    for root, _, files in os.walk(path):
        for file in files:
            full_path = os.path.join(root, file)

            if any(file.endswith(ext) for ext in [".txt", ".json", ".xml", ".log"]):
                parsed = parse_file(full_path)
                if parsed:
                    results.append(parsed)

    return results


# -------------------------------
# CONTEXT BUILDER (VERY IMPORTANT)
# -------------------------------

def build_context(data):
    all_urls = set()
    all_ips = set()
    all_ports = set()
    keywords = set()

    for item in data:
        all_urls.update(item["urls"])
        all_ips.update(item["ips"])
        all_ports.update(item["ports"])
        keywords.update(item["keywords"])

    context = {
        "urls": list(all_urls)[:200],
        "ips": list(all_ips),
        "ports": list(all_ports),
        "keywords": list(keywords)
    }

    return context


# -------------------------------
# OLLAMA QUERY
# -------------------------------

def query_ollama(context):
    prompt = f"""
You are an elite bug bounty hunter.

Analyze the recon data and provide ONLY actionable insights.

Focus on:
- High-risk endpoints
- Potential auth bypass / IDOR
- Misconfigurations
- Interesting attack surfaces
- Things worth manual testing

Avoid summaries. Be specific.

Recon Data:
{json.dumps(context, indent=2)}

Output format:
- Finding
- Why it matters
- What to test next
"""

    response = requests.post(OLLAMA_URL, json={
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    })

    return response.json()["response"]


# -------------------------------
# CLI
# -------------------------------

def main():
    path = input("Enter recon folder path: ").strip()

    if not os.path.exists(path):
        print("[red]Invalid path[/red]")
        return

    print("[cyan]Scanning files...[/cyan]")
    data = scan_directory(path)

    print(f"[green]Parsed {len(data)} files[/green]")

    context = build_context(data)

    print("[cyan]Analyzing with Ollama...[/cyan]")
    result = query_ollama(context)

    print("\n[bold green]=== BUG HUNTING INSIGHTS ===[/bold green]\n")
    print(result)


if __name__ == "__main__":
    main()
