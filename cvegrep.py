import requests
from bs4 import BeautifulSoup
import urllib.parse
import sys
import argparse

def normalize_query(query):
    parts = query.strip().split()
    if parts and "." in parts[-1]:
        version = parts[-1]
        major_minor = ".".join(version.split(".")[:2])
        return " ".join(parts[:-1] + [major_minor])
    return query

def scrape_opencve(query):
    encoded_query = urllib.parse.quote(f'description:"{query}"')
    url = f"https://app.opencve.io/cve/?q={encoded_query}"
    headers = {"User-Agent": "Mozilla/5.0"}

    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")

    headers = soup.select("tr.cve-header")
    summaries = soup.select("tr.cve-summary")

    results = []
    for head, summary in zip(headers, summaries):
        # Extract and filter by severity
        severity_td = head.select_one("td.col-md-1.text-center span")
        severity = severity_td.get_text(strip=True) if severity_td else ""
        if not any(level in severity for level in ("High", "Critical")):
            continue

        # Extract CVE ID and description
        cve_id_tag = head.select_one("td.col-md-2 a")
        if not cve_id_tag:
            continue
        cve_id = cve_id_tag.text.strip()
        cve_link = "https://app.opencve.io" + cve_id_tag["href"]
        cve_description = summary.select_one("td").text.strip()
        results.append((cve_id, cve_description, cve_link, severity))
    
    return results

def process_single_query(raw_query):
    query = normalize_query(raw_query)
    print(f"\n[*] Searching: description:\"{query}\"")
    results = scrape_opencve(query)
    if not results:
        print("No High or Critical CVEs found.")
    else:
        for cve_id, desc, link, severity in results:
            print(f"{cve_id} ({severity}) - {desc}\n{link}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OpenCVE description-based scraper")
    parser.add_argument("query", nargs="?", help="Software + version string, e.g. 'apache struts 2.0.1'")
    parser.add_argument("-f", "--file", help="File with one query per line (e.g. banners.txt)")

    args = parser.parse_args()

    if args.file:
        with open(args.file, "r") as f:
            for line in f:
                clean = line.strip()
                if clean:
                    process_single_query(clean)
    elif args.query:
        process_single_query(args.query)
    else:
        print("Usage:\n  python3 cvegrep.py \"apache struts 2.0.1\"\n  python3 cvegrep.py -f banners.txt")
        sys.exit(1)
