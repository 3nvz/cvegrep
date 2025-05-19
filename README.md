# Description
`cvegrep` is a simple and lightweight tool for scraping [OpenCVE](https://app.opencve.io) for **high** and **critical** vulnerabilities.  
You can use `cvegrep` either by:

- Directly passing it a software name + version (e.g., `nginx 1.18.0`)
- Providing a file (`banners.txt`) containing multiple software+version lines (e.g., generated from `httpx` output)

This tool is perfect for integrating into bug bounty recon pipelines, vuln scanners, or attack surface monitoring tools.

---

# Usage

```bash
# Check CVEs for a single software+version input
python3 cvegrep.py "apache struts 2.0.1"

# Check CVEs for all entries in a file
python3 cvegrep.py -f banners.txt

```
# Installation

- git clone https://github.com/yourusername/cvegrep.git
- cd cvegrep
- pip3 install -r requirements.txt
