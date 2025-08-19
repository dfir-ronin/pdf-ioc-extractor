# PDF IOC Extractor v1.0

**PDF IOC Extractor** is a simple, lightweight Python tool that extracts IP addresses, domains, and URLs from a PDF file. It's built for cybersecurity professionals, threat hunters, DFIR analysts, threat intel analyst, and SOC teams who need to quickly collect Indicators Of Compromise (IOCs) for investigation and enrichment.

May threat-intelligence reports "defang" malicious indicators to prevent accidental clicks or execution (example. `hxxp://malicious[.]com`). This tool is built to automatically extract and refang such values so that you can use them immediately in your threat analysis or detection pipeline.

## Features

Extracts:
- IP addresses (IPv4 only, defanged or not)
- Domains and URLs (including defanged and `hxxp`-format)

Refangs:
- `[.]`, `(dot)`, `(.)` → `.`
- `hxxp://`, `hxxps://` → `https://`,`https://`

Filters:
- Private/reserved IPs (like `192.168.x.x`)

Outputs:
- `reports_iocs.txt` - human-readable format
- `reports_iocs.json` - structured format for automation

## How To Use
`python project.py ./NCSC_APT28.pdf`
If no path is provided via command-line argument, the script will prompt you for it.

Example Output:
***IP Addresses***
45.77.23.109
103.45.67.122

***Domains & URLs***
malicious-site.com
http://evil.example/path

## How To Install
Ensure Python 3.6+ is installed then install dependencies:
`pip install -r requirements.txt`
If you're installing manually, the key dependencies are:
- `pdfminer.six` for PDF text extraction
- `pyfiglet` for ASCII banner display

## How It Works
1. PDF Text Extraction
The script uses pdfminer.six to extract all visible text content from the provided pdf file.

2. IOC Pattern Matching
- IP Extraction:
    The tool uses a flexible regex pattern to detect IPv4 addresses, even if they are obfuscated with [.], (dot), or similar delimiters.
- Refanging Logic:
    Identified IPs are automatically **refanged** back to standard format (example. 192[.]168.1.1 → 192.168.1.1). Private IPs are excluded to avoid noise. Only public IPs are returned.

- URL and Domain Extraction:
    URLs using schemes like hxxp:// pr containing [dot] obfuscation are corrected. The script captures full URLs and domain-only references using robust regex.

3. Output Reports
Results are written into:
    - A .txt file with a human-readable summary
    - A .json file for easy parsing in other tools or scripts.

## Common Use Cases
- Quickly gather IOCs from government alerts (example. US-CERT, NCSC, CISA PDFs)
- Parse multiple threat reports from malware infrastracture details
- Automate IOC extraction during an incident triage
Generate feed for honeypots or blacklist systems


## Future Improvements
- Support Email IOC extraction
- Batch Processing multiple PDFs
- Integration with Threat Intelligence platforms (STIX/TAXII)











