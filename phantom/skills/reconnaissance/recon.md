---
name: reconnaissance
description: Systematic reconnaissance methodology — subdomain enumeration, content discovery, JS analysis, parameter mining, technology fingerprinting
---

# Reconnaissance

Recon is the foundation of every successful engagement. Rushed or shallow recon leads to missed attack surface. Systematic recon uncovers the endpoints, parameters, and technology stack that make exploitation possible.

## Phase 1: Passive Reconnaissance

### Subdomain Enumeration
```bash
# DNS-based enumeration
subfinder -d target.com -silent -o subdomains.txt
# DNS resolution + alive checking
cat subdomains.txt | dnsx -silent -a -resp -o resolved.txt
# HTTP probing
cat subdomains.txt | httpx -silent -status-code -title -tech-detect -o alive.txt
```

### Certificate Transparency
```bash
# crt.sh query
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### Google Dorking Patterns
- `site:target.com filetype:pdf|doc|xls|env|conf|bak|sql`
- `site:target.com inurl:admin|login|dashboard|api|debug|test`
- `site:target.com intitle:"index of" | intext:"parent directory"`
- `site:github.com "target.com" password|secret|key|token`

### Wayback Machine / URL Archives
```bash
# Historical URLs
echo "target.com" | waybackurls | sort -u > wayback_urls.txt
# Filter interesting patterns
cat wayback_urls.txt | grep -iE "\.js$|\.json$|\.xml$|\.bak$|\.sql$|api/|admin"
```

## Phase 2: Active Reconnaissance

### Port Scanning
```bash
# Fast full port scan
nmap -sS -p- --min-rate 5000 -T4 target.com -oN ports.txt
# Service version detection on open ports
nmap -sV -sC -p <open_ports> target.com -oN services.txt
# UDP top ports
nmap -sU --top-ports 100 target.com -oN udp.txt
```

### Content Discovery
```bash
# Directory/file brute force
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc 200,301,302,403 -o dirs.json
# Hidden files
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -mc 200,301,302,403 -o files.json
# API endpoint discovery
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,204,301,302,401,403
```

### Technology Fingerprinting
```bash
# Comprehensive tech detection
whatweb -a 3 https://target.com
# Header analysis
curl -sI https://target.com | head -30
# Nuclei technology detection
nuclei -u https://target.com -t technologies/ -silent
```

### Web Crawling
```bash
# Deep crawl with katana
katana -u https://target.com -d 5 -jc -kf -ef css,png,jpg,gif,svg,woff -o crawl.txt
# Extract JS files
cat crawl.txt | grep -iE "\.js$" | sort -u > js_files.txt
```

## Phase 3: JavaScript Analysis

### Endpoint Extraction from JS
```bash
# Download and analyze JS files
for url in $(cat js_files.txt); do
    curl -s "$url" | grep -oE '"(/[a-zA-Z0-9_/.-]+)"' | sort -u
done
# Look for API keys, secrets, tokens
for url in $(cat js_files.txt); do
    curl -s "$url" | grep -iE "(api[_-]?key|secret|token|password|auth)" | head -5
done
```

### Source Map Discovery
```bash
# Check for .map files
for url in $(cat js_files.txt); do
    status=$(curl -s -o /dev/null -w "%{http_code}" "${url}.map")
    [ "$status" = "200" ] && echo "SOURCE MAP: ${url}.map"
done
```

## Phase 4: Parameter Discovery

### Parameter Mining
```bash
# Arjun for parameter discovery
arjun -u https://target.com/page -oJ params.json
# Extract parameters from crawl data
cat crawl.txt | grep "?" | cut -d'?' -f2 | tr '&' '\n' | cut -d'=' -f1 | sort -u > params.txt
```

### Hidden Input Fields
- Inspect forms for hidden fields (`type="hidden"`)
- Check JavaScript for dynamically added parameters
- Test removed/commented parameters that may still be processed server-side

## Recon Output Organization

Structure findings for exploitation phases:
1. **Endpoints**: Full URL list organized by functionality
2. **Parameters**: Per-endpoint parameter list with types
3. **Technologies**: Framework, server, language, WAF stack
4. **Entry Points**: Login, registration, password reset, file upload, API, WebSocket
5. **Attack Surface Priority**: Rank by risk (auth endpoints > static pages)

## Pro Tips

- **Spray before manual** — automated discovery first, manual deep-dive on interesting findings
- **403 is interesting** — forbidden endpoints hint at admin/internal functionality; try bypass techniques
- **Compare authenticated vs unauthenticated** — different content reveals authorization gaps
- **Version strings matter** — outdated software = known CVEs; check `nuclei -t cves/`
- **Mobile API endpoints** — often less protected than web; check mobile app traffic/APK for endpoints
- **Rate limit your scans** — aggressive scanning triggers WAF/bans; use delays for stealth mode
