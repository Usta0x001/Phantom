#!/usr/bin/env python3
"""Generate a professional PDF report for Phantom using fpdf2.

Author: Rodwan Gadouri
Supervisor: Dr. Allama Oussama
"""

from fpdf import FPDF, XPos, YPos
from datetime import datetime


class PhantomReport(FPDF):
    """Custom PDF class with Phantom branding."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=25)

    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, "Phantom - Autonomous Adversary Simulation Platform", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
        self.set_draw_color(200, 0, 0)
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-20)
        self.set_draw_color(200, 0, 0)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def chapter_title(self, num, title):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(180, 0, 0)
        self.cell(0, 12, f"{num}. {title}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
        self.set_draw_color(200, 0, 0)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 120, self.get_y())
        self.ln(6)

    def section_title(self, title):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(60, 60, 60)
        self.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
        self.ln(2)

    def body_text(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 5.5, text)
        self.ln(3)

    def bullet(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(180, 0, 0)
        self.cell(8, 5.5, "-", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 5.5, text)
        self.ln(1)

    def code_block(self, text):
        self.set_font("Courier", "", 9)
        self.set_fill_color(240, 240, 240)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 5, text, fill=True)
        self.ln(3)

    def table_row(self, cells, widths, bold=False, fill=False):
        style = "B" if bold else ""
        self.set_font("Helvetica", style, 9)
        if fill:
            self.set_fill_color(240, 240, 240)
        h = 7
        for i, cell in enumerate(cells):
            self.cell(widths[i], h, str(cell)[:60], border=1, fill=fill,
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.ln(h)


def build_report():
    pdf = PhantomReport()
    pdf.alias_nb_pages()

    # ─── COVER PAGE ─────────────────────────────────────────────
    pdf.add_page()
    pdf.ln(40)
    pdf.set_font("Helvetica", "B", 32)
    pdf.set_text_color(180, 0, 0)
    pdf.cell(0, 15, "PHANTOM", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 10, "Autonomous Adversary Simulation Platform", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf.ln(5)
    pdf.set_draw_color(200, 0, 0)
    pdf.set_line_width(0.8)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.ln(10)

    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 8, "System Design & Technical Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.cell(0, 8, "Version 1.0", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf.ln(20)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Author: Rodwan Gadouri", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, "Supervisor: Dr. Allama Oussama", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf.ln(10)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 7, datetime.now().strftime("%B %Y"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.cell(0, 7, "github.com/Usta0x001/Phantom", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    # ─── TABLE OF CONTENTS ──────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(180, 0, 0)
    pdf.cell(0, 12, "Table of Contents", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
    pdf.ln(6)

    toc_items = [
        "1. Introduction",
        "2. System Architecture",
        "3. Core Components",
        "4. Security Architecture",
        "5. LLM Integration",
        "6. Tool Ecosystem",
        "7. Data Models",
        "8. Scan Lifecycle",
        "9. Report Pipeline",
        "10. Skills & Knowledge System",
        "11. Testing & Quality Assurance",
        "12. Performance & Scalability",
        "13. Future Work (Architecture v2)",
        "14. Conclusion",
    ]
    for item in toc_items:
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(40, 40, 40)
        pdf.cell(0, 7, item, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")

    # ─── 1. INTRODUCTION ────────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("1", "Introduction")

    pdf.body_text(
        "Phantom is an autonomous AI-powered penetration testing agent that discovers and verifies "
        "real vulnerabilities in web applications, APIs, and network services. Unlike traditional "
        "vulnerability scanners that rely on static signatures and predefined rules, Phantom uses "
        "large language models (LLMs) to reason about targets, plan attack strategies, chain "
        "exploits, and adapt its approach based on observations."
    )

    pdf.section_title("1.1 Motivation")
    pdf.body_text(
        "Modern web applications are increasingly complex, with dynamic frontends, microservice "
        "backends, and cloud-native deployment patterns. Traditional scanners struggle with: "
        "(1) multi-step vulnerabilities that require chaining, (2) business logic flaws that "
        "signatures cannot detect, (3) novel attack surfaces in APIs and WebSockets, and "
        "(4) context-dependent vulnerabilities that require understanding application behavior. "
        "Phantom addresses these gaps by using LLM reasoning to perform human-like security testing."
    )

    pdf.section_title("1.2 Design Goals")
    pdf.bullet("Autonomous operation: Run a full pentest with zero human intervention")
    pdf.bullet("Real vulnerability discovery: Find exploitable bugs, not just theoretical risks")
    pdf.bullet("Verification: Confirm findings by re-exploiting them before reporting")
    pdf.bullet("Safety: Strict scope enforcement, sandboxed execution, audit trail")
    pdf.bullet("Extensibility: Skills system for domain-specific knowledge")
    pdf.bullet("Cost control: Hard budget limits to prevent runaway LLM spending")

    pdf.section_title("1.3 Key Capabilities")
    pdf.bullet("Reconnaissance: Port scanning, subdomain enumeration, technology fingerprinting")
    pdf.bullet("Vulnerability discovery: SQL injection, XSS, RCE, SSRF, IDOR, auth bypass")
    pdf.bullet("Browser automation: Full Playwright-based interaction for JS-heavy apps")
    pdf.bullet("Multi-agent delegation: Spawn sub-agents for specialized tasks")
    pdf.bullet("Attack graph generation: NetworkX-based attack surface visualization")
    pdf.bullet("Compliance mapping: OWASP Top 10, CWE, MITRE ATT&CK enrichment")

    # ─── 2. SYSTEM ARCHITECTURE ─────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("2", "System Architecture")

    pdf.body_text(
        "Phantom follows a layered architecture with clear separation of concerns. The system "
        "is organized into six major layers: User Interface, Orchestration, Agent Core, "
        "Security, Execution, and Output."
    )

    pdf.section_title("2.1 Architecture Layers")

    layers = [
        ["Layer", "Components", "Responsibility"],
        ["Interface", "CLI, TUI, Streaming Parser", "User interaction, live dashboard"],
        ["Orchestration", "Profile, Scope, Cost, Audit", "Scan configuration & governance"],
        ["Agent Core", "BaseAgent, State, LLM, Memory", "Reasoning loop & state management"],
        ["Security", "Firewall, Verifier, Scope", "Input validation & access control"],
        ["Execution", "Docker, Tool Server, Tools", "Sandboxed tool execution"],
        ["Output", "Reports, Graphs, Templates", "Structured result generation"],
    ]
    widths = [30, 65, 90]
    for i, row in enumerate(layers):
        pdf.table_row(row, widths, bold=(i == 0), fill=(i == 0))

    pdf.ln(5)
    pdf.section_title("2.2 Package Structure")
    pdf.body_text(
        "The codebase is organized into 11 Python packages under the phantom/ namespace. "
        "Total: 80+ modules, 15,000+ lines of production code."
    )

    pkgs = [
        ["Package", "Modules", "Purpose"],
        ["agents/", "5", "Agent core, state machine, ReAct loop"],
        ["core/", "20", "Security, verification, reporting, compliance"],
        ["tools/", "25+", "Tool implementations and dispatch"],
        ["llm/", "7", "LLM client, memory compression, providers"],
        ["runtime/", "4", "Docker sandbox and tool server"],
        ["models/", "5", "Pydantic domain models (vuln, host, scan)"],
        ["skills/", "50+", "Domain knowledge Markdown files"],
        ["interface/", "8", "CLI, TUI, formatters"],
        ["telemetry/", "2", "Run tracing and statistics"],
        ["config/", "1", "Environment-based configuration"],
        ["utils/", "1", "Resource path resolution"],
    ]
    widths = [30, 20, 135]
    for i, row in enumerate(pkgs):
        pdf.table_row(row, widths, bold=(i == 0), fill=(i == 0))

    # ─── 3. CORE COMPONENTS ─────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("3", "Core Components")

    pdf.section_title("3.1 BaseAgent (agents/base_agent.py)")
    pdf.body_text(
        "The BaseAgent implements the ReAct (Reason + Act) loop that drives all agent behavior. "
        "On each iteration, the agent: (1) sends the conversation history to the LLM, "
        "(2) parses tool invocations from the response, (3) validates each through the firewall, "
        "(4) executes approved tools, (5) records findings, and (6) checks stop conditions. "
        "The agent supports graceful crash handling, saving partial results if the LLM fails mid-scan. "
        "Key properties: 859 lines, asyncio-based, supports interactive and non-interactive modes."
    )

    pdf.section_title("3.2 AgentState (agents/state.py)")
    pdf.body_text(
        "AgentState is a Pydantic model that tracks the agent's complete state. Key bounded "
        "collections: messages (max 500, system prompt preserved on trim), findings_ledger "
        "(max 200, NEVER compressed), actions (max 5000), errors (max 1000). Wall-clock time "
        "limit: 4 hours, cumulative across resumes via _cumulative_elapsed_seconds. "
        "Max iterations: 200 (configurable per profile)."
    )

    pdf.section_title("3.3 EnhancedAgentState (agents/enhanced_state.py)")
    pdf.body_text(
        "Extends AgentState with vulnerability tracking, host discovery, scan phase management, "
        "endpoint deduplication, and priority queuing. Provides checkpoint save/restore for "
        "resumable scans and to_report_data() export for structured reporting. "
        "Tracks 537 lines of security-specific state management."
    )

    pdf.section_title("3.4 LLM Client (llm/llm.py)")
    pdf.body_text(
        "Wraps LiteLLM for multi-provider LLM access (OpenRouter, OpenAI, Anthropic, Ollama). "
        "Features: async streaming, cost tracking per request, prompt caching support, "
        "vision/screenshot support, reasoning model detection, automatic retries with backoff. "
        "Integrates with MemoryCompressor for context window management (80K token threshold)."
    )

    pdf.section_title("3.5 Memory Compressor (llm/memory_compressor.py)")
    pdf.body_text(
        "When conversation exceeds 80,000 tokens, the compressor: (1) keeps system prompt and "
        "last 12 messages verbatim, (2) summarizes older messages via a separate LLM call with "
        "strict preservation rules for URLs, payloads, credentials, and findings. "
        "The findings_ledger is NEVER compressed, serving as a permanent memory."
    )

    # ─── 4. SECURITY ARCHITECTURE ───────────────────────────────
    pdf.add_page()
    pdf.chapter_title("4", "Security Architecture")

    pdf.body_text(
        "Phantom implements 7 layers of defense-in-depth to prevent misuse, scope violations, "
        "and unintended damage. Every tool invocation passes through multiple security gates "
        "before reaching the execution layer."
    )

    pdf.section_title("4.1 Tool Invocation Firewall")
    pdf.body_text(
        "The ToolInvocationFirewall validates every tool call before execution. "
        "It checks 8 injection patterns (semicolons, pipes, backticks, $(), ${}, redirects, "
        "&&, ||), enforces per-tool argument whitelists for nmap/sqlmap/ffuf extra_args, "
        "rejects arguments longer than 4096 chars, and blocks dangerous sandbox commands "
        "(fork bombs, rm -rf /, curl|sh). Violations are logged to the HMAC-chained audit trail."
    )

    pdf.section_title("4.2 Scope Validator")
    pdf.body_text(
        "ScopeValidator enforces whitelist-based target authorization with DNS pinning. "
        "Supports domain, IP, CIDR, and regex rules. Private IP detection prevents SSRF to "
        "internal networks. DNS resolution is cached (bounded to 10K entries) and pinned to "
        "prevent DNS rebinding attacks. Validated on every tool call, not just at scan start."
    )

    pdf.section_title("4.3 Audit Logger")
    pdf.body_text(
        "AuditLogger provides a crash-safe, tamper-evident audit trail in JSONL format. "
        "Each entry is HMAC-SHA256 chained to the previous entry. On scan resume, the chain "
        "integrity is verified to detect tampering. File rotation at configurable size limits. "
        "All tool calls, findings, scope violations, and agent decisions are logged."
    )

    pdf.section_title("4.4 Sandbox Isolation")
    pdf.body_text(
        "All offensive tools execute inside an ephemeral Docker container with: "
        "no host filesystem access, restricted capabilities, port reservation with minimal "
        "TOCTOU window (socket held until Docker binds), symlink-safe file operations, "
        "tar archive size cap (500 MB), and automatic cleanup on scan completion or failure."
    )

    security_table = [
        ["Layer", "Component", "Protection"],
        ["L1", "Scope Validator", "Target authorization, DNS pinning"],
        ["L2", "Tool Firewall", "Injection detection, arg whitelist"],
        ["L3", "Docker Sandbox", "Process isolation, no host access"],
        ["L4", "Cost Controller", "Budget limits ($25 default)"],
        ["L5", "Time Control", "Wall-clock limit (4h cumulative)"],
        ["L6", "Audit Logger", "HMAC chain, tamper detection"],
        ["L7", "Output Sanitizer", "Credential scrub, CSV formula block"],
    ]
    widths = [15, 45, 125]
    for i, row in enumerate(security_table):
        pdf.table_row(row, widths, bold=(i == 0), fill=(i == 0))

    # ─── 5. LLM INTEGRATION ─────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("5", "LLM Integration")

    pdf.section_title("5.1 Provider Support")
    pdf.body_text(
        "Phantom uses LiteLLM to support 100+ LLM providers through a unified API. "
        "Recommended: OpenRouter for access to DeepSeek, Claude, GPT-4, Llama models. "
        "Also supports direct OpenAI, Anthropic, and local inference (Ollama, vLLM)."
    )

    pdf.section_title("5.2 Prompt Engineering")
    pdf.body_text(
        "The agent's system prompt is assembled from: (1) persona definition (PhantomAgent identity), "
        "(2) available tool schemas (XML format), (3) loaded skills (domain-specific knowledge), "
        "(4) scan profile directives, and (5) findings ledger (permanent discoveries). "
        "Jinja2 templates with autoescape are used for safe prompt construction."
    )

    pdf.section_title("5.3 Streaming & Cost Tracking")
    pdf.body_text(
        "LLM responses are streamed via async iterators for real-time CLI display. "
        "Every request tracks: input tokens, output tokens, cached tokens, and cost. "
        "The CostController enforces a hard budget limit with 80% warning threshold. "
        "Credential patterns are redacted from prompts before sending to the LLM."
    )

    # ─── 6. TOOL ECOSYSTEM ──────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("6", "Tool Ecosystem")

    pdf.body_text(
        "Phantom provides 30+ security tools organized into categories. Tools are registered "
        "via XML schemas and dispatched through a unified executor with firewall integration."
    )

    tools_table = [
        ["Category", "Tools", "Execution"],
        ["Recon", "nmap, httpx, subfinder", "Sandbox"],
        ["Discovery", "ffuf, nuclei, gobuster", "Sandbox"],
        ["Exploitation", "sqlmap, nikto, custom scripts", "Sandbox"],
        ["Browser", "Playwright (navigate, click, JS)", "Sandbox"],
        ["Agent", "sub_agent, todo, notes, finish", "Local"],
        ["Reporting", "record_finding, web_search", "Local"],
    ]
    widths = [35, 70, 80]
    for i, row in enumerate(tools_table):
        pdf.table_row(row, widths, bold=(i == 0), fill=(i == 0))

    pdf.ln(5)
    pdf.section_title("6.1 Tool Execution Path")
    pdf.body_text(
        "1. LLM response parsed for XML tool invocations\n"
        "2. Each invocation validated by ToolFirewall\n"
        "3. Blocked calls return error to LLM; allowed calls dispatched\n"
        "4. Local tools run in-process; sandbox tools sent via HTTP to container\n"
        "5. Results truncated to 8KB, XML-wrapped, auto-recorded to findings\n"
        "6. Audit logger records each tool call with timing and result summary"
    )

    pdf.section_title("6.2 Tool Registry")
    pdf.body_text(
        "Tools are registered at import time using @tool decorator with XML schema files. "
        "Each schema defines: tool name, description, parameters (type, required, description), "
        "and execution mode (local vs sandbox). The registry supports dynamic content injection "
        "for skills discovery."
    )

    # ─── 7. DATA MODELS ─────────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("7", "Data Models")

    pdf.body_text(
        "Phantom uses Pydantic models for type-safe data management. The core models are:"
    )

    pdf.section_title("7.1 Vulnerability Model")
    pdf.bullet("Fields: id, name, vulnerability_class, severity (enum), cvss_score (0-10)")
    pdf.bullet("Evidence: raw request/response data, payloads, screenshots")
    pdf.bullet("Verification: status (detected/verified/false_positive), verification method")
    pdf.bullet("Enrichment: CWE IDs, MITRE ATT&CK techniques, remediation steps")

    pdf.section_title("7.2 Host Model")
    pdf.bullet("Fields: ip, hostname, os_fingerprint")
    pdf.bullet("Ports: number, protocol, service, version, state")
    pdf.bullet("Technologies: name, version, category (framework, CMS, server)")

    pdf.section_title("7.3 Scan Model")
    pdf.bullet("ScanResult: scan_id, target, status, timing, vuln count")
    pdf.bullet("ScanPhase: RECON, ENUMERATION, EXPLOITATION, POST_EXPLOITATION, REPORTING")
    pdf.bullet("ScanStatus: INITIALIZING, RUNNING, COMPLETED, FAILED, CANCELLED")

    # ─── 8. SCAN LIFECYCLE ──────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("8", "Scan Lifecycle")

    pdf.section_title("8.1 Initialization")
    pdf.body_text(
        "1. CLI parses target URLs and scan profile\n"
        "2. ScopeValidator created with target whitelist\n"
        "3. DockerRuntime creates ephemeral sandbox container\n"
        "4. AuditLogger and Tracer initialized (HMAC chain started)\n"
        "5. ToolFirewall initialized with scope validator\n"
        "6. CostController initialized with budget limit\n"
        "7. KnowledgeStore loaded from previous scans"
    )

    pdf.section_title("8.2 Execution (ReAct Loop)")
    pdf.body_text(
        "Each iteration: LLM receives conversation + findings ledger, reasons about strategy, "
        "emits tool calls, executor validates and dispatches, results recorded. "
        "Memory compression triggers when context exceeds 80K tokens. "
        "Loop detector prevents repetitive behavior. "
        "Stop conditions: iteration limit (200), time limit (4h), cost limit ($25), "
        "agent finish, or user interrupt."
    )

    pdf.section_title("8.3 Finalization")
    pdf.body_text(
        "1. Verification engine re-tests HIGH/CRITICAL findings\n"
        "2. MITRE ATT&CK enrichment tags each vulnerability\n"
        "3. Compliance mapper generates OWASP/CWE/NIST report\n"
        "4. Attack graph built with NetworkX (nodes: hosts, services, vulns)\n"
        "5. Nuclei templates generated for reproducibility\n"
        "6. Knowledge store updated with new findings (encrypted at rest)\n"
        "7. Reports generated: JSON + HTML + Markdown (credential-scrubbed)\n"
        "8. Sandbox container destroyed, audit trail finalized"
    )

    # ─── 9. REPORT PIPELINE ─────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("9", "Report Pipeline")

    pdf.section_title("9.1 Report Formats")
    formats = [
        ["Format", "Purpose", "Features"],
        ["JSON", "Machine-readable", "Full vuln data, CVSS, evidence, MITRE"],
        ["HTML", "Executive/team", "Styled CSS, sortable tables, severity badges"],
        ["Markdown", "Documentation", "GitHub-compatible, CSV-injection safe"],
    ]
    widths = [30, 50, 105]
    for i, row in enumerate(formats):
        pdf.table_row(row, widths, bold=(i == 0), fill=(i == 0))

    pdf.ln(5)
    pdf.section_title("9.2 Output Structure")
    pdf.body_text(
        "Each scan generates a run directory under phantom_runs/ containing:\n"
        "- scan_stats.json: Timing, token usage, cost breakdown\n"
        "- vulnerabilities.csv: Quick reference index\n"
        "- report.json/html/md: Full structured reports\n"
        "- attack_graph.json: NetworkX graph data\n"
        "- compliance_report.json: OWASP/CWE/NIST mappings\n"
        "- nuclei_templates/: Generated YAML templates\n"
        "- audit.jsonl: HMAC-chained audit trail\n"
        "- screenshots/: Browser screenshots"
    )

    pdf.section_title("9.3 Credential Scrubbing")
    pdf.body_text(
        "Before report generation, all output passes through credential scrubbing: "
        "regular expressions detect password=, token=, api_key=, bearer, session_id patterns "
        "and replace values with [REDACTED]. Recursive dict scrubbing handles nested structures. "
        "CSV formula injection is prevented by prefixing dangerous cell values with single quotes."
    )

    # ─── 10. SKILLS & KNOWLEDGE ─────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("10", "Skills & Knowledge System")

    pdf.section_title("10.1 Skills")
    pdf.body_text(
        "Skills are Markdown files loaded into the agent's system prompt to provide domain "
        "expertise. Categories: reconnaissance, vulnerabilities, frameworks, technologies, "
        "protocols, cloud, scan_modes, coordination, custom. The agent selects relevant skills "
        "based on the target and scan profile. Custom skills can be added to phantom_knowledge/custom/."
    )

    pdf.section_title("10.2 Knowledge Persistence")
    pdf.body_text(
        "KnowledgeStore saves discovered hosts, vulnerabilities, false positive signatures, "
        "and scan history across scan sessions. This enables the agent to: skip known false "
        "positives, prioritize previously vulnerable endpoints, and build a cumulative picture "
        "of the target's attack surface. Optional Fernet encryption protects data at rest."
    )

    # ─── 11. TESTING & QA ───────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("11", "Testing & Quality Assurance")

    pdf.body_text(
        "Phantom has a comprehensive test suite with 808 tests, 0 failures, 21 skipped."
    )

    tests_table = [
        ["Suite", "Tests", "Scope"],
        ["test_e2e_system.py", "184", "Full system integration"],
        ["test_v0920_audit_fixes.py", "39", "Security fix verification"],
        ["test_all_modules.py", "~200", "Module-level unit tests"],
        ["test_v0918_features.py", "~100", "Feature regression"],
        ["test_v0910_coverage.py", "~80", "Coverage gaps"],
        ["test_security_fixes.py", "~50", "Security-specific tests"],
    ]
    widths = [60, 20, 105]
    for i, row in enumerate(tests_table):
        pdf.table_row(row, widths, bold=(i == 0), fill=(i == 0))

    pdf.ln(5)
    pdf.section_title("11.1 Security Audit")
    pdf.body_text(
        "The system underwent two deep offensive audits: (1) v0.9.19 audit found 83 findings "
        "(8 Critical, 19 High, 34 Medium, 22 Low). (2) All Critical and High bugs were fixed "
        "and verified with dedicated tests. System score improved from 5.8/10 to 8.0/10."
    )

    # ─── 12. PERFORMANCE ────────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("12", "Performance & Scalability")

    pdf.section_title("12.1 Resource Bounds")
    bounds = [
        ["Resource", "Limit", "Purpose"],
        ["Messages", "500", "Prevent OOM from conversation growth"],
        ["Findings", "200", "Bound permanent ledger"],
        ["Actions", "5000", "Bound tool history"],
        ["Errors", "1000", "Bound error log"],
        ["Iterations", "200", "Prevent infinite loops"],
        ["Wall-clock", "4 hours", "Prevent runaway scans"],
        ["Cost", "$25", "Prevent budget overrun"],
        ["Arg length", "4096 chars", "Prevent injection via long args"],
        ["Tar archive", "500 MB", "Prevent disk bombs"],
        ["DNS cache", "10K entries", "Prevent cache memory leak"],
        ["Screenshot", "10 MB", "Prevent memory bomb via images"],
    ]
    widths = [35, 30, 120]
    for i, row in enumerate(bounds):
        pdf.table_row(row, widths, bold=(i == 0), fill=(i == 0))

    pdf.ln(5)
    pdf.section_title("12.2 Optimization Techniques")
    pdf.bullet("Lazy debug logging: %-formatting avoids eager f-string evaluation")
    pdf.bullet("Module-level constants: Tool maps and regex patterns compiled once")
    pdf.bullet("Lightweight state summaries: Hot-path uses dict, not model_dump()")
    pdf.bullet("Bounded collections: FIFO eviction prevents unbounded memory growth")
    pdf.bullet("Truncated tool results: 8KB cap prevents token waste on verbose output")

    # ─── 13. FUTURE WORK ────────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("13", "Future Work (Architecture v2)")

    pdf.body_text(
        "The current architecture (v1) has been hardened through two security audits and "
        "achieves a system score of 8.0/10. Architecture v2 will focus on:"
    )

    pdf.section_title("13.1 Async-First Architecture")
    pdf.body_text(
        "Replace synchronous enrichment pipeline with fully async execution. "
        "Parallel tool execution with configurable concurrency. "
        "Non-blocking report generation."
    )

    pdf.section_title("13.2 Plugin-Based Tool System")
    pdf.body_text(
        "Replace hardcoded tool registry with plugin discovery (entry_points / plugin_loader). "
        "Enable third-party tool packages. Hot-reload tool schemas without restart."
    )

    pdf.section_title("13.3 State Machine Formalization")
    pdf.body_text(
        "Replace ad-hoc phase tracking with formal state machine. "
        "Enable checkpoint schema versioning for forward compatibility."
    )

    pdf.section_title("13.4 Multi-Agent Orchestration")
    pdf.body_text(
        "Hierarchical agent delegation with shared context. "
        "Specialized agents: ReconAgent, ExploitAgent, ReportAgent. "
        "Inter-agent message passing with priority routing."
    )

    # ─── 14. CONCLUSION ─────────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("14", "Conclusion")

    pdf.body_text(
        "Phantom represents a new paradigm in security testing: autonomous, intelligent, "
        "and adaptive. By combining LLM reasoning with a hardened execution sandbox and "
        "comprehensive security architecture, Phantom can discover real vulnerabilities "
        "that traditional scanners miss."
    )

    pdf.body_text(
        "The system has been validated through 808 automated tests, two deep security audits, "
        "and successful scans against real-world targets. With all Critical and High security "
        "findings resolved and verified, the system achieves a security score of 8.2/10 "
        "and overall system score of 8.0/10."
    )

    pdf.body_text(
        "The path forward is Architecture v2, which will bring async-first execution, "
        "plugin-based tool management, and hierarchical multi-agent orchestration. "
        "The foundation built in v1 is production-grade and ready for this evolution."
    )

    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 7, "Author: Rodwan Gadouri", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.cell(0, 7, "Supervisor: Dr. Allama Oussama", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.cell(0, 7, "Phantom v1.0 - Autonomous Adversary Simulation Platform", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    return pdf


if __name__ == "__main__":
    import sys
    output = sys.argv[1] if len(sys.argv) > 1 else "Phantom_Technical_Report.pdf"
    pdf = build_report()
    pdf.output(output)
    print(f"Report generated: {output}")
