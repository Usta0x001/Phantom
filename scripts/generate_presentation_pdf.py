#!/usr/bin/env python3
"""Generate a beautiful black-themed PDF presentation for Phantom using fpdf2.

Author: Rodwan Gadouri
Supervisor: Dr. Allama Oussama
"""

from fpdf import FPDF, XPos, YPos
from datetime import datetime


class PhantomPresentation(FPDF):
    """Landscape PDF presentation with dark theme."""

    def __init__(self):
        super().__init__(orientation="L", format="A4")
        self.set_auto_page_break(auto=False)
        self.slide_num = 0

    def _draw_bg(self):
        """Fill page with dark background."""
        self.set_fill_color(15, 15, 15)
        self.rect(0, 0, 297, 210, "F")

    def _draw_accent_line(self, y, width=200):
        """Draw red accent line."""
        self.set_draw_color(200, 30, 30)
        self.set_line_width(1.2)
        x_start = (297 - width) / 2
        self.line(x_start, y, x_start + width, y)

    def _draw_thin_accent(self, x, y, width):
        """Draw thin red accent."""
        self.set_draw_color(200, 30, 30)
        self.set_line_width(0.5)
        self.line(x, y, x + width, y)

    def _slide_number(self):
        """Draw slide number in bottom-right."""
        self.set_font("Helvetica", "", 8)
        self.set_text_color(80, 80, 80)
        self.set_xy(265, 195)
        self.cell(20, 8, f"{self.slide_num}", align="R")

    def _footer_text(self):
        """Draw footer."""
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(60, 60, 60)
        self.set_xy(10, 197)
        self.cell(100, 6, "Phantom - Autonomous Adversary Simulation")

    def new_slide(self):
        """Start a new slide."""
        self.add_page()
        self.slide_num += 1
        self._draw_bg()
        if self.slide_num > 1:
            self._slide_number()
            self._footer_text()

    def title_slide(self, title, subtitle, author, supervisor, date_str):
        """Create title slide."""
        self.new_slide()
        # Decorative top accent
        self._draw_accent_line(60, 180)

        self.set_font("Helvetica", "B", 44)
        self.set_text_color(200, 30, 30)
        self.set_xy(0, 65)
        self.cell(297, 20, title, align="C")

        self.set_font("Helvetica", "", 16)
        self.set_text_color(200, 200, 200)
        self.set_xy(0, 88)
        self.cell(297, 10, subtitle, align="C")

        # Decorative bottom accent
        self._draw_accent_line(105, 120)

        self.set_font("Helvetica", "B", 12)
        self.set_text_color(220, 220, 220)
        self.set_xy(0, 115)
        self.cell(297, 8, author, align="C")

        self.set_font("Helvetica", "", 11)
        self.set_text_color(160, 160, 160)
        self.set_xy(0, 126)
        self.cell(297, 8, supervisor, align="C")

        self.set_font("Helvetica", "", 10)
        self.set_text_color(100, 100, 100)
        self.set_xy(0, 140)
        self.cell(297, 8, date_str, align="C")

        self.set_xy(0, 150)
        self.cell(297, 8, "github.com/Usta0x001/Phantom", align="C")

    def section_slide(self, title):
        """Full-screen section divider slide."""
        self.new_slide()
        self._draw_accent_line(90, 160)

        self.set_font("Helvetica", "B", 36)
        self.set_text_color(200, 30, 30)
        self.set_xy(0, 95)
        self.cell(297, 18, title, align="C")

        self._draw_accent_line(118, 160)

    def content_slide(self, title, bullets, two_col=False):
        """Content slide with title and bullet points."""
        self.new_slide()
        # Title
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(200, 30, 30)
        self.set_xy(20, 15)
        self.cell(250, 14, title)

        self._draw_thin_accent(20, 32, 100)

        if not two_col:
            y = 40
            for text in bullets:
                if y > 185:
                    break
                self.set_xy(25, y)
                self.set_font("Helvetica", "B", 10)
                self.set_text_color(200, 30, 30)
                self.cell(8, 7, ">", new_x=XPos.RIGHT, new_y=YPos.TOP)
                self.set_font("Helvetica", "", 11)
                self.set_text_color(210, 210, 210)
                self.multi_cell(235, 7, text)
                y = self.get_y() + 4
        else:
            mid = len(bullets) // 2 + len(bullets) % 2
            left = bullets[:mid]
            right = bullets[mid:]

            y = 40
            for text in left:
                if y > 185:
                    break
                self.set_xy(25, y)
                self.set_font("Helvetica", "B", 10)
                self.set_text_color(200, 30, 30)
                self.cell(6, 7, ">", new_x=XPos.RIGHT, new_y=YPos.TOP)
                self.set_font("Helvetica", "", 10)
                self.set_text_color(210, 210, 210)
                self.multi_cell(110, 7, text)
                y = self.get_y() + 3

            y = 40
            for text in right:
                if y > 185:
                    break
                self.set_xy(155, y)
                self.set_font("Helvetica", "B", 10)
                self.set_text_color(200, 30, 30)
                self.cell(6, 7, ">", new_x=XPos.RIGHT, new_y=YPos.TOP)
                self.set_font("Helvetica", "", 10)
                self.set_text_color(210, 210, 210)
                self.multi_cell(110, 7, text)
                y = self.get_y() + 3

    def stat_slide(self, title, stats):
        """Slide with large stat numbers."""
        self.new_slide()
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(200, 30, 30)
        self.set_xy(20, 15)
        self.cell(250, 14, title)
        self._draw_thin_accent(20, 32, 100)

        cols = min(len(stats), 4)
        col_w = 257 / cols
        x_start = 20

        for i, (num, label) in enumerate(stats):
            x = x_start + i * col_w
            y_top = 55

            # Large number
            self.set_font("Helvetica", "B", 40)
            self.set_text_color(200, 30, 30)
            self.set_xy(x, y_top)
            self.cell(col_w, 30, str(num), align="C")

            # Label
            self.set_font("Helvetica", "", 11)
            self.set_text_color(180, 180, 180)
            self.set_xy(x, y_top + 32)
            self.cell(col_w, 8, label, align="C")

    def table_slide(self, title, headers, rows):
        """Slide with a styled table."""
        self.new_slide()
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(200, 30, 30)
        self.set_xy(20, 15)
        self.cell(250, 14, title)
        self._draw_thin_accent(20, 32, 100)

        n_cols = len(headers)
        col_w = 257 / n_cols
        widths = [col_w] * n_cols
        y = 42

        # Header row
        self.set_fill_color(200, 30, 30)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        for i, h in enumerate(headers):
            self.set_xy(20 + sum(widths[:i]), y)
            self.cell(widths[i], 9, h, border=0, fill=True, align="C")
        y += 11

        # Data rows
        for ri, row in enumerate(rows):
            if y > 185:
                break
            if ri % 2 == 0:
                self.set_fill_color(25, 25, 25)
            else:
                self.set_fill_color(35, 35, 35)
            self.set_text_color(200, 200, 200)
            self.set_font("Helvetica", "", 9)
            for i, val in enumerate(row):
                self.set_xy(20 + sum(widths[:i]), y)
                self.cell(widths[i], 8, str(val)[:45], border=0, fill=True, align="C")
            y += 9


def build_presentation():
    pdf = PhantomPresentation()

    # ─── SLIDE 1: TITLE ─────────────────────────────────────
    pdf.title_slide(
        "PHANTOM",
        "Autonomous Adversary Simulation Platform",
        "Author: Rodwan Gadouri",
        "Supervisor: Dr. Allama Oussama",
        datetime.now().strftime("%B %Y")
    )

    # ─── SLIDE 2: AGENDA ────────────────────────────────────
    pdf.content_slide("Agenda", [
        "1.  What is Phantom?",
        "2.  System Architecture",
        "3.  Core Components",
        "4.  Security Architecture",
        "5.  Tool Ecosystem",
        "6.  LLM Integration",
        "7.  Scan Lifecycle",
        "8.  Testing & Quality",
        "9.  Results & Metrics",
        "10. Future Work & Arch v2",
    ])

    # ─── SLIDE 3: WHAT IS PHANTOM ───────────────────────────
    pdf.section_slide("What is Phantom?")

    pdf.content_slide("The Problem", [
        "Traditional vulnerability scanners rely on static signatures and predefined rules",
        "They miss multi-step vulnerabilities that require chaining multiple attack vectors",
        "Business logic flaws are invisible to signature-based detection",
        "APIs, WebSockets, and modern SPAs create new attack surfaces",
        "Manual penetration testing is expensive and does not scale",
    ])

    pdf.content_slide("The Solution: Phantom", [
        "AI-powered autonomous penetration testing agent",
        "Uses Large Language Models (LLMs) to reason about targets like a human pentester",
        "Plans attack strategies, chains exploits, and adapts based on observations",
        "Discovers and VERIFIES real vulnerabilities with proof-of-concept",
        "Runs in a sandboxed Docker container for complete isolation",
        "Produces structured reports with OWASP/CWE/MITRE ATT&CK enrichment",
    ])

    # ─── SLIDE 4: ARCHITECTURE ──────────────────────────────
    pdf.section_slide("System Architecture")

    pdf.table_slide("Architecture Layers", 
        ["Layer", "Components", "Responsibility"],
        [
            ["Interface", "CLI, TUI, Streaming", "User interaction"],
            ["Orchestration", "Profile, Scope, Cost, Audit", "Governance"],
            ["Agent Core", "BaseAgent, State, LLM, Memory", "Reasoning loop"],
            ["Security", "Firewall, Verifier, Scope", "Access control"],
            ["Execution", "Docker, Tool Server, 30+ Tools", "Sandbox execution"],
            ["Output", "JSON, HTML, Markdown, Graphs", "Result generation"],
        ]
    )

    pdf.content_slide("Package Structure", [
        "agents/ - ReAct loop, state machine, enhanced state (5 modules)",
        "core/ - Security, verification, reporting, compliance (20 modules)",
        "tools/ - 30+ security tool implementations (25+ modules)",
        "llm/ - LLM client, memory compression, providers (7 modules)",
        "runtime/ - Docker sandbox, tool server, port reservation (4 modules)",
        "models/ - Pydantic domain models: Vuln, Host, Scan (5 modules)",
        "skills/ - 50+ domain knowledge Markdown files",
        "interface/ - CLI, TUI, formatters, streaming (8 modules)",
    ], two_col=True)

    # ─── SLIDE 5: CORE COMPONENTS ───────────────────────────
    pdf.section_slide("Core Components")

    pdf.content_slide("BaseAgent - The Reasoning Engine", [
        "Implements the ReAct (Reason + Act) loop driving all agent behavior",
        "Each iteration: LLM reasons -> emits tool calls -> firewall validates -> executor runs",
        "Graceful crash handling saves partial results if LLM fails mid-scan",
        "Supports interactive and non-interactive modes",
        "859 lines of asyncio-based Python, battle-tested through 808 tests",
    ])

    pdf.content_slide("State Management", [
        "AgentState: Pydantic model tracking complete agent state",
        "Bounded collections: messages (500), findings (200), actions (5000), errors (1000)",
        "Wall-clock limit: 4 hours cumulative across resumes",
        "Max iterations: 200 (configurable per scan profile)",
        "EnhancedAgentState adds vuln tracking, host discovery, phase management",
        "Checkpoint save/restore enables resumable scans",
    ])

    pdf.content_slide("Memory & Context Management", [
        "LLM context window managed via MemoryCompressor",
        "Triggers when conversation exceeds 80,000 tokens",
        "Keeps system prompt + last 12 messages verbatim",
        "Summarizes older messages preserving URLs, payloads, credentials",
        "findings_ledger is NEVER compressed - permanent memory",
        "Cost tracking: per-request token counting and budget enforcement",
    ])

    # ─── SLIDE 6: SECURITY ──────────────────────────────────
    pdf.section_slide("Security Architecture")

    pdf.content_slide("7 Layers of Defense-in-Depth", [
        "L1: Scope Validator - whitelist authorization, DNS pinning, SSRF prevention",
        "L2: Tool Firewall - 8 injection patterns, arg whitelists, length limits",
        "L3: Docker Sandbox - ephemeral containers, no host access, restricted caps",
        "L4: Cost Controller - hard budget limits ($25 default, 80% warning)",
        "L5: Time Control - wall-clock limit (4h cumulative across resumes)",
        "L6: Audit Logger - HMAC-SHA256 chained JSONL, tamper detection on resume",
        "L7: Output Sanitizer - credential scrubbing, CSV injection prevention",
    ])

    pdf.content_slide("Key Security Features", [
        "DNS pinning prevents DNS rebinding attacks (cache bounded to 10K entries)",
        "Sandbox commands blocked: fork bombs, rm -rf, curl|sh, etc.",
        "Tool arguments validated against per-tool whitelists (nmap, sqlmap, ffuf)",
        "Maximum argument length: 4096 characters (prevents injection via overflow)",
        "Tar archive cap: 500 MB (prevents disk bombs)",
        "HMAC chain integrity verified on every scan resume",
    ])

    # ─── SLIDE 7: TOOLS ─────────────────────────────────────
    pdf.section_slide("Tool Ecosystem")

    pdf.table_slide("30+ Security Tools",
        ["Category", "Tools", "Execution Mode"],
        [
            ["Reconnaissance", "nmap, httpx, subfinder", "Docker Sandbox"],
            ["Discovery", "ffuf, nuclei, gobuster", "Docker Sandbox"],
            ["Exploitation", "sqlmap, nikto, custom scripts", "Docker Sandbox"],
            ["Browser", "Playwright: navigate, click, JS eval", "Docker Sandbox"],
            ["Agent", "sub_agent, todo, notes, finish", "Local Process"],
            ["Reporting", "record_finding, web_search", "Local Process"],
        ]
    )

    pdf.content_slide("Tool Execution Pipeline", [
        "1. LLM response parsed for XML tool invocations",
        "2. ToolFirewall validates each invocation (scope, injection, args)",
        "3. Blocked calls return descriptive error to LLM for self-correction",
        "4. Sandbox tools sent via HTTP to container; local tools run in-process",
        "5. Results truncated to 8KB, XML-wrapped, appended to conversation",
        "6. Audit logger records tool call with timing and result hash",
    ])

    # ─── SLIDE 8: LLM INTEGRATION ───────────────────────────
    pdf.section_slide("LLM Integration")

    pdf.content_slide("Multi-Provider LLM Support", [
        "Built on LiteLLM: supports 100+ providers through unified API",
        "Recommended: OpenRouter (DeepSeek, Claude, GPT-4, Llama)",
        "Also supports: direct OpenAI, Anthropic, Ollama, vLLM",
        "Async streaming for real-time CLI display",
        "Per-request cost tracking (input/output/cached tokens)",
        "Credential redaction before sending prompts to LLM",
    ])

    pdf.content_slide("Prompt Architecture", [
        "System prompt assembled from 5 components:",
        "  1. Persona definition (PhantomAgent identity and rules)",
        "  2. Available tool schemas in XML format",
        "  3. Loaded skills (domain-specific Markdown knowledge)",
        "  4. Scan profile directives (depth, iteration limits)",
        "  5. Findings ledger (permanent discoveries, never compressed)",
        "Jinja2 templates with autoescape for safe prompt construction",
    ])

    # ─── SLIDE 9: SCAN LIFECYCLE ────────────────────────────
    pdf.section_slide("Scan Lifecycle")

    pdf.content_slide("Initialization Phase", [
        "CLI parses target URLs and scan profile (quick/standard/deep/stealth/api)",
        "ScopeValidator created with target whitelist",
        "DockerRuntime creates ephemeral sandbox container",
        "AuditLogger starts HMAC chain; Tracer initialized",
        "CostController set with budget limit; KnowledgeStore loaded",
    ])

    pdf.content_slide("Execution Phase (ReAct Loop)", [
        "LLM receives: conversation + findings_ledger + available tools",
        "Agent reasons about strategy, picks tools, executes attacks",
        "Memory compression at 80K tokens preserves critical context",
        "Loop detector prevents repetitive behavior patterns",
        "Stop conditions: 200 iterations, 4h wall-clock, $25 cost, agent finish",
    ])

    pdf.content_slide("Finalization Phase", [
        "Verification engine re-tests HIGH/CRITICAL findings for confirmation",
        "MITRE ATT&CK enrichment tags each vulnerability",
        "Compliance mapper generates OWASP Top 10, CWE, NIST report",
        "Attack graph built with NetworkX (hosts, services, vulns as nodes)",
        "Nuclei templates generated for reproducibility",
        "Reports generated: JSON + HTML + Markdown (credential-scrubbed)",
        "Sandbox destroyed, audit trail finalized",
    ])

    # ─── SLIDE 10: TESTING ──────────────────────────────────
    pdf.section_slide("Testing & Quality")

    pdf.stat_slide("Test Suite Metrics", [
        ("808", "Total Tests"),
        ("0", "Failures"),
        ("184", "E2E Tests"),
        ("8.0", "System Score"),
    ])

    pdf.table_slide("Test Breakdown",
        ["Test Suite", "Count", "Scope"],
        [
            ["test_e2e_system.py", "184", "Full system integration"],
            ["test_v0920_audit_fixes.py", "39", "Security fix verification"],
            ["test_all_modules.py", "~200", "Module-level unit tests"],
            ["test_v0918_features.py", "~100", "Feature regression"],
            ["test_v0910_coverage.py", "~80", "Coverage gaps"],
            ["test_security_fixes.py", "~50", "Security-specific"],
        ]
    )

    pdf.content_slide("Security Audit Results", [
        "Deep offensive audit of v0.9.19 found 83 findings:",
        "  8 Critical - all fixed and verified",
        "  19 High - all fixed and verified",
        "  34 Medium - all fixed and verified",
        "  22 Low - all fixed and verified",
        "System score improved from 5.8/10 to 8.0/10 after remediation",
    ])

    # ─── SLIDE 11: RESULTS ──────────────────────────────────
    pdf.section_slide("Results & Capabilities")

    pdf.stat_slide("System at a Glance", [
        ("30+", "Security Tools"),
        ("15K+", "Lines of Code"),
        ("50+", "Skill Files"),
        ("80+", "Modules"),
    ])

    pdf.content_slide("Proven Capabilities", [
        "Reconnaissance: Port scanning, subdomain enum, tech fingerprinting",
        "Web Vulnerabilities: SQLi, XSS, RCE, SSRF, IDOR, auth bypass",
        "Browser Automation: Full Playwright-based JS app interaction",
        "Multi-Agent: Spawn sub-agents for parallel specialized tasks",
        "Attack Graphs: NetworkX-based attack surface visualization",
        "Compliance: OWASP Top 10, CWE, MITRE ATT&CK mapping",
    ])

    # ─── SLIDE 12: FUTURE ───────────────────────────────────
    pdf.section_slide("Future Work")

    pdf.content_slide("Architecture v2 Roadmap", [
        "Async-First Architecture: Replace sync pipeline with fully async execution",
        "Plugin-Based Tool System: Third-party tools, hot-reload, entry_points discovery",
        "State Machine Formalization: Schema-versioned checkpoints, formal phase transitions",
        "Multi-Agent Orchestration: Hierarchical delegation with shared context",
        "  - Specialized agents: ReconAgent, ExploitAgent, ReportAgent",
        "  - Inter-agent message passing with priority routing",
        "Real-World Benchmark Suite: Standardized scoring on CTF-style targets",
    ])

    # ─── SLIDE 13: CLOSING ──────────────────────────────────
    pdf.new_slide()
    pdf._draw_accent_line(60, 180)

    pdf.set_font("Helvetica", "B", 36)
    pdf.set_text_color(200, 30, 30)
    pdf.set_xy(0, 65)
    pdf.cell(297, 20, "Thank You", align="C")

    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(180, 180, 180)
    pdf.set_xy(0, 90)
    pdf.cell(297, 10, "Phantom - Autonomous Adversary Simulation Platform", align="C")

    pdf._draw_accent_line(107, 120)

    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(160, 160, 160)
    pdf.set_xy(0, 115)
    pdf.cell(297, 8, "Author: Rodwan Gadouri", align="C")
    pdf.set_xy(0, 126)
    pdf.cell(297, 8, "Supervisor: Dr. Allama Oussama", align="C")
    pdf.set_xy(0, 140)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(297, 8, "github.com/Usta0x001/Phantom", align="C")

    return pdf


if __name__ == "__main__":
    import sys
    output = sys.argv[1] if len(sys.argv) > 1 else "Phantom_Presentation.pdf"
    pdf = build_presentation()
    pdf.output(output)
    print(f"Presentation generated: {output} ({pdf.slide_num} slides)")
