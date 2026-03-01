# Phantom Architecture — Module Wiring Guide

> How all 16 core modules connect to the runtime engine.

## Runtime Flow

```
CLI (cli_app.py)
  └── run_cli (cli.py)
        ├── Load ScanProfile (scan_profiles.py)
        ├── Create ScopeValidator (scope_validator.py)
        ├── Start AuditLogger (audit_logger.py)
        ├── Start Tracer
        └── PhantomAgent.execute_scan()
              ├── Inject profile constraints → LLM prompt
              ├── Agent loop (tool calls)
              │     └── Tools: nmap, nuclei, sqlmap, ffuf, ...
              └── finish_scan()
                    ├── Save final report fields
                    └── _run_post_scan_enrichment()
                          ├── 1. MITRE Enrichment
                          ├── 2. Compliance Mapping
                          ├── 3. Attack Graph + Path Analysis
                          ├── 4. Nuclei Template Generation
                          ├── 5. Knowledge Store Persistence
                          ├── 6. Notifications
                          └── 7. Report Generation (JSON/HTML/MD)
```

## Module Map

### Entry Points (3 Wiring Points)

| File | What it wires | Modules connected |
|------|--------------|-------------------|
| `interface/cli.py` | Scan startup | `ScanProfile`, `ScopeValidator`, `AuditLogger` |
| `agents/PhantomAgent/phantom_agent.py` | Agent behavior | `ScanProfile` (injected into task prompt) |
| `tools/finish/finish_actions.py` | Post-scan pipeline | All 14 remaining modules |

### Core Modules (16 total)

| Module | File | Status | Wired At |
|--------|------|--------|----------|
| Scan Profiles | `core/scan_profiles.py` | ✅ Active | cli.py + phantom_agent.py |
| Scope Validator | `core/scope_validator.py` | ✅ Active | cli.py (attached to tracer) |
| Audit Logger | `core/audit_logger.py` | ✅ Active | cli.py (global singleton) |
| MITRE Enrichment | `core/mitre_enrichment.py` | ✅ Active | finish_actions.py stage 1 |
| Compliance Mapper | `core/compliance_mapper.py` | ✅ Active | finish_actions.py stage 2 |
| Attack Graph | `core/attack_graph.py` | ✅ Active | finish_actions.py stage 3 |
| Attack Path Analyzer | `core/attack_path_analyzer.py` | ✅ Active | finish_actions.py stage 3 |
| Nuclei Templates | `core/nuclei_templates.py` | ✅ Active | finish_actions.py stage 4 |
| Knowledge Store | `core/knowledge_store.py` | ✅ Active | finish_actions.py stage 5 |
| Notifier | `core/notifier.py` | ✅ Active | finish_actions.py stage 6 |
| Report Generator | `core/report_generator.py` | ✅ Active | finish_actions.py stage 7 |
| Verification Engine | `core/verification_engine.py` | ✅ Active | Exported, available for agent tools |
| Interactsh Client | `core/interactsh_client.py` | ✅ Active | Exported, available for OOB testing |
| Priority Queue | `core/priority_queue.py` | ✅ Active | Exported, available for scan orchestration |
| Diff Scanner | `core/diff_scanner.py` | ✅ Active | `phantom diff` CLI command |
| Models | `models/vulnerability.py` | ✅ Active | Used by KnowledgeStore + ReportGenerator |

### Data Flow

```
Vulnerability Found (by agent tool)
  │
  ├── create_vulnerability_report() → tracer.vulnerability_reports[]
  │
  └── finish_scan() called by agent
        │
        ├── tracer.update_scan_final_fields()
        │
        └── _run_post_scan_enrichment(tracer)
              │
              ├── Read: tracer.vulnerability_reports
              │
              ├── MITRE: enrich_finding(dict) → adds CWE/CAPEC/OWASP to report
              │
              ├── Compliance: map_findings([dicts]) → compliance_report.md
              │
              ├── Attack Graph: ingest_scan_findings(reports) → attack_graph.json
              │   └── AttackPathAnalyzer(graph) → attack_paths.md
              │
              ├── Nuclei: from_finding(report) → nuclei_templates/*.yaml
              │
              ├── Knowledge: _dict_to_vulnerability() → save_vulnerability(model)
              │
              ├── Notify: notify_finding(dict) → webhook/Slack (if configured)
              │
              └── Reports: generate_json/html/markdown_report(models) → files
```

### Scan Profiles

```python
# Profile drives iteration limit, tool access, and agent behavior
{
    "quick":    {"max_iterations": 20,  "reasoning_effort": "low",    "enable_browser": False},
    "standard": {"max_iterations": 40,  "reasoning_effort": "medium", "enable_browser": True},
    "deep":     {"max_iterations": 80,  "reasoning_effort": "high",   "enable_browser": True},
    "stealth":  {"max_iterations": 30,  "reasoning_effort": "medium", "enable_browser": False},
    "api_only": {"max_iterations": 40,  "reasoning_effort": "medium", "enable_browser": False},
}
```

Profile constraints are injected into the agent's task description so the LLM respects them:
- Iteration limit warning
- `skip_tools` → "DO NOT use these tools: ..."
- `priority_tools` → "PRIORITIZE these tools: ..."
- `enable_browser` → "Do NOT use browser-based tools"

### Output Directory Structure

After a scan completes, the run directory (`phantom_runs/<run_id>/`) contains:

```
phantom_runs/<run_id>/
├── scan_config.json          # Scan parameters
├── audit.jsonl               # Audit trail (JSONL)
├── compliance_report.md      # OWASP/PCI/NIST mapping
├── attack_graph.json         # NetworkX graph data
├── attack_paths.md           # Attack chain analysis
├── report.json               # Structured JSON report
├── report.html               # HTML report
├── report.md                 # Markdown report
├── nuclei_templates/         # Per-vuln YAML templates
│   ├── vuln-001.yaml
│   └── vuln-002.yaml
└── ...                       # Tool outputs, screenshots, etc.
```

### Error Handling

Every enrichment stage is wrapped in `try/except`:
- A failure in stage 3 (attack graph) does NOT block stage 4-7
- Errors are logged with `_logger.warning()` and recorded in `enrichment_results`
- The scan always completes successfully regardless of enrichment failures
- `finish_scan()` returns `enrichment_results` dict showing success/failure per stage
