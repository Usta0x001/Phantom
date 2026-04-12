# Phantom Master Thesis — LaTeX Project

**Design and Implementation of an AI-Driven Orchestration and Decision System for Automated Penetration Testing**

## Files

| File | Description |
|------|-------------|
| `main.tex` | Complete thesis (1,937 lines, ~83 KB) |
| `references.bib` | BibTeX bibliography (17 real, verifiable entries) |
| `compile.bat` | Windows compile script (requires TeX Live / MiKTeX) |

## Compile Instructions

### Requires
- **TeX Live 2023+** or **MiKTeX** with:
  - `biber` (for APA bibliography)
  - Packages: `tikz`, `pgfplots`, `tcolorbox`, `biblatex`, `listings`, `algorithm`, `booktabs`, `longtable`, `tabularx`

### Command Sequence
```
pdflatex main.tex
biber main
pdflatex main.tex
pdflatex main.tex
```
Or simply run `compile.bat`.

### Online Option
Upload both files to **Overleaf** (set compiler to `pdflatex`, bibliography tool to `biber`).

---

## Thesis Structure (~45 pages)

1. **Title Page** — Author: Rodwan Gadouri | Supervisor: Dr. Allama Oussama
2. **Abstract** — bilingual summary in English
3. **Chapter 1 — Introduction** (~5 pp): context, problem, 5 RQs, hypotheses, contributions
4. **Chapter 2 — State of the Art** (~9 pp): signature scanning, PentestGPT, ReAct, multi-agent, gaps table
5. **Chapter 3 — Proposed Approach** (~4 pp): Phantom as scientific artifact, design decisions justified
6. **Chapter 4 — Architecture** (~10 pp): 6 TikZ diagrams, code-verified class hierarchy, ReAct loop, circuit breaker, memory pipeline, tool execution, sandbox, checkpoint
7. **Chapter 5 — Methodology** (~4 pp): 3-mode framework, targets, ground truth, metrics
8. **Chapter 6 — Evaluation** (~5 pp): full results tables, pgfplots bar chart, cost breakdown, vulnerability categories
9. **Chapter 7 — Discussion** (~5 pp): RQ answers, CVE Template Gap analysis, decision quality
10. **Chapter 8 — Threats to Validity** (~2 pp)
11. **Chapter 9 — Conclusion** (~3 pp): future work
12. **References** (~2 pp): 17 real papers
13. **Appendices** (~3 pp): ground truth tables, code-verified component map

## Verification Policy

Every architectural claim maps to a verified source file and line number.  
Every experimental result comes from live evaluation runs documented in `docs/thesis_beautiful.tex`.  
No unverifiable statements included.
