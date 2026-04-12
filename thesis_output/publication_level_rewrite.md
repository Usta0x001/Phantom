# Phantom Thesis — Publication-Level Rewrite

## 1. System Understanding

Phantom is a sandboxed, LLM-driven orchestration system for automated penetration testing. The implemented control path is:

1. a CLI or TUI builds a scan configuration,
2. `PhantomAgent` extends `BaseAgent` and constructs the live scan state,
3. the `BaseAgent` ReAct loop alternates between inference and tool execution,
4. tool invocations are validated and executed inside the runtime boundary,
5. observations are appended to the agent state,
6. structured memory objects are periodically reinjected into the prompt,
7. sub-agents may be spawned for parallel work and may share selected state.

The system has four principal stateful components:

- `AgentState`: conversation history, iteration counter, completion flags, observations, errors, and high-signal `finding_anchors`.
- `HypothesisLedger`: thread-safe registry of hypotheses keyed by exact `(surface, vuln_class)` equality.
- `CoverageTracker`: records tested surfaces and vulnerability classes.
- `CorrelationEngine`: consumes confirmed findings to suggest possible vulnerability chains.

The memory path is dual-layered. Message-level anchors are extracted from older conversation segments during compression, and state-level anchors are stored in `AgentState.finding_anchors` so they can be re-injected even if the corresponding messages are compressed away. This is a bounded retention mechanism, not a lossless archive.

Key invariants observed in the codebase:

- `HypothesisLedger` deduplicates on exact surface/class equality only.
- `AgentState.add_message()` suppresses exact duplicate string content using SHA-256 hashes.
- `MemoryCompressor` preserves recent messages and system messages, but older content may be summarised and therefore altered.
- `finding_anchors` are deduplicated by a short key or prefix and are therefore not guaranteed to represent every finding.
- `create_agent()` can share the parent ledger with sub-agents, which enables cross-agent deduplication.

Important ambiguities and inconsistencies:

- Some tests reference legacy names such as `current_iteration` and `conversation_history`, while the current implementation exposes `iteration` and `messages`.
- Claims in the thesis must be bounded: the code supports risk reduction and structured coordination, not universal detection or completeness.
- The heuristic evidence checks in `HypothesisLedger` classify weak evidence; they do not prove vulnerability validity.

## 2. Fully Rewritten Thesis

### 1. Introduction

Automated penetration testing remains constrained by a mismatch between the scale of modern attack surfaces and the availability of expert human analysis. Signature-based scanners are useful for deterministic checks on known patterns, but their coverage is limited by template availability. LLM-based agents expand the search space by reasoning over intermediate observations and adapting tool use, but they introduce new problems: context loss, redundant testing, inconsistent agent behaviour, and weak traceability.

This thesis presents Phantom as a code-verified orchestration and decision system for automated penetration testing. The contribution is not a claim of complete autonomy. It is a bounded architectural design that combines ReAct-style control, structured hypothesis tracking, memory compression with anchoring, and sandboxed tool execution.

### 2. Problem Definition

The core problem is to sustain long-horizon security reasoning under a finite context window while preserving the distinction between:

- transient conversational detail,
- durable security findings,
- tested hypotheses,
- and operational state required for continuation or recovery.

A second problem is avoiding redundant testing across iterations and across spawned sub-agents. A third problem is ensuring that the agent’s internal reasoning remains anchored in executed tool results rather than in unverified textual claims.

The system is therefore a stateful decision process under partial observability. It must update internal state from observations, preserve selected evidence across compression, and maintain bounded execution in a sandbox.

### 3. State of the Art

Signature-based scanners offer reproducibility and low variance, but they only detect cases encoded in their templates. Their limitation is structural: if a vulnerability class or instance is not represented in the template set, no amount of orchestration will recover it.

LLM-based security agents improve adaptability because they can reason about context, hypotheses, and next actions. However, most such systems are fragile when conversation history grows, when failures accumulate, or when multi-step reasoning is required. They also tend to lack explicit state boundaries, deduplication, and recovery semantics.

Multi-agent orchestration improves parallelism, but it can amplify token consumption and duplicate effort if shared state is weak. Therefore, the relevant state of the art problem is not “LLMs versus scanners” in the abstract; it is how to preserve reliable security reasoning in a long-running, tool-using, multi-agent system.

### 4. Identified Gaps

The codebase supports four gaps that are relevant to the thesis:

1. There is a structural gap between template-based detection and template-free vulnerability instances.
2. There is a context-management gap in long scans where critical findings may be lost during compression.
3. There is a coordination gap when multiple agents test overlapping surfaces independently.
4. There is a verification gap between tool intention, tool execution, and post-execution interpretation.

These gaps are engineering and methodological, not merely stylistic.

### 5. Proposed Approach

Phantom addresses these gaps through a bounded architecture:

- a ReAct loop in `BaseAgent`,
- a structured `AgentState`,
- a shared `HypothesisLedger`,
- a dual-anchor memory design,
- periodic status reinjection,
- and sandboxed tool execution.

The system should be read as an orchestration layer for evidence accumulation, not as an omniscient detector. It aims to improve coverage, reduce redundant actions, and preserve high-signal findings across long scans.

### 6. Formal Model

Let the agent state at iteration $t$ be
$$
S_t = (M_t, A_t, H_t, C_t, O_t, I_t)
$$
where $M_t$ is message history, $A_t$ is the anchor set, $H_t$ is the hypothesis ledger, $C_t$ is coverage state, $O_t$ is the observation set, and $I_t$ is the iteration counter.

The ReAct step is:
$$
S_t \xrightarrow{\text{observe}} O_t \xrightarrow{\text{reason}} T_t \xrightarrow{\text{act}} X_t \xrightarrow{\text{execute}} Y_t \xrightarrow{\text{update}} S_{t+1}
$$
where $T_t$ is the internal decision trace and $X_t$ is a batch of tool actions. The implementation should be understood as a state machine with a termination condition based on completion, stop request, or iteration limit.

### 7. System Architecture

The architecture is layered:

- Interface layer: CLI/TUI and scan configuration.
- Agent layer: `PhantomAgent` and `BaseAgent`.
- Memory layer: `AgentState`, `HypothesisLedger`, compression, and anchors.
- Tool layer: registry, executor, hypothesis tools, reporting tools, status tools.
- Runtime layer: sandboxed execution and scan persistence.

Data flows from interface to agent state, from state to LLM prompt, from LLM output to tool execution, and from tool results back into state. Some results are reinjected periodically through compact summaries, not through the full raw history.

Sub-agent creation can inherit selected context and a shared ledger. This reduces duplicate work, but it does not guarantee consistency across agents unless the shared state is actually used correctly.

### 8. Design Decisions

The main design decisions are:

- Use ReAct rather than a fixed script, because the target space is open-ended and observation-dependent.
- Use exact-match hypothesis deduplication rather than semantic similarity, because the primary operational need is deterministic avoidance of repeated tests on the same surface/class pair.
- Use dual anchoring rather than a single summary, because summary-only memory is vulnerable to omission.
- Use sandboxed execution rather than direct host execution, because the system must bound operational risk.
- Use periodic status reinjection, because state drift increases as scans grow.

These are engineering choices justified by operational constraints; they are not themselves scientific claims.

### 9. Limitations and Failure Modes

The system is bounded by several failure modes:

- anchor keyword miss,
- compression semantic drift,
- duplicate hypotheses that are not exact matches,
- agent inconsistency across spawned workers,
- tool hallucination versus execution mismatch,
- RBAC bypass risk in tool-facing surfaces.

Additional limitations follow from the formal design:

- template-based detection remains bounded by template coverage,
- evidence validation is heuristic, not semantic proof,
- repeated tool failures may still consume iterations,
- and any recovery workflow remains dependent on checkpoint correctness.

### 10. Discussion

The scientific value of Phantom lies in the combination of three properties: stateful reasoning, structured memory, and deterministic deduplication. The system does not solve vulnerability discovery in general. It provides an architecture for sustaining it under operational constraints.

The most defensible claim is that the architecture reduces specific failure modes: lost context, repeated testing, and unstructured hypothesis handling. Claims stronger than that require empirical evaluation under controlled benchmarks.

### 11. Conclusion

Phantom is best understood as a bounded autonomous security orchestration system. Its relevance to research is not that it eliminates uncertainty, but that it makes the decision process explicit, stateful, and inspectable. The thesis should therefore be framed as a code-verified systems contribution with formally bounded claims.

## 3. Formal Definitions

### 3.1 CVE Template Gap

Let $T$ be the template set of a signature-based scanner and $V$ the vulnerability space under consideration. For template-dependent systems, detection is defined by membership:
$$
\mathrm{detect}_T(v) = 1 \iff v \in T
$$
If $v \notin T$, then template-based detection fails by construction. This definition applies only to systems whose detection mechanism depends on a finite template library.

Bounded interpretation: the gap is an architectural limit on template-dependent scanners; it is not a universal statement about all security tools.

### 3.2 Dual-Anchor Memory

Let $M$ be the message history, and let $C(M)$ be the compressed history after applying the memory compressor. Let $A_m$ be message-level anchors extracted before compression and $A_s$ be state-level anchors stored in `AgentState`. Define
$$
A = A_m \cup A_s
$$
The intended invariant is
$$
A \subseteq C(M) \cup A_s
$$
when compression and reinjection both succeed. In operational terms, the system aims to preserve anchors across compression, but this is not lossless.

Failure cases:

- keywords do not match a high-signal finding,
- a finding is paraphrased before extraction,
- the compressed summary omits a key detail,
- the anchor key deduplication collapses distinct but similar findings.

### 3.3 HypothesisLedger

Let $H$ be a deterministic finite set of hypotheses. Each hypothesis is keyed by exact equality on $(surface, vuln\_class)$.

Membership is defined as:
$$
\mu_H(s, c) =
\begin{cases}
1 & \text{if } \exists h \in H: h.surface = s \wedge h.vuln\_class = c \\
0 & \text{otherwise}
\end{cases}
$$
Payloads, evidence, and status are auxiliary fields; they do not change the deduplication rule.

Limitation: the ledger does not perform semantic similarity matching, near-duplicate clustering, or embedding-based retrieval.

### 3.4 ReAct Loop

The implementation can be modeled as a state machine:
$$
S_t \xrightarrow{\text{LLM}} R_t \xrightarrow{\text{parse}} X_t \xrightarrow{\text{tools}} O_t \xrightarrow{\text{state update}} S_{t+1}
$$
where $R_t$ is the model response, $X_t$ is a set of tool invocations, and $O_t$ is the observation produced by execution.

Termination occurs when one of the following holds:

- the agent sets `completed`,
- the user requests stop,
- the iteration limit is reached,
- or the execution path enters a terminal failure state.

## 4. Contributions

### C1 — CVE Template Gap

A formal, bounded description of the structural limit of template-dependent scanners. This is a conceptual contribution, not a claim that all scanners fail equally.

### C2 — Dual-Anchor Memory Architecture

A two-level retention mechanism that combines compression-time anchor extraction with state-level anchor storage. The contribution is architectural and operational.

### C3 — Deterministic Hypothesis Deduplication

A thread-safe exact-match ledger for avoiding repeated testing on the same attack surface and vulnerability class.

### C4 — Code-Verified Architectural Methodology

A method for tying architectural claims to source code, runtime wiring, and observable tests. This improves traceability and reduces unsupported narrative claims.

## 5. Limitations

The system limitations and failure modes are structural, not incidental:

- anchor keyword miss,
- compression semantic drift,
- duplicate hypotheses not caught by exact matching,
- agent inconsistency across parallel workers,
- tool hallucination versus execution mismatch,
- RBAC bypass risk,
- stale-state bugs in checkpoint or resume paths,
- and loss of detail when summaries compress evidence too aggressively.

Accordingly, the thesis must avoid claims of completeness, guarantees, or impossibility unless those claims are explicitly proved.

## 6. Scientific Positioning

Phantom belongs to the intersection of autonomous agents, security tooling, and systems engineering. Its scientific position is:

- more adaptive than a pure signature scanner,
- more operationally grounded than a generic LLM agent,
- and more inspectable than an ad hoc orchestration script.

The correct research framing is:

- **scientific contribution**: formal bounded mechanisms for persistence, deduplication, and orchestration;
- **engineering decision**: specific tools, runtime, and prompt organization;
- **implementation**: the current codebase and its wiring.

The strongest defensible statement is that Phantom aims to improve evidence-preserving autonomous testing under strict operational constraints. It does not establish universal superiority, completeness, or guaranteed detection.
