import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("COMPLETE SYSTEM COMPONENTS LIST")
print("=" * 70)

print("""
=============================================================
PHANTOM AUTONOMOUS PENTESTING SYSTEM
ALL COMPONENTS
=============================================================
""")

components = [
    # ======================================
    # CORE AGENT COMPONENTS
    # ======================================
    ("1. AGENT SYSTEM", [
        ("BaseAgent", "Main agent class - executes tasks"),
        ("AgentState", "State management - messages, anchors, context"),
        ("AgentMeta", "Metaclass for agent"),
    ]),
    
    # ======================================
    # MEMORY & CONTEXT
    # ======================================
    ("2. MEMORY & CONTEXT", [
        ("MemoryCompressor", "Compresses conversation history"),
        ("_extract_anchors_from_chunk", "Extracts key findings before compression"),
        ("_summarize_messages", "LLM-based summarization"),
        ("_handle_images", "Image eviction handling"),
    ]),
    
    # ======================================
    # HYPOTHESIS LEDGER SYSTEM
    # ======================================
    ("3. HYPOTHESIS LEDGER", [
        ("HypothesisLedger", "Tracks hypotheses about vulnerabilities"),
        ("Hypothesis", "Dataclass for single hypothesis"),
        ("add_hypothesis", "Register new hypothesis"),
        ("record_payload", "Mark payload as tested"),
        ("has_tested", "Check if payload tested"),
        ("confirm_hypothesis", "Mark as confirmed"),
    ]),
    
    # ======================================
    # ANCHOR SYSTEM
    # ======================================
    ("4. ANCHOR SYSTEM", [
        ("finding_anchors", "List of key findings in state"),
        ("add_finding_anchor", "Add finding to anchors"),
        ("expire_stale_anchors", "Remove old anchors"),
        ("_extract_anchors_from_chunk", "Extract from messages"),
    ]),
    
    # ======================================
    # AGENT SPAWNING
    # ======================================
    ("5. AGENT SPAWNING", [
        ("create_agent", "Spawn sub-agent"),
        ("agents_graph", "Track agent relationships"),
        ("inherit_context", "Pass state to sub-agent"),
        ("parent_findings", "Inject anchors to sub-agent"),
    ]),
    
    # ======================================
    # COVERAGE & TRACKING
    # ======================================
    ("6. COVERAGE & TRACKING", [
        ("CoverageTracker", "Track tested attack surfaces"),
        ("CorrelationEngine", "Identify vulnerability chains"),
        ("AttackGraph", "Visualize vulnerability relationships"),
    ]),
    
    # ======================================
    # LLM INTERACTION
    # ======================================
    ("7. LLM INTERACTION", [
        ("LLM", "Main LLM interface"),
        ("_prepare_messages", "Prepare prompts with compression"),
        ("_force_compress_messages", "Emergency compression"),
        ("_is_context_too_large", "Detect overflow errors"),
    ]),
    
    # ======================================
    # TOOL EXECUTION
    # ======================================
    ("8. TOOL EXECUTION", [
        ("execute_tool", "Run tool"),
        ("execute_tool_with_validation", "Run with validation"),
        ("_validate_tool_arguments", "Validate tool inputs"),
        ("_detect_prompt_injection", "Security check"),
    ]),
    
    # ======================================
    # CONFIG & SETTINGS
    # ======================================
    ("9. CONFIGURATION", [
        ("Config", "Configuration management"),
        ("PHANTOM_LLM", "Model selection"),
        ("phantom_compressor_chunk_size", "Chunk size config"),
        ("phantom_max_context_ceiling", "Token limit config"),
    ]),
    
    # ======================================
    # CHECKPOINT & PERSISTENCE
    # ======================================
    ("10. CHECKPOINT", [
        ("save_checkpoint", "Save agent state"),
        ("load_checkpoint", "Restore agent state"),
        ("get_execution_summary", "Get execution stats"),
    ]),
]

for category, items in components:
    print(f"\n{category}")
    print("-" * 60)
    for name, desc in items:
        print(f"  {name:<35} - {desc}")

print("\n" + "=" * 70)
print("INTERACTION MAP")
print("=" * 70)

print("""
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SYSTEM INTERACTIONS                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  USER TASK                                                            │
│       │                                                               │
│       ▼                                                               │
│  BaseAgent.execute()                                                 │
│       │                                                               │
│       ├──► AgentState.add_message()                                   │
│       │         │                                                      │
│       │         ▼                                                      │
│       │    LLM.generate()                                            │
│       │         │                                                      │
│       │         ├──► _prepare_messages()                              │
│       │         │         │                                           │
│       │         │         ├──► MemoryCompressor.compress_history()   │
│       │         │         │         │                                  │
│       │         │         │         ├──► _extract_anchors_from_chunk()│
│       │         │         │         └──► _summarize_messages()        │
│       │         │         │                                           │
│       │         │         └──► Inject anchors to prompt              │
│       │         │                                                   │
│       │         ▼                                                   │
│       │    LLM API call                                             │
│       │         │                                                   │
│       │         ▼                                                   │
│       │    AgentState.add_message(response)                          │
│       │         │                                                   │
│       │         ├──► HypothesisLedger.record_payload()              │
│       │         │                                                   │
│       │         └──► add_finding_anchor()                          │
│       │                                                               │
│       ▼                                                               │
│  SPAWN SUB-AGENT                                                     │
│       │                                                               │
│       ├──► Pass finding_anchors (parent_findings)                   │
│       ├──► Pass HypothesisLedger (shared)                            │
│       └──► Pass conversation_history (truncated)                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
""")

print("\n" + "=" * 70)
print("COMPLETE LIST FINISHED")
print("=" * 70)