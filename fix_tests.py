with open("tests/test_adversarial_deep_fuzz.py", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace("agent = FakeAgent()", "agent = FakeAgent(config={})")
text = text.replace("agent = TargetAgent()", "agent = TargetAgent(config={})")
text = text.replace("graph = AttackGraph(scan_config={})", "graph = AttackGraph()")

with open("tests/test_adversarial_deep_fuzz.py", "w", encoding="utf-8") as f:
    f.write(text)
print("Fixed fuzzing script args.")
