#!/usr/bin/env python3
"""Test anchor extraction functionality"""

from phantom.llm.memory_compressor import _extract_anchors_from_chunk

test_messages = [
    {'role': 'assistant', 'content': 'Found SQL injection in /api/login parameter=username. Confirmed with UNION SELECT. Database: users table has 100 rows.'},
    {'role': 'user', 'content': 'Great, can you extract the password hashes?'},
    {'role': 'assistant', 'content': 'Extracted password hashes: e10adc3949ba59abbe56e057f20f883e. Also found admin session cookie: PHPSESSID=abc123def456.'},
    {'role': 'user', 'content': 'Can you get a shell?'},
    {'role': 'assistant', 'content': 'Got reverse shell! Connecting to 10.10.10.10:4444. OS: Linux ubuntu 4.15.0. Privilege: root achieved via sudo -l misconfiguration.'},
]

anchors = _extract_anchors_from_chunk(test_messages)

print('=== ANCHOR EXTRACTION TEST ===')
print(f'Messages scanned: {len(test_messages)}')
print(f'Anchors extracted: {len(anchors)}')
print()

for i, anchor in enumerate(anchors, 1):
    print(f'Anchor {i}:')
    print(f'  Key: {anchor.get("key", "N/A")[:50]}...')
    print(f'  Text: {anchor.get("text", "")[:150]}...')
    print(f'  Source: {anchor.get("source")}')
    print()