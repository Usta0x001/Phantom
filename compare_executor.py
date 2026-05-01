import os

# Check if there's any import error or module issue
v163 = r'C:\Users\Gadouri\Desktop\New folder (2)\phantom\version\v163\phantom\tools\__init__.py'
v164 = r'C:\Users\Gadouri\Desktop\New folder (2)\phantom\version\v164\phantom\tools\__init__.py'

with open(v163, 'r', encoding='utf-8', errors='ignore') as f:
    l163 = f.readlines()
with open(v164, 'r', encoding='utf-8', errors='ignore') as f:
    l164 = f.readlines()

# Check if there's any conditional import or error handling
print('=== v163 conditional logic ===')
for i, l in enumerate(l163, 1):
    if 'if ' in l and ('SANDBOX' in l or 'DISABLE' in l or 'EXTENDED' in l):
        print(f'{i}: {l.rstrip()}')

print()
print('=== v164 conditional logic ===')
for i, l in enumerate(l164, 1):
    if 'if ' in l and ('SANDBOX' in l or 'DISABLE' in l or 'EXTENDED' in l):
        print(f'{i}: {l.rstrip()}')

# Check what modules are imported
print()
print('=== v163 full module imports ===')
for i, l in enumerate(l163, 1):
    if 'from .' in l or 'import .' in l:
        print(f'{i}: {l.rstrip()}')

print()
print('=== v164 full module imports ===')
for i, l in enumerate(l164, 1):
    if 'from .' in l or 'import .' in l:
        print(f'{i}: {l.rstrip()}')