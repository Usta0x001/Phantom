import re

message = message.decode('utf-8', errors='replace')

# Specific phrase substitutions (most specific first)
message = message.replace('Strix/Phantom differences', 'engine architecture differences')  # legacy filter
message = message.replace('Strix', 'Phantom')
message = message.replace('Phantom-alignment fixes', 'core engine fixes')
message = message.replace('Phantom-alignment', 'core engine alignment')
message = message.replace('Return to Phantom philosophy', 'Return to lean engine philosophy')
message = message.replace('DeepWiki docs for Phantom', 'DeepWiki docs for Phantom')
message = message.replace('Phantom.ai', 'phantom.ai')
message = message.replace('.Phantom/', '.phantom/')
message = message.replace('Phantom/interface/', 'phantom/interface/')

# All-caps with underscores: Phantom_X -> PHANTOM_X
message = re.sub(r'Phantom_', 'PHANTOM_', message)
# lowercase with underscores: Phantom_x -> phantom_x
message = re.sub(r'Phantom_', 'phantom_', message)

# Remaining word-only occurrences
message = re.sub(r'(?<![A-Za-z_])Phantom(?![A-Za-z_])', 'PHANTOM', message)
message = re.sub(r'(?<![A-Za-z_])Phantom(?![A-Za-z_])', 'Phantom', message)
message = re.sub(r'(?<![A-Za-z_])Phantom(?![A-Za-z_])', 'phantom', message)

return message.encode('utf-8')
