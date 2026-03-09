import re

message = message.decode('utf-8', errors='replace')

# Specific phrase substitutions (most specific first)
message = message.replace('Strix/Phantom differences', 'engine architecture differences')
message = message.replace('Strix-alignment fixes', 'core engine fixes')
message = message.replace('Strix-alignment', 'core engine alignment')
message = message.replace('Return to Strix philosophy', 'Return to lean engine philosophy')
message = message.replace('DeepWiki docs for Strix', 'DeepWiki docs for Phantom')
message = message.replace('strix.ai', 'phantom.ai')
message = message.replace('.strix/', '.phantom/')
message = message.replace('strix/interface/', 'phantom/interface/')

# All-caps with underscores: STRIX_X -> PHANTOM_X
message = re.sub(r'STRIX_', 'PHANTOM_', message)
# lowercase with underscores: strix_x -> phantom_x
message = re.sub(r'strix_', 'phantom_', message)

# Remaining word-only occurrences
message = re.sub(r'(?<![A-Za-z_])STRIX(?![A-Za-z_])', 'PHANTOM', message)
message = re.sub(r'(?<![A-Za-z_])Strix(?![A-Za-z_])', 'Phantom', message)
message = re.sub(r'(?<![A-Za-z_])strix(?![A-Za-z_])', 'phantom', message)

return message.encode('utf-8')
