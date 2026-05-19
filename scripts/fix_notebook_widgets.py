import json
import shutil
from pathlib import Path

nb_path = Path('CVE_NLP_Trend_Analysis_with_prediction_(1).ipynb')
backup_path = nb_path.with_suffix('.ipynb.bak')

print('Loading', nb_path)
shutil.copy2(nb_path, backup_path)
print('Backup created at', backup_path)

with nb_path.open('r', encoding='utf-8') as f:
    data = json.load(f)

modified = False

# Ensure top-level metadata.widgets has 'state'
meta = data.get('metadata', {})
if 'widgets' in meta:
    w = meta['widgets']
    if isinstance(w, dict) and 'state' not in w:
        w['state'] = {}
        modified = True

# Also check each cell's metadata
for cell in data.get('cells', []):
    md = cell.get('metadata', {})
    if 'widgets' in md:
        w = md['widgets']
        if isinstance(w, dict) and 'state' not in w:
            w['state'] = {}
            modified = True

if modified:
    with nb_path.open('w', encoding='utf-8') as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    print('Notebook updated to include missing widget state entries.')
else:
    print('No widget metadata needed updating.')

print('Done.')
