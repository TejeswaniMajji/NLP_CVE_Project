import json
from pathlib import Path

nb = Path('CVE_NLP_Trend_Analysis_with_prediction_(1).ipynb')
backup = nb.with_suffix('.ipynb.pre-remove-widgets.bak')

print('Backing up', nb, '->', backup)
backup.write_bytes(nb.read_bytes())

data = json.loads(nb.read_text(encoding='utf-8'))

def remove_widgets(obj):
    if isinstance(obj, dict):
        if 'widgets' in obj:
            del obj['widgets']
        for k, v in list(obj.items()):
            remove_widgets(v)
    elif isinstance(obj, list):
        for item in obj:
            remove_widgets(item)

remove_widgets(data)

nb.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding='utf-8')
print('Removed all metadata.widgets entries and wrote notebook.')
