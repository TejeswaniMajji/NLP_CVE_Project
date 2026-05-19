import re
import requests

EXPLOIT_PATTERNS = {
    'RCE': r'remote code execution|rce|arbitrary code|execute.*command',
    'XSS': r'cross.site scripting|xss|inject.*script|script.*inject',
    'SQLi': r'sql injection|sql inject',
    'Buffer Overflow': r'buffer overflow|heap overflow|use.after.free|stack overflow|out.of.bounds',
    'Privilege Escalation': r'privilege escalat|elevation of privilege|gain.*privilege|local.*privilege',
    'DoS': r'denial.of.service|\bdos\b|server crash|resource exhaustion|infinite loop',
    'Command Injection': r'command injection|os command|shell injection|arbitrary.*command',
    'Info Disclosure': r'information disclosure|memory leak|sensitive.*leak|expose.*data|read.*arbitrary',
    'Auth Bypass': r'improper auth|authentication bypass|man.in.the.middle|unauthorized access|missing.*auth',
    'Path Traversal': r'path traversal|directory traversal|\.\./|local file inclusion',
    'CSRF': r'cross.site request forgery|csrf',
    'Open Redirect': r'open redirect|url redirect|redirect.*attacker',
}

COMPONENT_PATTERNS = {
    'Windows Kernel': r'windows kernel|win32k|ntoskrnl',
    'Linux Kernel': r'linux kernel',
    'Apache HTTP Server': r'apache http|apache web server|httpd',
    'Chrome / V8': r'google chrome|chromium|v8 engine',
    'OpenSSL': r'openssl',
    'Spring Framework': r'spring framework|spring boot|springframework',
    'WordPress': r'wordpress|wp-plugin|wp plugin',
    'Android': r'android',
    'Nginx': r'nginx',
    'Web Interface': r'web interface|web application|web app',
    'Database': r'\bmysql\b|\bpostgres\b|\bmongodb\b|\bsqlite\b|database',
    'Python': r'\bpython\b|django|flask',
    'Container': r'\bdocker\b|kubernetes|\bk8s\b|container',
}


def extract_exploit_type(text: str) -> str:
    t = (text or "").lower()
    for label, pattern in EXPLOIT_PATTERNS.items():
        if re.search(pattern, t):
            return label
    return 'Other'


def extract_component(text: str) -> str:
    t = (text or "").lower()
    for label, pattern in COMPONENT_PATTERNS.items():
        if re.search(pattern, t):
            return label
    return 'Unknown'


def extract_impact(text: str) -> str:
    t = (text or "").lower()
    impacts = []
    if re.search(r'code execution|root access|system compromise', t):
        impacts.append('Code Execution')
    if re.search(r'privilege escalat|elevation', t):
        impacts.append('Privilege Escalation')
    if re.search(r'denial of service|crash', t):
        impacts.append('DoS')
    if re.search(r'information disclosure|memory leak|sensitive', t):
        impacts.append('Info Disclosure')
    return ', '.join(impacts) if impacts else 'Unknown'


def cvss_to_severity(score: float) -> str:
    try:
        score = float(score)
    except Exception:
        return 'UNKNOWN'
    if score == 0:
        return 'UNKNOWN'
    if score >= 9.0:
        return 'CRITICAL'
    if score >= 7.0:
        return 'HIGH'
    if score >= 4.0:
        return 'MEDIUM'
    return 'LOW'


def fetch_cve_from_nvd(cve_id: str):
    cve_id = (cve_id or '').strip().upper()
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
        return None
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code != 200:
            return None
        data = resp.json()
        vulns = data.get('vulnerabilities', [])
        if not vulns:
            return None
        cve = vulns[0].get('cve', {})
        descs = cve.get('descriptions', [])
        desc = 'No description available.'
        for d in descs:
            if d.get('lang') == 'en':
                desc = d.get('value')
                break
        metrics = cve.get('metrics', {})
        score = 0.0
        if 'cvssMetricV31' in metrics:
            score = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore', 0.0)
        elif 'cvssMetricV30' in metrics:
            score = metrics['cvssMetricV30'][0]['cvssData'].get('baseScore', 0.0)
        elif 'cvssMetricV2' in metrics:
            score = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore', 0.0)
        weaknesses = cve.get('weaknesses', [])
        cwe = 'N/A'
        if weaknesses:
            d = weaknesses[0].get('description', [])
            if d:
                cwe = d[0].get('value', 'N/A')
        year = ''
        m = re.search(r'CVE-(\d{4})-', cve_id)
        if m:
            year = m.group(1)
        return {
            'cve_id': cve_id,
            'description': desc,
            'year': year or 'Unknown',
            'cvss_score': float(score),
            'cwe': cwe,
        }
    except Exception:
        return None


def predict_with_rules(cve_data: dict) -> dict:
    desc = cve_data.get('description', '')
    score = cve_data.get('cvss_score', 0.0) or 0.0
    exploit = extract_exploit_type(desc)
    component = extract_component(desc)
    impact = extract_impact(desc)
    if score == 0:
        sev = 'UNKNOWN'
    elif score >= 9:
        sev = 'CRITICAL'
    elif score >= 7:
        sev = 'HIGH'
    elif score >= 4:
        sev = 'MEDIUM'
    else:
        sev = 'LOW'
    confidence = 85 if score > 0 else 55
    return {
        'severity': sev,
        'cvss_score': score,
        'exploit_type': exploit,
        'affected_component': component if component != 'Unknown' else 'See description',
        'impact': impact if impact != 'Unknown' else 'See description',
        'confidence': confidence,
        'reasoning': f'CVSS {score} maps to {sev}. Pattern matched: {exploit}.'
    }


def predict_from_cve_id(cve_id: str) -> dict:
    cve_data = fetch_cve_from_nvd(cve_id)
    if not cve_data:
        return {'error': 'CVE not found or API error'}
    result = predict_with_rules(cve_data)
    return {**cve_data, **result}


def predict_from_description(description: str) -> dict:
    cve_data = {
        'cve_id': 'N/A',
        'description': description,
        'year': 'Unknown',
        'cvss_score': 0.0,
        'cwe': 'N/A',
    }
    result = predict_with_rules(cve_data)
    return {**cve_data, **result}
