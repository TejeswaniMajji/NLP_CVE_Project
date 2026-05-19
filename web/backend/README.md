# CVE NLP Analyzer (backend)

This is a lightweight Flask backend that exposes a `/api/predict` endpoint. It can:

- Fetch CVE details from the NVD API if you provide a `cve_id`.
- Run a rule-based NLP extractor on a description string.

Quick start:

1. Create a virtualenv and install dependencies:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

2. Run the app:

```bash
python app.py
```

3. Open http://localhost:5000 in your browser.
