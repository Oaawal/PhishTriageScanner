# PhishTriage Scanner (deprecated)

This service is replaced by **PhishTriagePlatform**, which serves `POST /analyze`
and also the old `/analyze-message` and `/advanced-ai-scan` endpoints in the
same response format.

Keep this service running only until users have updated to PhishTriage app
1.1.0 or later, then shut it down on Render.

Changes:
- the MiMo AI integration is removed; `/advanced-ai-scan` returns the basic scan result
- `requirements.txt` and `.gitignore` re-saved as UTF-8 (they were UTF-16, which pip and git cannot read)
- compiled `__pycache__` removed from the repository

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```
