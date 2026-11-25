# PhishTriage Scanner (deprecated)

This service is replaced by **PhishTriagePlatform**, which serves `POST /analyze`
and also the old `/analyze-message` and `/advanced-ai-scan` endpoints in the
same response format.

Keep this service running only until users have updated to PhishTriage app
1.1.0 or later, then shut it down on Render.

This branch contains security fixes only:
- requests to the AI provider now time out after 25 seconds
- raw provider responses and error details are no longer sent to the app
- the user's message is passed to the AI as untrusted data (prompt-injection guard)
- `requirements.txt` and `.gitignore` re-saved as UTF-8 (they were UTF-16, which pip and git cannot read)
- compiled `__pycache__` removed from the repository

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```
