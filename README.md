# Gadyen Safeguard

*Security compliance for tax professionals, in your language.*

Prototype of an AI agent that checks the security of a small tax practice, explains the
findings in English, Spanish, French or Haitian Creole, and drafts its Written Information
Security Plan (WISP). Term project, UMass Lowell, Fall 2026.

> Security guidance, not legal advice. Only test domains you own or are authorized in
> writing to test.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                 # then edit .env with your keys
pytest -q                            # all tests must pass

# Milestone 1: passive email check, no LLM needed
python -m gadyen.cli quickcheck yourdomain.com
# Active checks only on a domain you own
python -m gadyen.cli quickcheck yourdomain.com --i-own-this-domain

# Run the API, then open http://127.0.0.1:8000/docs
uvicorn gadyen.api:app --reload
```

## How it works

1. The owner answers the questionnaire and proves domain ownership with a DNS TXT record.
2. The LLM agent plans and calls tools; **every call goes through the policy guard**
   (`gadyen/scope.py`), which refuses unverified domains, private addresses and unknown tools.
3. A baseline guarantees the required checks always run.
4. **Deterministic rules** (`gadyen/scoring.py`) decide pass / warn / fail / unknown.
5. The LLM only explains the findings in the owner's language; its output is validated.
6. Everything is written to a hash-chained evidence log (`gadyen/store.py`).

## Layout

| Path | Purpose |
|---|---|
| `gadyen/scope.py` | Policy guard and scope checks |
| `gadyen/tools/` | Scanners (DNS, TLS, HTTP, ports) and endpoint report validation |
| `gadyen/scoring.py` | Deterministic control rules |
| `gadyen/agent.py`, `gadyen/prompts.py` | Agent loop and prompts |
| `gadyen/store.py` | SQLite storage and evidence chain |
| `gadyen/wisp.py` | WISP draft generator (.docx) |
| `gadyen/api.py`, `gadyen/cli.py` | HTTP API and command line |
| `endpoint-check/` | Read-only Windows and macOS self-check scripts |
| `lab/injection_cases.json` | Prompt-injection test catalog |
| `tests/` | Unit and adversarial tests |
