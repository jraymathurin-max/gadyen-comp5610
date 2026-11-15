"""HTTP API (FastAPI). Start with:  uvicorn gadyen.api:app --reload
Interactive documentation: http://127.0.0.1:8000/docs

Authentication here is a single development key (header X-Api-Key). Replace it with
real user accounts and enforced MFA (Supabase Auth or Auth0) before any pilot."""
import secrets
import tempfile

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import config, scoring
from .agent import AssessmentAgent
from .questionnaire import QUESTIONS, validate_answers
from .scope import ScopeError, normalize_domain
from .store import Store
from .tools.dns_tools import verify_domain
from .tools.endpoint import parse_endpoint_report
from .wisp import build_wisp

app = FastAPI(title="Gadyen Safeguard API", version="0.1.0")
store = Store(config.DB_PATH)


def require_key(x_api_key: str = Header(default="")):
    if not config.DEV_KEY or not secrets.compare_digest(x_api_key, config.DEV_KEY):
        raise HTTPException(401, "invalid API key")


def tenant_or_404(tenant_id: str) -> dict:
    try:
        return store.get_tenant(tenant_id)
    except KeyError:
        raise HTTPException(404, "unknown tenant") from None


class NewTenant(BaseModel):
    practice_name: str = Field(min_length=1, max_length=120)
    language: str = Field(pattern="^(en|es|fr|ht)$")


class NewDomain(BaseModel):
    domain: str = Field(max_length=253)


@app.post("/tenants", dependencies=[Depends(require_key)])
def create_tenant(body: NewTenant):
    return {"tenant_id": store.create_tenant(body.practice_name, body.language)}


@app.post("/tenants/{tenant_id}/domains", dependencies=[Depends(require_key)])
def add_domain(tenant_id: str, body: NewDomain):
    tenant_or_404(tenant_id)
    try:
        domain = normalize_domain(body.domain)
    except ScopeError as exc:
        raise HTTPException(400, str(exc)) from None
    token = store.add_domain(tenant_id, domain)
    return {"domain": domain, "dns_record_name": f"_gadyen-verify.{domain}",
            "dns_record_type": "TXT", "dns_record_value": f"gadyen-verify={token}",
            "next_step": f"Add the TXT record, wait a few minutes, then POST "
                         f"/tenants/{tenant_id}/domains/{domain}/verify"}


@app.post("/tenants/{tenant_id}/domains/{domain}/verify", dependencies=[Depends(require_key)])
def verify(tenant_id: str, domain: str):
    tenant_or_404(tenant_id)
    try:
        token = store.domain_token(tenant_id, domain)
    except KeyError:
        raise HTTPException(404, "add the domain first") from None
    result = verify_domain(domain, token)
    if result["verified"]:
        store.mark_verified(tenant_id, domain)
        store.add_evidence(tenant_id, "domain_verified", result, target=domain)
    return result


@app.get("/questionnaire")
def questionnaire():
    return QUESTIONS


@app.put("/tenants/{tenant_id}/answers", dependencies=[Depends(require_key)])
def save_answers(tenant_id: str, answers: dict):
    tenant_or_404(tenant_id)
    try:
        clean = validate_answers(answers)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    store.save_answers(tenant_id, clean)
    store.add_evidence(tenant_id, "answers", clean)
    return {"saved": len(clean)}


@app.post("/tenants/{tenant_id}/endpoint-reports", dependencies=[Depends(require_key)])
async def upload_endpoint_report(tenant_id: str, request: Request):
    tenant_or_404(tenant_id)
    raw = await request.body()
    try:
        report = parse_endpoint_report(raw)
    except ValueError as exc:
        raise HTTPException(400, f"invalid report: {str(exc)[:300]}") from None
    store.add_endpoint_report(tenant_id, report)
    store.add_evidence(tenant_id, "endpoint_report", report, target=report["hostname"])
    return {"accepted": report["hostname"]}


@app.post("/tenants/{tenant_id}/assessments", dependencies=[Depends(require_key)])
def run_assessment(tenant_id: str):
    tenant_or_404(tenant_id)
    return AssessmentAgent(store, tenant_id).run()


@app.get("/tenants/{tenant_id}/wisp", dependencies=[Depends(require_key)])
def download_wisp(tenant_id: str):
    tenant = tenant_or_404(tenant_id)
    findings = scoring.evaluate(store.evidence(tenant_id), store.answers(tenant_id),
                                store.endpoint_reports(tenant_id))
    path = tempfile.NamedTemporaryFile(suffix=".docx", delete=False).name
    build_wisp(path, tenant["practice_name"], store.answers(tenant_id),
               [f.to_dict() for f in findings], store.verified_domains(tenant_id))
    return FileResponse(path, filename="WISP_draft.docx")


@app.get("/tenants/{tenant_id}/evidence/verify", dependencies=[Depends(require_key)])
def verify_evidence(tenant_id: str):
    tenant_or_404(tenant_id)
    return {"chain_intact": store.verify_chain(tenant_id)}
