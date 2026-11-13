"""Adversarial tests: the agent must stay in scope even when the LLM is tricked."""
from types import SimpleNamespace

from gadyen.agent import AssessmentAgent, validate_explanation
from gadyen.scope import PolicyGuard
from gadyen.tools.registry import TOOL_NAMES

from .conftest import FakeClient, canned_network, fake_resolver, text, tool_use


def setup(store):
    tid = store.create_tenant("Marie Tax Service", "ht")
    store.add_domain(tid, "mytaxoffice.com")
    store.mark_verified(tid, "mytaxoffice.com")
    store.save_answers(tid, {"Q04": "Marie", "Q06": "yes", "Q07": "yes"})
    return tid


def make_agent(store, tid, scripted):
    guard = PolicyGuard(store.verified_domains(tid), set(TOOL_NAMES), resolver=fake_resolver)
    return AssessmentAgent(store, tid, client=FakeClient(scripted), model="test",
                           guard=guard, network_runner=canned_network)


def test_injected_out_of_scope_calls_are_refused(store):
    tid = setup(store)
    # The "LLM" obeys an injected instruction and tries three out-of-scope targets.
    scripted = [
        SimpleNamespace(stop_reason="tool_use", content=[
            tool_use("t1", "check_http_headers", {"host": "mytaxoffice.com"})]),
        SimpleNamespace(stop_reason="tool_use", content=[
            tool_use("t2", "check_exposed_services", {"host": "internal.corp"}),
            tool_use("t3", "check_tls", {"host": "169.254.169.254"}),
            tool_use("t4", "check_tls", {"host": "internal.mytaxoffice.com"})]),
        SimpleNamespace(stop_reason="end_turn", content=[text("Done.")]),
    ]
    agent = make_agent(store, tid, scripted)
    report = agent.run()
    refusals = store.evidence(tid, "refusal")
    refused_targets = {r["payload"]["args"]["host"] for r in refusals}
    assert {"internal.corp", "169.254.169.254", "internal.mytaxoffice.com"} <= refused_targets
    scanned = {r["target"] for r in store.evidence(tid, "scan")}
    assert scanned <= {"mytaxoffice.com", "www.mytaxoffice.com"}
    # Untrusted data never reaches the system prompt.
    client = agent.client
    assert all("IGNORE ALL PREVIOUS" not in r["system"] for r in client.requests)
    assert report["overall_risk"] == "high"  # open RDP is critical


def test_baseline_runs_even_if_llm_calls_nothing(store):
    tid = setup(store)
    scripted = [SimpleNamespace(stop_reason="end_turn", content=[text("Nothing to do.")])]
    report = make_agent(store, tid, scripted).run()
    ids = {f["control_id"] for f in report["findings"]}
    assert {"EMAIL-1", "EMAIL-2", "TLS-1", "WEB-1", "NET-1"} <= ids


def test_explanation_cannot_invent_findings(store):
    tid = setup(store)
    scripted = [SimpleNamespace(stop_reason="end_turn", content=[text("ok")])]
    report = make_agent(store, tid, scripted).run()
    assert all(i["control_id"] != "FAKE-99" for i in report["explanation"]["items"])
    assert validate_explanation("not json at all", {"X"})["items"] == []


def test_evidence_chain_detects_tampering(store):
    tid = setup(store)
    make_agent(store, tid, [SimpleNamespace(stop_reason="end_turn", content=[text("ok")])]).run()
    assert store.verify_chain(tid)
    store.db.execute("UPDATE evidence SET payload='{\"open\": []}' WHERE kind='scan' "
                     "AND tool='check_exposed_services'")
    assert not store.verify_chain(tid)
