"""Account menu, sign-out and automatic sign-out after inactivity (gadyen_web)."""
import time

import pytest

from tests.test_chat_web import web  # noqa: F401  (pytest fixture)


@pytest.fixture
def signed_in(web, monkeypatch):  # noqa: F811
    import gadyen_web.accounts as accounts
    people = {7: {"username": "alice", "name": "Alice Martin"}}
    monkeypatch.setattr(accounts, "get_profile", lambda user_id: people.get(user_id))
    return web


def set_last_seen(web, seconds_ago):  # noqa: F811
    with web.client.session_transaction() as sess:
        sess["last_seen"] = time.time() - seconds_ago


def test_account_menu_shows_the_signed_in_user(signed_in):
    data = signed_in.client.get("/me").get_json()
    assert data == {"name": "Alice Martin", "username": "alice", "idle_seconds": 600}


def test_me_requires_a_session(signed_in):
    anonymous = signed_in.server.app.test_client()
    assert anonymous.get("/me").status_code == 401


def test_me_never_takes_the_user_from_the_request(signed_in):
    # A user id in the query string or body is ignored: only the session counts.
    data = signed_in.client.get("/me?user_id=1&id=1").get_json()
    assert data["username"] == "alice"


def test_sign_out_ends_the_session(signed_in):
    res = signed_in.client.post("/logout")
    assert res.status_code == 302 and res.headers["Location"] == "/"
    assert signed_in.client.get("/me").status_code == 401
    assert signed_in.client.post("/chat", json={"message": "hi"}).status_code == 401
    assert signed_in.client.get("/dashboard").headers["Location"] == "/"


def test_cross_origin_sign_out_is_refused(signed_in):
    res = signed_in.client.post("/logout", headers={"Origin": "https://evil.example"})
    assert res.status_code == 403
    assert signed_in.client.get("/me").status_code == 200       # still signed in


def test_idle_session_is_closed_by_the_server(signed_in):
    set_last_seen(signed_in, 601)                # 10 minutes and 1 second without a request
    res = signed_in.client.get("/conversations")
    assert res.status_code == 401
    assert res.get_json() == {"error": "not_logged_in", "reason": "idle"}
    # The session is really gone, not just refused once
    assert signed_in.client.get("/me").get_json() == {"error": "not_logged_in"}


def test_idle_chat_message_never_reaches_the_model(signed_in):
    set_last_seen(signed_in, 3600)
    res = signed_in.client.post("/chat", json={"message": "hello", "language": "en"})
    assert res.status_code == 401
    assert signed_in.created == [] and signed_in.db.messages == []


def test_idle_dashboard_goes_to_sign_in_with_a_reason(signed_in):
    set_last_seen(signed_in, 601)
    res = signed_in.client.get("/dashboard")
    assert res.status_code == 302 and res.headers["Location"] == "/?error=idle"


def test_activity_keeps_the_session_alive(signed_in):
    set_last_seen(signed_in, 590)                # just inside the limit
    assert signed_in.client.get("/me").status_code == 200
    with signed_in.client.session_transaction() as sess:
        assert time.time() - sess["last_seen"] < 5          # the clock was reset
    set_last_seen(signed_in, 590)
    assert signed_in.client.get("/conversations").status_code == 200


def test_sign_in_starts_the_idle_clock(signed_in):
    client = signed_in.server.app.test_client()
    res = client.post("/login", data={"username": "alice", "password": "a-long-test-passphrase"})
    assert res.headers["Location"] == "/dashboard"
    with client.session_transaction() as sess:
        assert time.time() - sess["last_seen"] < 5
