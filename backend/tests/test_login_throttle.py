# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Login throttling cannot be walked around.

  - the per-account counter is keyed by the organization slug as the
    lookup normalizes it, so "ACME ", " acme" and "acme" share one budget;
  - a successful login never resets the per-IP counter: someone who knows
    one valid password cannot use it to keep guessing other accounts;
  - legitimate sign-ins still never use up an IP's budget;
  - each limit counts only its own counter: the per-account check does not
    also bump the IP counter and judge it against the per-account limit
    (which used to lock an IP out after its third failed attempt).
"""

from app.api import auth as auth_api

L = "/api/v1/auth/login"


def _body(slug, email, password):
    return {"org_slug": slug, "email": email, "password": password}


async def test_slug_spelling_does_not_buy_extra_attempts(client, org_and_users):
    slug, email = org_and_users["org"].slug, org_and_users["admin"].email
    variants = [f" {slug}", f"{slug} ", slug.upper(), f"  {slug.upper()} ", slug]
    for v in variants[: auth_api.LOGIN_EMAIL_LIMIT]:
        r = await client.post(L, json=_body(v, email, "wrong"))
        assert r.status_code == 401, r.text

    # the next guess, under yet another spelling, is over the account budget
    r = await client.post(L, json=_body(f"\t{slug.upper()}", email, "wrong"))
    assert r.status_code == 429
    assert r.json()["detail"]["code"] == "auth.rate_limited"


async def test_ip_gets_its_full_budget_of_failed_attempts(client, org_and_users):
    org = org_and_users["org"]
    for i in range(auth_api.LOGIN_IP_LIMIT):
        r = await client.post(L, json=_body(org.slug, f"user{i}@example.com", "guess"))
        assert r.status_code == 401, (i, r.text)
    r = await client.post(L, json=_body(org.slug, "one-more@example.com", "guess"))
    assert r.status_code == 429


async def test_a_valid_login_does_not_reset_the_ip_budget(client, org_and_users):
    org = org_and_users["org"]
    me = _body(org.slug, org_and_users["admin"].email, org_and_users["password"])

    # guesses against many accounts (so the per-account limit never trips)
    for i in range(auth_api.LOGIN_IP_LIMIT - 1):
        r = await client.post(L, json=_body(org.slug, f"victim{i}@example.com", "guess"))
        assert r.status_code == 401, r.text

    # the attacker signs in to their own account ...
    assert (await client.post(L, json=me)).status_code == 200
    # ... which leaves exactly the one guess that was still left, no more
    r = await client.post(L, json=_body(org.slug, "victim-a@example.com", "guess"))
    assert r.status_code == 401
    r = await client.post(L, json=_body(org.slug, "victim-b@example.com", "guess"))
    assert r.status_code == 429


async def test_successful_logins_never_use_up_the_ip_budget(client, org_and_users):
    org = org_and_users["org"]
    me = _body(org.slug, org_and_users["admin"].email, org_and_users["password"])
    for _ in range(auth_api.LOGIN_IP_LIMIT * 2):
        assert (await client.post(L, json=me)).status_code == 200


async def test_success_clears_only_that_accounts_counter(client, org_and_users, _isolated_rate_limit):
    org = org_and_users["org"]
    email = org_and_users["admin"].email
    for _ in range(auth_api.LOGIN_EMAIL_LIMIT - 1):
        assert (await client.post(L, json=_body(org.slug, email, "typo"))).status_code == 401
    assert (await client.post(L, json=_body(org.slug, email, org_and_users["password"]))).status_code == 200

    store = _isolated_rate_limit
    assert f"rl:login:key:{org.slug.lower()}:{email.lower()}" not in store
    # the IP counter still remembers the failed attempts
    ip_keys = [k for k in store if k.startswith("rl:login:ip:")]
    assert ip_keys and store[ip_keys[0]] == auth_api.LOGIN_EMAIL_LIMIT - 1


def test_refund_never_leaves_a_negative_counter(_isolated_rate_limit):
    from types import SimpleNamespace

    from app.core import rate_limit

    req = SimpleNamespace(client=SimpleNamespace(host="203.0.113.5"), headers={})
    rate_limit.refund(req, scope="login")  # counter already expired / never set
    assert "rl:login:ip:203.0.113.5" not in _isolated_rate_limit
