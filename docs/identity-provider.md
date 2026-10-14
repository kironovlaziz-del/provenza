# Identity provider: single sign-on, provisioning and offboarding

Your identity provider is the source of truth for who works at the company.
Connect it, and Provenza follows it: people are created here when they are
assigned the app there. When someone leaves, they are switched off here at
once, and so is everything that acts in their name.

## What happens when someone is switched off

It does not matter whether the identity provider switched them off
(`active: false` or deletion) or an admin did under **Settings → Users →
Deactivate**:

| | |
|---|---|
| the person | disabled; every session ends immediately |
| their agents | every agent they own: its API key is revoked (it stops authenticating everywhere, including the egress proxy and tool permits) and the agent is suspended |
| enrollment tokens | the ones they issued and nobody used are closed |

Every step is in the audit log (`offboarded`, `suspended_with_owner`).

When the person comes back (switched on again), their agents do **not** come
back on their own. An admin reviews each agent, issues it a new key and
reactivates it.

On "wipe the agent's local cache": revoking the key is what protects you,
and it is immediate. A command to erase data on a machine is only as good as
that machine's willingness to obey it. A compromised host would not obey,
but its key is useless anyway.

## Connecting

**Settings → Users → Provisioning (SCIM) → Turn on and create a token.** Copy
the base URL and the token, which is shown once, into your identity provider.

### Okta

1. Applications → your Provenza app → General: enable **SCIM provisioning**.
2. Provisioning → Integration:
   - SCIM connector base URL: the base URL from Provenza;
   - Unique identifier field for users: `userName`;
   - Supported provisioning actions: Push New Users, Push Profile Updates;
   - Authentication mode: HTTP Header, with the token as the Bearer.
3. Provisioning → To App: enable **Create Users**, **Update User Attributes**,
   **Deactivate Users**.

### Microsoft Entra ID

1. Enterprise applications → your app → Provisioning → **Automatic**.
2. Tenant URL: the base URL. Secret token: the token. Click **Test Connection**.
3. Mappings: keep `userPrincipalName` (or `mail`) → `userName`, `objectId` →
   `externalId`, `Switch([IsSoftDeleted]…)` → `active`.
4. Turn provisioning **On**. Entra ID syncs every 40 minutes; "Provision on
   demand" pushes one user at once.

## Rules

- The identity provider never sets roles. New users get the role chosen in
  Provenza (user or approver); admins change roles in Provenza.
- An existing account with the same e-mail is adopted, not duplicated.
- The organization's last active admin cannot be switched off from the
  identity provider, so the organization always keeps a way in.
- Users created by the identity provider have no password. They sign in
  with single sign-on (see below).
- One organization's token sees only that organization's users.

## API

`/api/v1/scim/v2`: `ServiceProviderConfig`, `ResourceTypes`, `Schemas`,
`Users` (`GET` with `filter=userName eq "…"` / `externalId eq "…"`, `POST`,
`PUT`, `PATCH`, `DELETE`). Groups are not provisioned; roles are set in
Provenza.


## Single sign-on (OpenID Connect)

**Settings → Users → Single sign-on.** Register Provenza at the provider as a
web application (authorization code flow) with the redirect URI shown there,
then enter the issuer, the client ID and the client secret. Before saving,
Provenza reads the provider's discovery document. The sign-in page then shows
**Sign in with single sign-on** once the organization's slug is typed.

| Provider | Issuer |
|---|---|
| Okta | `https://<org>.okta.com` (or a custom authorization server's issuer) |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| Google Workspace | `https://accounts.google.com` |
| Keycloak | `https://<host>/realms/<realm>` |

What Provenza checks on every sign-in:

- **The flow:** authorization code with PKCE. The state, nonce and verifier
  are sealed in a short-lived HttpOnly cookie, encrypted with the server
  key.
- **The `id_token`:** the signature against the provider's keys, plus
  `iss`, `aud`, expiry and `nonce`.
- **The e-mail:** it must be verified when the provider says so, and it
  must be in an allowed domain, if you list any.
- **The account it is bound to.** The first sign-in binds the person to
  the provider's account (issuer + subject). If the provider later gives
  that e-mail to someone else, their sign-in is refused.
- **The hand-off.** The browser receives a one-time code (60 seconds) in
  the URL fragment, which never reaches a server log, and exchanges it for
  a session.

Options:

| | |
|---|---|
| Allowed e-mail domains | only these; empty = any |
| Create accounts on first sign-in | off by default: only people an admin added or SCIM provisioned may sign in |
| SSO only | passwords stop working for everyone but admins - the break-glass way in when the provider is down |
| Require the provider's second factor | sign-ins without a second factor reported by the provider (`amr`) are refused |

**Two-factor sign-in.** If the organization requires a second factor from a
person, the provider must report one (`amr`: mfa, otp, hwk, ...). Provenza
then does not ask for its own TOTP, because the provider already did.
Microsoft Entra ID and Okta report `amr`. Google Workspace does not, so with
the Provenza policy on, Google sign-ins are refused: require two-factor
sign-in in Google Workspace instead and leave the Provenza policy off.

The web app and the API must be on one address (as the bundled Caddy serves
them): the provider sends the browser back to `/api/v1/auth/sso/callback`,
and from there to `/login/sso`. Set `PUBLIC_BASE_URL` when a reverse proxy
does not pass the original host.
