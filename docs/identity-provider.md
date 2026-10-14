# Identity provider: provisioning and offboarding (SCIM 2.0)

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
  with single sign-on (see below), or an admin sets them up otherwise.
- One organization's token sees only that organization's users.

## API

`/api/v1/scim/v2`: `ServiceProviderConfig`, `ResourceTypes`, `Schemas`,
`Users` (`GET` with `filter=userName eq "…"` / `externalId eq "…"`, `POST`,
`PUT`, `PATCH`, `DELETE`). Groups are not provisioned; roles are set in
Provenza.
