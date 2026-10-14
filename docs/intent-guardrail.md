# Intent guardrail

The Prompt Firewall finds secrets, personal data and blocked terms by their
form. It cannot tell "write a sort function" from "write code that gets
around the login of our billing app", because both are plain words. The
intent guardrail asks a classifier model what each prompt is for.

## Before the classifier: undoing disguises

The Prompt Firewall first undoes the usual disguises (`core/text_normalize.py`),
then looks for secrets:

| Disguise | Example | Flag |
|---|---|---|
| invisible characters | a zero-width space inside an API key | `deobfuscated:api_key` |
| width and form | `ＡＫＩＡ…` (full-width) | `deobfuscated:api_key` |
| look-alike letters | `pаssword` with a Cyrillic `а` | |
| spacing | `j o h n @ e x a m p l e . c o m` | `deobfuscated:email` |
| spelled out | `john (at) example [dot] com` | `deobfuscated:email` |
| base64 / hex | a card number in base64 | `decoded:base64:credit_card` |

Whatever is found is masked where it stands in the original text. Look-alike
letters are replaced only in words that already contain Latin letters or
digits, so Russian and Uzbek text is left as written. A blocked term hidden
in base64 or hex blocks the prompt (`decoded:base64`).

## The classifier

**Control → Policies → Intent guardrail** (admins).

| | |
|---|---|
| Connection | one of the organization's AI connections. A self-hosted model (Ollama, vLLM) keeps prompts inside the company. Under the "self-hosted providers only" policy, a cloud connection is refused. |
| Llama Guard | Llama Guard 3 or 4 (`llama-guard3` on Ollama). It answers with the MLCommons hazard categories S1–S14 (S2: non-violent crimes such as hacking or fraud, S7: privacy, S14: code interpreter abuse, ...). |
| Instruction model | any instruction model (Qwen, Llama, Mistral...), given the organization's own categories in plain words, e.g. `AUTHZ_BYPASS`: "getting around authentication of our own systems". The prompt is passed as fenced data with a random marker, and the model is told never to follow instructions inside it. |
| Monitor / enforce | monitor: the prompt goes through, flagged `intent:<category>`. Enforce: a prompt in a blocking category is refused. If no category is ticked, every category blocks. |
| On failure | the model is unreachable, too slow (timeout) or gives an answer that cannot be parsed: either let the prompt through, flagged `intent:unavailable`, or refuse it (enforce mode only). |
| Applies to | the playground, the LLM gateway (agents; the last user message) and requests. |

What the classifier sees is the text **after** the Prompt Firewall masked it.
Secrets and personal data never reach it. Verdicts are cached for ten
minutes per text. **Try it** runs the saved settings on a sample, also while
the guardrail is switched off.

Running Llama Guard locally:

```sh
ollama pull llama-guard3        # 8B; llama-guard3:1b is the small one
```

Then add an OpenAI-compatible connection with base URL `http://<host>:11434/v1`.

## What a refusal looks like

| Surface | |
|---|---|
| Playground | `blocked: true`, reason "Intent guardrail: …" |
| LLM gateway | HTTP 403, `blocked_by_guardrail`; the call is logged as blocked |
| Requests | status `blocked`, flags `intent:…` |

## Limits

A classifier is a second opinion, not a proof. It can miss a cleverly framed
request and can flag a harmless one. Start in monitor mode, read the
`intent:` flags for a while, then enforce the categories that turned out
reliable. Pattern rules (blocked terms, PII rules) still apply in every mode.

## API

`GET/PUT /api/v1/guardrail/settings`, `POST /api/v1/guardrail/test`
`{"text": "…"}` (admins).
