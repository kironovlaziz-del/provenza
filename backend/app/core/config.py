from pydantic import model_validator
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings


# Fragments that only appear in placeholder / example / test keys. A real
# key comes from a random generator and contains none of them.
_PLACEHOLDER_FRAGMENTS = (
    "change", "example", "default", "placeholder", "your-", "your_",
    "secret-key", "secret_key", "not-for-production", "do-not-use", "replace",
)


def secret_key_problems(key: str) -> list[str]:
    """Why `key` is not fit to sign production JWTs (empty list = fine).

    Anyone who knows the key can mint a token for any user of any
    organization, so a key copied from documentation or an example file
    is as good as no key."""
    problems: list[str] = []
    if len(key) < 32:
        problems.append("SECRET_KEY is shorter than 32 characters - too weak for HS256.")
    low = key.lower()
    if any(f in low for f in _PLACEHOLDER_FRAGMENTS):
        problems.append(
            "SECRET_KEY looks like a placeholder from an example file. Generate one with "
            "'python3 -c \"import secrets; print(secrets.token_urlsafe(48))\"'."
        )
    elif len(set(key)) < 8:
        problems.append("SECRET_KEY is not random enough (too few distinct characters).")
    return problems


class Settings(BaseSettings):
    PROJECT_NAME: str = "Provenza"
    API_V1_STR: str = "/api/v1"

    # "development" | "production". In production, insecure defaults for
    # SECRET_KEY and ENCRYPTION_KEY are rejected at startup, and /docs is
    # disabled. Set ENVIRONMENT=production in backend/.env on any real
    # deployment.
    ENVIRONMENT: str = "development"

    # When true, SQLAlchemy logs every SQL statement. Off by default;
    # enable for local debugging only.
    DEBUG: bool = False

    # Comma-separated list of allowed frontend origins for CORS. Never use
    # "*" together with allow_credentials=True - browsers reject it and it
    # lets any site make authenticated requests as the logged-in user.
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    # Self-service sign-up: POST /users/register creates a NEW organization
    # and makes the caller its admin. Off by default - on a company's own
    # instance anyone who can reach the site would otherwise get an admin
    # account. Create the first admin with scripts/create_admin.py and add
    # teammates by invitation; turn this on only for a public demo/SaaS.
    ALLOW_PUBLIC_SIGNUP: bool = False

    # PVP Input Guard (app/pvp/guard.py): requests per minute one agent key -
    # or one user acting for agents - may send to the PVP endpoints
    # (check, record, delegate) together. Over it: 429 pvp.rate_limited.
    PVP_RATE_LIMIT_PER_MINUTE: int = 1200

    # Telemetry ingestion (/api/v1/shadow-ai/ingest): batches per minute one
    # ingestion key may send. A browser extension's key ships inside the
    # extension, so anyone who has the extension has it: its limit is lower.
    INGEST_BATCHES_PER_MINUTE: int = 120
    INGEST_EXTENSION_BATCHES_PER_MINUTE: int = 30

    # The address agents reach this server at, e.g. "https://provenza.example.com".
    # Agent cards served by the A2A gateway point there. Empty = taken from the
    # request (fine when the reverse proxy passes the original host and scheme).
    PUBLIC_BASE_URL: str = ""
    # Passkeys (app/core/webauthn.py): the relying party id. Empty = the host
    # of the first CORS origin, which is the site administrators sign in at.
    WEBAUTHN_RP_ID: str = ""
    # Prometheus HTTP API, used by /observability/query proxies.
    # The backend and Prometheus run on the same host, loopback only.
    PROMETHEUS_URL: str = "http://127.0.0.1:9090"
    # The egress sensor's installer, unit and binaries, built into the
    # production image (deploy/backend.Dockerfile) and served at
    # /api/v1/egress-sensor/download/ (app/api/sensor_download.py).
    SENSOR_DIST_DIR: str = "/app/sensor-dist"

    # Outbound calls to user-configured URLs (AI providers, gateway
    # upstreams, Vault Transit, webhooks) are refused when the target is a
    # private, loopback or reserved address - see core/outbound.py. List
    # your own internal services here to allow them, comma-separated
    # hostnames, IPs or CIDRs: "vault.corp.local,10.20.0.0/16,127.0.0.1".
    # Link-local addresses (cloud metadata) are never allowed. The list is
    # server-wide: every organization's admins can reach what is listed.
    OUTBOUND_PRIVATE_ALLOWLIST: str = ""
    # Egress proxy for those same outbound calls, when the network requires
    # one (e.g. "http://proxy.corp.local:3128"). HTTP(S)_PROXY environment
    # variables are deliberately NOT used - see core/outbound.py.
    OUTBOUND_PROXY: str = ""

    # Egress checks (app/services/egress_check.py): the hosts an agent's host
    # tries to reach directly - a confined agent reaches none of them - and the
    # address of the beacon, which must NOT be on the agents' allowlist. Empty
    # = PUBLIC_BASE_URL: right when agents reach Provenza only through the
    # egress proxy's relay; when they may reach Provenza directly, give the
    # beacon a name of its own pointing at this server (e.g.
    # "https://egress-check.example.com") and keep it off their allowlist.
    EGRESS_PROBE_TARGETS: str = "api.openai.com:443,1.1.1.1:443"
    EGRESS_BEACON_BASE_URL: str = ""


    # Audit key rotation (docs/audit-proofs.md): how many distinct admins of
    # the organization must approve a new audit key, and how long its
    # fingerprint must be announced before it can take effect - time to
    # publish it outside Provenza. Lower the quorum to 1 only for
    # organizations that really have a single admin.
    AUDIT_KEY_ROTATION_QUORUM: int = 2
    AUDIT_KEY_ROTATION_NOTICE_HOURS: float = 24.0

    # Database
    POSTGRES_USER: str = "ai_user"
    POSTGRES_PASSWORD: str = "ai_password"
    POSTGRES_DB: str = "ai_control_tower"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""

    # JWT - must be overridden in production
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Removed features (MLOps training/deployments and RAG). Nothing in the
    # application reads these any more. They stay so that an existing .env
    # that still sets them keeps loading (extra="forbid"), and so that
    # scripts/delete_org.py can name the directories where those features
    # left files on disk. Relative paths resolve against backend/.
    DATASETS_DIR: str = "data/datasets"
    MODELS_DIR: str = "data/models"
    RAG_DOCUMENTS_DIR: str = "data/rag_documents"
    RAG_VECTORIZERS_DIR: str = "data/rag_vectorizers"
    TRAINING_USE_DOCKER: bool = False
    TRAINING_RUNNER_IMAGE: str = ""
    TRAINING_CONTAINER_CPUS: float = 2.0
    TRAINING_CONTAINER_MEMORY: str = ""
    # Removed content-safety features (Prompt Firewall, PII masking, blocked
    # terms, guards): kept, unread, for the same reason.
    CONTENT_SAFETY_ENABLED: bool = False
    PROMPT_FIREWALL_NER_ENABLED: bool = False
    PROMPT_FIREWALL_NER_MODELS: dict = {}
    PROMPT_FIREWALL_NER_DEFAULT_LANG: str = "en"

    # Source tree for the browser extension template that
    # GET /shadow-ai/extension/download packages on demand - configurable
    # since the deploy layout (monorepo checkout path) isn't guaranteed
    # to be the same across environments.
    EXTENSION_TEMPLATE_DIR: str = "../extension"

    # Connections: symmetric key used to encrypt provider API keys at rest.
    # Generate with:
    #   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Required in production.
    ENCRYPTION_KEY: str = ""

    # Optional: new key to rotate to. Set this alongside ENCRYPTION_KEY and
    # run scripts/rotate_encryption_key.py, then move the new value into
    # ENCRYPTION_KEY and clear this field. See README for details.
    ENCRYPTION_KEY_NEW: str = ""

    # Notification Service: email is optional
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "provenza@localhost"
    SMTP_USE_TLS: bool = True

    # Bearer secret Alertmanager presents on /api/v1/observability/alerts.
    # Empty means the endpoint is disabled (503) - safer than an open
    # webhook, and the self-hosted default is "the operator sets this in
    # .env on first install".
    ALERTMANAGER_SECRET: str = ""

    class Config:
        env_file = ".env"
        # Reject unknown variables in .env so a typo like "POSTGRESS_PASSWORD"
        # surfaces as a clear startup error instead of being silently ignored.
        extra = "forbid"

    @model_validator(mode="after")
    def _resolve_relative_paths(self):
        """
        Anchor the data directories to the backend package directory so
        that starting uvicorn from a different working directory does not
        silently point at a second data/ tree somewhere else on disk.
        """
        backend_root = Path(__file__).resolve().parents[2]
        for field in ("DATASETS_DIR", "MODELS_DIR", "RAG_DOCUMENTS_DIR", "RAG_VECTORIZERS_DIR", "EXTENSION_TEMPLATE_DIR"):
            value = getattr(self, field)
            p = Path(value)
            if not p.is_absolute():
                setattr(self, field, str((backend_root / p).resolve()))
        return self

    @model_validator(mode="after")
    def _audit_rotation_bounds(self):
        if self.AUDIT_KEY_ROTATION_QUORUM < 1:
            raise ValueError("AUDIT_KEY_ROTATION_QUORUM must be at least 1")
        if self.AUDIT_KEY_ROTATION_NOTICE_HOURS < 0:
            raise ValueError("AUDIT_KEY_ROTATION_NOTICE_HOURS must not be negative")
        return self

    @model_validator(mode="after")
    def _enforce_production_secrets(self):
        """
        Refuse to start in production with insecure default secrets. This
        prevents a copy-pasted .env.example from quietly running with a
        well-known JWT key or an empty Fernet key.
        """
        if self.ENVIRONMENT != "production":
            return self

        problems: list[str] = []

        problems.extend(secret_key_problems(self.SECRET_KEY))
        if not self.ENCRYPTION_KEY:
            problems.append(
                "ENCRYPTION_KEY is empty. Generate one with "
                "'python3 -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\"'."
            )
        if self.POSTGRES_PASSWORD in ("", "ai_password", "change_me_in_dot_env"):
            problems.append(
                "POSTGRES_PASSWORD is still a default value."
            )
        if not self.REDIS_PASSWORD:
            problems.append("REDIS_PASSWORD is empty.")

        if problems:
            raise ValueError(
                "Refusing to start with ENVIRONMENT=production and insecure "
                "configuration:\n  - " + "\n  - ".join(problems)
            )

        return self


settings = Settings()


