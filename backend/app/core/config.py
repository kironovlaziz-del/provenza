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
    PROJECT_NAME: str = "AI Control Tower"
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

    # Training isolation: when true, each training job runs in its own
    # Docker container built from backend/training_runner/. When false,
    # training runs in-process inside the Celery worker (the legacy
    # behaviour, useful for local development without Docker).
    TRAINING_USE_DOCKER: bool = False

    # Image used for isolated training jobs. Build it once with:
    #   docker build -t ai-control-tower/training-runner:latest backend/training_runner
    TRAINING_RUNNER_IMAGE: str = "ai-control-tower/training-runner:latest"

    # Container resource limits. Match these to the host's capacity.
    TRAINING_CONTAINER_CPUS: float = 2.0
    TRAINING_CONTAINER_MEMORY: str = "2g"

    # Prompt Firewall: enable NER-based PII detection (person names,
    # organizations, locations) on top of the built-in regex detectors.
    # Requires spaCy plus a language model; when the model is not
    # installed, NER is skipped silently.
    PROMPT_FIREWALL_NER_ENABLED: bool = True
    PROMPT_FIREWALL_NER_MODELS: dict = {
    "en": "en_core_web_sm",
    "uz": "ner_training/output/uz_ner_model",
    }
    PROMPT_FIREWALL_NER_DEFAULT_LANG: str = "en"

    # MLOps - relative paths are resolved against the project root
    # (backend/) so they work regardless of the current working directory.
    # Absolute paths from .env are used as-is.
    DATASETS_DIR: str = "data/datasets"
    MODELS_DIR: str = "data/models"
    RAG_DOCUMENTS_DIR: str = "data/rag_documents"
    RAG_VECTORIZERS_DIR: str = "data/rag_vectorizers"
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
    SMTP_FROM: str = "ai-control-tower@localhost"
    SMTP_USE_TLS: bool = True

    class Config:
        env_file = ".env"
        # Reject unknown variables in .env so a typo like "POSTGRESS_PASSWORD"
        # surfaces as a clear startup error instead of being silently ignored.
        extra = "forbid"

    @model_validator(mode="after")
    def _resolve_relative_paths(self):
        """
        Anchor MODELS_DIR and DATASETS_DIR to the backend package directory
        so that starting uvicorn from a different working directory does
        not silently create a second data/ tree somewhere else on disk.
        """
        backend_root = Path(__file__).resolve().parents[2]
        for field in ("DATASETS_DIR", "MODELS_DIR", "RAG_DOCUMENTS_DIR", "RAG_VECTORIZERS_DIR", "EXTENSION_TEMPLATE_DIR"):
            value = getattr(self, field)
            p = Path(value)
            if not p.is_absolute():
                setattr(self, field, str((backend_root / p).resolve()))
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


