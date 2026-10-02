"""
Model allow-list for the transformer fine-tuning track.

Kept deliberately small and curated rather than letting people type any
Hugging Face model id on a CPU-only box - a bad choice there doesn't fail
fast, it just hangs for hours. Once a GPU is present, the actual free VRAM
is checked against a conservative estimate of what full fine-tuning needs
(fp32 weights + gradients + Adam optimizer state is roughly 16 bytes per
parameter, plus headroom for activations) - this is a soft pre-flight
check, not a guarantee: VRAM fragmentation or other processes on the GPU
can still cause an out-of-memory error at train time, which
training_tasks.py catches separately and reports clearly.
"""

from typing import Any, Dict, List, Optional

# estimated_vram_gb is a conservative estimate for full fine-tuning at a
# modest batch size (~8) and sequence length (~256) in fp32.
CPU_SAFE_MODELS: List[Dict[str, Any]] = [
    {
        "id": "google/bert_uncased_L-2_H-128_A-2",
        "label": "BERT-Tiny Google (~4M params)",
        "note": "Fastest option on CPU - minutes, not hours, on small datasets. Official Google release with a complete tokenizer file set.",
        "estimated_vram_gb": 0.3,
    },
    {
        "id": "microsoft/MiniLM-L12-H384-uncased",
        "label": "MiniLM-L12 (~33M params)",
        "note": "A speed/quality trade-off, still practical on CPU.",
        "estimated_vram_gb": 1.0,
    },
    {
        "id": "distilbert-base-uncased",
        "label": "DistilBERT (~66M params)",
        "note": "Noticeably slower on CPU - expect tens of minutes to hours even on a small dataset.",
        "estimated_vram_gb": 2.0,
    },
]

GPU_ADDITIONAL_MODELS: List[Dict[str, Any]] = [
    {
        "id": "bert-base-uncased",
        "label": "BERT-base (~110M params)",
        "note": "Requires a GPU for practical training time.",
        "estimated_vram_gb": 3.0,
    },
    {
        "id": "roberta-base",
        "label": "RoBERTa-base (~125M params)",
        "note": "Requires a GPU for practical training time.",
        "estimated_vram_gb": 3.5,
    },
]

# Models suitable for causal language modeling (text generation).
# Small enough to train on CPU for demos; larger ones need a GPU.
GENERATION_MODELS: List[Dict[str, Any]] = [
    {
        "id": "sshleifer/tiny-gpt2",
        "label": "Tiny GPT-2 (~2M params)",
        "note": "A toy model, only good for smoke-testing the pipeline.",
        "estimated_vram_gb": 0.2,
    },
    {
        "id": "distilgpt2",
        "label": "DistilGPT-2 (~82M params)",
        "note": "Fast generation on CPU; lower quality than full GPT-2.",
        "estimated_vram_gb": 2.5,
    },
    {
        "id": "gpt2",
        "label": "GPT-2 (~124M params)",
        "note": "Base GPT-2; needs a GPU for practical training time.",
        "estimated_vram_gb": 4.0,
    },
]

# Curated models are downloaded at a fixed commit, so a later push to the Hub
# repo (by mistake or by whoever takes it over) cannot change what gets
# trained here. Update a pin deliberately, after checking the new commit.
PINNED_REVISIONS: Dict[str, str] = {
    "google/bert_uncased_L-2_H-128_A-2": "30b0a37ccaaa32f332884b96992754e246e48c5f",
    "microsoft/MiniLM-L12-H384-uncased": "44acabbec0ef496f6dbc93adadea57f376b7c0ec",
    "distilbert-base-uncased": "12040accade4e8a0f71eabdb258fecc2e7e948be",
    "bert-base-uncased": "86b5e0934494bd15c9632b12f734a8a67f723594",
    "roberta-base": "e2da8e2f811d1448a5b465c236feacd80ffbac7b",
    "sshleifer/tiny-gpt2": "5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be",
    "distilgpt2": "2290a62682d06624634c1f46a6ad5be0f47f38aa",
    "gpt2": "607a30d783dfa663caf39e06633721c8d4cfcd7e",
}


def pinned_revision(model_id: str) -> Optional[str]:
    """The commit a curated model is pinned to; None for a free-form model id
    (allowed on GPU hosts only), which resolves to the repo's default branch.
    Either way the commit actually used is recorded in the model's meta.json."""
    return PINNED_REVISIONS.get(model_id)


# Safety margin: require this multiple of the estimate to be free, since the
# estimate doesn't account for activation memory growing with batch size,
# CUDA context overhead, or other processes sharing the GPU.
VRAM_SAFETY_MARGIN = 1.3


def allowed_models(
    gpu_available: bool,
    gpu_vram_free_gb: Optional[float] = None,
    task_type: str = "transformer_text_classification",
) -> List[Dict[str, Any]]:
    """
    Returns the curated model list for the given task type, annotated with
    whether each model currently fits in the detected free VRAM
    (fits_vram: true/false/null). null means "unknown" - either no GPU, or
    VRAM couldn't be read.
    """
    if task_type == "transformer_text_generation":
        candidates = list(GENERATION_MODELS)
        if gpu_available:
            candidates += [
                m for m in GENERATION_MODELS if m["estimated_vram_gb"] >= 3.0
            ]
    else:
        candidates = CPU_SAFE_MODELS + GPU_ADDITIONAL_MODELS if gpu_available else list(CPU_SAFE_MODELS)
    result = []
    for m in candidates:
        entry = dict(m)
        if gpu_available and gpu_vram_free_gb is not None:
            required = m["estimated_vram_gb"] * VRAM_SAFETY_MARGIN
            entry["fits_vram"] = gpu_vram_free_gb >= required
        else:
            entry["fits_vram"] = None
        result.append(entry)
    return result


def check_model_fit(
    model_id: str,
    task_type: str,
    gpu_available: bool,
    gpu_vram_free_gb: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Validates a specific model choice against detected hardware and the
    requested task type. Returns {"allowed": bool, "reason": str|None}.

    The task type determines which curated list is authoritative: a model
    that exists in GENERATION_MODELS is not valid for classification, and
    vice versa.
    """
    if task_type == "transformer_text_generation":
        candidates = list(GENERATION_MODELS)
    else:
        candidates = CPU_SAFE_MODELS + GPU_ADDITIONAL_MODELS

    match = next((m for m in candidates if m["id"] == model_id), None)

    if match is None:
        # Not in the curated list: only trust a free-form model id if a GPU
        # is present, and we can't estimate its VRAM need, so just warn.
        if gpu_available:
            return {
                "allowed": True,
                "reason": (
                    "Model is not from the curated list - required VRAM is "
                    "unknown, an out-of-memory error during training is possible."
                ),
            }
        return {
            "allowed": False,
            "reason_code": "training.model_not_allowed_no_gpu",
        }

    if not gpu_available and match in GPU_ADDITIONAL_MODELS:
        return {"allowed": False, "reason_code": "training.model_requires_gpu", "model": model_id}

    if gpu_available and gpu_vram_free_gb is not None:
        required = match["estimated_vram_gb"] * VRAM_SAFETY_MARGIN
        if gpu_vram_free_gb < required:
            return {
                "allowed": False,
                "reason_code": "training.model_insufficient_vram",
                    "required_gb": round(required, 1),
                    "available_gb": gpu_vram_free_gb,
            }

    return {"allowed": True, "reason": None}


def is_model_allowed(model_id: str, gpu_available: bool, gpu_vram_free_gb: Optional[float] = None) -> bool:
    return check_model_fit(model_id, gpu_available, gpu_vram_free_gb)["allowed"]
