import logging
import json
import traceback
from datetime import datetime, timezone
from pathlib import Path

from app.core.celery_app import celery_app
from app.core.config import settings
from app.core.sync_database import SyncSessionLocal
from app.models.training_job import TrainingJob
from app.models.dataset import Dataset
from app.services import notification_service
from app.services import transformer_models

logger = logging.getLogger("training_tasks")


# ---------------------------------------------------------------------------
# Progress reporting
# ---------------------------------------------------------------------------

def _update_progress(job_id: int, pct: float, stage: str) -> None:
    """
    Persist progress to the training_jobs row and broadcast it on the
    Redis pub/sub channel used by the SSE endpoint.

    Uses a direct UPDATE on exactly two columns instead of loading the row
    through the ORM - the earlier ORM version caused a race with the main
    worker session that could write stale status / finished_at back.
    """
    from sqlalchemy import update

    normalized_pct = max(0.0, min(round(pct, 2), 100.0))
    normalized_stage = stage[:255] if stage else None

    db = SyncSessionLocal()
    try:
        db.execute(
            update(TrainingJob)
            .where(TrainingJob.id == job_id)
            .values(
                progress_pct=normalized_pct,
                progress_stage=normalized_stage,
            )
        )
        db.commit()
    except Exception:  # noqa: BLE001 - progress reporting must not fail the job
        db.rollback()
    finally:
        db.close()

    # Broadcast to SSE subscribers. Failures are swallowed inside the
    # helper, so a missing Redis here cannot kill the run.
    from app.core import events

    events.publish_progress_sync(
        job_id, normalized_pct, normalized_stage, status="running"
    )




def _maybe_apply_lora(model, hyperparameters: dict):
    """
    Wrap a Hugging Face model in a LoRA adapter when hyperparameters.use_lora
    is true. Returns (model, is_lora). When LoRA is off, returns the model
    unchanged. The adapter is trained and later merged into the base model
    before saving (see merge call in _run_transformer_training), so the
    final artifact is a plain Hugging Face model.

    target_modules is left to peft's default for the architecture unless
    the user provided an explicit list. Defaults are: query,value for
    BERT-family encoders; c_attn for GPT-2-family decoders.
    """
    if not hyperparameters.get("use_lora"):
        return model, False

    from peft import LoraConfig, TaskType, get_peft_model

    # TaskType depends on the model class - check via config
    if model.config.model_type in ("gpt2", "gpt_neo", "gptj", "llama"):
        task_type = TaskType.CAUSAL_LM
    else:
        task_type = TaskType.SEQ_CLS

    target_modules = hyperparameters.get("lora_target_modules")
    lora_config = LoraConfig(
        r=int(hyperparameters.get("lora_r", 8)),
        lora_alpha=int(hyperparameters.get("lora_alpha", 16)),
        lora_dropout=float(hyperparameters.get("lora_dropout", 0.05)),
        bias="none",
        task_type=task_type,
        target_modules=target_modules,  # None → peft picks defaults
    )
    model = get_peft_model(model, lora_config)
    return model, True


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def _resolve_dataset_path(dataset) -> str:
    """
    Dataset rows uploaded before the A15 fix have a relative file_path
    (e.g. "data/datasets/7/abc.csv") stored in the DB. Resolve such paths
    against the backend project root so they work regardless of the
    process's current working directory - which matters inside the
    isolated training container, where CWD is /app.
    """
    from pathlib import Path

    from app.core.config import settings

    p = Path(dataset.file_path)
    if p.is_absolute():
        return str(p)
    # settings.DATASETS_DIR is absolute (resolved in config.py); its parent
    # is the backend root.
    backend_root = Path(settings.DATASETS_DIR).resolve().parent
    return str((backend_root / p).resolve())


# ---------------------------------------------------------------------------
# Optuna hyperparameter search
# ---------------------------------------------------------------------------


def _run_auto_tune(job: "TrainingJob", dataset: "Dataset") -> None:
    """
    Run Optuna over the algorithm's search space, then persist the best
    hyperparameters on the job so the regular sklearn path uses them.
    Progress is reported via the same SSE channel as normal training.
    """
    import optuna
    from sklearn.metrics import accuracy_score, f1_score, r2_score

    from app.services import hyperparameter_search, ml_algorithms

    optuna.logging.set_verbosity(optuna.logging.WARNING)

    user_hp = dict(job.hyperparameters_json or {})
    n_trials = int(user_hp.pop("n_trials", user_hp.pop("auto_tune_trials", 20)))
    algorithm = job.algorithm
    is_classification = job.task_type == "tabular_classification"
    metric_name = "f1_weighted" if is_classification else "r2"

    # Pre-load the dataset once so every trial reuses the same data
    # matrix. Avoids re-reading the CSV on each trial.
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder

    sep = "\t" if dataset.file_format == "tsv" else ","
    df = pd.read_csv(_resolve_dataset_path(dataset), sep=sep)
    if job.target_column not in df.columns:
        raise ValueError(f"Target column '{job.target_column}' not found")

    y_raw = df[job.target_column]
    all_features = df.drop(columns=[job.target_column])
    X = all_features.select_dtypes(include="number")

    if X.shape[1] == 0:
        raise ValueError("No numeric feature columns found")

    combined = X.copy()
    combined["__target__"] = y_raw
    combined = combined.dropna()
    X = combined.drop(columns=["__target__"])
    y_raw = combined["__target__"]

    if is_classification and y_raw.dtype == object:
        y = LabelEncoder().fit_transform(y_raw)
    else:
        y = y_raw

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    def objective(trial):
        suggested = hyperparameter_search.suggest(algorithm, trial)
        # User-supplied values win over suggestions so callers can pin
        # any parameter.
        merged = {**suggested, **user_hp}
        # Optuna does not handle None in categorical well; skip and
        # normalise.
        merged.pop("n_trials", None)
        merged.pop("auto_tune_trials", None)
        model = _build_sklearn_model(algorithm, merged, is_classification)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        if is_classification:
            return float(f1_score(y_test, y_pred, average="weighted"))
        return float(r2_score(y_test, y_pred))

    study = optuna.create_study(
        direction="maximize", study_name=f"job_{job.id}"
    )

    def callback(study, trial):
        pct = 5.0 + 15.0 * (len(study.trials) / n_trials)
        _update_progress(
            job.id,
            pct,
            f"Auto-tune trial {len(study.trials)}/{n_trials} "
            f"best={study.best_value:.3f}",
        )

    study.optimize(objective, n_trials=n_trials, callbacks=[callback])

    # Persist winning params. User-supplied values are already in `user_hp`
    # and take precedence in `objective`, so the merged best params is
    # what the final training pass should use.
    best_params = {**study.best_params, **user_hp}
    best_params["_auto_tune"] = {
        "n_trials": n_trials,
        "best_value": float(study.best_value),
        "metric": metric_name,
    }
    job.hyperparameters_json = best_params
    _update_progress(
        job.id,
        20.0,
        f"Auto-tune done, best {metric_name}={study.best_value:.3f}",
    )


# ---------------------------------------------------------------------------
# Sklearn track
# ---------------------------------------------------------------------------

def _resolve_class_weight(hyperparameters: dict) -> str | None:
    """
    Class imbalance silently kills classifier accuracy: on a 95/5 split, a
    model that always predicts the majority class scores 95% while being
    useless. Scikit-learn's 'balanced' mode reweights the loss by inverse
    class frequency.

    Default is 'balanced' for classification. Users can override to None
    (no reweighting) via hyperparameters.class_weight = null.
    """
    if "class_weight" in hyperparameters:
        return hyperparameters["class_weight"]
    return "balanced"


def _build_sklearn_model(algorithm: str, hyperparameters: dict, is_classification: bool):
    class_weight = _resolve_class_weight(hyperparameters) if is_classification else None

    if algorithm == "logistic_regression":
        from sklearn.linear_model import LogisticRegression

        return LogisticRegression(
            max_iter=hyperparameters.get("max_iter", 1000),
            class_weight=class_weight,
        )

    if algorithm == "random_forest_classifier":
        from sklearn.ensemble import RandomForestClassifier

        return RandomForestClassifier(
            n_estimators=hyperparameters.get("n_estimators", 100),
            max_depth=hyperparameters.get("max_depth"),
            class_weight=class_weight,
            random_state=42,
        )

    if algorithm == "linear_regression":
        from sklearn.linear_model import LinearRegression

        return LinearRegression()

    if algorithm == "random_forest_regressor":
        from sklearn.ensemble import RandomForestRegressor

        return RandomForestRegressor(
            n_estimators=hyperparameters.get("n_estimators", 100),
            max_depth=hyperparameters.get("max_depth"),
            random_state=42,
        )

    raise ValueError(f"Unknown algorithm: {algorithm}")


def _run_sklearn_training(job: "TrainingJob", dataset: "Dataset") -> None:
    import joblib
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, f1_score, mean_squared_error, r2_score
    from sklearn.preprocessing import LabelEncoder

    _update_progress(job.id, 10.0, "Loading dataset")

    sep = "\t" if dataset.file_format == "tsv" else ","
    df = pd.read_csv(_resolve_dataset_path(dataset), sep=sep)

    if job.target_column not in df.columns:
        raise ValueError(
            f"Target column '{job.target_column}' not found in dataset. "
            f"Available columns: {', '.join(df.columns)}"
        )

    y_raw = df[job.target_column]
    all_features = df.drop(columns=[job.target_column])
    X = all_features.select_dtypes(include="number")

    dropped_columns = [c for c in all_features.columns if c not in X.columns]
    warnings: list[str] = []
    if dropped_columns:
        dropped_ratio = len(dropped_columns) / max(len(all_features.columns), 1)
        if dropped_ratio >= 0.5:
            warnings.append(
                f"Dropped {len(dropped_columns)} of {len(all_features.columns)} "
                f"non-numeric feature columns ({', '.join(dropped_columns[:5])}"
                f"{'…' if len(dropped_columns) > 5 else ''}). Consider one-hot "
                f"encoding or removing them before upload."
            )
        else:
            warnings.append(
                f"Dropped non-numeric columns: {', '.join(dropped_columns[:10])}"
                f"{'…' if len(dropped_columns) > 10 else ''}."
            )

    if X.shape[1] == 0:
        raise ValueError(
            "No numeric feature columns found after dropping the target. "
            "The tabular track only supports numeric features."
        )

    combined = X.copy()
    combined["__target__"] = y_raw
    combined = combined.dropna()
    X = combined.drop(columns=["__target__"])
    y_raw = combined["__target__"]

    if len(X) < 10:
        raise ValueError(
            f"Only {len(X)} usable rows after dropping missing values - "
            "need at least 10 to train a meaningful model."
        )

    label_classes = None
    is_classification = job.task_type == "tabular_classification"
    if is_classification and y_raw.dtype == object:
        encoder = LabelEncoder()
        y = encoder.fit_transform(y_raw)
        label_classes = encoder.classes_.tolist()
    else:
        y = y_raw

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    _update_progress(job.id, 40.0, "Fitting model")

    model = _build_sklearn_model(
        job.algorithm, job.hyperparameters_json or {}, is_classification
    )
    model.fit(X_train, y_train)

    _update_progress(job.id, 85.0, "Evaluating")

    y_pred = model.predict(X_test)

    if is_classification:
        metrics = {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "f1_weighted": float(f1_score(y_test, y_pred, average="weighted")),
            "test_rows": int(len(X_test)),
            "train_rows": int(len(X_train)),
        }
        if y_test.nunique() == 1:
            warnings.append(
                "Test split contains only one class - accuracy and F1 are "
                "not meaningful on this run. Add more rows or balance the dataset."
            )
    else:
        metrics = {
            "mse": float(mean_squared_error(y_test, y_pred)),
            "r2": float(r2_score(y_test, y_pred)),
            "test_rows": int(len(X_test)),
            "train_rows": int(len(X_train)),
        }

    if warnings:
        metrics["warnings"] = warnings

    models_dir = Path(settings.MODELS_DIR) / str(job.org_id)
    models_dir.mkdir(parents=True, exist_ok=True)
    model_path = models_dir / f"job_{job.id}.joblib"
    joblib.dump(
        {"model": model, "feature_columns": list(X.columns), "label_classes": label_classes},
        model_path,
    )

    _update_progress(job.id, 100.0, "Completed")

    job.feature_columns_json = list(X.columns)
    job.metrics_json = metrics
    job.model_path = str(model_path)
    job.status = "completed"
    job.error_message = None


# ---------------------------------------------------------------------------
# Transformer track - text classification
# ---------------------------------------------------------------------------

def _make_classification_metrics():
    """compute_metrics function for the Trainer, resolved lazily."""
    import numpy as np
    from sklearn.metrics import accuracy_score, f1_score

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        return {
            "accuracy": float(accuracy_score(labels, preds)),
            "f1_weighted": float(f1_score(labels, preds, average="weighted")),
        }

    return compute_metrics


def _run_transformer_training(job: "TrainingJob", dataset: "Dataset") -> None:
    import pandas as pd
    import torch
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        TrainerCallback,
        Trainer,
        TrainingArguments,
    )

    hyperparameters = job.hyperparameters_json or {}
    text_column = hyperparameters.get("text_column")
    if not text_column:
        raise ValueError("hyperparameters.text_column is required for this task type.")

    _update_progress(job.id, 5.0, "Loading dataset")

    sep = "\t" if dataset.file_format == "tsv" else ","
    df = pd.read_csv(_resolve_dataset_path(dataset), sep=sep)

    for col in (text_column, job.target_column):
        if col not in df.columns:
            raise ValueError(
                f"Column '{col}' not found in dataset. "
                f"Available columns: {', '.join(df.columns)}"
            )

    df = df[[text_column, job.target_column]].dropna()
    if len(df) < 20:
        raise ValueError(
            f"Only {len(df)} usable rows after dropping missing values - "
            "need at least 20 to fine-tune a text classifier meaningfully."
        )

    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder

    texts = df[text_column].astype(str).tolist()
    encoder = LabelEncoder()
    labels = encoder.fit_transform(df[job.target_column].astype(str))
    label_classes = encoder.classes_.tolist()
    num_labels = len(label_classes)

    train_texts, test_texts, train_labels, test_labels = train_test_split(
        texts, labels, test_size=0.2, random_state=42
    )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type == "cuda":
        torch.cuda.empty_cache()

    _update_progress(job.id, 10.0, "Tokenizing")

    # use_fast=False: some published repos (e.g. prajjwal1/bert-tiny) ship
    # only vocab.txt without tokenizer.json/tokenizer_config.json, and
    # the fast-tokenizer auto-detection fails on them in recent
    # transformers versions.
    revision = transformer_models.pinned_revision(job.base_model)
    tokenizer = AutoTokenizer.from_pretrained(job.base_model, revision=revision, use_fast=False)
    max_length = int(hyperparameters.get("max_length", 256))
    train_encodings = tokenizer(
        train_texts, truncation=True, padding=True, max_length=max_length
    )
    test_encodings = tokenizer(
        test_texts, truncation=True, padding=True, max_length=max_length
    )

    class _TextDataset(torch.utils.data.Dataset):
        def __init__(self, encodings, labels):
            self.encodings = encodings
            self.labels = labels

        def __len__(self):
            return len(self.labels)

        def __getitem__(self, idx):
            item = {k: torch.tensor(v[idx]) for k, v in self.encodings.items()}
            item["labels"] = torch.tensor(int(self.labels[idx]))
            return item

    train_dataset = _TextDataset(train_encodings, train_labels)
    test_dataset = _TextDataset(test_encodings, test_labels)

    _update_progress(job.id, 15.0, "Loading model")

    base_model = AutoModelForSequenceClassification.from_pretrained(
        job.base_model, revision=revision, num_labels=num_labels
    ).to(device)
    base_commit = getattr(base_model.config, "_commit_hash", None) or revision

    model, is_lora = _maybe_apply_lora(base_model, hyperparameters)
    if is_lora:
        _update_progress(job.id, 17.0, "Applying LoRA adapter")
        model.print_trainable_parameters()

    models_dir = Path(settings.MODELS_DIR) / str(job.org_id) / f"job_{job.id}"
    models_dir.mkdir(parents=True, exist_ok=True)

    # Progress callback — runs on every logging step and writes the current
    # global_step / max_steps ratio to the job row so the UI can render a
    # live progress bar.
    class _ProgressCallback(TrainerCallback):
        def on_log(self, args, state, control, **kwargs):
            if state.max_steps and state.max_steps > 0:
                # Reserve 15-100% for training; 0-15% covers data prep.
                pct = 15.0 + 85.0 * (state.global_step / state.max_steps)
                _update_progress(
                    job.id,
                    pct,
                    f"Training step {state.global_step}/{state.max_steps}",
                )
            return control

        def on_train_end(self, args, state, control, **kwargs):
            _update_progress(job.id, 95.0, "Evaluating")
            return control

    training_args = TrainingArguments(
        output_dir=str(models_dir / "_trainer_tmp"),
        num_train_epochs=float(hyperparameters.get("epochs", 1)),
        per_device_train_batch_size=int(hyperparameters.get("batch_size", 8)),
        per_device_eval_batch_size=int(hyperparameters.get("batch_size", 8)),
        learning_rate=float(hyperparameters.get("learning_rate", 5e-5)),
        logging_steps=10,
        save_strategy="epoch",
        save_total_limit=2,
        eval_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="accuracy",
        greater_is_better=True,
        report_to=[],
        disable_tqdm=True,
        use_cpu=(device.type == "cpu"),
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
        compute_metrics=_make_classification_metrics(),
        callbacks=[_ProgressCallback()],
    )

    try:
        trainer.train()
    except RuntimeError as exc:
        if "out of memory" in str(exc).lower() or "alloc" in str(exc).lower():
            raise ValueError(
                f"Out of memory while training '{job.base_model}' "
                f"(batch_size={training_args.per_device_train_batch_size}, "
                f"device={device.type}). Try a smaller model, a smaller "
                f"batch_size, or a shorter max_length."
            ) from exc
        raise

    predictions = trainer.predict(test_dataset)
    y_pred = predictions.predictions.argmax(axis=-1)

    from sklearn.metrics import accuracy_score, f1_score

    metrics = {
        "accuracy": float(accuracy_score(test_labels, y_pred)),
        "f1_weighted": float(f1_score(test_labels, y_pred, average="weighted")),
        "train_rows": int(len(train_texts)),
        "test_rows": int(len(test_texts)),
        "device_used": device.type,
    }

    # Merge the LoRA adapter back into the base weights so the saved
    # artifact is a plain Hugging Face model - inference code does not
    # need to know LoRA was ever used.
    if is_lora:
        model = model.merge_and_unload()

    model.save_pretrained(models_dir)
    tokenizer.save_pretrained(models_dir)
    meta = {"label_classes": label_classes, "mode": "transformer",
            "base_model": job.base_model, "base_model_commit": base_commit}
    if is_lora:
        meta["lora"] = {
            "r": int(hyperparameters.get("lora_r", 8)),
            "alpha": int(hyperparameters.get("lora_alpha", 16)),
            "dropout": float(hyperparameters.get("lora_dropout", 0.05)),
            "target_modules": hyperparameters.get("lora_target_modules"),
            "merged": True,
        }
    (models_dir / "meta.json").write_text(json.dumps(meta))

    _update_progress(job.id, 100.0, "Completed")

    job.feature_columns_json = [text_column]
    job.metrics_json = metrics
    job.model_path = str(models_dir)
    job.status = "completed"
    job.error_message = None


# ---------------------------------------------------------------------------
# Transformer track - text generation
# ---------------------------------------------------------------------------

def _run_generation_training(job: "TrainingJob", dataset: "Dataset") -> None:
    import math

    import pandas as pd
    import torch
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        DataCollatorForLanguageModeling,
        TrainerCallback,
        Trainer,
        TrainingArguments,
    )

    hyperparameters = job.hyperparameters_json or {}
    text_column = hyperparameters.get("text_column")
    if not text_column:
        raise ValueError("hyperparameters.text_column is required for this task type.")

    _update_progress(job.id, 5.0, "Loading dataset")

    sep = "\t" if dataset.file_format == "tsv" else ","
    df = pd.read_csv(_resolve_dataset_path(dataset), sep=sep)
    if text_column not in df.columns:
        raise ValueError(
            f"Column '{text_column}' not found in dataset. "
            f"Available columns: {', '.join(df.columns)}"
        )

    texts = [t for t in df[text_column].dropna().astype(str).tolist() if t.strip()]
    if len(texts) < 20:
        raise ValueError(
            f"Only {len(texts)} usable rows after dropping missing/empty values - "
            "need at least 20 to fine-tune a generator meaningfully."
        )

    # Simple Mode wizard's "personality" step (screen 7): human-language
    # style rules, already converted to a plain string by the frontend,
    # get prepended to every training example rather than passed to the
    # model as a special token or chat-template field - this is a causal-LM
    # continuation model, not an instruction-tuned chat model, so there is
    # no separate "system message" concept to hook into. Prepending it
    # consistently at training time means prompting with the same prefix
    # at inference time reliably steers generation toward that style.
    system_prompt = hyperparameters.get("system_prompt")
    if system_prompt:
        texts = [f"{system_prompt}\n\n{t}" for t in texts]

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type == "cuda":
        torch.cuda.empty_cache()

    _update_progress(job.id, 10.0, "Tokenizing")

    # use_fast=False: some published repos (e.g. prajjwal1/bert-tiny) ship
    # only vocab.txt without tokenizer.json/tokenizer_config.json, and
    # the fast-tokenizer auto-detection fails on them in recent
    # transformers versions.
    revision = transformer_models.pinned_revision(job.base_model)
    tokenizer = AutoTokenizer.from_pretrained(job.base_model, revision=revision, use_fast=False)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    max_length = int(hyperparameters.get("max_length", 128))

    class _GenDataset(torch.utils.data.Dataset):
        def __init__(self, examples):
            self.examples = examples

        def __len__(self):
            return len(self.examples)

        def __getitem__(self, idx):
            return {"input_ids": self.examples[idx]}

    tokenized = [
        tokenizer(t, truncation=True, max_length=max_length)["input_ids"] for t in texts
    ]
    split_idx = max(1, int(len(tokenized) * 0.9))
    train_dataset = _GenDataset(tokenized[:split_idx])
    eval_examples = tokenized[split_idx:] or tokenized[-2:]
    eval_dataset = _GenDataset(eval_examples)

    data_collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)

    _update_progress(job.id, 15.0, "Loading model")

    base_model = AutoModelForCausalLM.from_pretrained(job.base_model, revision=revision)
    base_commit = getattr(base_model.config, "_commit_hash", None) or revision
    base_model.resize_token_embeddings(len(tokenizer))
    base_model.to(device)

    model, is_lora = _maybe_apply_lora(base_model, hyperparameters)
    if is_lora:
        _update_progress(job.id, 17.0, "Applying LoRA adapter")
        model.print_trainable_parameters()

    models_dir = Path(settings.MODELS_DIR) / str(job.org_id) / f"job_{job.id}"
    models_dir.mkdir(parents=True, exist_ok=True)

    class _ProgressCallback(TrainerCallback):
        def on_log(self, args, state, control, **kwargs):
            if state.max_steps and state.max_steps > 0:
                pct = 15.0 + 85.0 * (state.global_step / state.max_steps)
                _update_progress(
                    job.id,
                    pct,
                    f"Training step {state.global_step}/{state.max_steps}",
                )
            return control

        def on_train_end(self, args, state, control, **kwargs):
            _update_progress(job.id, 95.0, "Evaluating")
            return control

    training_args = TrainingArguments(
        output_dir=str(models_dir / "_trainer_tmp"),
        num_train_epochs=float(hyperparameters.get("epochs", 1)),
        per_device_train_batch_size=int(hyperparameters.get("batch_size", 4)),
        per_device_eval_batch_size=int(hyperparameters.get("batch_size", 4)),
        learning_rate=float(hyperparameters.get("learning_rate", 5e-5)),
        logging_steps=10,
        save_strategy="epoch",
        save_total_limit=2,
        eval_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        report_to=[],
        disable_tqdm=True,
        use_cpu=(device.type == "cpu"),
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        data_collator=data_collator,
        callbacks=[_ProgressCallback()],
    )

    try:
        trainer.train()
    except RuntimeError as exc:
        if "out of memory" in str(exc).lower() or "alloc" in str(exc).lower():
            raise ValueError(
                f"Out of memory while training '{job.base_model}' "
                f"(batch_size={training_args.per_device_train_batch_size}, "
                f"device={device.type}). Try a smaller model, a smaller "
                f"batch_size, or a shorter max_length."
            ) from exc
        raise

    eval_metrics = trainer.evaluate(eval_dataset=eval_dataset)
    eval_loss = float(eval_metrics.get("eval_loss", 0))
    try:
        perplexity = math.exp(eval_loss)
    except OverflowError:
        perplexity = None

    metrics = {
        "eval_loss": eval_loss,
        "perplexity": perplexity,
        "train_rows": int(len(train_dataset)),
        "eval_rows": int(len(eval_dataset)),
        "device_used": device.type,
    }

    # Merge LoRA back into the base weights so the artifact is a standard
    # Hugging Face causal LM.
    if is_lora:
        model = model.merge_and_unload()

    model.save_pretrained(models_dir)
    tokenizer.save_pretrained(models_dir)
    meta = {"mode": "transformer_generation",
            "base_model": job.base_model, "base_model_commit": base_commit}
    if is_lora:
        meta["lora"] = {
            "r": int(hyperparameters.get("lora_r", 8)),
            "alpha": int(hyperparameters.get("lora_alpha", 16)),
            "dropout": float(hyperparameters.get("lora_dropout", 0.05)),
            "target_modules": hyperparameters.get("lora_target_modules"),
            "merged": True,
        }
    (models_dir / "meta.json").write_text(json.dumps(meta))

    _update_progress(job.id, 100.0, "Completed")

    job.feature_columns_json = [text_column]
    job.metrics_json = metrics
    job.model_path = str(models_dir)
    job.status = "completed"
    job.error_message = None


# ---------------------------------------------------------------------------
# Celery entry point
# ---------------------------------------------------------------------------

def _train_model_sync(job_id: int) -> None:
    """
    In-process training body. Called both by the Celery task (legacy mode)
    and by the isolated container's entrypoint (Docker mode). Performs the
    full DB read, training, and status update cycle.
    """
    db = SyncSessionLocal()
    try:
        job = db.get(TrainingJob, job_id)
        if not job:
            return
        if job.status == "cancelled":
            return

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        job.progress_pct = 0.0
        job.progress_stage = "Starting"
        db.commit()

        try:
            dataset = db.get(Dataset, job.dataset_id)
            if not dataset:
                raise ValueError("Dataset no longer exists")

            if job.task_type == "transformer_text_classification":
                _run_transformer_training(job, dataset)
            elif job.task_type == "transformer_text_generation":
                _run_generation_training(job, dataset)
            else:
                hp = job.hyperparameters_json or {}
                logger.warning(
                    "dispatch: task_type=%s auto_tune_requested=%s",
                    job.task_type, hp.get("_auto_tune_requested"),
                )
                if hp.get("_auto_tune_requested"):
                    _run_auto_tune(job, dataset)
                    db.commit()
                    db.refresh(job)
                _run_sklearn_training(job, dataset)

        except Exception as exc:  # noqa: BLE001 - report any failure back to the job row
            job.status = "failed"
            job.error_message = f"{exc}\n{traceback.format_exc(limit=3)}"
            job.progress_stage = "Failed"

        # Race guard: the API may have marked this job cancelled while we
        # were training. Do NOT call db.refresh(job) here - it would sync
        # the in-memory object with the DB row, discarding any in-flight
        # changes (including the "failed" status and error_message we just
        # set above). Query the current status with a separate SELECT
        # instead, leaving the pending changes on `job` untouched.
        from sqlalchemy import select

        current_status = db.execute(
            select(TrainingJob.status).where(TrainingJob.id == job.id)
        ).scalar()

        if current_status == "cancelled":
            # The API already set the final status; drop our changes.
            db.rollback()
            return

        job.finished_at = datetime.now(timezone.utc)
        if job.status == "completed":
            job.progress_pct = 100.0
            job.progress_stage = "Completed"
        db.commit()

        # Publish the terminal event so any SSE listener closes cleanly.
        from app.core import events

        events.publish_progress_sync(
            job.id,
            job.progress_pct,
            job.progress_stage,
            status=job.status,
        )

        if job.status == "completed":
            notification_service.notify_sync(
                db, job.org_id, "training_completed",
                f"Training completed: {job.name}",
                f"Job #{job.id} ({job.base_model or job.algorithm}) finished successfully.",
                {"job_id": job.id, "metrics": job.metrics_json},
            )
        elif job.status == "failed":
            notification_service.notify_sync(
                db, job.org_id, "training_failed",
                f"Training failed: {job.name}",
                f"Job #{job.id} failed: {job.error_message[:300] if job.error_message else 'see details in the UI'}",
                {"job_id": job.id},
            )
    finally:
        db.close()


@celery_app.task(name="training.train_model")
def train_model(job_id: int) -> None:
    """
    Celery entry point.

    In Docker mode, this launches an isolated container and waits for it
    to finish. In legacy mode (TRAINING_USE_DOCKER=false) it calls the
    training body directly in-process.
    """
    from app.core.config import settings

    if settings.TRAINING_USE_DOCKER:
        from app.services.docker_runner import run_job_in_container

        run_job_in_container(job_id)
    else:
        _train_model_sync(job_id)


