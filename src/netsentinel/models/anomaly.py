"""Normal-behaviour models and the 0-100 anomaly score.

What the score measures: `score = 100 * F_ref(raw)`, where `raw` is a model's anomaly score
(higher = more unusual) and `F_ref` is the empirical CDF of `raw` on a *reference set of benign
flows held out from the training split* (20 % of benign train rows, never used to fit the
detector; per service category for the conditioned model). A score of 99.5 means "more
unusual than 99.5 % of benign reference flows of the same context". Consequences:
* It is a benign-tail rank, NOT a probability of attack, and not calibrated as one.
* Thresholds on it map directly to an expected benign alert rate: score >= 99.9 flags about
  0.1 % of benign reference traffic (if the reference is representative).
* Scores are comparable across service contexts in that benign-tail sense only.
* The reference must be refreshed when traffic drifts; the score changes when the reference or
  the underlying model changes (both are versioned in the artifact).
Models are fit on benign TRAIN flows only (normal-behaviour modelling); attack labels are used
only for evaluation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from netsentinel.models.baselines import FiniteSignedLog

log = logging.getLogger(__name__)


class EmpiricalScorer:
    """Map raw anomaly scores to [0, 100) via the benign reference CDF.

    score = 100 * (k + tail) / (n + 1), where k = number of reference values <= raw and, above
    the reference maximum, tail = 1 - exp(-(raw - max) / s) with s = spread of the top 1 % of
    the reference. The score is strictly increasing beyond the reference maximum (so drifted
    traffic does not tie at 100); it reaches 100 only when exp() underflows for extreme outliers."""

    def __init__(self, reference_raw: np.ndarray, max_points: int = 20_000):
        ref = np.sort(np.asarray(reference_raw, dtype=np.float64))
        if len(ref) == 0:
            raise ValueError("empty reference set")
        if len(ref) > max_points:  # keep artifacts small; quantiles are enough
            ref = np.quantile(ref, np.linspace(0, 1, max_points))
        self.ref = ref
        top = ref[int(0.99 * (len(ref) - 1)) :]
        spread = float(top[-1] - top[0])
        self.tail_scale = spread if spread > 1e-12 else max(abs(float(ref[-1])), 1.0)

    def __call__(self, raw: np.ndarray) -> np.ndarray:
        raw = np.asarray(raw, dtype=np.float64)
        n = len(self.ref)
        k = np.searchsorted(self.ref, raw, side="right").astype(np.float64)
        excess = np.maximum(raw - self.ref[-1], 0.0)
        tail = np.where(raw > self.ref[-1], 1.0 - np.exp(-excess / self.tail_scale), 0.0)
        return 100.0 * (k + tail) / (n + 1)


class RobustZ:
    """Interpretable baseline: max over features of |x - median| / scale after a signed-log
    transform, scale = max(1.4826 * MAD, scale_floor). Also returns per-feature z for evidence.

    v2 (audit 2026-10-19): v1 used scale = MAD (nan if < 1e-9) and clipped z at 50. Within one
    service context many features are nearly constant, so MAD ~ 0, z explodes, and 15-19 % of
    benign validation flows tied at the cap - the conditioned variant had zero recall at every
    FPR and could not flag injected outliers. The floor (in signed-log units; 0.25 ~ a factor
    of 1.28) bounds z for near-constant features while keeping them informative, and no cap is
    applied, so larger deviations always score higher."""

    def __init__(self, scale_floor: float = 0.25):
        self.scale_floor = scale_floor

    def fit(self, X: np.ndarray) -> RobustZ:  # noqa: N803
        Z = FiniteSignedLog().transform(X)  # noqa: N806
        self.median_ = np.nan_to_num(np.nanmedian(Z, axis=0), nan=0.0)
        mad = np.nan_to_num(np.nanmedian(np.abs(Z - self.median_), axis=0) * 1.4826, nan=0.0)
        self.scale_ = np.maximum(mad, self.scale_floor)
        return self

    def feature_z(self, X: np.ndarray) -> np.ndarray:  # noqa: N803
        Z = FiniteSignedLog().transform(X)  # noqa: N806
        z = np.abs(Z - self.median_) / self.scale_
        return np.nan_to_num(z, nan=0.0)

    def score(self, X: np.ndarray) -> np.ndarray:  # noqa: N803
        return self.feature_z(X).max(axis=1)


class IForest:
    def __init__(self, seed: int = 42, n_estimators: int = 200, max_samples: int = 512):
        from sklearn.ensemble import IsolationForest

        self.model = IsolationForest(
            n_estimators=n_estimators, max_samples=max_samples, random_state=seed, n_jobs=2
        )

    def _prep(self, X):  # noqa: N803
        Z = FiniteSignedLog().transform(X)  # noqa: N806
        return np.nan_to_num(Z, nan=0.0)

    def fit(self, X):  # noqa: N803
        self.model.fit(self._prep(X))
        return self

    def score(self, X):  # noqa: N803
        return -self.model.score_samples(self._prep(X))  # higher = more anomalous


def make_detector(kind: str, seed: int, params: dict[str, Any] | None = None):
    params = dict(params or {})
    if kind == "robust_z":
        return RobustZ()
    if kind == "iforest":
        return IForest(seed=seed, **params)
    raise ValueError(f"unknown detector {kind!r}")


@dataclass
class ConditionedAnomalyModel:
    """Global or service-conditioned detector with per-context benign reference scorers.

    `conditioned=False` -> one global model. `conditioned=True` -> one model per context with at
    least `min_rows` benign training flows; other contexts fall back to the global model (and its
    global reference), which is recorded per prediction in `used_context`."""

    kind: str = "iforest"
    conditioned: bool = False
    min_rows: int = 2000
    seed: int = 42
    params: dict[str, Any] = field(default_factory=dict)

    def fit(self, X: np.ndarray, ctx: np.ndarray, X_ref: np.ndarray, ctx_ref: np.ndarray):  # noqa: N803
        self.models_: dict[str, Any] = {}
        self.scorers_: dict[str, EmpiricalScorer] = {}
        self.models_["__global__"] = make_detector(self.kind, self.seed, self.params).fit(X)
        self.scorers_["__global__"] = EmpiricalScorer(self.models_["__global__"].score(X_ref))
        if self.conditioned:
            for c in np.unique(ctx):
                m_tr, m_ref = ctx == c, ctx_ref == c
                if m_tr.sum() < self.min_rows or m_ref.sum() < max(50, self.min_rows // 20):
                    continue
                det = make_detector(self.kind, self.seed, self.params).fit(X[m_tr])
                self.models_[c] = det
                self.scorers_[c] = EmpiricalScorer(det.score(X_ref[m_ref]))
        log.info("anomaly model %s conditioned=%s contexts=%s", self.kind, self.conditioned,
                 sorted(k for k in self.models_ if k != "__global__"))  # fmt: skip
        return self

    def score(self, X: np.ndarray, ctx: np.ndarray) -> tuple[np.ndarray, np.ndarray]:  # noqa: N803
        """Return (0-100 score, context actually used)."""
        out = np.empty(len(X), dtype=np.float64)
        used = np.full(len(X), "__global__", dtype=object)
        keys = np.where(np.isin(ctx, list(self.models_)), ctx, "__global__")
        for k in np.unique(keys):
            m = keys == k
            out[m] = self.scorers_[k](self.models_[k].score(X[m]))
            used[m] = k
        return out, used.astype(str)
