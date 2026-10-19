"""Classical model factory. Every model is an sklearn estimator/Pipeline so preprocessing is
fit on the training split only, and all of them accept `sample_weight` in `fit`."""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


class FiniteSignedLog(BaseEstimator, TransformerMixin):
    """inf -> NaN, then sign(x) * log1p(|x|). Stateless; tames heavy-tailed rates/byte counts
    for linear models (trees are invariant to it and do not use it)."""

    def fit(self, X, y=None):  # noqa: N803 - sklearn convention
        return self

    def transform(self, X):  # noqa: N803
        X = np.asarray(X, dtype=np.float64).copy()
        X[~np.isfinite(X)] = np.nan
        return np.sign(X) * np.log1p(np.abs(X))


class InfToNaN(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):  # noqa: N803
        return self

    def transform(self, X):  # noqa: N803
        X = np.asarray(X, dtype=np.float32).copy()
        X[~np.isfinite(X)] = np.nan
        return X


MODEL_NAMES = ("dummy", "logreg", "random_forest", "hist_gb", "lightgbm")


def make_model(name: str, params: dict[str, Any] | None = None, seed: int = 42):
    params = dict(params or {})
    if name == "dummy":
        return DummyClassifier(strategy=params.pop("strategy", "prior"), **params)
    if name == "logreg":
        return Pipeline(
            [
                ("log", FiniteSignedLog()),
                ("impute", SimpleImputer(strategy="median", add_indicator=True)),
                ("scale", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=params.pop("max_iter", 500),
                        C=params.pop("C", 1.0),
                        class_weight=params.pop("class_weight", "balanced"),
                        random_state=seed,
                        **params,
                    ),
                ),
            ]
        )
    if name == "random_forest":
        return Pipeline(
            [
                ("finite", InfToNaN()),
                ("impute", SimpleImputer(strategy="median", add_indicator=True)),
                (
                    "clf",
                    RandomForestClassifier(
                        n_estimators=params.pop("n_estimators", 200),
                        max_depth=params.pop("max_depth", 20),
                        min_samples_leaf=params.pop("min_samples_leaf", 2),
                        class_weight=params.pop("class_weight", "balanced_subsample"),
                        n_jobs=params.pop("n_jobs", 2),
                        random_state=seed,
                        **params,
                    ),
                ),
            ]
        )
    if name == "hist_gb":
        return Pipeline(
            [
                ("finite", InfToNaN()),
                (
                    "clf",
                    HistGradientBoostingClassifier(
                        max_iter=params.pop("max_iter", 300),
                        learning_rate=params.pop("learning_rate", 0.1),
                        class_weight=params.pop("class_weight", "balanced"),
                        early_stopping=False,
                        random_state=seed,
                        **params,
                    ),
                ),
            ]
        )
    if name == "lightgbm":
        from lightgbm import LGBMClassifier

        return Pipeline(
            [
                ("finite", InfToNaN()),
                (
                    "clf",
                    LGBMClassifier(
                        n_estimators=params.pop("n_estimators", 400),
                        learning_rate=params.pop("learning_rate", 0.05),
                        num_leaves=params.pop("num_leaves", 63),
                        min_child_samples=params.pop("min_child_samples", 50),
                        subsample=params.pop("subsample", 0.8),
                        subsample_freq=1,
                        colsample_bytree=params.pop("colsample_bytree", 0.8),
                        class_weight=params.pop("class_weight", "balanced"),
                        n_jobs=params.pop("n_jobs", 2),
                        random_state=seed,
                        deterministic=True,
                        force_row_wise=True,
                        verbose=-1,
                        **params,
                    ),
                ),
            ]
        )
    raise ValueError(f"unknown model {name!r}; choose from {MODEL_NAMES}")


def fit_weighted(model, X, y, sample_weight=None):
    """Fit and route `sample_weight` to the final step of a Pipeline."""
    if sample_weight is None:
        return model.fit(X, y)
    if isinstance(model, Pipeline):
        return model.fit(X, y, **{f"{model.steps[-1][0]}__sample_weight": sample_weight})
    return model.fit(X, y, sample_weight=sample_weight)
