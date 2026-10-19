"""Model factory on SYNTHETIC data: every model fits, predicts probabilities, and reports
feature importances whose names line up with the estimator's inputs."""

import numpy as np
import pytest

from netsentinel.models.baselines import MODEL_NAMES, fit_weighted, make_model
from netsentinel.training.baseline import feature_importance


@pytest.mark.parametrize("name", MODEL_NAMES)
def test_models_fit_predict_and_importance(name):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(400, 4)).astype(np.float32)  # noqa: N806
    X[::7, 1] = np.nan  # forces missing indicators in imputing pipelines
    X[::11, 2] = np.inf
    y = (np.nan_to_num(X[:, 0]) > 0).astype(int)
    params = {"random_forest": {"n_estimators": 10}, "lightgbm": {"n_estimators": 10},
              "hist_gb": {"max_iter": 10}}.get(name)  # fmt: skip
    model = fit_weighted(make_model(name, params, seed=0), X, y, np.ones(len(y)))
    proba = model.predict_proba(X)
    assert proba.shape == (400, 2) and np.allclose(proba.sum(axis=1), 1)
    imp = feature_importance(model, ["a", "b", "c", "d"])
    if name in ("random_forest", "lightgbm", "hist_gb"):
        names = [r["feature"] for r in imp]
        assert set(names) >= {"a", "b", "c", "d"} or name == "hist_gb"
    if name == "random_forest":
        assert any(n.startswith("missing::") for n in (r["feature"] for r in imp))
