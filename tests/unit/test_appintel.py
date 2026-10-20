"""Application classifier artifact: abstention reasons and integrity (synthetic; software only)."""

import json

import numpy as np
import polars as pl
import pytest
from lightgbm import LGBMClassifier

from netsentinel.appintel.model import AppClassifier, load_classifier, save_classifier

FEATS = ["in_bytes", "out_bytes", "in_pkts", "out_pkts"]


def clf(threshold: float = 0.5) -> AppClassifier:
    rng = np.random.default_rng(0)
    X = np.vstack([rng.normal(100, 10, (200, 4)), rng.normal(5000, 100, (200, 4))])  # noqa: N806
    y = np.array(["dns"] * 200 + ["tls"] * 200)
    m = LGBMClassifier(n_estimators=20, num_leaves=7, min_child_samples=5, verbose=-1).fit(X, y)
    return AppClassifier(model=m, features=FEATS, classes=[str(c) for c in m.classes_],
                         feature_set="test", confidence_threshold=threshold,
                         ood_low=np.percentile(X, 0.5, axis=0),
                         ood_high=np.percentile(X, 99.5, axis=0))  # fmt: skip


def frame(rows):
    return pl.DataFrame(rows, schema=["protocol", *FEATS], orient="row")


def test_statuses_and_semantics():
    c = clf()
    out = c.predict(frame([
        (17, 100.0, 100.0, 100.0, 100.0),        # dns-like
        (6, 5000.0, 5000.0, 5000.0, 5000.0),     # tls-like
        (1, 100.0, 100.0, 100.0, 100.0),         # ICMP: unsupported
        (6, None, 100.0, 100.0, 100.0),          # missing feature
        (6, 1e9, 1e9, 1e9, 1e9),                 # far outside the training range
    ]))  # fmt: skip
    assert out["app_status"].to_list() == ["predicted", "predicted", "unsupported_protocol",
                                           "missing_features", "out_of_distribution"]  # fmt: skip
    assert out["app_protocol"].to_list()[:2] == ["dns", "tls"]
    assert out["app_protocol"].to_list()[2:] == [None, None, None]  # abstentions carry no label
    assert out["transport"].to_list() == ["udp", "tcp", "icmp", "tcp", "tcp"]


def test_low_confidence_abstains():
    out = clf(threshold=1.01).predict(frame([(17, 100.0, 100.0, 100.0, 100.0)]))
    assert out["app_status"].to_list() == ["low_confidence"] and out["app_protocol"][0] is None


def test_absent_column_is_missing_features():
    out = clf().predict(pl.DataFrame({"protocol": [6], "in_bytes": [100.0]}))
    assert out["app_status"].to_list() == ["missing_features"]


def test_artifact_integrity(tmp_path):
    path = save_classifier(clf(), tmp_path)
    loaded, mf = load_classifier(path)
    assert mf["application_identity"].startswith("not provided") and loaded.features == FEATS
    m = json.loads((path / "manifest.json").read_text())
    m["schema_version"] = "appintel-0"
    (path / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(ValueError, match="schema"):
        load_classifier(path)
    m["schema_version"] = mf["schema_version"]
    (path / "manifest.json").write_text(json.dumps(m))
    with open(path / "classifier.joblib", "ab") as fh:
        fh.write(b"x")
    with pytest.raises(ValueError, match="hash"):
        load_classifier(path)


def test_conservative_policy_combines_ml_and_port_evidence():
    from netsentinel.appintel.model import build_port_table, resolve_policy

    table = build_port_table(np.array([6] * 100 + [6] * 100 + [17] * 10),
                             np.array([80] * 100 + [5000] * 100 + [53] * 10),
                             np.array(["http"] * 99 + ["tls"] + ["http"] * 50 + ["tls"] * 50
                                      + ["dns"] * 10))  # fmt: skip
    assert table[6 * 65536 + 80] == {"label": "http", "purity": 0.99, "support": 100}
    ml = np.array(["http", "tls", "tls", None, "dns", "tls"], dtype=object)
    top = np.array(["http", "tls", "tls", "dns", "dns", "tls"], dtype=object)
    conf = np.array([0.99, 0.97, 0.97, 0.3, 0.9, 0.9])
    st = np.array(["predicted", "predicted", "predicted", "low_confidence", "predicted",
                   "unsupported_protocol"], dtype=object)  # fmt: skip
    proto = np.array([6, 6, 6, 6, 17, 1])
    port = np.array([80, 80, 5000, 9999, 53, 0])
    pol = {"min_purity": 0.9, "min_support": 50, "conflict": "unknown"}
    lab, meth, stat, ev = resolve_policy(ml, top, conf, st, proto, port, table, pol)
    # 0 ML agrees with port 80 -> http; 1 HTTP-on-80 called TLS -> conflict, abstain;
    # 2 port 5000 is mixed (not port-supported) -> ML; 3 low-confidence ML, no port support ->
    # abstain; 4 port 53 support 10 < 50 -> ML; 5 ICMP -> unsupported
    assert lab == ["http", None, "tls", None, "dns", None]
    assert meth == ["ml_port_agree", None, "ml", None, "ml", None]
    assert stat == ["predicted", "port_ml_conflict", "predicted", "low_confidence", "predicted",
                    "unsupported_protocol"]  # fmt: skip
    assert any(e.startswith("port:6/80->http") for e in ev[1])
    lab2, meth2, _, _ = resolve_policy(ml, top, conf, st, proto, port, table,
                                       {**pol, "conflict": "port"})  # fmt: skip
    assert lab2[1] == "http" and meth2[1] == "port_estimate"


def test_v1_artifact_without_port_table_still_loads_and_predicts(tmp_path):
    import json as _json

    path = save_classifier(clf(), tmp_path)
    m = _json.loads((path / "manifest.json").read_text())
    m["schema_version"] = "appintel-1.0.0"  # artifacts written in Phase 6
    (path / "manifest.json").write_text(_json.dumps(m))
    loaded, _ = load_classifier(path)
    out = loaded.predict(frame([(17, 100.0, 100.0, 100.0, 100.0)]))
    assert out["app_method"].to_list() == ["ml"] and out["app_protocol"][0] == "dns"
