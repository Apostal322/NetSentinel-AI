import polars as pl

from netsentinel.features.schema import SCALE_INVARIANT_MARKERS, feature_set
from netsentinel.training.data import clean_labels


def _df():
    return pl.DataFrame(
        {
            "label": ["ssh_bruteforce", "ssh_bruteforce", "web_xss", "web_xss", "benign"],
            "protocol": [6, 6, 6, 17, 6],
            "dst_port": [22, 21, 80, 500, 21],
        }
    )


def test_clean_labels_v1_keeps_off_port_ssh_v2_drops_it():
    v1, d1 = clean_labels(_df(), 1)
    v2, d2 = clean_labels(_df(), 2)
    assert d1 == {"web_xss": 1} and v1.height == 4
    assert d2 == {"web_xss": 1, "ssh_bruteforce": 1} and v2.height == 3
    assert v2.filter(pl.col("label") == "benign").height == 1  # benign never dropped


def test_context_ablation_sets_partition_the_context_features():
    flow = set(feature_set("flow"))
    inv = set(feature_set("flow_ctx_inv")) - flow
    absolute = set(feature_set("flow_ctx_abs")) - flow
    full = set(feature_set("flow_ctx")) - flow
    assert inv | absolute == full and not (inv & absolute)
    assert all(any(m in c for m in SCALE_INVARIANT_MARKERS) for c in inv)
    assert not any("rate" in c and "surge" not in c for c in inv)
