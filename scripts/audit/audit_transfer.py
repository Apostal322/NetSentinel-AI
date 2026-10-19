"""Mission 1: quantify why NF-IDS2018 <-> NF-UNSW-NB15 transfer fails.

Uses TRAIN + VALIDATION rows of both processed NF datasets (test protected) and the interim
per-day files for topology statistics. Outputs reports/audit/transfer.json and figures.

1. Covariate shift, benign vs benign: KS statistic, PSI (deciles of the source), null and zero
   shares, quantiles - per feature.
2. Semantic consistency of shared fields: identities that must hold if the fields mean the same
   thing in both datasets (IAT units, rate definitions, packet-size bounds, timeouts).
3. Class-conditional direction: per-feature ROC-AUC attack vs benign within each dataset; a
   feature whose AUC is on opposite sides of 0.5 in the two datasets pushes transfer below chance.
4. Domain classifier: LightGBM separating IDS2018-benign from UNSW-benign (5-fold, grouped by
   day) - AUC ~1 means the benign domains are trivially distinguishable.
5. Label taxonomy overlap and topology (distinct hosts, private-address share, port diversity).

Usage: uv run python scripts/audit/audit_transfer.py
"""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from netsentinel.features.context import context_feature_names  # noqa: E402
from netsentinel.features.nf_schema import NF_FLOW_COLUMNS  # noqa: E402

DS = {"ids": "nf_cicids2018_v3", "unsw": "nf_unsw_nb15_v3"}
OUT = ROOT / "reports/audit"
FIG = ROOT / "reports/figures"
FEATS = [*NF_FLOW_COLUMNS, *context_feature_names()]


def load(name: str) -> pl.DataFrame:
    """Processed rows minus the test split (episode protocol, seed 42 - as in batch v4)."""
    from netsentinel.training.data import prepare

    cfg = {"seed": 42, "feature_set": "nf_flow_ctx", "task": "binary",
           "data": {"processed_dir": f"data/processed/{name}", "drop_labels": ["infiltration"],
                    "clean_labels": 2 if name.startswith("nf_cic") else 0},
           "split": {"protocol": "episode", "block_minutes": 30, "purge_seconds": 150,
                     "fractions": [0.6, 0.2, 0.2]}}  # fmt: skip
    prep = prepare(cfg)
    return prep.frame.filter(pl.col("split") != "test").select(
        "day", "label", "family", "dst_port", "protocol", *FEATS
    )


def slog(x: np.ndarray) -> np.ndarray:
    x = np.nan_to_num(x.astype(np.float64), nan=np.nan, posinf=np.nan, neginf=np.nan)
    return np.sign(x) * np.log1p(np.abs(x))


def ks(a: np.ndarray, b: np.ndarray) -> float:
    a, b = np.sort(a[~np.isnan(a)]), np.sort(b[~np.isnan(b)])
    if not len(a) or not len(b):
        return float("nan")
    grid = np.unique(np.r_[a, b])
    return float(np.max(np.abs(np.searchsorted(a, grid, "right") / len(a)
                              - np.searchsorted(b, grid, "right") / len(b))))  # fmt: skip


def psi(src: np.ndarray, tgt: np.ndarray) -> float:
    src, tgt = src[~np.isnan(src)], tgt[~np.isnan(tgt)]
    if not len(src) or not len(tgt):
        return float("nan")
    edges = np.unique(np.quantile(src, np.linspace(0, 1, 11)))
    if len(edges) < 3:
        return float("nan")
    p = np.histogram(np.clip(src, edges[0], edges[-1]), edges)[0] / len(src) + 1e-6
    q = np.histogram(np.clip(tgt, edges[0], edges[-1]), edges)[0] / len(tgt) + 1e-6
    return float(np.sum((p - q) * np.log(p / q)))


def auc(score: np.ndarray, y: np.ndarray) -> float:
    from sklearn.metrics import roc_auc_score

    m = ~np.isnan(score)
    if len(np.unique(y[m])) < 2:
        return float("nan")
    return float(roc_auc_score(y[m], score[m]))


def semantics(df: pl.DataFrame) -> dict:
    """Share of rows satisfying identities that should hold under one field semantics."""
    d = df.filter(pl.col("in_pkts") > 2)
    dur_s = pl.col("flow_duration_milliseconds") / 1000
    out = {
        # IAT in ms: mean IAT * (pkts - 1) ~ client-side duration (within 20 % or 5 ms)
        "iat_avg_x_pkts_matches_duration_in": d.select(
            ((pl.col("src_to_dst_iat_avg") * (pl.col("in_pkts") - 1) - pl.col("duration_in")).abs()
             <= pl.max_horizontal(5, 0.2 * pl.col("duration_in"))).mean()).item(),
        # bytes/s field ~ in_bytes / duration (only flows >= 1 s)
        "second_bytes_matches_bytes_per_s": df.filter(dur_s >= 1).select(
            ((pl.col("src_to_dst_second_bytes") - pl.col("in_bytes") / dur_s).abs()
             <= 0.2 * (pl.col("in_bytes") / dur_s) + 1).mean()).item(),
        # throughput in bit/s ~ 8 * bytes / duration
        "throughput_matches_8x_bytes_per_s": df.filter(dur_s >= 1).select(
            ((pl.col("src_to_dst_avg_throughput") - 8 * pl.col("in_bytes") / dur_s).abs()
             <= 0.2 * (8 * pl.col("in_bytes") / dur_s) + 8).mean()).item(),
        # packet length bounds
        "max_pkt_ge_mean_pkt": df.filter(pl.col("in_pkts") > 0).select(
            (pl.col("longest_flow_pkt") >= pl.col("in_bytes") / pl.col("in_pkts") - 1).mean()).item(),
        "size_bins_sum_eq_pkts": df.select(
            ((pl.sum_horizontal([c for c in NF_FLOW_COLUMNS if c.startswith("num_pkts_")])
              - pl.col("in_pkts") - pl.col("out_pkts")).abs() <= 1).mean()).item(),
        "duration_in_le_duration": df.select(
            (pl.col("duration_in") <= pl.col("flow_duration_milliseconds") + 1).mean()).item(),
        "zero_duration_share": df.select((pl.col("flow_duration_milliseconds") == 0).mean()).item(),
        "single_packet_flow_share": df.select(
            ((pl.col("in_pkts") + pl.col("out_pkts")) <= 1).mean()).item(),
        "duration_p99_ms": float(df["flow_duration_milliseconds"].quantile(0.99)),
        "duration_max_ms": float(df["flow_duration_milliseconds"].max()),
        "share_duration_ge_119s": df.select(
            (pl.col("flow_duration_milliseconds") >= 119_000).mean()).item(),
        "tcp_share": df.select((pl.col("protocol") == 6).mean()).item(),
        "udp_share": df.select((pl.col("protocol") == 17).mean()).item(),
        "distinct_dst_ports": df["dst_port"].n_unique(),
    }  # fmt: skip
    return {k: float(v) if not isinstance(v, (int, float)) else v for k, v in out.items()}


def topology(name: str) -> dict:
    lf = pl.concat([pl.scan_parquet(p).select("ipv4_src_addr", "ipv4_dst_addr", "label")
                    for p in sorted((ROOT / f"data/interim/{name}").glob("[0-9]*.parquet"))])  # fmt: skip
    src = lf.select(pl.col("ipv4_src_addr").unique()).collect()["ipv4_src_addr"].to_list()
    dst = lf.select(pl.col("ipv4_dst_addr").unique()).collect()["ipv4_dst_addr"].to_list()
    att_src = (lf.filter(pl.col("label") != "benign").select(pl.col("ipv4_src_addr").unique())
               .collect()["ipv4_src_addr"].to_list())  # fmt: skip

    def private_share(ips):
        ok = [ipaddress.ip_address(i).is_private for i in ips if i]
        return float(np.mean(ok)) if ok else float("nan")

    return {"distinct_src": len(src), "distinct_dst": len(dst),
            "src_private_share": private_share(src), "dst_private_share": private_share(dst),
            "distinct_attack_src": len(att_src),
            "attack_src_private_share": private_share(att_src)}  # fmt: skip


def domain_classifier(a: pl.DataFrame, b: pl.DataFrame, feats: list[str]) -> dict:
    from lightgbm import LGBMClassifier
    from sklearn.model_selection import GroupKFold

    n = min(a.height, b.height, 60_000)
    da, db = a.sample(n=n, seed=0), b.sample(n=n, seed=0)
    X = np.r_[da.select(feats).to_numpy(), db.select(feats).to_numpy()].astype(np.float32)  # noqa: N806
    y = np.r_[np.zeros(n), np.ones(n)]
    groups = np.r_[da["day"].to_numpy(), db["day"].to_numpy()]
    scores, imps = [], np.zeros(len(feats))
    for tr, te in GroupKFold(n_splits=3).split(X, y, groups):
        m = LGBMClassifier(n_estimators=100, num_leaves=31, verbose=-1, random_state=0)
        m.fit(X[tr], y[tr])
        scores.append(auc(m.predict_proba(X[te])[:, 1], y[te]))
        imps += m.booster_.feature_importance("gain")
    order = np.argsort(-imps)[:10]
    return {"auc_per_fold": scores, "top_features": [feats[i] for i in order]}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    data = {k: load(v) for k, v in DS.items()}
    ben = {k: d.filter(pl.col("label") == "benign") for k, d in data.items()}
    shift = []
    for f in FEATS:
        a = slog(ben["ids"][f].to_numpy())
        b = slog(ben["unsw"][f].to_numpy())
        ya = (data["ids"]["label"] != "benign").to_numpy().astype(int)
        yb = (data["unsw"]["label"] != "benign").to_numpy().astype(int)
        auc_a = auc(slog(data["ids"][f].to_numpy()), ya)
        auc_b = auc(slog(data["unsw"][f].to_numpy()), yb)
        shift.append({
            "feature": f, "ks_benign": ks(a, b), "psi_benign_ids_to_unsw": psi(a, b),
            "null_share_ids": float(np.isnan(a).mean()), "null_share_unsw": float(np.isnan(b).mean()),
            "zero_share_ids": float((a == 0).mean()), "zero_share_unsw": float((b == 0).mean()),
            "median_ids": float(np.nanmedian(a)) if not np.isnan(a).all() else None,
            "median_unsw": float(np.nanmedian(b)) if not np.isnan(b).all() else None,
            "auc_attack_ids": auc_a, "auc_attack_unsw": auc_b,
            "direction_conflict": bool(not np.isnan(auc_a) and not np.isnan(auc_b)
                                       and (auc_a - 0.5) * (auc_b - 0.5) < 0
                                       and abs(auc_a - 0.5) > 0.1 and abs(auc_b - 0.5) > 0.1),
        })  # fmt: skip
    shift.sort(key=lambda r: -(r["ks_benign"] if not np.isnan(r["ks_benign"]) else -1))
    result = {
        "rows": {k: d.height for k, d in data.items()},
        "attack_labels": {k: d.filter(pl.col("label") != "benign")["label"].unique().sort().to_list()
                          for k, d in data.items()},  # fmt: skip
        "family_overlap": sorted(set(data["ids"]["family"]) & set(data["unsw"]["family"])),
        "semantics": {k: semantics(d) for k, d in data.items()},
        "topology": {k: topology(v) for k, v in DS.items()},
        "domain_classifier_benign": domain_classifier(ben["ids"], ben["unsw"], FEATS),
        "domain_classifier_benign_portable": domain_classifier(
            ben["ids"], ben["unsw"],
            ["in_bytes", "in_pkts", "out_bytes", "out_pkts", "flow_duration_milliseconds"]),
        "feature_shift": shift,
        "share_features_ks_gt_0_3": float(np.mean([r["ks_benign"] > 0.3 for r in shift])),
        "direction_conflicts": [r["feature"] for r in shift if r["direction_conflict"]],
    }  # fmt: skip
    (OUT / "transfer.json").write_text(json.dumps(result, indent=2, default=str), "utf-8")
    plot(shift)
    print(json.dumps({k: v for k, v in result.items() if k != "feature_shift"}, indent=2,
                     default=str))  # fmt: skip
    for r in shift[:15]:
        print(f"{r['feature']:32s} KS={r['ks_benign']:.3f} PSI={r['psi_benign_ids_to_unsw']:.2f} "
              f"AUC ids={r['auc_attack_ids']:.2f} unsw={r['auc_attack_unsw']:.2f}"
              f"{'  CONFLICT' if r['direction_conflict'] else ''}")  # fmt: skip


def plot(shift: list[dict]) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = [
        r for r in shift if not np.isnan(r["auc_attack_ids"]) and not np.isnan(r["auc_attack_unsw"])
    ]
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    top = shift[:25][::-1]
    axes[0].barh([r["feature"] for r in top], [r["ks_benign"] for r in top], color="#4C72B0")
    axes[0].set_xlabel("KS statistic, benign IDS2018 vs benign UNSW-NB15")
    axes[0].set_title("Largest benign covariate shifts (25)", fontsize=10)
    axes[0].tick_params(axis="y", labelsize=6)
    x = [r["auc_attack_ids"] for r in rows]
    y = [r["auc_attack_unsw"] for r in rows]
    c = ["#C44E52" if r["direction_conflict"] else "#8C8C8C" for r in rows]
    axes[1].scatter(x, y, c=c, s=14)
    axes[1].axhline(0.5, color="k", lw=0.5)
    axes[1].axvline(0.5, color="k", lw=0.5)
    axes[1].set_xlabel("per-feature AUC attack vs benign, IDS2018")
    axes[1].set_ylabel("per-feature AUC attack vs benign, UNSW-NB15")
    axes[1].set_title("Direction of class effects (red = opposite, |AUC-0.5|>0.1)", fontsize=10)
    fig.tight_layout()
    FIG.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG / "transfer_shift.png", dpi=140)
    plt.close(fig)


if __name__ == "__main__":
    main()
