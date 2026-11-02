"""Phase 8i shared code (docs/phase8i/PREREGISTRATION.md sections 2-3).

Domain loading, network-balanced source training, representations (raw, no-volume, C1 feature
removal, C2 relative volume), the T0 threshold and window/entity metrics (Phase 8h `metrics`).
Pure helpers (`draw_pool`, `network_weights`, `relative_volume`, `blocks`, `risk_coverage`) are
unit-tested in tests/unit/test_phase8i_calc.py.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8b"))
sys.path.insert(0, str(ROOT / "scripts" / "phase8h"))
import lodo as L  # noqa: E402, N812
import scorers as S  # noqa: E402, N812

from netsentinel.behavior.profile import conformal_threshold  # noqa: E402

FEATS = S.FEATS
VOLUME = ["log_flows", "log_up_bytes", "log_down_bytes", "log_pkts"]
VOL_IDX = [FEATS.index(f) for f in VOLUME]
ALPHA = 0.01
CAP = 50_000  # training windows per source domain (section 3)
NEG_CAP = 20_000  # target benign-train negatives for the label-budget models (amendment A1)
DERIVED = Path("data/derived/phase8i")
DEV_NETWORKS = ("nfcic", "nfunsw", "nfton")
PRIMARY_N1 = ["2018-02-14", "2018-02-16", "2018-02-20", "2018-02-21", "2018-03-02"]
SECONDARY_N1 = ["2018-02-22"]
LGB = dict(n_estimators=200, learning_rate=0.05, num_leaves=15, min_child_samples=20,
           subsample=0.8, subsample_freq=1, colsample_bytree=0.8, n_jobs=2, verbose=-1)  # fmt: skip


# ----------------------------------------------------------------------------- data
def load_domain(d: Path, network: str) -> dict:
    ev = pl.read_parquet(d / "eval_clean.parquet").sort("win", "key")
    tr = pl.read_parquet(d / "truth.parquet").select("key", "win", "y")
    ev = ev.join(tr, on=["key", "win"], how="left").with_columns(pl.col("y").fill_null(False))
    noisy = d / "noisy.parquet"
    if noisy.exists():
        nz = pl.read_parquet(noisy).with_columns(pl.lit(True).alias("noisy"))
        ev = ev.join(nz, on=["key", "win"], how="left")
    ev = ev.with_columns(pl.col("noisy").fill_null(False) if "noisy" in ev.columns
                         else pl.lit(False).alias("noisy"))  # fmt: skip
    ev = ev.with_columns((pl.col("y") & ~pl.col("noisy")).alias("y"))
    ct_path = d / "cal_truth.parquet"
    ct = pl.read_parquet(ct_path) if ct_path.exists() else pl.DataFrame(
        schema={"key": pl.Utf8, "win": pl.Int64, "y": pl.Boolean})  # fmt: skip
    attackers = set(ev.filter(pl.col("y"))["key"].unique().to_list())
    cal_attackers = set(ct.filter(pl.col("y"))["key"].unique().to_list())
    every = attackers | cal_attackers
    ev = ev.with_columns((~pl.col("key").is_in(list(every)) & ~pl.col("noisy")).alias("benign"))
    meta = json.loads((d / "meta.json").read_text("utf-8"))
    # benign calibration: clean windows of entities that never attack in the domain (section 2)
    cal = pl.read_parquet(d / "cal_clean.parquet").filter(~pl.col("key").is_in(list(every)))
    cal = cal.sort("win", "key")
    pool = pl.DataFrame()
    if ct.height and (d / "cal_unlabelled.parquet").exists():
        pool = (pl.read_parquet(d / "cal_unlabelled.parquet")
                .join(ct.filter(pl.col("y")).select("key", "win"), on=["key", "win"])
                .sort("win", "key"))  # fmt: skip
    first = {k: v for k, v in (meta.get("first_attack_ms") or {}).items() if k in attackers}
    return {"network": network, "name": d.name, "cal": cal, "ev": ev, "pool": pool,
            "attackers": attackers, "hours": meta.get("eval_hours") or 0.0,
            "first_attack": first}  # fmt: skip


def load_network(network: str, root: Path = DERIVED) -> dict[str, dict]:
    out = {}
    for d in sorted((root / network).iterdir()):
        if (d / "meta.json").exists():
            dom = load_domain(d, network)
            if dom["cal"].height >= 60 and dom["ev"].height >= 60:
                out[f"{network}/{d.name}"] = dom
    return out


def split_benign(d: dict) -> tuple[pl.DataFrame, pl.DataFrame]:
    """(benign-train, threshold hold-out) = first 70% / last 30% of the calibration slots."""
    cal = d["cal"]
    cut = S.split_cut(cal)
    return cal.filter(pl.col("win") < cut), cal.filter(pl.col("win") >= cut)


def attack_eligible(d: dict) -> bool:
    if not d["attackers"]:
        return False
    per = d["ev"].filter(pl.col("y")).group_by("key").len()
    return bool((per["len"] >= 5).any())


# ----------------------------------------------------------------------------- representations
def relative_volume(x: np.ndarray, ref_median: np.ndarray) -> np.ndarray:
    """C2: volume columns minus the domain's benign-train median; other columns unchanged."""
    out = x.copy()
    out[:, VOL_IDX] = out[:, VOL_IDX] - ref_median[None, :]
    return out


def volume_median(benign_train: pl.DataFrame) -> np.ndarray:
    x = S._x(benign_train)
    return np.median(x[:, VOL_IDX], axis=0) if len(x) else np.zeros(len(VOL_IDX))


class Rep:
    """A feature representation: column subset and optional relative-volume transform."""

    def __init__(self, name: str, keep: list[int] | None = None, relvol: bool = False):
        self.name, self.keep, self.relvol = name, keep, relvol

    def apply(self, x: np.ndarray, d: dict) -> np.ndarray:
        if self.relvol:
            x = relative_volume(x, d["_volmed"])
        return x if self.keep is None else x[:, self.keep]


def prepare(d: dict) -> dict:
    """Cache the benign split and the C2 reference median on the domain."""
    if "_btrain" not in d:
        d["_btrain"], d["_hold"] = split_benign(d)
        d["_volmed"] = volume_median(d["_btrain"])
    return d


# ----------------------------------------------------------------------------- training
def network_weights(networks: list[str]) -> np.ndarray:
    """Per-domain weight: each network gets equal total weight, split equally over its
    domains (section 3). `networks` lists each source domain's network."""
    nets = sorted(set(networks))
    count = {n: networks.count(n) for n in nets}
    return np.array([1.0 / (len(nets) * count[n]) for n in networks])


def source_matrix(d: dict, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Raw X and y of a source domain: benign calibration + evaluation (Phase 8h train_matrix
    with the Phase 8i cap and strict benign calibration)."""
    saved = L.CAP
    L.CAP = CAP
    try:
        x, _, y = L.train_matrix(d, seed)
    finally:
        L.CAP = saved
    return x, y


def fit_source(sources: dict[str, dict], seed: int, rep: Rep):
    import lightgbm as lgb

    names = list(sources)
    dw = network_weights([sources[n]["network"] for n in names])
    xs, ys, ws = [], [], []
    for n, w_dom in zip(names, dw, strict=True):
        d = prepare(sources[n])
        x, y = source_matrix(d, seed)
        xs.append(rep.apply(x, d))
        ys.append(y)
        ws.append(w_dom * np.where(y == 1, 0.5 / max(y.sum(), 1), 0.5 / max((y == 0).sum(), 1)))
    X, y, w = np.vstack(xs), np.concatenate(ys), np.concatenate(ws)  # noqa: N806
    m = lgb.LGBMClassifier(random_state=seed, **LGB).fit(X, y, sample_weight=w * len(y) / w.sum())
    neg = m.predict_proba(X[y == 0])[:, 1] if (y == 0).any() else np.array([0.0])
    return m, float(np.quantile(neg, 1 - ALPHA)), len(y)


# ----------------------------------------------------------------------------- evaluation
def t0(scores_hold: np.ndarray) -> tuple[float, bool]:
    return conformal_threshold(scores_hold, ALPHA)


def evaluate(d: dict, s_ev: np.ndarray, thr: float) -> dict:
    out = L.metrics(d, s_ev, s_ev > thr)
    out["threshold"] = float(thr)
    return out


def draw_pool(pool_keys: np.ndarray, ka: int, draw: int,
              single_entity: bool = False) -> np.ndarray:  # fmt: skip
    """Indices of `ka` labelled attack windows (uniform without replacement; or all from one
    random attacker). Returns all indices when the pool (or entity) is smaller than ka."""
    rng = np.random.default_rng(1_000_003 * draw + ka + (7 if single_entity else 0))
    idx = np.arange(len(pool_keys))
    if single_entity and len(idx):
        ents = np.unique(pool_keys)
        idx = idx[pool_keys == ents[rng.integers(len(ents))]]
    if len(idx) <= ka:
        return idx
    return np.sort(rng.choice(idx, ka, replace=False))


def blocks(win_end_ms: np.ndarray, start_ms: int, hours: float = 1.0) -> np.ndarray:
    """Block index of each window (hours since `start_ms`); -1 before the start."""
    b = np.floor((win_end_ms - start_ms) / (hours * 3.6e6)).astype(int)
    return np.where(win_end_ms < start_ms, -1, b)


def risk_coverage(score: np.ndarray, overrun: np.ndarray,
                  coverages=(0.2, 0.4, 0.6, 0.8, 1.0)) -> list[dict]:  # fmt: skip
    """Exceedance rate among the `c` share of units with the LOWEST shift score."""
    order = np.argsort(score, kind="stable")
    out = []
    for c in coverages:
        n = max(1, int(math.floor(c * len(score) + 1e-9)))
        cov = overrun[order[:n]]
        out.append({"coverage": n / len(score), "n": n, "exceedance": float(cov.mean())})
    return out


def auc(score: np.ndarray, y: np.ndarray) -> float | None:
    from sklearn.metrics import roc_auc_score

    return float(roc_auc_score(y, score)) if 0 < y.sum() < len(y) else None


def confirm_args(ap) -> None:
    ap.add_argument("--confirm", action="store_true", help="the protected N4 evaluation")
    ap.add_argument("--stand-in", help="code dry run of --confirm with a DEVELOPMENT network as the "
                    "target (output must go under reports/phase8i/smoke)")  # fmt: skip
    ap.add_argument("--out")


def confirm_guard(a) -> None:
    """--confirm on N4 requires FREEZE.md; a stand-in dry run must write to the smoke folder."""
    if a.stand_in:
        if not a.confirm or a.stand_in not in DEV_NETWORKS:
            sys.exit("--stand-in needs --confirm and a development network")
        if not a.out or not Path(a.out).as_posix().startswith("reports/phase8i/smoke"):
            sys.exit("a stand-in dry run must write under reports/phase8i/smoke")
    elif a.confirm and not Path("docs/phase8i/FREEZE.md").exists():
        sys.exit("confirmatory run refused: docs/phase8i/FREEZE.md does not exist")


def dump(path: Path, obj) -> None:
    """Write JSON atomically: a crash never leaves a truncated result that looks complete."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".partial")
    tmp.write_text(json.dumps(obj, indent=1, default=float), "utf-8")
    tmp.replace(path)
