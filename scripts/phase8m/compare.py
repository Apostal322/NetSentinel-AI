"""Phase 8m Stage 4-6: registered development comparison (docs/phase8m/PREREGISTRATION.md
sections 3-5). No model is fitted here; everything is computed from saved scores.

Per variant, domain and seed: T0 = conformal rank at alpha = 1 % on the P1x calibration
hold-out (alerts strictly above T0), then on the evaluation windows: verified-benign FPR and
false alerts, attack-window recall, entity recall (entities = sources with >= 5 attack windows),
median detection delay and precision. Network value = mean over its domains and seeds.

- B0: the Phase 8j scores (data/derived/phase8j/dev), reused as registered.
- B1, B2, B1u, A_none, A_novol and B0r (pipeline check): data/derived/phase8m/dev/<variant>.
- B3: score = log_new_guarded of the P1x memory, calibrated in the same way (no model).
- Q1: the B0r models at their own T0 on evaluation windows with new_dst_frac := nov_guarded.

H3 (primary, B2 vs B0) and H1 are decided by the registered rules; B1 vs B0 is secondary; the
rest is exploratory. H2 is read from reports/phase8m/contamination.json if it exists.
Uncertainty per domain: paired host-cluster bootstrap of the B2 - B0 differences (seed-mean
counts per host; B = 2,000, seed 8; one-sided 95 % bounds). Across networks: sign counts only.

Output: reports/phase8m/model_comparison.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8m/compare.py
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
B0_DIR = ROOT / "data" / "derived" / "phase8j" / "dev"
DEV = ROOT / "data" / "derived" / "phase8m" / "dev"
NOV = ROOT / "data" / "derived" / "phase8m" / "novelty"
OUT = ROOT / "reports" / "phase8m" / "model_comparison.json"
CONTAM = ROOT / "reports" / "phase8m" / "contamination.json"
ALPHA = 0.01
SEEDS = (0, 1, 2)
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
TRAINED = ("B0r", "B1", "B2", "B1u", "A_none", "A_novol")
ORDER = ("B0", "B0r", "B1", "B2", "B3", "B1u", "A_none", "A_novol", "Q1")
LABEL = {"B0": "registered development (reference)", "B2": "registered development (primary)",
         "B1": "registered development (secondary)", "B0r": "pipeline check"}  # fmt: skip
MIN_ENTITY_WINDOWS = 5
GAIN, LOSS, FA_RATIO, FPR_DROP = 0.05, 0.05, 1.25, 0.20
AGE_BINS = (0, 1, 6, 24, 72, math.inf)
H_MS = 3_600_000
BOOT, BOOT_SEED = 2000, 8


def k_of(n: int) -> int:
    return min(math.ceil((n + 1) * (1 - ALPHA)), n)


def t0_of(hold: np.ndarray) -> float:
    return float(np.sort(hold)[k_of(hold.size) - 1])


def mean(v):
    v = [x for x in v if x is not None and not (isinstance(x, float) and math.isnan(x))]
    return float(np.mean(v)) if v else None


# ----------------------------------------------------------------------------- per domain
class Domain:
    """One domain's evaluation windows, labels and novelty, aligned to the B0 score files."""

    def __init__(self, path: Path):
        d = np.load(path)
        self.name = path.name.split("__seed")[0].replace("__", "/")
        self.network = str(d["network"])
        self.key, self.win, self.end = d["ev_key"], d["ev_win"], d["ev_end"]
        self.y, self.benign = d["ev_y"].astype(bool), d["ev_benign"].astype(bool)
        self.cal_key, self.cal_win, self.hold = d["cal_key"], d["cal_win"], d["cal_hold"]
        self.cal_end_max = int(d["cal_end"].max())
        nov = pl.read_parquet(NOV / self.network / self.name.split("/")[1] / "p1x.parquet")
        self.nov_ev = self._align(nov, self.key, self.win)
        self.nov_cal = self._align(nov, self.cal_key, self.cal_win)
        self.age_h = (self.end - self.cal_end_max) / H_MS
        self.seen = np.isin(self.key, np.unique(self.cal_key))
        counts: dict[str, int] = {}
        for k in self.key[self.y]:
            counts[k] = counts.get(k, 0) + 1
        self.entities = sorted(k for k, c in counts.items() if c >= MIN_ENTITY_WINDOWS)
        self.hosts, self.host_idx = np.unique(self.key, return_inverse=True)

    @staticmethod
    def _align(nov: pl.DataFrame, key: np.ndarray, win: np.ndarray) -> pl.DataFrame:
        idx = pl.DataFrame({"key": key.astype(str), "win": win.astype(np.int64)}).with_row_index(
            "_i"
        )
        j = idx.join(nov, on=["key", "win"], how="left").sort("_i")
        if j.height != len(key) or j["nov_guarded"].null_count():
            raise SystemExit("novelty features do not cover the scored windows")
        return j

    def metrics(self, alert: np.ndarray) -> dict:
        y, ben = self.y, self.benign
        out = {"fpr": float(alert[ben].mean()) if ben.any() else None,
               "false_alerts": int(alert[ben].sum()),
               "window_recall": float(alert[y].mean()) if y.any() else None}  # fmt: skip
        det, delays = 0, []
        for e in self.entities:
            m = y & (self.key == e)
            if (alert & m).any():
                det += 1
                delays.append(float(self.end[alert & m].min() - self.end[m].min()) / 1000)
        out["entities"] = len(self.entities)
        out["entities_detected"] = det
        out["entity_recall"] = det / len(self.entities) if self.entities else None
        out["median_delay_s"] = float(np.median(delays)) if delays else None
        judged = alert & (y | ben)
        out["precision"] = float((alert & y).sum() / judged.sum()) if judged.any() else None
        fa = alert & ben
        a0_not_a3 = (self.nov_ev["nov_frozen"].to_numpy() > 0) & (
            self.nov_ev["nov_guarded"].to_numpy() == 0
        )
        out["fa_share_stale_novelty"] = float(a0_not_a3[fa].mean()) if fa.any() else None
        out["by_age"] = []
        for lo, hi in zip(AGE_BINS[:-1], AGE_BINS[1:], strict=True):
            m = (self.age_h >= lo) & (self.age_h < hi)
            if (m & ben).any() or (m & y).any():
                out["by_age"].append({"age_h": [lo, hi if math.isfinite(hi) else None],
                                      "benign": int((m & ben).sum()), "attack": int((m & y).sum()),
                                      "fpr": float(alert[m & ben].mean()) if (m & ben).any() else None,
                                      "recall": float(alert[m & y].mean()) if (m & y).any() else None})  # fmt: skip
        out["by_host_seen"] = {}
        for name, m in (("seen_in_calibration", self.seen), ("new_after_calibration", ~self.seen)):
            out["by_host_seen"][name] = {
                "benign": int((m & ben).sum()),
                "fpr": float(alert[m & ben].mean()) if (m & ben).any() else None,
                "recall": float(alert[m & y].mean()) if (m & y).any() else None}  # fmt: skip
        return out


def scores(variant: str, dom: Domain, seed: int) -> tuple[np.ndarray, np.ndarray] | None:
    """(hold-out scores, evaluation scores) of a variant, aligned to the B0 windows."""
    stem = f"{dom.name.replace('/', '__')}__seed{seed}.npz"
    if variant == "B0":
        d = np.load(B0_DIR / stem)
        return d["cal_s"][d["cal_hold"]], d["ev_s"]
    if variant == "B3":
        s_cal = dom.nov_cal["log_new_guarded"].to_numpy()
        return s_cal[dom.hold], dom.nov_ev["log_new_guarded"].to_numpy()
    src = "B0r" if variant == "Q1" else variant
    p = DEV / src / stem
    if not p.exists():
        return None
    d = np.load(p)
    if not (np.array_equal(d["ev_key"], dom.key) and np.array_equal(d["ev_win"], dom.win)
            and np.array_equal(d["cal_hold"], dom.hold)):  # fmt: skip
        raise SystemExit(f"{variant} {stem}: windows differ from B0")
    return d["cal_s"][d["cal_hold"]], d["ev_s_q1" if variant == "Q1" else "ev_s"]


# ----------------------------------------------------------------------------- bootstrap
def host_counts(dom: Domain, alerts: list[np.ndarray]) -> dict[str, np.ndarray]:
    """Seed-mean benign false alerts and attack hits per host."""
    h, n = dom.host_idx, len(dom.hosts)
    fa = np.mean([np.bincount(h, (a & dom.benign).astype(float), n) for a in alerts], axis=0)
    hit = np.mean([np.bincount(h, (a & dom.y).astype(float), n) for a in alerts], axis=0)
    return {
        "fa": fa,
        "hit": hit,
        "ben": np.bincount(h, dom.benign.astype(float), n),
        "att": np.bincount(h, dom.y.astype(float), n),
    }


def paired_bootstrap(dom: Domain, a: list[np.ndarray], b: list[np.ndarray]) -> dict:
    """B - A differences (FPR, window recall), hosts resampled with replacement, the same
    resample for both models."""
    ca, cb = host_counts(dom, a), host_counts(dom, b)
    rng = np.random.default_rng(BOOT_SEED)
    idx = rng.integers(0, len(dom.hosts), (BOOT, len(dom.hosts)))
    out = {}
    for name, num, den in (("fpr", "fa", "ben"), ("window_recall", "hit", "att")):
        d_all = ca[den].sum()
        if d_all == 0:
            out[name] = None
            continue
        point = float((cb[num] - ca[num]).sum() / d_all)
        den_b = ca[den][idx].sum(1)
        diff = (cb[num] - ca[num])[idx].sum(1) / np.where(den_b > 0, den_b, np.nan)
        out[name] = {"diff": point, "lower95": float(np.nanquantile(diff, 0.05)),
                     "upper95": float(np.nanquantile(diff, 0.95))}  # fmt: skip
    return out


# ----------------------------------------------------------------------------- decisions
def network_means(per: dict) -> dict:
    """variant -> network -> mean over domains and seeds of fpr, false alerts, recall, ..."""
    out: dict[str, dict] = {}
    for v, doms in per.items():
        for net in NETWORKS:
            rows = [
                r
                for name, seeds in doms.items()
                if name.startswith(net + "/")
                for r in seeds.values()
            ]
            if rows:
                out.setdefault(v, {})[net] = {
                    m: mean([r[m] for r in rows]) for m in
                    ("fpr", "false_alerts", "window_recall", "entity_recall", "median_delay_s",
                     "precision", "fa_share_stale_novelty")}  # fmt: skip
    return out


def h3(nm: dict, cand: str, ref: str = "B0") -> dict:
    nets = [n for n in NETWORKS if n in nm.get(cand, {}) and n in nm[ref]]
    d_rec = {n: nm[cand][n]["window_recall"] - nm[ref][n]["window_recall"] for n in nets}
    ratio = {n: (nm[cand][n]["false_alerts"] / nm[ref][n]["false_alerts"]
                 if nm[ref][n]["false_alerts"] else (1.0 if nm[cand][n]["false_alerts"] == 0 else math.inf))
             for n in nets}  # fmt: skip
    gains = sum(d >= GAIN for d in d_rec.values())
    c1, c2 = gains >= 3, all(d >= -LOSS for d in d_rec.values())
    c3 = all(r <= FA_RATIO for r in ratio.values())
    return {"networks": nets, "recall_diff": d_rec, "false_alert_ratio": ratio,
            "networks_with_gain": gains, "c1_gain_on_3_of_4": c1, "c2_no_loss": c2,
            "c3_workload": c3, "supported": bool(len(nets) == 4 and c1 and c2 and c3),
            "recall_diff_sign_count": f"{sum(d > 0 for d in d_rec.values())}/{len(nets)} positive"}  # fmt: skip


def h1(nm: dict, cand: str = "B2") -> dict:
    high = [n for n in NETWORKS if nm["B0"][n]["fpr"] > 2 * ALPHA]
    low = [n for n in NETWORKS if n not in high]
    rel = {n: 1 - nm[cand][n]["fpr"] / nm["B0"][n]["fpr"] for n in high}
    lower_all = all(nm[cand][n]["fpr"] < nm["B0"][n]["fpr"] for n in high)
    drop20 = any(r >= FPR_DROP for r in rel.values())
    keep_low = all(nm[cand][n]["fpr"] <= 2 * ALPHA for n in low)
    return {"high_fpr_networks": high, "relative_fpr_reduction": rel, "lower_on_every_high": lower_all,
            "at_least_20pct_on_one": drop20, "low_stay_within_2alpha": keep_low,
            "supported": bool(high and lower_all and drop20 and keep_low)}  # fmt: skip


def select(h3_b2: dict, h3_b1: dict, nm: dict) -> dict:
    if h3_b2["supported"]:
        if h3_b1["supported"]:
            better = sum(nm["B2"][n]["window_recall"] - nm["B1"][n]["window_recall"] >= GAIN
                         for n in NETWORKS)  # fmt: skip
            if better < 3:
                return {
                    "candidate": "B1",
                    "rule": "both meet H3; B2 not >= 0.05 better on >= 3 networks",
                }
        return {"candidate": "B2", "rule": "B2 meets H3"}
    if h3_b1["supported"]:
        return {
            "candidate": None,
            "rule": "only B1 meets H3: secondary finding, no candidate (amendment 1)",
        }
    return {"candidate": None, "rule": "neither B2 nor B1 meets H3: NO-GO, B0 stays"}


def main() -> None:
    t_start = time.perf_counter()
    files = sorted(B0_DIR.glob("*__seed0.npz"))
    per: dict[str, dict] = {v: {} for v in ORDER}
    boot: dict[str, dict] = {}
    b0_check: dict[str, float] = {}
    for f in files:
        dom = Domain(f)
        alerts: dict[str, list] = {}
        for v in ORDER:
            for seed in SEEDS:
                sc = scores(v, dom, seed)
                if sc is None:
                    continue
                hold, s_ev = sc
                thr = t0_of(hold)
                alert = s_ev > thr
                r = dom.metrics(alert)
                r["t0"] = thr
                per[v].setdefault(dom.name, {})[f"seed{seed}"] = r
                alerts.setdefault(v, []).append(alert)
                if v == "B0r":
                    ref = np.load(B0_DIR / f"{dom.name.replace('/', '__')}__seed{seed}.npz")["ev_s"]
                    b0_check[f"{dom.name} seed{seed}"] = float(np.abs(ref - s_ev).max())
        for cand in ("B2", "B1"):
            if len(alerts.get(cand, [])) == len(SEEDS):
                boot.setdefault(cand, {})[dom.name] = paired_bootstrap(
                    dom, alerts["B0"], alerts[cand]
                )
        print(dom.name, {v: len(a) for v, a in alerts.items()}, flush=True)
    per = {v: d for v, d in per.items() if d}
    nm = network_means(per)
    res = {"status": "REGISTERED DEVELOPMENT (B2 vs B0 primary, B1 vs B0 secondary); other variants "
                     "EXPLORATORY; no result here is independent confirmation",
           "labels": LABEL, "b0r_reproduces_b0_max_abs_diff": max(b0_check.values()) if b0_check else None,
           "network_means": nm, "per_domain": per, "bootstrap_vs_B0": boot}  # fmt: skip
    if "B2" in nm and len(nm["B2"]) == 4:
        res["H3_B2"] = h3(nm, "B2")
        res["H1_B2"] = h1(nm, "B2")
        if "B1" in nm and len(nm["B1"]) == 4:
            res["H3_B1_secondary"] = h3(nm, "B1")
            res["selection"] = select(res["H3_B2"], res["H3_B1_secondary"], nm)
        for v in ("B3", "B1u", "A_none", "A_novol", "Q1"):
            if v in nm and len(nm[v]) == 4:
                res.setdefault("exploratory_vs_B0", {})[v] = h3(nm, v)
    if CONTAM.exists():
        res["H2"] = json.loads(CONTAM.read_text("utf-8")).get("H2")
    res["seconds"] = round(time.perf_counter() - t_start, 1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(json.dumps(res, indent=1).encode())
    print(json.dumps({k: res.get(k) for k in ("b0r_reproduces_b0_max_abs_diff", "H3_B2", "H1_B2", "selection")},
                     indent=1))  # fmt: skip


if __name__ == "__main__":
    main()
