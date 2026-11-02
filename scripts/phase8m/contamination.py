"""Phase 8m Stage 5: contamination of the destination memory (H2; docs/phase8m/PREREGISTRATION.md
section 3). REGISTERED DEVELOPMENT for the H2 measures; the sensitivity grid is EXPLORATORY.

Everything replays the saved P1x contact stream of each domain (build_novelty.py) through
`NoveltyMemory`; the memory at the end of calibration is checkpointed and restored for every
scenario.

Synthetic injection (SYNTHETIC traffic, stated as such): from the first full evaluation window
to the last one, the most active verified-benign evaluation host (and, for the two-host variant,
also the second most active) contacts a fresh destination every 1 min, 10 min or 1 h.
- share of beacon windows in which the beacon destination is still novel under A3 (guarded:
  not yet promoted when the window is scored) and under A1 (unconditional: only its first window);
- time to acceptance;
- the alert change at the frozen T0 on the host's existing evaluation windows that carry the
  beacon, for B2 (guarded features) and B1u (unconditional): only the novelty columns change; the
  other 11 features keep their observed values (the beacon adds one small flow), so this is the
  effect of the memory, not a full traffic simulation. Windows with only the beacon are counted,
  not scored.

Real: the evaluation attack windows' destinations that were not known at the freeze, and the
benign-only post-freeze destinations; the share the guarded memory promotes by the end of the
evaluation (A1 learns all of them after one window by definition).

Negative controls: A0 (frozen) and always-quarantine promote nothing after the freeze.

H2 (registered): pooled single-host beacon windows novel under A3 >= 95 %, under A1 <= 5 %, and
the guarded memory promotes >= 50 % of the benign post-freeze destinations; pooled = network
means (each network = mean of its domains), equal weight per network (amendment 1).

Output: reports/phase8m/contamination.json
Usage: python scripts/run_capped.py -- <python> scripts/phase8m/contamination.py [--no-grid]
"""

from __future__ import annotations

import argparse
import json
import pickle
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
from netsentinel.behavior.novelty import NoveltyMemory, destination_state  # noqa: E402
from netsentinel.resources import peak_rss_mb  # noqa: E402

NOV = ROOT / "data" / "derived" / "phase8m" / "novelty"
B0_DIR = ROOT / "data" / "derived" / "phase8j" / "dev"
DEV = ROOT / "data" / "derived" / "phase8m" / "dev"
MODELS = ROOT / "data" / "derived" / "phase8m" / "models"
P1X = ROOT / "data" / "derived" / "phase8j" / "p1x"
OUT = ROOT / "reports" / "phase8m" / "contamination.json"
W_MS = 30_000
PERIODS_MIN = (1, 10, 60)
SEEDS = (0, 1, 2)
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
BEACON = "synthetic-beacon.invalid"
GRID = [(s, m) for s in (2, 3) for m in (10, 60, 360)]  # (min_sources, min_span minutes)
SCORED = {"B2": ["nov_guarded", "log_new_guarded", "familiarity_decay", "nov_host", "log_prevalence"],
          "B1u": ["nov_unconditional", "familiarity_decay"]}  # fmt: skip


def parts(dom_dir: Path) -> list[Path]:
    return sorted((dom_dir / "contacts_p1x").glob("part-*.parquet"))


def checkpoint(dom_dir: Path, mid: int, straddle: int, **params) -> tuple[bytes, list[Path]]:
    """Pickled memory after every window before the straddle window, and the parts holding
    the rest of the stream."""
    mem = NoveltyMemory(freeze_ms=mid, **params)
    rest = []
    for p in parts(dom_dir):
        c = pl.read_parquet(p)
        pre = c.filter(pl.col("win") < straddle)
        if pre.height:
            mem.process(pre, emit=frozenset())
        if pre.height < c.height:
            rest.append(p)
    return pickle.dumps(mem), rest


def replay(state: bytes, rest: list[Path], straddle: int, inject: pl.DataFrame | None,
           emit: frozenset) -> tuple[NoveltyMemory, pl.DataFrame]:  # fmt: skip
    mem = pickle.loads(state)
    rows, used = [], 0
    for i, p in enumerate(rest):
        c = pl.read_parquet(p).filter(pl.col("win") >= straddle)
        if inject is not None and inject.height:
            hi = int(c["win"].max()) if i < len(rest) - 1 else int(inject["win"].max())
            take = inject.filter((pl.col("win") <= hi) & (pl.col("_n") >= used))
            used += take.height
            take = take.drop("_n")
            if "pre_freeze" in c.columns:  # injected contacts are all after the freeze
                take = take.with_columns(pl.lit(False).alias("pre_freeze")).select(c.columns)
            c = pl.concat([c, take]).unique(maintain_order=True)
        rows.append(mem.process(c, emit=emit))
    return mem, pl.concat(rows) if rows else pl.DataFrame()


def beacon_frame(hosts: list[str], first_win: int, last_win: int, period_min: int) -> pl.DataFrame:
    step = period_min * 60_000 // W_MS
    wins = np.arange(first_win, last_win + 1, step, dtype=np.int64)
    f = pl.DataFrame({"win": np.repeat(wins, len(hosts)), "src": np.tile(hosts, len(wins))})
    return (f.with_columns(pl.lit(BEACON).alias("dst"), ((pl.col("win") + 1) * W_MS).alias("window_end_ms"))
            .select("win", "src", "dst", "window_end_ms").with_row_index("_n"))  # fmt: skip


def booster(variant: str, network: str, seed: int):
    import lightgbm as lgb

    return lgb.Booster(model_file=str(MODELS / variant / f"{network}__seed{seed}.txt"))


def alert_change(dom: dict, host: str, rows: pl.DataFrame, beacon_wins: np.ndarray) -> dict:
    """Alert rate of the host's existing evaluation windows that carry the beacon, at the frozen
    T0, with the observed (baseline) and the injected novelty columns."""
    ev = pl.read_parquet(P1X / dom["network"] / dom["domain"] / "eval_p1x.parquet")
    ev = ev.filter((pl.col("key") == host) & pl.col("win").is_in(beacon_wins.tolist()))
    base = pl.read_parquet(NOV / dom["network"] / dom["domain"] / "p1x.parquet")
    out = {
        "host_windows_with_beacon": ev.height,
        "beacon_only_windows": int(len(beacon_wins) - ev.height),
    }
    if not ev.height:
        return out
    variants = json.loads((ROOT / "reports/phase8m/dev/scores_seed0.json").read_text("utf-8"))[
        "variants"
    ]
    for v, cols in SCORED.items():
        feats = variants[v]  # the feature lists the models were trained with
        rates = {"baseline": [], "injected": []}
        for seed in SEEDS:
            mp = MODELS / v / f"{dom['network']}__seed{seed}.txt"
            npz = DEV / v / f"{dom['domain_key']}__seed{seed}.npz"
            if not (mp.exists() and npz.exists()):
                continue
            z = np.load(npz)
            hold = np.sort(z["cal_s"][z["cal_hold"]])
            thr = float(hold[min(int(np.ceil((hold.size + 1) * 0.99)), hold.size) - 1])
            b = booster(v, dom["network"], seed)
            for name, nov in (("baseline", base), ("injected", rows)):
                x = ev.drop([c for c in cols if c in ev.columns]).join(
                    nov.select("key", "win", *cols), on=["key", "win"], how="left"
                )
                X = np.nan_to_num(x.select([pl.col(f).cast(pl.Float64) for f in feats]).to_numpy())  # noqa: N806
                rates[name].append(float((b.predict(X) > thr).mean()))
        if rates["baseline"]:
            out[v] = {k: float(np.mean(r)) for k, r in rates.items()}
    return out


def synthetic(dom: dict, state: bytes, rest: list[Path]) -> list[dict]:
    z = np.load(B0_DIR / f"{dom['domain_key']}__seed0.npz")
    keys, ben, win = z["ev_key"], z["ev_benign"].astype(bool), z["ev_win"]
    hk, hc = np.unique(keys[ben], return_counts=True)
    hosts = [str(h) for h in hk[np.argsort(-hc, kind="stable")][:2]]
    first, last = dom["straddle"] + 1, int(win.max())
    res = []
    for period in PERIODS_MIN:
        for variant, hs in (("single_host", hosts[:1]), ("two_hosts", hosts)):
            inj = beacon_frame(hs, first, last, period)
            mem, rows = replay(state, rest, dom["straddle"], inj, emit=frozenset(hs))
            s = mem.dst.get(BEACON)
            t_wins = inj["win"].to_numpy()
            t_score = (t_wins + 1) * W_MS - 1
            pm = s.promoted_ms if s is not None else None
            a3 = np.ones(len(t_wins), bool) if pm is None else t_score <= pm
            a1 = t_wins == t_wins.min()
            r = {"period_min": period, "variant": variant, "hosts": len(hs), "beacon_windows": len(t_wins),
                 "a3_novel_share": float(a3.mean()), "a1_novel_share": float(a1.mean()),
                 "a3_accepted_after_h": None if pm is None else (pm - int(t_score.min())) / 3.6e6,
                 "a1_accepted_after_h": W_MS / 3.6e6}  # fmt: skip
            if variant == "single_host":
                bw = np.unique(t_wins[np.array(inj["src"].to_list()) == hs[0]])
                r["alerts"] = alert_change(dom, hs[0], rows, bw)
            res.append(r)
            print(dom["domain_key"], period, variant, {k: r[k] for k in ("a3_novel_share", "a1_novel_share")},
                  flush=True)  # fmt: skip
    return res


def real(dom: dict, state_df: pl.DataFrame, rest: list[Path]) -> dict:
    """Post-freeze attack and benign-only destinations, and the share the guarded memory
    accepted by the end of the evaluation."""
    z = np.load(B0_DIR / f"{dom['domain_key']}__seed0.npz")
    att_w = pl.DataFrame({"src": z["ev_key"].astype(str), "win": z["ev_win"].astype(np.int64),
                          "y": z["ev_y"].astype(bool)}).filter(pl.col("y")).drop("y")  # fmt: skip
    attackers = [str(a) for a in z["attackers"]]
    att_d, atk_any = set(), set()
    for p in rest:
        c = pl.read_parquet(p).filter(pl.col("win") >= dom["straddle"])
        att_d |= set(c.join(att_w, on=["src", "win"])["dst"].unique().to_list())
        atk_any |= set(c.filter(pl.col("src").is_in(attackers))["dst"].unique().to_list())
    post = state_df.filter(~pl.col("frozen"))
    a = post.filter(pl.col("dst").is_in(list(att_d)))
    b = post.filter(~pl.col("dst").is_in(list(atk_any)))

    def share(f: pl.DataFrame) -> dict:
        prom = f.filter(pl.col("promoted_ms").is_not_null())
        lag = ((prom["promoted_ms"] - prom["first_ms"]) / 3.6e6).to_numpy()
        return {"destinations": f.height, "a1_learned_share": 1.0 if f.height else None,
                "a3_promoted_share": prom.height / f.height if f.height else None,
                "a3_median_hours_to_accept": float(np.median(lag)) if lag.size else None}  # fmt: skip

    return {
        "attack_destinations_post_freeze": share(a),
        "benign_only_destinations_post_freeze": share(b),
    }


def network_mean(per: dict, get) -> dict:
    out = {}
    for n in NETWORKS:
        v = [get(r) for k, r in per.items() if k.startswith(n + "/")]
        v = [x for x in v if x is not None]
        if v:
            out[n] = float(np.mean(v))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-grid", action="store_true")
    ap.add_argument("--domains", help="comma-separated network/domain (smoke runs)")
    a = ap.parse_args()
    t0 = time.perf_counter()
    per: dict[str, dict] = {}
    for meta_p in sorted(NOV.glob("*/*/meta.json")):
        net, name = meta_p.parent.parent.name, meta_p.parent.name
        key = f"{net}/{name}"
        if a.domains and key not in a.domains.split(","):
            continue
        meta = json.loads(meta_p.read_text("utf-8"))
        dom = {"network": net, "domain": name, "domain_key": f"{net}__{name}",
               "mid": meta["mid_ms"], "straddle": meta["straddle_win"]}  # fmt: skip
        if not (B0_DIR / f"{dom['domain_key']}__seed0.npz").exists():
            continue
        state, rest = checkpoint(meta_p.parent, dom["mid"], dom["straddle"])
        st = pl.read_parquet(meta_p.parent / "dst_state_p1x.parquet")
        r = {"synthetic": synthetic(dom, state, rest), "real": real(dom, st, rest),
             "negative_controls": {"A0_frozen": {"benign_post_freeze_promoted_share": 0.0,
                                                 "single_host_beacon_novel_share": 1.0},
                                   "always_quarantine": {"benign_post_freeze_promoted_share": 0.0,
                                                         "single_host_beacon_novel_share": 1.0}}}  # fmt: skip
        if not a.no_grid:
            r["grid_exploratory"] = []
            for ms, span in GRID:
                g_state, g_rest = checkpoint(meta_p.parent, dom["mid"], dom["straddle"], min_sources=ms,
                                             min_span_ms=span * 60_000)  # fmt: skip
                mem, _ = replay(g_state, g_rest, dom["straddle"], None, emit=frozenset())
                g = real(dom, destination_state(mem), g_rest)
                r["grid_exploratory"].append({"min_sources": ms, "min_span_min": span, **g})
        per[key] = r
        print(key, "done", round(time.perf_counter() - t0, 1), flush=True)

    def pooled(variant: str, field: str):
        return network_mean(per, lambda r: float(np.mean([s[field] for s in r["synthetic"]
                                                           if s["variant"] == variant])))  # fmt: skip

    a3 = pooled("single_host", "a3_novel_share")
    a1 = pooled("single_host", "a1_novel_share")
    ben = network_mean(
        per, lambda r: r["real"]["benign_only_destinations_post_freeze"]["a3_promoted_share"]
    )
    h2 = {"single_host_a3_novel_by_network": a3, "single_host_a1_novel_by_network": a1,
          "benign_post_freeze_promoted_by_network": ben,
          "a3_novel_mean": float(np.mean(list(a3.values()))) if a3 else None,
          "a1_novel_mean": float(np.mean(list(a1.values()))) if a1 else None,
          "benign_promoted_mean": float(np.mean(list(ben.values()))) if ben else None}  # fmt: skip
    h2["supported"] = bool(len(a3) == 4 and h2["a3_novel_mean"] >= 0.95 and h2["a1_novel_mean"] <= 0.05
                           and h2["benign_promoted_mean"] >= 0.50)  # fmt: skip
    res = {"status": "REGISTERED DEVELOPMENT (H2); synthetic injections are SYNTHETIC; grid EXPLORATORY",
           "H2": h2, "per_domain": per, "periods_min": PERIODS_MIN, "beacon_destination": BEACON,
           "tau_grid": "not run: tau changes only familiarity_decay, which needs retrained models",
           "peak_rss_mb": peak_rss_mb(), "seconds": round(time.perf_counter() - t0, 1)}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(json.dumps(res, indent=1).encode())
    print(json.dumps(h2, indent=1))


if __name__ == "__main__":
    main()
