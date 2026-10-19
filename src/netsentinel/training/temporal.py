"""Experiment 2: compact temporal deep learning vs a same-setup MLP control (and, in the
report, vs LightGBM on the same split).

Pipeline: prepare() (same split and label rules as the baselines) -> per-day causal sequences
from the full day stream -> standardise flow features on TRAIN only -> train with early
stopping on validation PR-AUC (prevalence-weighted), ReduceLROnPlateau, gradient clipping,
best-checkpointing and optional resume -> validation threshold at target FPR.
Mixed precision is OFF: the GTX 1050 Ti (Pascal) has no tensor cores, fp16 gives no speedup.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from netsentinel.evaluation.metrics import binary_metrics, threshold_at_fpr
from netsentinel.features.schema import FEATURE_SCHEMA_VERSION, schema_fingerprint
from netsentinel.ledger import Run
from netsentinel.models.baselines import FiniteSignedLog
from netsentinel.seed import set_seed
from netsentinel.temporal.sequences import N_STEP, build_day_sequences
from netsentinel.training.baseline import error_analysis
from netsentinel.training.data import prepare

log = logging.getLogger(__name__)


def _sequences(prep_frame: pl.DataFrame, interim_dir: Path, length: int):
    out = {}
    for (day,), g in prep_frame.group_by("day"):
        ids, X, m = build_day_sequences(interim_dir / f"{day}.parquet", g["row_id"].to_numpy(),  # noqa: N806
                                        length)  # fmt: skip
        out[day] = (ids, X, m)
    return out


def _gather(part: pl.DataFrame, seqs: dict, features: list[str], scaler):
    X_seq = np.zeros((part.height, *next(iter(seqs.values()))[1].shape[1:]), np.float32)  # noqa: N806
    M = np.zeros(X_seq.shape[:2], dtype=bool)  # noqa: N806
    for (day,), g in part.with_row_index("_i").group_by("day"):
        ids, X, m = seqs[day]  # noqa: N806
        pos = {int(r): k for k, r in enumerate(ids)}
        k = np.array([pos[int(r)] for r in g["row_id"]])
        X_seq[g["_i"].to_numpy()] = X[k]
        M[g["_i"].to_numpy()] = m[k]
    flow = FiniteSignedLog().transform(part.select(features).to_numpy())
    flow = np.nan_to_num((flow - scaler[0]) / scaler[1], nan=0.0).astype(np.float32)
    y = (part["label"] != "benign").to_numpy().astype(np.float32)
    return flow, X_seq, M, y, part["sample_weight"].to_numpy()


def run_temporal(cfg: dict[str, Any]) -> list[str]:
    import torch
    from sklearn.metrics import average_precision_score

    from netsentinel.temporal.model import FlowMLP, SeqGRU, count_parameters

    set_seed(cfg["seed"])
    torch.manual_seed(cfg["seed"])
    tcfg = cfg["temporal"]
    device = torch.device("cuda" if torch.cuda.is_available() and tcfg.get("gpu", True) else "cpu")
    prep = prepare({**cfg, "task": "binary"})
    frame = prep.frame
    train = frame.filter(pl.col("split") == "train")
    if cfg.get("max_train_rows") and train.height > cfg["max_train_rows"]:
        train = train.sample(n=cfg["max_train_rows"], seed=cfg["seed"])
    val = frame.filter(pl.col("split") == "val")
    seqs = _sequences(pl.concat([train, val]).select("day", "row_id"),
                      Path(cfg["data"]["interim_dir"]), tcfg["length"])  # fmt: skip
    tr_flow = FiniteSignedLog().transform(train.select(prep.features).to_numpy())
    scaler = (np.nanmean(tr_flow, axis=0), np.nanstd(tr_flow, axis=0) + 1e-6)  # train only
    tr = _gather(train, seqs, prep.features, scaler)
    va = _gather(val, seqs, prep.features, scaler)
    # Keep only what later steps need; drop the wide frames before training (8 GB machine:
    # holding them made the first attempt page heavily).
    split_tbl = frame.select("day", "row_id", "split")
    val_meta = val.select("day", "row_id", "split", "label", "dst_port", "protocol",
                          "sample_weight")  # fmt: skip
    prep = type(prep)(val_meta, prep.features, prep.split_cfg, prep.leakage, prep.coverage)
    del frame, train, val, seqs, tr_flow
    import gc

    gc.collect()
    pos_weight = torch.tensor((tr[3] == 0).sum() / max((tr[3] == 1).sum(), 1), device=device)

    run_ids = []
    for arch in tcfg["architectures"]:
        run = Run(cfg, name=f"{cfg['experiment']}_{arch}")
        split_tbl.write_parquet(run.dir / "split.parquet")
        model = (SeqGRU(len(prep.features), N_STEP, tcfg.get("hidden", 64)) if arch == "gru"
                 else FlowMLP(len(prep.features))).to(device)  # fmt: skip
        opt = torch.optim.AdamW(model.parameters(), lr=tcfg.get("lr", 1e-3), weight_decay=1e-4)
        sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, mode="max", factor=0.5,
                                                           patience=1)  # fmt: skip
        loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        ckpt = run.dir / "best.pt"
        tensors = [torch.from_numpy(a) for a in tr[:4]]
        g = torch.Generator().manual_seed(cfg["seed"])
        bs = tcfg.get("batch_size", 512)

        def predict(data, model=model) -> np.ndarray:
            model.eval()
            out = []
            with torch.no_grad():
                for i in range(0, len(data[0]), 4096):
                    f, s, m = (torch.from_numpy(a[i : i + 4096]).to(device) for a in data[:3])
                    out.append(torch.sigmoid(model(f, s, m)).cpu().numpy())
            return np.concatenate(out)

        best, bad, history = -1.0, 0, []
        t0 = time.perf_counter()
        for epoch in range(tcfg.get("max_epochs", 15)):
            model.train()
            perm = torch.randperm(len(tensors[0]), generator=g)
            total = 0.0
            for i in range(0, len(perm), bs):
                idx = perm[i : i + bs]
                f, s, m, y = (t[idx].to(device) for t in tensors)
                opt.zero_grad()
                loss = loss_fn(model(f, s, m), y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
                total += float(loss) * len(idx)
            score = predict(va)
            ap = float(average_precision_score(va[3], score, sample_weight=va[4]))
            sched.step(ap)
            history.append({"epoch": epoch, "train_loss": total / len(perm), "val_pr_auc": ap,
                            "lr": opt.param_groups[0]["lr"]})  # fmt: skip
            log.info(
                "%s epoch %d loss %.4f val PR-AUC %.4f", arch, epoch, history[-1]["train_loss"], ap
            )
            if ap > best + 1e-4:
                best, bad = ap, 0
                torch.save({"state_dict": model.state_dict(), "epoch": epoch}, ckpt)
            else:
                bad += 1
                if bad >= tcfg.get("patience", 3):
                    break
        fit_s = time.perf_counter() - t0
        model.load_state_dict(torch.load(ckpt, map_location=device)["state_dict"])
        t1 = time.perf_counter()
        score = predict(va)
        pred_us = 1e6 * (time.perf_counter() - t1) / len(score)
        thr = threshold_at_fpr(va[3].astype(int), score, cfg.get("target_fpr", 1e-3), va[4])
        metrics = binary_metrics(va[3].astype(int), score, thr, va[4])
        run.save_json("error_analysis_val.json", error_analysis(prep, score, thr))
        run.save_json("history.json", history)
        torch.save({"state_dict": model.state_dict(), "arch": arch, "scaler": scaler,
                    "features": prep.features, "threshold": thr,
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                    "feature_fingerprint": schema_fingerprint(prep.features),
                    "sequence_length": tcfg["length"]}, run.dir / "model.pt")  # fmt: skip
        run.log_metrics(metrics, prefix="val/")
        run.log_metrics({"fit_seconds": fit_s, "val_predict_us_per_row": pred_us,
                         "train_rows": len(tr[3]), "val_rows": len(va[3]),
                         "parameters": count_parameters(model), "epochs": len(history),
                         "gpu": float(device.type == "cuda")}, prefix="cost/")  # fmt: skip
        run.finish(notes=f"temporal {arch} len={tcfg['length']} split={prep.split_cfg.protocol}")
        log.info("%s val %s", run.id, {k: round(v, 4) for k, v in metrics.items()})
        run_ids.append(run.id)
    return run_ids
