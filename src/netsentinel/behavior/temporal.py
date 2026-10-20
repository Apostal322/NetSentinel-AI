"""Phase 8B: temporal scorers over causal sequences of entity-window features.

Every scorer sees, for window t of entity k, only windows of k that ENDED no later than t
(causal). Rows are ordered by (key, win). All scorers share one interface:

    s = Scorer(...).fit(fit_windows)             # calibration windows (benign by assumption)
    scores = s.score(history_and_target_windows)  # score every row, using only its past

Scorers
* RobustZ        - static per-entity median/MAD (the Phase 6/7 production baseline).
* GuardedEWMA    - exponentially weighted mean/variance per entity; a window only updates the
                   state if its score is below the guard (anomalous windows cannot pull the
                   baseline), so it adapts to slow benign drift but not to attacks.
* LagIForest     - Isolation Forest on [x_t, mean(x_{t-L..t-1}), x_t - x_{t-1}].
* GRUForecaster / TCNForecaster - predict x_t from the previous L windows (plus inter-window
                   gaps); score = mean of the 2 largest normalised forecast errors.

`multiscale_windows` adds, to each base window, the features of the most recent COMPLETED
coarse window of the same entity: coarse index = window_end_ms // (W_coarse * 1000) - 1.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field

import numpy as np
import polars as pl

from netsentinel.behavior.windows import WINDOW_FEATURES, aggregate

FRACTIONS = {"no_reply_frac", "rst_frac", "udp_share", "upload_share", "new_dst_frac"}


def feature_names(windows: pl.DataFrame) -> list[str]:
    extra = [c for c in windows.columns if any(c == f"{f}_c{s}" for f in WINDOW_FEATURES
                                              for s in ("60", "300", "600"))]  # fmt: skip
    return [*WINDOW_FEATURES, *sorted(extra)]


def multiscale_windows(flows: pl.DataFrame, level: str, base_s: int, coarse_s: tuple[int, ...],
                       known_dst=None, prior_dst=None) -> pl.DataFrame:  # fmt: skip
    """Base windows + causal coarse-window features (suffix _c<seconds>)."""
    base = aggregate(flows, level, base_s, known_dst=known_dst, prior_dst=prior_dst)
    for cs in coarse_s:
        co = aggregate(flows, level, cs, known_dst=known_dst, prior_dst=prior_dst)
        co = co.select("key", pl.col("win").alias("cwin"),
                       *[pl.col(f).alias(f"{f}_c{cs}") for f in WINDOW_FEATURES])  # fmt: skip
        base = (
            base.with_columns((pl.col("window_end_ms") // (cs * 1000) - 1).alias("cwin"))
            .join(co, on=["key", "cwin"], how="left")
            .drop("cwin")
        )
    return base.sort("key", "win")


# ----------------------------------------------------------------------------- scaling
@dataclass
class RobustScaler:
    med: np.ndarray | None = None
    scale: np.ndarray | None = None

    def fit(self, X: np.ndarray, names: list[str]) -> RobustScaler:  # noqa: N803
        self.med = np.nan_to_num(np.nanmedian(X, axis=0))
        mad = np.nan_to_num(1.4826 * np.nanmedian(np.abs(X - self.med), axis=0))
        floor = np.array([0.15 if n.split("_c")[0] in FRACTIONS else 0.25 for n in names])
        self.scale = np.maximum(mad, floor)
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:  # noqa: N803
        return np.nan_to_num((X - self.med) / self.scale, nan=0.0).astype(np.float32)


def top2(z: np.ndarray) -> np.ndarray:
    a = np.sort(np.abs(z), axis=1)[:, ::-1]
    return a[:, :2].mean(axis=1)


def _matrix(df: pl.DataFrame, names: list[str]) -> np.ndarray:
    return df.select([pl.col(n).cast(pl.Float64) for n in names]).to_numpy()


def _ordered(df: pl.DataFrame) -> pl.DataFrame:
    return df.sort("key", "win")


# ----------------------------------------------------------------------------- scorers
@dataclass
class RobustZ:
    min_windows: int = 30
    names: list[str] = field(default_factory=list)
    name: str = "robust_z"

    def fit(self, fit: pl.DataFrame) -> RobustZ:
        self.names = self.names or feature_names(fit)
        X = _matrix(fit, self.names)  # noqa: N806
        self.pooled = RobustScaler().fit(X, self.names)
        self.per_key = {}
        keys = fit["key"].to_numpy()
        for k in np.unique(keys):
            m = keys == k
            if m.sum() >= self.min_windows:
                self.per_key[k] = RobustScaler().fit(X[m], self.names)
        return self

    def score(self, df: pl.DataFrame) -> np.ndarray:
        X = _matrix(df, self.names)  # noqa: N806
        keys = df["key"].to_numpy()
        out = np.empty(len(X))
        for k in np.unique(keys):
            m = keys == k
            out[m] = top2(self.per_key.get(k, self.pooled).transform(X[m]))
        return out


@dataclass
class GuardedEWMA:
    alpha: float = 0.05
    guard_quantile: float = 0.99
    warmup: int = 10
    names: list[str] = field(default_factory=list)
    name: str = "guarded_ewma"

    def fit(self, fit: pl.DataFrame) -> GuardedEWMA:
        self.names = self.names or feature_names(fit)
        X = _matrix(fit, self.names)  # noqa: N806
        self.scaler = RobustScaler().fit(X, self.names)  # global floors and initial state
        z = top2(self.scaler.transform(X))
        self.guard = float(np.quantile(z, self.guard_quantile)) if len(z) else math.inf
        return self

    def score(self, df: pl.DataFrame) -> np.ndarray:
        """Per entity, in time order: score against the running state, then update the state
        only if the window is below the guard. The first `warmup` windows of an entity are
        scored against the pooled calibration statistics."""
        df = df.with_row_index("_i")
        out = np.empty(df.height)
        floor = self.scaler.scale
        for (_k,), g in _ordered(df).group_by("key", maintain_order=True):
            X = np.nan_to_num(_matrix(g, self.names), nan=0.0)  # noqa: N806
            idx = g["_i"].to_numpy()
            mean, var, n = self.scaler.med.copy(), floor**2, 0
            for j in range(len(X)):
                z = (X[j] - mean) / np.sqrt(np.maximum(var, floor**2))
                s = float(top2(z[None, :])[0])
                out[idx[j]] = s
                if s < self.guard or n < self.warmup:
                    a = self.alpha if n >= self.warmup else 1.0 / (n + 1)
                    d = X[j] - mean
                    mean = mean + a * d
                    var = (1 - a) * (var + a * d * d)
                    n += 1
        return out


def _lag_features(df: pl.DataFrame, names: list[str], lags: int) -> np.ndarray:
    """[x_t, mean of previous `lags` windows of the same key, x_t - x_{t-1}] (causal)."""
    d = _ordered(df).with_row_index("_i")
    exprs = []
    for n in names:
        c = pl.col(n).cast(pl.Float64)
        prev = [c.shift(i).over("key") for i in range(1, lags + 1)]
        exprs.append(
            pl.mean_horizontal(prev).fill_null(c).alias(f"{n}__lagmean")
        )  # no history: x_t
        exprs.append((c - c.shift(1).over("key")).fill_null(0.0).alias(f"{n}__d1"))
    d = d.with_columns(exprs)
    cols = [*names, *[f"{n}__lagmean" for n in names], *[f"{n}__d1" for n in names]]
    X = np.nan_to_num(_matrix(d, cols), nan=0.0)  # noqa: N806
    out = np.empty_like(X)
    out[d["_i"].to_numpy()] = X
    return out


@dataclass
class LagIForest:
    lags: int = 4
    seed: int = 0
    names: list[str] = field(default_factory=list)
    name: str = "lag_iforest"

    def fit(self, fit: pl.DataFrame) -> LagIForest:
        from sklearn.ensemble import IsolationForest

        self.names = self.names or feature_names(fit)
        self.scaler = RobustScaler().fit(_matrix(fit, self.names), self.names)
        X = self._x(fit)  # noqa: N806
        self.model = IsolationForest(n_estimators=200, max_samples=min(256, len(X)),
                                     random_state=self.seed, n_jobs=1).fit(X)  # fmt: skip
        return self

    def _x(self, df: pl.DataFrame) -> np.ndarray:
        raw = _lag_features(df, self.names, self.lags)
        k = len(self.names)
        x, lag = (self.scaler.transform(raw[:, i * k : (i + 1) * k]) for i in range(2))
        d1 = np.nan_to_num(raw[:, 2 * k :] / self.scaler.scale).astype(np.float32)  # not centred
        scaled = [x, lag, d1]
        return np.hstack(scaled)

    def score(self, df: pl.DataFrame) -> np.ndarray:
        return -self.model.score_samples(self._x(df))


def _sequences(df: pl.DataFrame, names: list[str], scaler: RobustScaler,
               seq_len: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:  # fmt: skip
    """For every row: the previous `seq_len` windows of the same key (zero-padded) with a gap
    channel, and the row's own scaled features (forecast target). Returns (Xseq, y, order)."""
    d = _ordered(df).with_row_index("_i")
    X = scaler.transform(_matrix(d, names))  # noqa: N806
    win = d["win"].to_numpy()
    keys = d["key"].to_numpy()
    n, f = X.shape
    seq = np.zeros((n, seq_len, f + 1), dtype=np.float32)
    start = 0
    for i in range(n):
        if i > 0 and keys[i] != keys[i - 1]:
            start = i
        lo = max(start, i - seq_len)
        hist = X[lo:i]
        if len(hist):
            gaps = np.log1p(np.diff(np.r_[win[lo] - 1, win[lo:i]]).astype(np.float32))
            seq[i, seq_len - len(hist) :, :f] = hist
            seq[i, seq_len - len(hist) :, f] = gaps
    return seq, X, d["_i"].to_numpy()


class _Forecaster:
    seq_len: int = 8
    epochs: int = 20
    hidden: int = 32
    seed: int = 0
    name: str = "forecaster"

    def _net(self, f: int):  # pragma: no cover - overridden
        raise NotImplementedError

    def fit(self, fit: pl.DataFrame):
        import torch

        torch.manual_seed(self.seed)
        torch.use_deterministic_algorithms(True, warn_only=True)
        self.names = getattr(self, "names", None) or feature_names(fit)
        self.scaler = RobustScaler().fit(_matrix(fit, self.names), self.names)
        seq, y, _ = _sequences(fit, self.names, self.scaler, self.seq_len)
        self.net = self._net(y.shape[1])
        opt = torch.optim.Adam(self.net.parameters(), lr=3e-3)
        xs, ys = torch.from_numpy(seq), torch.from_numpy(np.clip(y, -20, 20))
        g = torch.Generator().manual_seed(self.seed)
        t0 = time.perf_counter()
        self.net.train()
        for _ in range(self.epochs):
            perm = torch.randperm(len(xs), generator=g)
            for i in range(0, len(xs), 128):
                b = perm[i : i + 128]
                opt.zero_grad()
                loss = torch.nn.functional.smooth_l1_loss(self.net(xs[b]), ys[b])
                loss.backward()
                opt.step()
        self.train_seconds = time.perf_counter() - t0
        self.net.eval()
        err = np.abs(self._predict(seq) - y)
        self.err_scale = np.maximum(np.median(err, axis=0) * 1.4826, 0.1)
        return self

    def _predict(self, seq: np.ndarray) -> np.ndarray:
        import torch

        with torch.no_grad():
            return self.net(torch.from_numpy(seq)).numpy()

    def score(self, df: pl.DataFrame) -> np.ndarray:
        seq, y, order = _sequences(df, self.names, self.scaler, self.seq_len)
        s = top2((self._predict(seq) - np.clip(y, -20, 20)) / self.err_scale)
        out = np.empty(len(s))
        out[order] = s
        return out

    def n_parameters(self) -> int:
        return int(sum(p.numel() for p in self.net.parameters()))


class GRUForecaster(_Forecaster):
    name = "gru"

    def __init__(self, seq_len: int = 8, epochs: int = 20, hidden: int = 32, seed: int = 0):
        self.seq_len, self.epochs, self.hidden, self.seed = seq_len, epochs, hidden, seed

    def _net(self, f: int):
        from torch import nn

        class Net(nn.Module):
            def __init__(self, f_in, h, f_out):
                super().__init__()
                self.gru = nn.GRU(f_in, h, batch_first=True)
                self.out = nn.Linear(h, f_out)

            def forward(self, x):
                _, hN = self.gru(x)  # noqa: N806
                return self.out(hN[-1])

        return Net(f + 1, self.hidden, f)


class TCNForecaster(_Forecaster):
    name = "tcn"

    def __init__(self, seq_len: int = 8, epochs: int = 20, hidden: int = 32, seed: int = 0):
        self.seq_len, self.epochs, self.hidden, self.seed = seq_len, epochs, hidden, seed

    def _net(self, f: int):
        from torch import nn

        class CausalConv(nn.Module):
            def __init__(self, c_in, c_out, dilation):
                super().__init__()
                self.pad = 2 * dilation  # kernel 3: left padding only -> causal
                self.conv = nn.Conv1d(c_in, c_out, 3, dilation=dilation)

            def forward(self, x):
                return self.conv(nn.functional.pad(x, (self.pad, 0)))

        class Net(nn.Module):
            def __init__(self, f_in, h, f_out):
                super().__init__()
                self.l1, self.l2, self.l3 = CausalConv(f_in, h, 1), CausalConv(h, h, 2), (
                    CausalConv(h, h, 4))  # fmt: skip
                self.out = nn.Linear(h, f_out)

            def forward(self, x):  # x: (n, L, f) -> (n, f, L)
                z = x.transpose(1, 2)
                z = nn.functional.relu(self.l1(z))
                z = nn.functional.relu(self.l2(z)) + z
                z = nn.functional.relu(self.l3(z)) + z
                return self.out(z[:, :, -1])

        return Net(f + 1, self.hidden, f)


SCORERS = {"robust_z": RobustZ, "guarded_ewma": GuardedEWMA, "lag_iforest": LagIForest,
           "gru": GRUForecaster, "tcn": TCNForecaster}  # fmt: skip
