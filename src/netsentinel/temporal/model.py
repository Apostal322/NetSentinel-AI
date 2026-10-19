"""Compact temporal models (PyTorch, imported lazily by callers).

`FlowMLP`  : target-flow features only (control: same training setup, no sequence).
`SeqGRU`   : GRU over the causal per-port flow sequence + the same flow MLP, fused by a head.
Sizes are deliberately small (~50k parameters) for a 4 GB GTX 1050 Ti / CPU.
"""

from __future__ import annotations

import torch
from torch import nn


class FlowMLP(nn.Module):
    def __init__(self, n_flow: int, hidden: int = 128, dropout: float = 0.1):
        super().__init__()
        self.body = nn.Sequential(
            nn.Linear(n_flow, hidden), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden, 64), nn.ReLU(),
        )  # fmt: skip
        self.head = nn.Linear(64, 1)

    def forward(self, flow: torch.Tensor, seq=None, mask=None) -> torch.Tensor:
        return self.head(self.body(flow)).squeeze(-1)


class SeqGRU(nn.Module):
    def __init__(self, n_flow: int, n_step: int, hidden: int = 64, dropout: float = 0.1):
        super().__init__()
        self.flow = FlowMLP(n_flow).body
        self.gru = nn.GRU(n_step + 1, hidden, batch_first=True)  # + mask channel
        self.head = nn.Sequential(
            nn.Linear(64 + hidden, 64), nn.ReLU(), nn.Dropout(dropout), nn.Linear(64, 1)
        )

    def forward(self, flow: torch.Tensor, seq: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        # Sequences are right-aligned (padding first), so the last hidden state summarises the
        # most recent flows; the mask channel tells the GRU which steps are padding.
        _, h = self.gru(torch.cat([seq, mask.unsqueeze(-1).float()], dim=-1))
        return self.head(torch.cat([self.flow(flow), h[-1]], dim=-1)).squeeze(-1)


def count_parameters(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters() if p.requires_grad)
