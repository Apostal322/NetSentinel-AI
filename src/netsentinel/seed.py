"""Seeding without importing heavy frameworks that the current process does not use."""

from __future__ import annotations

import os
import random
import sys

import numpy as np


def set_seed(seed: int, deterministic_torch: bool = True) -> None:
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
    # Only touch torch if this process already imported it (keeps tabular runs light).
    torch = sys.modules.get("torch")
    if torch is not None:
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        if deterministic_torch:
            torch.backends.cudnn.deterministic = True
            torch.backends.cudnn.benchmark = False
