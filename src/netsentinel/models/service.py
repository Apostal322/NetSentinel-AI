"""Port-derived service categories.

This is a deterministic IANA-port heuristic, NOT a learned application classifier. A
destination port says which service a flow *claims* to talk to; it is not the application
identity (port 443 carries browsing, streaming, VPNs and malware alike). It is used as
(a) the conditioning context for service-aware anomaly detection and (b) the label of the
service-inference experiment, which asks how well flow shape alone recovers this category.
"""

from __future__ import annotations

import numpy as np
import polars as pl

SERVICE_PORTS: dict[str, tuple[int, ...]] = {
    "web": (80, 443, 8080, 8443, 8000, 8888),
    "dns": (53, 5353),
    "mail": (25, 110, 143, 465, 587, 993, 995),
    "file_transfer": (20, 21, 69, 989, 990),
    "remote_access": (22, 23, 3389, 5900, 5938),
    "windows_directory": (88, 135, 137, 138, 139, 389, 445, 464, 636, 3268, 3269),
    "time_mgmt": (123, 161, 162, 514),
}
SERVICE_CATEGORIES: tuple[str, ...] = (*SERVICE_PORTS, "other_wellknown", "ephemeral", "no_port")
_PORT_TO_SERVICE = {p: s for s, ports in SERVICE_PORTS.items() for p in ports}


def service_category_expr(port: str = "dst_port", protocol: str = "protocol") -> pl.Expr:
    mapping = pl.col(port).replace_strict(_PORT_TO_SERVICE, default=None, return_dtype=pl.Utf8)
    return (
        pl.when((pl.col(port) == 0) | (pl.col(protocol) == 0))
        .then(pl.lit("no_port"))
        .when(mapping.is_not_null())
        .then(mapping)
        .when(pl.col(port) < 1024)
        .then(pl.lit("other_wellknown"))
        .otherwise(pl.lit("ephemeral"))
        .alias("service")
    )


def service_category(dst_port: np.ndarray, protocol: np.ndarray) -> np.ndarray:
    df = pl.DataFrame({"dst_port": np.asarray(dst_port), "protocol": np.asarray(protocol)})
    return df.select(service_category_expr())["service"].to_numpy()
