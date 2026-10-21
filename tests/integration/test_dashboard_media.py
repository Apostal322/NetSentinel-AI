"""Pillow 13 under Streamlit 1.66 (accepted temporary exception, see
docs/security/DEPENDENCY_EXCEPTIONS.md): the image paths the dashboard and Streamlit use, with
the bytes Streamlit actually stored decoded again by Pillow; matplotlib figure rendering; the
dashboard's real image and chart pages. Needs the `dashboard` extra."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
APP = str(ROOT / "dashboard" / "app.py")


def _image_matrix_script(figure: str, tmp: str) -> None:  # runs inside AppTest
    import io
    import json

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    import streamlit as st
    from PIL import Image
    from streamlit.runtime import Runtime

    fig, ax = plt.subplots(figsize=(3, 2), dpi=80)
    ax.plot([0, 1, 2], [1, 0, 2])
    mpl_png = f"{tmp}/mpl.png"
    fig.savefig(mpl_png)
    plt.close(fig)
    rgba = Image.new("RGBA", (40, 30), (200, 10, 10, 128))
    jpeg = io.BytesIO()
    Image.new("RGB", (32, 32), (0, 128, 255)).save(jpeg, format="JPEG")
    gif = io.BytesIO()
    frames = [Image.new("RGB", (16, 16), c) for c in ((255, 0, 0), (0, 255, 0), (0, 0, 255))]
    frames[0].save(gif, format="GIF", save_all=True, append_images=frames[1:], duration=50)
    big = Image.new("RGB", (3000, 200), (10, 200, 10))
    cases = {
        "repo_figure_path": dict(image=figure),
        "matplotlib_png_path": dict(image=mpl_png),
        "pil_rgba": dict(image=rgba),
        "numpy_rgb": dict(image=np.full((20, 30, 3), 127, dtype=np.uint8)),
        "jpeg_bytes": dict(image=jpeg.getvalue()),
        "gif_bytes": dict(image=gif.getvalue()),
        "resized_width": dict(image=big, width=300),
        "pil_rgba_as_jpeg": dict(image=rgba, output_format="JPEG"),
    }
    out = {}
    storage = Runtime.instance().media_file_mgr._storage
    for kw in cases.values():
        st.image(**kw)
    # Decode every stored media file with Pillow 13
    for fid, mf in list(storage._files_by_id.items()):
        im = Image.open(io.BytesIO(mf.content))
        im.load()
        out[fid] = {"mimetype": mf.mimetype, "format": im.format, "mode": im.mode,
                    "size": list(im.size), "frames": getattr(im, "n_frames", 1)}  # fmt: skip
    # Pillow 13 no longer clips 32-bit "I" images when saving PNG (streamlit#17589):
    try:
        st.image(Image.new("I", (8, 8), 70_000), output_format="PNG")
        out["_i_mode_png"] = "accepted"
    except Exception as exc:  # noqa: BLE001 - recorded, asserted by the test
        out["_i_mode_png"] = f"raised {type(exc).__name__}"
    st.code(json.dumps(out))


def test_streamlit_image_pipeline_with_pillow13(tmp_path):
    import PIL

    assert int(PIL.__version__.split(".")[0]) >= 13  # security floor (2026-10-20 advisories)
    figure = str(ROOT / "reports/figures/openset_recall.png")
    at = AppTest.from_function(_image_matrix_script, args=(figure, str(tmp_path)),
                               default_timeout=60)  # fmt: skip
    at.run()
    assert not at.exception, at.exception
    imgs = at.get("image")
    assert len(imgs) == 8, len(imgs)  # one element per case; I-mode case raised before render
    res = json.loads(at.code[0].value)
    i_mode = res.pop("_i_mode_png")
    assert i_mode.startswith("raised"), "Pillow/Streamlit I-mode PNG behaviour changed: review"
    decoded = list(res.values())
    assert len(decoded) == 8
    assert all(d["size"][0] > 0 and d["size"][1] > 0 for d in decoded)
    fmts = sorted(d["format"] for d in decoded)
    assert "GIF" in fmts and "JPEG" in fmts and "PNG" in fmts
    assert any(d["format"] == "GIF" and d["frames"] == 3 for d in decoded)  # animation kept
    assert any(d["size"] == [300, 20] for d in decoded)  # width=300 resize of 3000x200
    assert any(d["size"] == [1400, 476] and d["mode"] == "RGBA" for d in decoded)  # repo figure


def _store(tmp_path: Path) -> Path:
    from netsentinel.storage.events import EventStore
    from tests.integration.test_dashboard import _pred

    db = tmp_path / "events.sqlite"
    st = EventStore(db)
    st.add([_pred(i, "unusual" if i % 10 == 0 else "benign") for i in range(60)])
    st.close()
    return db


CHART_PAGES = [("Live traffic", 1), ("Traffic explorer", 1), ("Anomalies", 1),
               ("Application intelligence", 1)]  # fmt: skip


@pytest.mark.parametrize("page,min_charts", CHART_PAGES)
def test_dashboard_chart_pages_render_charts(tmp_path, monkeypatch, page, min_charts):
    monkeypatch.setenv("NETSENTINEL_EVENTS_DB", str(_store(tmp_path)))
    monkeypatch.setenv("NETSENTINEL_MODELS_DIR", str(tmp_path / "models"))
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.sidebar.radio[0].set_value(page).run()
    assert not at.exception, at.exception
    charts = at.get("vega_lite_chart")
    assert len(charts) >= min_charts, (page, len(charts))


def test_dashboard_research_page_serves_decodable_figures(tmp_path, monkeypatch):
    """The Research & diagnostics page shows the committed report figures through st.image."""
    monkeypatch.setenv("NETSENTINEL_EVENTS_DB", str(_store(tmp_path)))
    monkeypatch.setenv("NETSENTINEL_MODELS_DIR", str(tmp_path / "models"))
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.sidebar.radio[0].set_value("Research & diagnostics").run()
    assert not at.exception, at.exception
    imgs = at.get("image")
    names = ("binary_recall_by_label.png", "openset_recall.png", "adaptation_calibration.png")
    expected = [f for f in names if (ROOT / "reports/figures" / f).exists()]
    assert len(imgs) == len(expected) and expected
    urls = [u for el in imgs for u in el.value]
    assert all(u.startswith("/mock/media/") and u.endswith(".png") for u in urls), urls
