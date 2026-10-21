# Dependency exceptions

This file lists deliberate deviations from upstream dependency metadata. Each one is
**an accepted temporary exception, not supported upstream compatibility**. It is enforced by
`scripts/release/check_dependency_exceptions.py`, which runs in CI and in
`tests/unit/test_dependency_exceptions.py`.

## E1: Pillow 13.0.0 with Streamlit 1.66.0 (accepted 2026-10-21)

| | |
|---|---|
| Upstream metadata | `streamlit 1.66.0` (latest release, and the 1.66.1 nightly of 2026-10-19) requires `pillow>=9.2.0,<13` |
| What we install | `pillow 13.0.0`, forced by `[tool.uv] override-dependencies = ["pillow>=13.0.0"]` in `pyproject.toml` |
| Why | Pillow 12.3.0 is affected by the advisories published 2026-10-20 (critical: GHSA-8g5g-8vmr-9782, GHSA-5x8w-8jj5-q52h, CVE-2026-96639; high: TIFF/PDF/JPEG/OpenJPEG issues; full list in the [Pillow 13.0.0 release notes](https://pillow.readthedocs.io/en/stable/releasenotes/13.0.0.html)). They are fixed only in 13.0.0; there is no 12.x backport |
| Scope | Lockfile-wide, since uv resolves one version per lock. The **Docker image** has no Streamlit (base dependencies only), so there the override conflicts with nothing and `uv pip check` is clean. The conflict exists only with the `dashboard` extra |
| `uv pip check` | With `--extra dashboard`, exactly one incompatibility: `streamlit requires pillow>=9.2.0,<13, but 13.0.0 is installed`. The gate accepts only this one |
| Upstream status | [streamlit/streamlit#17589](https://github.com/streamlit/streamlit/pull/17589) "Allow Pillow 13" (open since 2026-10-20) raises the bound to `<14`; issues [#17586](https://github.com/streamlit/streamlit/issues/17586), [#17587](https://github.com/streamlit/streamlit/issues/17587) |

### Compatibility review (Pillow 13.0.0 changes against our code paths)

- **NetSentinel itself** never imports PIL.
  - Its images are matplotlib (Agg) PNG figures, shown with `st.image` from files.
- **Removed APIs:** no use in NetSentinel, Streamlit 1.66.0 or matplotlib 3.11.2 (code search
  over the installed packages):
  - `Image.get_child_images`, `Image._show`;
  - `ImageCms...product_name/product_info`, `ExifTags.IFD.Makernote`;
  - `fromarray(mode=...)` type changes.
- **Streamlit's Pillow use** (`streamlit/elements/lib/image_utils.py`, `runtime/caching/hashing.py`):
  - `Image.open`, `convert("RGB")`, `save` (JPEG/PNG), `fromarray` without `mode`;
  - `resize` without `reducing_gap`;
  - GIF detection.
  - None of these changed behaviour in 13.0.0.
- **The one known break** (named in the upstream PR): `st.image` with a 32-bit `I`-mode image
  and `output_format="PNG"` now raises `OSError` instead of silently clipping to 16 bits.
  - The dashboard never produces `I`-mode images.
  - The test suite asserts this behaviour, so a change is noticed.
- **Not reviewed beyond the release notes:** Pillow C-level behaviour that Streamlit does not
  reach: TIFF/PSD/FITS/ICO/APNG encoding, `ImageColor.getcolor` for premultiplied modes,
  HarfBuzz text rendering.

### Verification (2026-10-21)

| Check | Result |
|---|---|
| Clean environment: fresh clone, empty venv, `uv sync --locked --extra dashboard --no-cache` | installs; versions identical to `uv.lock` (Python 3.12 markers) |
| `uv pip check` (dashboard extra) | 1 incompatibility, exactly E1 |
| Full test suite in the clean environment (no torch extra) | passes (torch tests skipped) |
| `tests/integration/test_dashboard_media.py` | `st.image` with repo PNG figure, matplotlib PNG, RGBA, numpy, JPEG, animated GIF and resize: Streamlit's stored bytes decode with Pillow 13 (formats, sizes, 3 GIF frames kept); the `I`-mode PNG raises; chart pages render Vega-Lite charts; the Research page serves the committed figures |
| Browser smoke (real `streamlit run`, Chromium, `scripts/release/dashboard_browser_probe.js`) | 10/10 pages without exceptions; 14/14 charts drawn; 3/3 figures decoded in the browser (one resized server-side by Pillow 13, 1800x840 -> 1460x681) |
| Docker (CI `docker` job) | `uv sync --frozen --no-dev --check` (image = lock), `uv pip check` clean, Pillow >= 13, no Streamlit in the image |
| OSV query of all locked packages | no known vulnerabilities |

Uploaded images are **not a dashboard feature**: the only upload accepts PCAP/Zeek captures,
so image upload decoding is not exercised and not claimed.

### Removal procedure (when Streamlit supports Pillow 13)

The gate fails CI as soon as the installed Streamlit's own metadata accepts the installed Pillow
("exception ... is no longer needed"). With `--online`, CI already warns when a Streamlit
release on PyPI allows Pillow 13. Then:

1. `uv lock --upgrade-package streamlit` (with approval).
2. Remove `override-dependencies` from `pyproject.toml`; `uv lock`; confirm Pillow stays >= 13.0.0.
3. Remove E1 from `ACCEPTED` in `scripts/release/check_dependency_exceptions.py` and mark it
   closed here.
4. Run the full suite, the browser probe and CI.

### Alternatives considered

- **Stay on Pillow 12.3.0** (metadata-consistent): rejected, keeps known critical
  vulnerabilities.
- **Separate resolution for the dashboard extra** (uv `conflicts`, Pillow 12 only with
  Streamlit): rejected. It is consistent but puts the vulnerable Pillow exactly where
  untrusted-looking image handling exists (Streamlit).
- **Older or newer Streamlit:** no released version allows Pillow 13 (checked PyPI and the
  nightly channel).
- **Vendor-patched Pillow 12.x:** none published.

Conclusion: no demonstrably safer, dependency-consistent alternative exists today; the override
stays.

### Remaining risk

- Streamlit has not run its own test suite against Pillow 13 in a release.
  - Code paths of Streamlit that NetSentinel does not use (e.g. `st.camera_input`,
    `st.file_uploader` with images, PIL-based caching hashes of user images) are covered only
    by the upstream PR's claim, not by our tests.
- A future Streamlit release could start using an API whose behaviour changed in 13.0.0
  before lifting the cap. The gate will not detect that; the media tests and browser probe
  might.
