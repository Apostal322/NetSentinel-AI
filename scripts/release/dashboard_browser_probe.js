// Browser smoke probe for the Streamlit dashboard (docs/security/DEPENDENCY_EXCEPTIONS.md).
//
// 1. Start the dashboard on demo data:
//      uv run netsentinel demo --workspace artifacts/demo --quiet
//      uv run --extra dashboard streamlit run dashboard/app.py --server.headless true \
//        -- --events-db artifacts/demo/events.sqlite --models-dir artifacts/demo/models
// 2. Open it in a browser, paste this into the developer console, wait about 60 s,
//    then run  JSON.stringify(window.__ns, null, 1)
// Pass: done=true, exceptions=0 on every page, vega_drawn == vega_charts, and on
// "Research & diagnostics" images_decoded == images > 0.
window.__ns = { done: false, out: {} };
(async () => {
  const pages = ["Live traffic", "Behavior intelligence", "Application intelligence",
    "Incident explorer", "Traffic explorer", "Anomalies", "Threats", "Analyze capture",
    "Model management", "Research & diagnostics"];
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  for (const p of pages) {
    const lab = [...document.querySelectorAll("label")].find((l) => l.innerText.trim() === p);
    if (!lab) { window.__ns.out[p] = "radio not found"; continue; }
    lab.click();
    await sleep(5000);
    const imgs = [...document.querySelectorAll("img")].filter((i) => i.src.includes("/media/"));
    const charts = document.querySelectorAll('[data-testid="stVegaLiteChart"]');
    window.__ns.out[p] = {
      images: imgs.length,
      images_decoded: imgs.filter((i) => i.complete && i.naturalWidth > 0).length,
      image_sizes: imgs.map((i) => `${i.naturalWidth}x${i.naturalHeight}`),
      vega_charts: charts.length,
      vega_drawn: [...document.querySelectorAll(
        '[data-testid="stVegaLiteChart"] canvas, [data-testid="stVegaLiteChart"] svg')]
        .filter((c) => (c.width?.baseVal?.value || c.width || c.clientWidth) > 0).length,
      exceptions: document.querySelectorAll('[data-testid="stException"]').length,
      tables: document.querySelectorAll('[data-testid="stDataFrame"]').length,
    };
  }
  window.__ns.done = true;
})();
