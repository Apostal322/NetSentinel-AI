# Phase 8q Experiment A: ground-truth audit (`label-audit-1.0.0`)

**Status:** EXPLORATORY audit. It uses official documentation and raw labels; the raw labels are
never modified.

**Sources:**
- `scripts/phase8q/label_audit.py`;
- `data/derived/phase8q/label_audit/<domain>.parquet` (one row per evaluation window, in the
  Phase 8j B0 order);
- `reports/phase8q/label_audit.json`.

## 1. Datasets and label sources

| dataset (NetFlow v3 release) | publisher of the original capture | label unit | official attacker documentation | timezone / precision |
|---|---|---|---|---|
| NF-CIC-IDS2018-v3 (CSE-CIC-IDS2018) | UNB CIC and the Communications Security Establishment | flow (`label`, `attack`, `family`) | Table 2 at https://www.unb.ca/cic/datasets/ids-2018.html: attacker "valid IPs", victims, local start/finish per attack | local = UTC−4 (Atlantic standard time; DST began 2018-03-11, after every target day); minute precision |
| NF-UNSW-NB15-v3 | UNSW Canberra (Cyber Range) | flow | attack hosts 175.45.176.0–3 | — |
| NF-ToN-IoT-v3 | UNSW Canberra | flow | attacker range .30–.39 (the project page gives 192.168.159.30–39; in NF-ToN-IoT-v3 they appear as 192.168.1.30–39) | — |
| NF-BoT-IoT-v3 | UNSW Canberra | flow | none on the project page; roles are **data-derived** (> 100,000 evaluation attack flows) | — |

**Aggregation (unchanged since Phase 8b/8i):**
- A (source, 30 s) window is positive if one of its flows is labelled attack.
- Phase 8i's **benign** set excludes every window of any host that attacks in the domain
  (evaluation or calibration), and NF-CIC `infiltration` windows.

## 2. Evidence categories per evaluation window

The rules are given in full in the docstring of `label_audit.py`.

| domain | documented attack | documented, family mismatch | documented, outside interval | attacked-host traffic | undocumented source | attacker host, other window | benign (uninvolved / involved host) |
|---|---|---|---|---|---|---|---|
| NF-CIC 02-14 | 181 | 0 | 3 | 0 | 0 | 0 | 108,297 / 0 |
| NF-CIC 02-16 | 27 | 0 | 0 | 0 | 0 | 0 | 79,524 / 3 |
| NF-CIC 02-20 | 0 | **106** | 0 | 0 | 0 | 0 | 113,827 / 22 |
| NF-CIC 02-21 | 1,080 | 0 | 6 | 0 | 0 | 0 | 115,797 / 243 |
| NF-CIC 02-22 | 52 | 0 | 1 | 0 | **796** | 13,035 | 114,337 / 0 |
| NF-CIC 03-02 | 91 | 0 | **2,317** | 0 | 0 | 8 | 91,935 / 0 |
| NF-UNSW | 4,091 | — | — | 0 | 0 | 0 | 11,937 / 0 |
| NF-ToN | 5,598 | — | — | 3,187 | 0 | **32,924** | 7,447 / 0 |
| NF-BoT | 1,344 | — | — | 235 | 0 | 1,250 | 620 / 0 |

**Sources by role:**
- documented attackers: 48 (NF-CIC 30, NF-UNSW 4, NF-ToN 10, NF-BoT 4). On 03-02 these are the
  **documented infected hosts**: Table 2 lists them as Bot victims, and they are the sources of the
  bot traffic;
- attacked hosts: 7 (NF-ToN 3, NF-BoT 4);
- undocumented: 290, all on NF-CIC 02-22.

This reproduces the Phase 8p entity roles exactly: 48 / 5 / 22 entities with ≥ 5 windows.

**No window is "verified benign".** No dataset supplies independent benign evidence, so every
negative is dataset-labelled benign. `benign_uninvolved` is the stricter sensitivity population.

## 3. Conflicts found

| conflict | evidence | handling |
|---|---|---|
| **02-20: "LOIC-HTTP" windows inside the documented DDoS-LOIC-UDP interval** (13:13–13:32) | all 106 evaluation attack windows; 1,363 TCP SYN-only and 790 UDP flows; the raw day has *no* `ddos_loic_udp` label, though 02-21 does | `documented_family_mismatch`; kept in the documented-attacker view (V2), dropped in V1 strict |
| **03-02: bot traffic outside the documented intervals** | 2,317 of 2,408 windows (96 %) | the intervals describe operator activity, while infected hosts beacon all day. *Outside interval* does **not** imply mislabelled here, so V1 strict is a sensitivity view only |
| **02-22: 290 undocumented sources labelled `web_*`** | none is in the official table; 79 % of their windows are outside every documented interval of the day (Phase 8p) | `undocumented_source`; preserved; reported separately |
| **NF-ToN: 32,924 non-attack windows of attacker hosts** | they outnumber the 7,447 benign windows | outside both numerator and denominator (historical rule), reported |
| mixed attack windows (benign and attack flows in one window) | 02-22 192, 03-02 69, NF-ToN 5,979, NF-BoT 198 | flagged `mixed`; counted as attack (historical rule) |

## 4. Frozen M2 on the benchmark views (`reports/phase8q/benchmark_metrics.json`)

| score set | view | macro recall | entities R₂₀ / total |
|---|---|---|---|
| frozen M2, reference replicate (Phase 8n M2 base r0) | V0 historical | 0.788 | 44 / 75 |
| | **V2 documented attackers** | **0.904** | 37 / 48 |
| | V1 strict | 0.938 | 37 / 38 |
| | attacked-host traffic | 0.332 | 4 / 5 |
| | undocumented sources | 0.046 | 3 / 22 |
| Phase 8n M2 (12 fits) | V0 / V2 | 0.767 / 0.882 | 33 / 75 · 30 / 48 |
| Phase 8o F0 (6 fits; = Phase 8p S0) | V0 / V2 | 0.762 / 0.869 | 40 / 75 · 37 / 48 |

**The view changes the evaluation population, not the detector.** The higher V2 numbers do not
mean M2 improved. They mean the historical V0 counted undocumented sources, with recall 0.03–0.05,
as missed attackers.

**Reproduction:** the Phase 8o F0 rows reproduce Phase 8o (V0 0.762, R₂₀ 40) and Phase 8p S0 (V2
0.869, R₂₀ 37) exactly.

**Negative-population sensitivity:**
- **Uninvolved benign only:** false alerts change by at most 5 windows per domain.
- **Undocumented sources counted as benign:** they add 7–9 false-alert windows (frozen r0 NF-CIC
  1,345 → 1,354). M2 almost never alerts on them.

## 5. What is and is not established

- **Established:** a reproducible, versioned mapping from raw labels to evidence categories, its
  counts and the conflicts above.
- **Not established:**
  - that the undocumented sources are benign (undocumented is not benign);
  - that NF-BoT's data-derived roles match the testbed. The four heavy senders, 192.168.100.147–150,
    appear to be the BoT-IoT paper's attacking machines (Koroniotis et al. 2019); this is recalled,
    not verified here;
  - any per-host attack interval outside NF-CIC.
