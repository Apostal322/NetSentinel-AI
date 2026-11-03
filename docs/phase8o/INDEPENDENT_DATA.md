# Phase 8o: desk check for an independent evaluation network (Part 13)

**What was done:** a desk check on 2026-11-03 of the official documentation pages only.
- Nothing was downloaded, no account or form was used, and no terms were accepted.
- The criteria are the Phase 8l E1–E7 (docs/phase8l/DATASET_ELIGIBILITY.md).
- The power requirement is docs/phase8l/POWER_ANALYSIS.md: 13–30 independent networks for an
  80 %-power network-level claim.

The check was done by a research subagent and its facts were not re-verified line by line. Each
verdict names its failing criterion.

| dataset (institution) | key facts | verdict |
|---|---|---|
| CIC-IDS2017 (UNB CIC) | benign Monday before the attack days; attacker and victim IPs and times published; CICFlowMeter bidirectional flows; 12 victim machines | **NOT ELIGIBLE**: E7 (same lab, traffic generator and flow tool as the consumed NF-CIC) and E2 (12 hosts) |
| CICIoT2023, CICIoMT2024, CICAPT-IIoT 2024, the 2025 IIoT release (UNB CIC) | per-attack captures; some CSVs have no IPs or timestamps | NOT ELIGIBLE: E7, E1, E4/E5 |
| BCCC-cPacket-Cloud-DDoS-2024 (York U., CIC lineage) | generated benign traffic; DDoS only | NOT ELIGIBLE: E7, E3 |
| Gotham 2025 (Cardiff U. / Toshiba) | GNS3 emulation, 78 IoT devices; one benign segment, but its timing is undocumented; one 23.8 GB archive | UNCLEAR, likely not eligible: E2 (emulated, scripted), E4, E6 |
| TII-SSRC-23 | benign ≈ 0.015 % of flows; separate per-type captures | NOT ELIGIBLE: E2, E4, E6 |
| TRUST Lab (2026), CyberFlowIoT-GICAP (2026), IoT-SFC v2 (2025), ACI-IoT-2023, Westermo (2023) | small IoT or testbed labs; benign and attack mostly in separate sessions; logins for some | NOT ELIGIBLE or UNCLEAR: E2, E4/E5, E6 |
| LANL 2015 / 2017 (real enterprise) | red-team *authentication* events, or no labels; flows without per-direction counts | NOT ELIGIBLE: E1, E3 |
| Edge-IIoTset, 5G-NIDD, Kitsune, MAWILab, CICIoV2024 | ≤ about 10 devices, backbone heuristics, or CAN bus | NOT ELIGIBLE: E2, E3, E1 |
| UGR'16 (real ISP) | calibration months before the test; injected attacks; unidirectional nfdump; site returned HTTP 403 | UNCLEAR, development only: E1, E2, E6 |

**Conclusion:**
- No eligible fresh independent network was found.
- A borderline candidate would add at most one unit, against the 13–30 needed.
- The Phase 8n status stands: **M2 is development-only; independent confirmation NOT
  EVALUABLE.**

**Unread sources:**
- the Gotham full text (benign timeline);
- the CyberFlowIoT-GICAP paper (HTTP 403);
- the UGR'16 site (HTTP 403).

**Official pages consulted:**
- unb.ca/cic/datasets: ids-2017, iotdataset-2023, iiot-dataset-2024, iiot-dataset-2025;
- zenodo.org/records/14502760 (Gotham);
- arxiv.org/abs/2502.03134 and arxiv.org/abs/2310.10661;
- frontiersin.org (10.3389/fcomp.2026.1803271);
- riubu.ubu.es/handle/10259/11273;
- zenodo.org/records/23371775;
- ieee-dataport.org (ACI-IoT-2023);
- github.com/westermo/network-traffic-dataset;
- csr.lanl.gov/data/cyber1 and csr.lanl.gov/data/2017;
- yorku.ca BCCC datasets;
- stratosphereips.org/datasets-overview;
- nesg.ugr.es/nesg-ugr16 (HTTP 403).
