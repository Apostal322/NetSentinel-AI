# NetSentinel AI: Literature Review

- **Review date:** 2026-10-19
- **Scope:** flow-based network intrusion detection (NIDS) on CSE-CIC-IDS2018, plus the evaluation-methodology literature that should shape how NetSentinel is tested.
- **Status:** This document reports **no NetSentinel results**. Every number below comes from the cited authors and is marked as such. If a number was not checked against the paper or its abstract, the entry says "not extracted".

## How sources were verified

Each source was checked on 2026-10-19 with web search plus at least one of:

1. Crossref metadata lookup for the DOI (`api.crossref.org/works/<DOI>`). This confirmed title, authors, venue and year.
2. A fetch of the publisher, proceedings or arXiv landing page.
3. A full-text read of the PDF.

The **Verified via** field shows which checks apply. Summaries are written in our own words. "Reported results" lists only figures that were seen in the paper, its abstract or its official landing page.

Abbreviations: **FT** = full text read; **Abs** = abstract or landing page read; **XR** = Crossref metadata confirmed.

---

## 1. Surveys of ML-based and flow-based NIDS

### 1.1 Outside the Closed World: On Using Machine Learning for Network Intrusion Detection
- **Authors / Year / Venue:** R. Sommer, V. Paxson. 2010. IEEE Symposium on Security and Privacy.
- **DOI:** https://doi.org/10.1109/SP.2010.25 (XR). Author PDF: https://www1.icsi.berkeley.edu/pubs/networking/outsidethe10.pdf
- **Dataset(s):** None (position paper).
- **Approach:** Argues that intrusion detection differs structurally from domains where ML succeeds. The reasons given are: anomaly detection finds novelty, not maliciousness; errors are very costly; there is a semantic gap between alerts and operator meaning; traffic is highly diverse; and evaluation is hard.
- **Evaluation protocol:** Not applicable.
- **Reported results:** Not applicable.
- **Limitations:** Written before deep learning and before the CIC datasets existed. It gives qualitative guidance only.
- **Relevance:** This is the foundation for H2 and H4. "Unusual" is not the same as "malicious", so an anomaly score needs context (service, time) before it means anything to an operator. It also motivates reporting false alerts per hour rather than accuracy.

### 1.2 A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection
- **Authors / Year / Venue:** A. L. Buczak, E. Guven. 2016. IEEE Communications Surveys & Tutorials 18(2).
- **DOI:** https://doi.org/10.1109/COMST.2015.2494502 (XR)
- **Dataset(s):** Reviews work on DARPA/KDD-era and other datasets.
- **Approach:** Taxonomy of ML and data-mining methods (misuse, anomaly, hybrid) used for intrusion detection.
- **Evaluation protocol / Reported results:** Survey. Not extracted.
- **Limitations:** Predates CIC-IDS2017/2018 and modern deep sequence models. Most of the surveyed work uses KDD-era data with known flaws.
- **Relevance:** Background taxonomy only. It supports the choice of classical baselines.

### 1.3 Flow-based intrusion detection: Techniques and challenges
- **Authors / Year / Venue:** M. F. Umer, M. Sher, Y. Bi. 2017. Computers & Security 70, pp. 238-254.
- **DOI:** https://doi.org/10.1016/j.cose.2017.05.009 (XR)
- **Dataset(s):** Survey of flow-based datasets.
- **Approach:** Introduces flow-based IDS, gives a taxonomy organised by detection technique on IP flow records, and lists open challenges.
- **Evaluation protocol / Reported results:** Survey. Not extracted.
- **Limitations:** Predates CSE-CIC-IDS2018.
- **Relevance:** Defines the flow-record setting that NetSentinel works in, where there is no payload and only per-flow statistics.

### 1.4 SoK: Pragmatic Assessment of Machine Learning for Network Intrusion Detection
- **Authors / Year / Venue:** G. Apruzzese, P. Laskov, J. Schneider. 2023. IEEE EuroS&P, pp. 592-614.
- **DOI:** https://doi.org/10.1109/EuroSP57164.2023.00042 (XR). arXiv: https://arxiv.org/abs/2305.00550 (Abs)
- **Dataset(s):** Not named in the abstract. Not extracted.
- **Approach:** Argues that NID research optimises for "outperforming" prior work and ignores deployment factors. Proposes a "pragmatic assessment" methodology and includes a user study with practitioners.
- **Evaluation protocol:** Re-assessment across hundreds of configurations, adversarial scenarios and four hardware platforms (per the abstract).
- **Reported results:** Not extracted.
- **Limitations:** Full methodology not reviewed here.
- **Relevance:** Supports reporting runtime and memory, operating-point metrics, and practitioner-facing costs. This matters for an 8 GB / 4 GB VRAM development budget.

### 1.5 Dos and Don'ts of Machine Learning in Computer Security
- **Authors / Year / Venue:** D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro, K. Rieck. 2022. USENIX Security, pp. 3971-3988.
- **URL:** https://www.usenix.org/conference/usenixsecurity22/presentation/arp (Abs). arXiv:2010.09470 (FT)
- **Dataset(s):** Prevalence study of 30 top-tier security papers. Impact case studies on Android malware, vulnerability discovery, authorship attribution, and the Kitsune Mirai capture.
- **Approach:** Names ten pitfalls: sampling bias, label inaccuracy, data snooping (test, temporal, selective), spurious correlations, biased parameter selection, inappropriate baseline, inappropriate measures, base-rate fallacy, lab-only evaluation, and inappropriate threat model.
- **Evaluation protocol:** Two independent reviewers per paper. Krippendorff's alpha of 0.832 is reported.
- **Reported results (by the authors):**
  - Sampling bias was at least partly present in 90% of papers and data snooping in 73%.
  - Every paper showed at least three pitfalls.
  - On the Kitsune Mirai capture, a one-feature boxplot baseline (packet count per 10 s window) beat the Kitsune autoencoder ensemble. AUC was 0.998 vs 0.968, and TPR at FPR 0.001 was 0.996 vs 0.882.
- **Limitations:** The paper selection is not exhaustive. The NIDS case uses a single, very conspicuous attack capture.
- **Relevance:** This is the methodological checklist for the project. The Kitsune result supports H1 and H3 directly: simple windowed volume statistics are a mandatory baseline before any GRU or TCN model.

---

## 2. Original dataset papers

### 2.1 Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization
- **Authors / Year / Venue:** I. Sharafaldin, A. Habibi Lashkari, A. A. Ghorbani. 2018. ICISSP, pp. 108-116.
- **DOI:** https://doi.org/10.5220/0006639801080116 (XR, FT)
- **Dataset(s):** **CICIDS2017**, captured 3-7 July 2017 over five days. The paper describes this dataset, not CSE-CIC-IDS2018.
- **Approach:** Testbed with B-Profile benign agents. Flows extracted with CICFlowMeter (80 features). Per-attack feature importance from a random forest regressor, then seven classifiers.
- **Evaluation protocol:** Weighted-average precision, recall and F1. The split procedure is not described in the paper.
- **Reported results (by the authors, CICIDS2017):** RF weighted Pr 0.98, Rc 0.97, F1 0.97. ID3 0.98/0.98/0.98. Naive Bayes Rc 0.04.
- **Limitations:**
  - Labels come from attack schedule and IP addresses only.
  - Metrics are aggregate weighted averages with no per-class detail.
  - No split protocol is given.
  - Init Win bytes features are listed among the top features for brute force, web attacks and port scan. Section 3.1 treats these as likely artefacts.
- **Relevance:** The CSE-CIC-IDS2018 page on the UNB site names this paper as the one to cite for IDS2018. It is the de facto citation, but its experiments are on CICIDS2017. See "Facts that affect the pipeline" below.

### 2.2 CSE-CIC-IDS2018 dataset page (primary documentation, not peer reviewed)
- **URL:** https://www.unb.ca/cic/datasets/ids-2018.html (Abs). AWS registry: https://registry.opendata.aws/cse-cic-ids2018
- **Content:**
  - Attack schedule: brute force 14 Feb; DoS 15-16 Feb; DDoS 20-21 Feb; web attacks 22-23 Feb; infiltration 28 Feb and 1 Mar; botnet (Zeus and Ares) 2 Mar.
  - Infrastructure: 50 attacking machines; a victim organisation with 420 machines and 30 servers.
  - Flows extracted with CICFlowMeter-V3. Flows are labelled by schedule, IP, port and protocol.
- **Notes (observed on the page):**
  - Times are listed without a time zone.
  - The feature count is stated inconsistently ("more than 80" in one place, 83 in another).
  - Heartbleed is described but has no date in the schedule table.
- **Relevance:** This is the authoritative attack schedule. Any time-window logic in NetSentinel must treat these windows as approximate (Section 3.2).

### 2.3 Characterization of Encrypted and VPN Traffic Using Time-Related Features
- **Authors / Year / Venue:** G. Draper-Gil, A. H. Lashkari, M. S. I. Mamun, A. A. Ghorbani. 2016. ICISSP, pp. 407-414.
- **DOI:** https://doi.org/10.5220/0005740704070414 (XR)
- **Dataset(s):** ISCX VPN-nonVPN, introduced in this paper.
- **Approach:** Uses time-related flow features to detect VPN traffic and to classify encrypted traffic into categories such as browsing and streaming. Classifiers are C4.5 and KNN.
- **Evaluation protocol / Reported results:** Not extracted.
- **Limitations:** Small, lab-generated capture. Later work shows datasets of this kind contain shortcuts (Section 5).
- **Relevance:** This is the only labelled service/application dataset that matches the CICFlowMeter feature family. Adding it would let H2 condition on real application labels rather than port-derived categories.

### 2.4 CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment
- **Authors / Year / Venue:** E. C. P. Neto, S. Dadkhah, R. Ferreira, A. Zohourian, R. Lu, A. A. Ghorbani. 2023. Sensors 23(13):5941.
- **DOI:** https://doi.org/10.3390/s23135941 (XR, Abs)
- **Dataset(s):** CICIoT2023. 33 attacks in 7 categories (DDoS, DoS, Recon, web, brute force, spoofing, Mirai) on a 105-device IoT topology (per the abstract).
- **Evaluation protocol / Reported results:** Not extracted.
- **Limitations:** Corpus sizes quoted by third parties disagree, so the source paper should be checked before citing a count. This is the same lab lineage as IDS2018, so similar labelling caveats may apply. That is untested.
- **Relevance:** A possible later external-validity dataset. Unlike IDS2018 it contains a Recon (scan) category.

---

## 3. Dataset critiques and labelling errors (highest priority for NetSentinel)

### 3.1 Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study
- **Authors / Year / Venue:** G. Engelen, V. Rimmer, W. Joosen. 2021. IEEE Security and Privacy Workshops (WTMC), pp. 7-12.
- **DOI:** https://doi.org/10.1109/SPW53761.2021.00009 (XR, FT)
- **Dataset(s):** CICIDS2017, regenerated from the original PCAPs. Includes a preliminary check of CSE-CIC-IDS2018.
- **Approach:** Manual audit of attack simulation, flow construction, labelling and features. Fixes CICFlowMeter so that a flow ends on mutual FIN and on RST. Adds an "X - Attempted" label for attack-tool connections that carry no forward payload.
- **Evaluation protocol:** Random forest with a 75/25 split. Per-class precision, recall and F1.
- **Reported results (by the authors):**
  - **Data problems:**
    - "TCP appendices" make up 25.9% of CICIDS2017 flows. These are leftover flows created because CICFlowMeter ends a flow at the first FIN.
    - More than 20% of traces were reconstructed or relabelled.
    - The DoS Hulk tool was misimplemented (it set Connection: Close).
  - **Model behaviour:**
    - Aggregate weighted metrics stayed at 0.99 across all dataset versions, while per-class F1 changed sharply. Web XSS went from 0.18 to 0.79 and Bot from 0.60 to 0.99.
    - The RF separated appendix flows by class using Fwd Header Len, Total Fwd Pkt, Min Seg Size Fwd and Init Win bytes Fwd. The authors describe this as shortcut learning.
  - **IDS2018:** They state that their preliminary look at CSE-CIC-IDS2018 also found flow-construction errors.
- **Limitations:** Detailed analysis covers CICIDS2017 only. The evaluation uses a random split.
- **Relevance:** The original IDS2018 CSVs (CICFlowMeter-V3) probably share these flow-construction artefacts. Init Win bytes and header-length features need explicit ablation. Aggregate metrics must never be the headline.

### 3.2 Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018
- **Authors / Year / Venue:** L. Liu, G. Engelen, T. Lynar, D. Essam, W. Joosen. 2022. IEEE CNS, pp. 254-263.
- **DOI:** https://doi.org/10.1109/CNS56114.2022.9947235 (XR, Abs). Companion documentation (read 2026-10-19): https://intrusion-detection.distrinet-research.be/CNS2022/ and its CSE-CIC-IDS2018 page https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html
- **Dataset(s):** CIC-IDS-2017 and CSE-CIC-IDS-2018, recreated from PCAPs with corrected labelling logic that is published.
- **Approach:** Lifecycle audit covering attack orchestration, feature generation, documentation and labelling. Introduces "Attempted" sub-categories.
- **Evaluation protocol:** Experiments demonstrating impact. Details not extracted.
- **Reported results:** The paper's experiment numbers were not extracted. Documented issues for IDS2018 (from the companion page) are listed below.
  - **Brute force and DoS (14-16 Feb):**
    - 14 Feb, FTP brute force: port 21 was closed, so no brute force took place. Flows are relabelled Attempted.
    - 16 Feb, DoS SlowHTTPTest: no successful attack was found. The tool appears to have targeted port 21.
    - Heartbleed: no evidence of it in the data.
  - **DDoS (20-21 Feb):**
    - 20 Feb: LOIC-UDP flows were originally labelled LOIC-HTTP.
    - 21 Feb: HOIC began about 6 minutes after the documented time.
  - **Web attacks (22-23 Feb):**
    - 22 Feb, web brute force: the documented time does not match the original labels. The documentation gives it in New Brunswick local time.
    - 23 Feb, web brute force: 151 of 362 originally labelled flows (41.7%) are mislabelled. These include 128 UDP flows on port 500 and DHCP traffic.
  - **Infiltration (28 Feb and 1 Mar):**
    - The "Infiltration" period includes an Nmap scan run from the victim against 21 hosts.
    - Victim-to-attacker communication flows were originally labelled benign.
    - The Dropbox download stage cannot be verified because the traffic is TLS-encrypted.
  - **Bot (2 Mar):** Only Ares traffic was found, no Zeus. It used port 8080 only, and some activity falls outside the stated time window.
  - **Cross-cutting issues:**
    - Official time windows are often off by minutes.
    - The old CICFlowMeter treated ICMP as UDP and parsed ARP as IP flows (8.6.0.1 / 8.6.0.4).
    - A TCP segmentation issue produces flows with protocol and ports equal to 0.
    - The 120 s flow timeout splits long connections such as Slowloris.
    - The published labelling rules themselves contain errors (copy-paste time windows, a corrupted Unix timestamp, a date typo).
- **Limitations:** Corrections cover what could be reverse-engineered from PCAPs. Encrypted stages stay unverifiable.
- **Relevance:** This is the single most important source for the NetSentinel pipeline. Several original IDS2018 classes are partly or largely artefacts of failed attacks, so per-class results on the original CSVs measure label artefacts as much as detection ability.

### 3.3 Bad Design Smells in Benchmark NIDS Datasets
- **Authors / Year / Venue:** R. Flood, G. Engelen, D. Aspinall, L. Desmet. 2024. IEEE EuroS&P, pp. 658-675.
- **DOI:** https://doi.org/10.1109/EuroSP60621.2024.00042 (XR). Abstract seen via search snippets of https://ieeexplore.ieee.org/document/10629000. The IEEE page did not render on direct fetch.
- **Dataset(s):** Seven highly cited NIDS benchmark datasets (the list was not extracted).
- **Approach:** Manual analysis identifying six "data design smells". The search summary lists them as limited feature diversity, high feature interdependence, ambiguous ground truth, collapsed traffic distributions, artificial diversity and labelling inaccuracies. Six heuristics are then used to measure how common each smell is.
- **Reported results:** Four demonstrated cases of severe experimental bias (per the abstract). Numbers not extracted.
- **Limitations:** The full text was not read. The smell list above comes from a secondary summary.
- **Relevance:** Supports testing for "collapsed" distributions: if one or two features separate a class perfectly, that should be treated as suspicious rather than celebrated.

### 3.4 A survey and analysis of intrusion detection models based on CSE-CIC-IDS2018 Big Data
- **Authors / Year / Venue:** J. L. Leevy, T. M. Khoshgoftaar. 2020. Journal of Big Data 7.
- **DOI:** https://doi.org/10.1186/s40537-020-00382-x (XR, Abs)
- **Dataset(s):** CSE-CIC-IDS2018. The authors describe it as about 16,000,000 instances over ten days, with roughly 17% attack traffic.
- **Approach:** Survey of published IDS2018 models.
- **Reported results (by the authors):** Best reported scores were unexpectedly high, possibly from overfitting. Most works did not address class imbalance, and data-cleaning descriptions were inadequate.
- **Limitations:** Does not use the later error analyses (3.1-3.2).
- **Relevance:** Independent confirmation that the published IDS2018 numbers are not a reliable bar to beat.

### 3.5 Investigating Generalized Performance of Data-Constrained Supervised ML Models on Novel, Related Samples in Intrusion Detection
- **Authors / Year / Venue:** L. D'hooge, M. Verkerken, T. Wauters, F. De Turck, B. Volckaert. 2023. Sensors 23(4):1846.
- **DOI:** https://doi.org/10.3390/s23041846 (XR, Abs)
- **Dataset(s):** Trained on CSE-CIC-IDS2018 attack classes. Tested on the matching classes of CIC-IDS2017, CIC-DoS2017 and CIC-DDoS2019.
- **Approach:** Binary classifiers from several algorithm families, at several levels of data access.
- **Evaluation protocol:** Cross-dataset transfer.
- **Reported results (by the authors):**
  - For brute force, DoS and DDoS, the best models lost less than 5% in precision and recall.
  - For botnet, recall dropped by about 35% while precision stayed at 98% or higher.
  - Web-attack and infiltration models showed total loss of precision.
- **Limitations:** Uses the original labels, which carry the errors in 3.2.
- **Relevance:** Expect volumetric families to transfer and web/infiltration to fail. This is a prior for H4.

### 3.6 Machine Learning in Network Intrusion Detection: A Cross-Dataset Generalization Study
- **Authors / Year / Venue:** M. Cantone, C. Marrocco, A. Bria. 2024. IEEE Access 12, pp. 144489-144508. arXiv title: "On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection".
- **DOI:** https://doi.org/10.1109/ACCESS.2024.3472907 (XR). arXiv: https://arxiv.org/abs/2402.10974 (Abs)
- **Dataset(s):** CIC-IDS-2017, CSE-CIC-IDS2018, LycoS-IDS2017, and LycoS-Unicas-IDS2018 (a corrected IDS2018 that the authors built).
- **Approach:** Four classifiers trained on one dataset and tested on another.
- **Reported results (by the authors):** Near-perfect within a dataset. Cross-dataset results were largely at chance level, except for a few attack/dataset pairs.
- **Limitations:** Model families are limited.
- **Relevance:** A strong prior that high within-IDS2018 scores reflect dataset-specific signal. LycoS-Unicas-IDS2018 is a candidate corrected-label source (not yet assessed).

### 3.7 Towards a Standard Feature Set for Network Intrusion Detection System Datasets
- **Authors / Year / Venue:** M. Sarhan, S. Layeghy, M. Portmann. Mobile Networks and Applications 27, pp. 357-370. Published online 2021; volume 2022.
- **DOI:** https://doi.org/10.1007/s11036-021-01843-0 (XR). arXiv: https://arxiv.org/abs/2101.11315
- **Dataset(s):** NetFlow versions of UNSW-NB15, BoT-IoT, ToN-IoT and CSE-CIC-IDS2018 (NF-*-v2).
- **Approach:** Proposes a common 43-feature NetFlow set so results can be compared across datasets. Evaluated with Extra Trees.
- **Reported results:** Not extracted.
- **Limitations:** NetFlow v9 fields (for example TTL fields) differ from CICFlowMeter features, so artefacts differ between the two versions.
- **Relevance:** An alternative representation of IDS2018 that could be used for robustness checks.

---

## 4. Anomaly detection and multivariate time-series AD

### 4.1 Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection
- **Authors / Year / Venue:** Y. Mirsky, T. Doitshman, Y. Elovici, A. Shabtai. 2018. NDSS.
- **DOI:** https://doi.org/10.14722/ndss.2018.23204 (XR; resolves to the NDSS PDF). arXiv:1802.09089 (Abs)
- **Dataset(s):** The authors' own captures, including an IoT Mirai capture.
- **Approach:** Unsupervised and online. Damped-window incremental statistics per channel feed an ensemble of small autoencoders (KitNET). Training uses a benign prefix.
- **Reported results:** The abstract makes only qualitative claims (comparable to offline detectors; runs on a Raspberry Pi). Not extracted. Arp et al. (1.5) report Kitsune AUC 0.968 on the Mirai capture.
- **Limitations:** Needs per-host, per-channel state built from packet streams. A simple volume baseline matched or beat it on its own Mirai data (1.5).
- **Relevance:** Model for multi-scale damped temporal statistics (H3). Its per-host channels cannot be rebuilt from IDS2018 CSVs that lack IPs.

### 4.2 USAD: UnSupervised Anomaly Detection on Multivariate Time Series
- **Authors / Year / Venue:** J. Audibert, P. Michiardi, F. Guyard, S. Marti, M. A. Zuluaga. 2020. KDD, pp. 3395-3404.
- **DOI:** https://doi.org/10.1145/3394486.3403392 (XR)
- **Dataset(s):** Five public MTS benchmarks plus Orange proprietary data.
- **Approach:** Autoencoders trained adversarially. Anomaly score from reconstruction error.
- **Reported results:** Not extracted.
- **Limitations:** Evaluated on the benchmark families criticised in 4.4.
- **Relevance:** Candidate window-level reconstruction scorer for network-wide or per-port aggregate series.

### 4.3 Anomaly Transformer: Time Series Anomaly Detection with Association Discrepancy
- **Authors / Year / Venue:** J. Xu, H. Wu, J. Wang, M. Long. 2022. ICLR (spotlight).
- **URL:** https://arxiv.org/abs/2110.02642. ICLR page: https://iclr.cc/virtual/2022/spotlight/7024
- **Dataset(s):** Six benchmarks (service monitoring, space/earth, water treatment).
- **Approach:** Self-attention with an "association discrepancy" criterion and minimax training.
- **Reported results:** The authors claim state of the art on six benchmarks. Numbers not extracted.
- **Limitations:** Uses the same benchmark families criticised in 4.4. Too heavy for the local 4 GB GPU at scale.
- **Relevance:** Cited as context only. Not planned for NetSentinel.

### 4.4 Current Time Series Anomaly Detection Benchmarks are Flawed and are Creating the Illusion of Progress
- **Authors / Year / Venue:** R. Wu, E. J. Keogh. IEEE TKDE (published 2021 per Crossref). Extended abstract at ICDE 2022.
- **DOI:** https://doi.org/10.1109/TKDE.2021.3112126 (XR). arXiv: https://arxiv.org/abs/2009.13807 (Abs)
- **Dataset(s):** Yahoo, Numenta, NASA and related benchmarks.
- **Approach:** Shows that most benchmark exemplars have at least one of four flaws. Introduces the UCR Time Series Anomaly Archive.
- **Reported results:** Qualitative; the authors argue reported progress may be illusory.
- **Limitations:** Not about network traffic.
- **Relevance:** Before claiming gains from temporal deep learning, check whether a one-line detector (a threshold on a rolling count) already solves the task. Section 3.2 suggests several IDS2018 attacks are this kind of trivial volume spike.

### 4.5 An Empirical Evaluation of Generic Convolutional and Recurrent Networks for Sequence Modeling (TCN)
- **Authors / Year / Venue:** S. Bai, J. Z. Kolter, V. Koltun. 2018. arXiv preprint.
- **URL:** https://arxiv.org/abs/1803.01271 (Abs)
- **Dataset(s):** Standard sequence-modelling benchmarks (not security).
- **Approach:** Causal dilated convolutions with residual blocks (TCN), compared with LSTM/GRU.
- **Reported results:** The authors report that a simple convolutional architecture beats canonical recurrent networks across many tasks and has longer effective memory. Numbers not extracted.
- **Limitations:** Not peer reviewed in this form. No network-traffic tasks.
- **Relevance:** Justifies TCN alongside GRU as the compact temporal model (H3).

---

## 5. Transformers, representation learning and encrypted-traffic classification

### 5.1 ET-BERT: A Contextualized Datagram Representation with Pre-training Transformers for Encrypted Traffic Classification
- **Authors / Year / Venue:** X. Lin, G. Xiong, G. Gou, Z. Li, J. Shi, J. Yu. 2022. The Web Conference (WWW), pp. 633-642.
- **DOI:** https://doi.org/10.1145/3485447.3512217 (XR). arXiv:2202.06335 (Abs)
- **Dataset(s):** Five tasks. The abstract names ISCX-Tor, ISCX-VPN-Service, Cross-Platform (Android) and CSTNET-TLS 1.3.
- **Approach:** BERT-style pre-training on unlabelled datagram bytes, then fine-tuning.
- **Reported results (by the authors):** F1 99.2% (ISCX-Tor, +4.4), 98.9% (ISCX-VPN-Service, +5.2), 92.5% (Cross-Platform, +5.4), 97.4% (CSTNET-TLS 1.3, +10.0).
- **Limitations:** Needs packet bytes, which IDS2018 CSVs do not have. The Sugar critique (5.4) attributes much of this class of result to shortcuts.
- **Relevance:** Context for why NetSentinel does not use payload-level pre-training.

### 5.2 FlowTransformer: A Transformer Framework for Flow-based Network Intrusion Detection Systems
- **Authors / Year / Venue:** L. D. Manocchio, S. Layeghy, W. W. Lo, G. K. Kulatilleke, M. Sarhan, M. Portmann. 2024. Expert Systems with Applications 241:122564.
- **DOI:** https://doi.org/10.1016/j.eswa.2023.122564 (XR). arXiv:2304.14746 (Abs)
- **Dataset(s):** Three public NIDS benchmarks (not named in the abstract).
- **Approach:** Modular transformer over sequences of flows with swappable input encoding and classification head (GPT-2 and BERT-style variants).
- **Reported results (by the authors):** The classification head has the largest effect on performance. Global average pooling performs poorly. Model size can be cut by more than 50% without losing accuracy.
- **Limitations:** The split protocol for flow sequences was not reviewed. Sequence windows over correlated flows are prone to the leakage described in 6.3.
- **Relevance:** The closest prior work to NetSentinel's flow-sequence models. A design reference for GRU/TCN heads.

### 5.3 Deep Packet: a novel approach for encrypted traffic classification using deep learning
- **Authors / Year / Venue:** M. Lotfollahi, M. Jafari Siavoshani, R. Shirali Hossein Zade, M. Saberian. Soft Computing (online 2019; issue 3/2020).
- **DOI:** https://doi.org/10.1007/s00500-019-04030-2 (XR). arXiv:1709.02656 (Abs). Author order differs between the arXiv and published versions; the published order is given here.
- **Dataset(s):** ISCX VPN-nonVPN.
- **Approach:** CNN and stacked autoencoder on packet bytes.
- **Reported results (by the authors, arXiv abstract):** Recall 0.98 for application identification and 0.94 for traffic categorisation.
- **Limitations:** Packet-level only. Exposed to the shortcut issues in 5.4.
- **Relevance:** Shows that ISCX VPN-nonVPN application labels are learnable, which bears on H2 feasibility. Its numbers should not be taken as a ceiling for flow-only features.

### 5.4 The Sweet Danger of Sugar: Debunking Representation Learning for Encrypted Traffic Classification
- **Authors / Year / Venue:** Y. Zhao, G. Dettori, M. Boffa, L. Vassio, M. Mellia. 2025. ACM SIGCOMM.
- **DOI:** https://doi.org/10.1145/3718958.3750498 (XR). arXiv:2507.16438 (Abs)
- **Dataset(s):** Public encrypted-traffic benchmarks (list not extracted).
- **Approach:** Re-evaluates pre-trained traffic models under corrected data preparation. Proposes Pcap-Encoder.
- **Reported results (by the authors):** Prior models promise up to 98% accuracy. The authors find these successes come largely from data-preparation problems that let models learn shortcuts, and that performance is poor once the shortcuts are removed.
- **Limitations:** Only the abstract was read.
- **Relevance:** Strong evidence that application inference on ISCX-style data needs leakage-aware splits by capture session. Directly relevant if ISCX VPN-nonVPN is added for H2.

### 5.5 Yet Another Traffic Classifier: A Masked Autoencoder Based Traffic Transformer with Multi-Level Flow Representation (YaTC)
- **Authors / Year / Venue:** R. Zhao, M. Zhan, X. Deng, Y. Wang, Y. Wang, G. Gui, Z. Xue. 2023. AAAI 37(4).
- **DOI:** https://doi.org/10.1609/aaai.v37i4.25674 (XR)
- **Dataset(s):** Five traffic datasets. The code repository lists ISCXVPN2016, ISCXTor2016, USTC-TFC2016 and CICIoT2022.
- **Approach:** Masked-autoencoder pre-training of a traffic transformer with packet-level and flow-level attention.
- **Reported results:** The authors claim large gains over the prior state of the art. Numbers not extracted.
- **Limitations:** Raw-byte input. Falls within the scope of the 5.4 critique.
- **Relevance:** Self-supervised representation context. Not planned.

### 5.6 Anomal-E: A Self-Supervised Network Intrusion Detection System based on Graph Neural Networks
- **Authors / Year / Venue:** E. Caville, W. W. Lo, S. Layeghy, M. Portmann. 2022. Knowledge-Based Systems 258:110030.
- **DOI:** https://doi.org/10.1016/j.knosys.2022.110030 (XR). arXiv:2207.06819
- **Dataset(s):** NF-UNSW-NB15-v2 and NF-CSE-CIC-IDS2018.
- **Approach:** Self-supervised edge-feature GNN over flow graphs (IP endpoints as nodes). Embeddings feed anomaly detectors.
- **Reported results:** The authors report improved detection over raw features. Numbers not extracted.
- **Limitations:** Needs endpoint IPs to build the graph. The NetFlow version of IDS2018 has these; the CICFlowMeter CSVs do not, apart from 2018-02-20.
- **Relevance:** A self-supervised flow representation that NetSentinel cannot reproduce on the IP-less CSVs. This documents an approach we deliberately do not take.

---

## 6. Open-set recognition, OOD, and concept drift

### 6.1 Toward Open Set Recognition
- **Authors / Year / Venue:** W. J. Scheirer, A. de Rezende Rocha, A. Sapkota, T. E. Boult. 2013. IEEE TPAMI 35(7), pp. 1757-1772.
- **DOI:** https://doi.org/10.1109/TPAMI.2012.256 (XR)
- **Approach:** Formalises open-set recognition and "open space risk". Proposes the 1-vs-set machine.
- **Reported results:** Not extracted (vision benchmarks).
- **Relevance:** Formal framing for leave-attack-family-out evaluation (H4): at test time an unknown family must be flagged, not forced into a known class.

### 6.2 A Baseline for Detecting Misclassified and Out-of-Distribution Examples in Neural Networks
- **Authors / Year / Venue:** D. Hendrycks, K. Gimpel. 2017. ICLR.
- **URL:** https://arxiv.org/abs/1610.02136. MLAnthology: https://mlanthology.org/iclr/2017/hendrycks2017iclr-baseline
- **Approach:** Uses the maximum softmax probability as an OOD and error score.
- **Reported results:** Not extracted.
- **Relevance:** The required trivial OOD baseline for H4. Any fused score must beat 1 - max predicted probability from the supervised model.

### 6.3 TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time
- **Authors / Year / Venue:** F. Pendlebury, F. Pierazzi, R. Jordaney, J. Kinder, L. Cavallaro. 2019. USENIX Security, pp. 729-746.
- **URL:** https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury (Abs)
- **Dataset(s):** 129K Android apps over three years.
- **Approach:** Defines spatial bias (an unrealistic class ratio in the test set) and temporal bias (impossible time splits). Proposes time-aware split constraints and an AUT metric (area under time).
- **Reported results (by the authors):** Published F1 scores of up to 0.99 are shown to be inflated by these biases. Specific drops not extracted.
- **Limitations:** Malware domain. IDS2018 spans only about two weeks, so "time decay" there is mostly a change in which attacks are present, not drift within a family.
- **Relevance:** Template for H5. Training data must precede test data in time, and the test class ratio must be realistic.

### 6.4 CADE: Detecting and Explaining Concept Drift Samples for Security Applications
- **Authors / Year / Venue:** L. Yang, W. Guo, Q. Hao, A. Ciptadi, A. Ahmadzadeh, X. Xing, G. Wang. 2021. USENIX Security, pp. 2327-2344.
- **URL:** https://usenix.org/conference/usenixsecurity21/presentation/yang (Abs)
- **Dataset(s):** Android malware and network intrusion detection, plus a company malware database. The specific NIDS dataset was not extracted.
- **Approach:** Contrastive autoencoder that learns a distance-preserving latent space. Drifting samples are flagged by distance to class centroids and explained by distance-based attributions.
- **Reported results:** Not extracted (the abstract is qualitative).
- **Relevance:** Methodological template for a leave-family-out protocol. A contrastive or centroid-distance score is a candidate H4 comparator.

### 6.5 Do Transformers Actually Help Intrusion Detection? A Temporal Sequence Evaluation on CIC-IDS2017 (preprint, not peer reviewed)
- **Authors / Year / Venue:** Z. Moczkodan, H. Ragab. 2026. arXiv preprint (v2 dated 24 July 2026).
- **URL:** https://arxiv.org/abs/2606.11098 (Abs)
- **Dataset(s):** CIC-IDS2017.
- **Approach:** Ordered flow sequences. Nine models compared under a random split, two leakage-free splits, and a padding ablation.
- **Reported results (by the authors):**
  - The Transformer reaches the highest macro-F1 (0.89) on non-padded sequential windows. It degrades under zero-pad plus mask.
  - A repeat-last padding cue hides a 67x increase in the Transformer's false-alarm rate.
  - A class-balanced RF is the most robust model.
- **Limitations:** Unreviewed preprint. Different dataset.
- **Relevance:** Directly relevant to H3 and H5. Padding convention and split protocol can matter more than architecture, so both must be fixed and disclosed.

---

## 7. Calibration and probability estimation under imbalance

### 7.1 On Calibration of Modern Neural Networks
- **Authors / Year / Venue:** C. Guo, G. Pleiss, Y. Sun, K. Q. Weinberger. 2017. ICML, PMLR 70:1321-1330.
- **URL:** https://proceedings.mlr.press/v70/guo17a.html (Abs)
- **Approach:** Shows modern deep networks are miscalibrated. Temperature scaling, a one-parameter form of Platt scaling, is an effective fix.
- **Reported results:** Not extracted.
- **Relevance:** Temperature, Platt or isotonic calibration on a validation split is required before supervised and anomaly scores are fused (H4).

### 7.2 Improving class probability estimates for imbalanced data
- **Authors / Year / Venue:** B. C. Wallace, I. J. Dahabreh. Knowledge and Information Systems. Published online 2013; issue year commonly given as 2014.
- **DOI:** https://doi.org/10.1007/s10115-013-0670-6 (XR)
- **Approach:** Reports that minority-class probability estimates are systematically too low even when overall calibration looks good. Proposes a stratified (per-class) Brier score and balanced-bagging calibration.
- **Reported results:** Not extracted.
- **Limitations:** A later preprint (arXiv:2501.04903, not verified in depth) disputes part of the interpretation.
- **Relevance:** Calibration should be reported per class (stratified Brier, per-class reliability), not only as global ECE.

### 7.3 Calibrating Probability with Undersampling for Unbalanced Classification
- **Authors / Year / Venue:** A. Dal Pozzolo, O. Caelen, R. A. Johnson, G. Bontempi. 2015. IEEE Symposium Series on Computational Intelligence (SSCI).
- **DOI:** https://doi.org/10.1109/SSCI.2015.33 (XR)
- **Approach:** Shows undersampling leaves the ranking unchanged but biases posteriors. Gives an analytic correction based on the sampling rate and a matching threshold adjustment.
- **Reported results:** Not extracted.
- **Relevance:** NetSentinel will subsample benign flows for RAM reasons, so probabilities must be corrected back to the deployment base rate before thresholds or fusion.

---

## 8. Tabular-model strength

### 8.1 Why do tree-based models still outperform deep learning on typical tabular data?
- **Authors / Year / Venue:** L. Grinsztajn, E. Oyallon, G. Varoquaux. 2022. NeurIPS Datasets and Benchmarks track.
- **URL:** https://arxiv.org/abs/2207.08815. NeurIPS page: https://neurips.cc/virtual/2022/poster/55627
- **Dataset(s):** A benchmark of medium-sized tabular datasets (about 10K samples each). The count is 45 on the NeurIPS listing and differs in other versions.
- **Approach:** Standardised tuning budget. Studies inductive biases: robustness to uninformative features, rotation invariance, and the ability to fit irregular functions.
- **Reported results:** Tree-based models remain state of the art on medium-sized tabular data. Numbers not extracted.
- **Limitations:** Covers medium-sized data, not 16M rows. No temporal structure.
- **Relevance:** LightGBM/HistGB is the expected strongest single-flow baseline. Deep temporal models must beat it, not just LogReg.

---

## Synthesis

### What is established
1. **Benchmark labels in CIC datasets are substantially wrong in places.** Engelen et al. (3.1) and Liu et al. (3.2) document flow-construction artefacts, failed attacks labelled as attacks, wrong time windows, and mislabelled protocols. For IDS2018 this is documented per day.
2. **Within-dataset scores do not transfer.** Two independent groups (3.5, 3.6) find that models trained on IDS2018 lose much or all of their performance on related datasets. The exceptions are mainly volumetric DoS, DDoS and brute force.
3. **Aggregate metrics hide per-class failure.** Engelen et al. show weighted F1 stuck at 0.99 while minority-class F1 moves from 0.18 to 0.79. Arp et al. show ROC can look excellent under a 1:100 imbalance while precision is poor.
4. **Simple baselines are often competitive.** A one-feature windowed boxplot matched or beat Kitsune (1.5). Trees remain strong on tabular data (8.1). Flow-level RF is the most robust model under leakage-free sequence evaluation (6.5, preprint).
5. **Ignoring time inflates results.** This is established in malware (6.3) and is a named pitfall in Arp et al. (1.5).
6. **Post-hoc calibration is necessary**, and resampling distorts posteriors in a predictable way (7.1-7.3).

### What is contested or open
- Whether deep sequence models give real gains over windowed aggregate features plus GBDT on flow data. The evidence is mixed and mostly not leakage-free.
- Whether representation learning or pre-training helps traffic classification once shortcuts are removed. 5.4 says largely no; 5.1 and 5.5 report large gains under older protocols.
- How well anomaly detection separates "unusual but harmless" from "malicious" (Sommer and Paxson's semantic gap). We found no rigorous flow-level evidence either way.
- How much of IDS2018 is detectable from the attack schedule alone, for example a "this time window is busy" signal. This has not been measured as far as we found.

### Pitfalls that must shape NetSentinel's evaluation
1. **Leakage from random row splits of correlated flows.**
   - Attacks are bursts of near-identical flows from one tool and configuration, and the 120 s timeout splits one connection into several flows.
   - A random row split puts siblings of the same burst in train and test.
   - Rule: never use a random split as the headline result. Report it only as the H5 contrast.
2. **Label errors in the original CSVs.**
   - Treat the following original classes as label-suspect: FTP-BruteForce (14 Feb), DoS-SlowHTTPTest (16 Feb), LOIC-HTTP vs LOIC-UDP (20 Feb), web brute force/XSS/SQLi (22-23 Feb), Infiltration (28 Feb and 1 Mar), and Bot (2 Mar).
   - Report per-class results with a flag.
   - Where possible, evaluate on the DistriNet corrected labels, with "Attempted" mapped to benign or reported as a separate class.
3. **Dataset-specific artefacts.**
   - Candidate shortcut features: Init Win bytes Fwd/Bwd, Fwd Header Len, Min Seg Size Fwd, SYN/RST flag counts, Dst Port, Protocol = 0 flows, and Timestamp.
   - Each needs an ablation. Timestamp, Flow ID and IPs must never be model inputs.
   - **TTL caveat:** TTL is not a CICFlowMeter-V3 CSV feature, so TTL artefacts apply only to the NetFlow (NF-*) versions. We found no verified source documenting a TTL shortcut in IDS2018 (see Unverified leads).
4. **Prevalence mismatch.**
   - About 17% attack overall (3.4), but prevalence varies enormously by day and by hour.
   - Precision, PR-AUC and false alerts per hour must be reported at the test day's real base rate, after undoing any benign subsampling (7.3).
   - Recall should be reported at fixed benign FPR (for example 1e-3 and 1e-4).
5. **Evaluation that ignores temporal order.**
   - Window features must be strictly causal: computed from trailing windows only, with no centred windows and no future flows.
   - Chronological splits need an embargo gap, because trailing windows near the boundary otherwise contain training-period flows.
6. **Temporal context can encode the attack schedule.**
   - Network-wide trailing counts rise whenever any attack runs.
   - On IDS2018 each day has one or two scheduled attacks, so a window model can learn "high load on day X means attack" without learning anything that transfers.
   - Controls: hold out whole days, and test on held-out attack families (H4).
7. **Family and day are confounded.** Each family appears on only one or two days, so leave-family-out equals leave-day-out for most families. Any open-set result is also a cross-day result, and its claims must be scoped that way.

---

## Facts that affect the NetSentinel pipeline (corrections and additions to the project assumptions)

1. **No dedicated peer-reviewed paper describes CSE-CIC-IDS2018.**
   - The paper UNB asks users to cite (Sharafaldin et al. 2018) describes **CICIDS2017** (July 2017, 5 days). Its reported results are for CICIDS2017.
   - Project docs should cite it as "the dataset's designated citation", not as the IDS2018 description.
2. **Several original IDS2018 attack labels largely cover failed attacks.** According to Liu et al.'s documentation:
   - FTP brute force on 14 Feb hit a closed port.
   - DoS-SlowHTTPTest on 16 Feb shows no successful attack and appears to target port 21.
   - Heartbleed is absent.
   - Bot contains only Ares traffic.
3. **LOIC-UDP flows on 2018-02-20 were originally labelled LOIC-HTTP.**
4. **The documented attack windows are imprecise.**
   - Windows are often off by minutes; HOIC started about 6 minutes late.
   - The web brute-force time on 22 Feb is given in New Brunswick local time and does not match the labels.
   - The UNB page gives no time zone at all.
   - The corrected CICFlowMeter writes UTC timestamps, so the original CSV timestamps may not be UTC. This is an inference that must be checked empirically against the attack windows before any trailing-window features are built.
5. **A scan is present even though no scan label exists.** The Infiltration days include an Nmap scan from the compromised victim against 21 hosts, inside the "Infiltration" label.
6. **Infiltration labels are unreliable in both directions.** Victim-to-attacker flows were originally labelled benign, and the Dropbox stage cannot be verified.
7. **Flow-construction artefacts are present.**
   - The old CICFlowMeter treated ICMP as UDP, parsed ARP as IP flows (8.6.0.1 / 8.6.0.4), and produced protocol/port-0 flows.
   - It terminated flows at the first FIN (shown for CICIDS2017; preliminary evidence for IDS2018).
   - The 120 s timeout splits long connections.
8. **Corrected alternatives exist.** The DistriNet recreated IDS2018 (CSV labels updated in 2023) and LycoS-Unicas-IDS2018 (3.6) both exist. Neither has been assessed for NetSentinel yet. Note that the DistriNet CSVs come from a modified CICFlowMeter, so their features are not identical to the original CSVs.

---

## Unverified leads (not used as evidence)

- **TTL shortcut in IDS2018:** no verified source found. TTL is not in the CICFlowMeter-V3 feature set. It may apply to NF-CSE-CIC-IDS2018-v2. Do not cite without a source.
- **BCCC-CSE-CIC-IDS2018** (York University BCCC relabelling that reportedly aligns DoS labels to attacker IPs rather than timestamps): seen only in a search snippet of https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/large-scale-intrusion-detection-dataset-bccc-cse-cic-ids2018/. The page was not read.
- **Shortcut-detection frameworks for traffic classification** (BiasSeeker, arXiv:2601.10180; ShortcutCatcher, Politecnico di Torino): seen in search results only.
- **A critique of Wallace and Dahabreh** (arXiv:2501.04903): seen in a search result only.
- **Edinburgh thesis by R. Flood** (https://era.ed.ac.uk/handle/1842/43694), which extends 3.3 and reportedly finds artefacts that reduce accuracy by more than 90%: secondary summary only.
- **Liu et al. 2022 experimental numbers:** the paper body was not read. Only the abstract and the companion documentation were.
