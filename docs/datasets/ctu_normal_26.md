# CTU-Normal-26 (real-traffic validation capture)

Used **only** for Mission 6: validating the pure-Python PCAP reader and flow assembler against a
reference extractor, and for an end-to-end run of the offline application on real benign
traffic. It is not used for training, model selection or threshold setting.

| Item | Value |
|---|---|
| Source | Stratosphere Lab, Malware Capture Facility Project, `CTU-Normal-26` |
| Capture | `https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-26/2017-04-28_normal.pcap` |
| Reference | `.../CTU-Normal-26/bro/conn.log` (Zeek/Bro 2.5.1, produced by the dataset authors) |
| Size | 118,444,523 bytes (pcap); 1,815,904 bytes (conn.log) |
| MD5 (pcap) | `7a2fd23534b9b4189adba707f73c24fd` (matches the published value) |
| SHA-256 (pcap) | `b66103fd89c8f0fc53b76e718f53320f3af27edd302c58695fc1870ede3663c5` |
| SHA-256 (conn.log) | `e39cc368e42e2b69e119737f727b073ee1abe6289c0488beb2d0db55d7d40008` |
| Content | 199,279 packets, classic pcap, Ethernet; one host (10.0.2.15; 15,029 of 15,081 conns; the rest IPv6 link-local and DHCP) browsing normally, about 6.5 h; services by Zeek: dns 13,146, ssl 1,414, http 308 |
| Timestamps | shifted by the authors to start near the Unix epoch (first flow at about 50 s) |
| Local path | `data/raw/ctu_normal_26/` (git-ignored) |
| Downloaded | 2026-10-20, with the user's authorisation |

**Licence / citation (required by the provider):** "You are free to use these files as long as
you reference this project and the authors as follows: Garcia, Sebastian. Malware Capture
Facility Project. Retrieved from https://stratosphereips.org".

**Caveats.**
- One host, one network, benign only. The capture validates telemetry extraction. It says
  nothing about detection performance on attacks.
- The epoch-shifted timestamps make wall-clock features (hour of day) meaningless for this
  capture.
- The reference is Zeek's connection model, not nProbe's. Agreement with Zeek does not by
  itself establish agreement with the NF-v3 training features (see
  `reports/audit/pcap_vs_zeek.json` and report section 4).
