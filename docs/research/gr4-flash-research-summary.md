# GR IV / GF-2 flash research summary

2026-10-13. Sample version 1.11.10.7; SHA-256 `c4e597c7c9ca1bc181b30e35139ed90a4fd876ddcca14f12be0e00b6702233ae`.

## Findings and evidence

- GF-2 replied C1 `11 00` on the tested setup. Kind 0x12 remains unidentified; the nine raw GF3 matches are not product-name evidence.
- A0 carries an output code with accessory-specific correction. It is not a linear power percentage; physical output and minimum energy require calibration.
- v3 native RX readings: C0=A5, C1=11 00, C2=01 00, C3/C4=00 00, C5=1A. No waveform capture; zero capability fields do not mean zero brightness.
- v4 completed all logged stages. The lamp closed after A6 01 00; repeated C0 and A6 01 02 did not restore A5 or full startup. This tested software wake sequence is ineffective, without excluding unknown wake mechanisms.
- v5 user observations: no automatic startup, normal icon and shutdown link after manual reopening. Its SD log remains unread; macro completion and RX values are unverified.
- Nikon bridging remains a prototype proposal: accessory simulation, calibrated output conversion, lamp control and independent synchronization. It does not establish Nikon preflash TTL metering on GR IV.

## Reports

- [2026-10-12-gr4-flash](2026-10-12-gr4-flash.md)
- [2026-10-12-gr4-gf3-byte-matches](2026-10-12-gr4-gf3-byte-matches.md)
- [2026-10-12-gr4-hotshoe-protocol](2026-10-12-gr4-hotshoe-protocol.md)
- [2026-10-13-gr4-hotshoe-a6-test-v4](2026-10-13-gr4-hotshoe-a6-test-v4.md)
- [2026-10-13-gr4-hotshoe-c0-test](2026-10-13-gr4-hotshoe-c0-test.md)
- [2026-10-13-gr4-hotshoe-live-readings](2026-10-13-gr4-hotshoe-live-readings.md)
- [2026-10-13-gr4-hotshoe-manual-power-v5](2026-10-13-gr4-hotshoe-manual-power-v5.md)
- [2026-10-13-gr4-hotshoe-power-batch-test](2026-10-13-gr4-hotshoe-power-batch-test.md)
- [2026-10-13-gr4-hotshoe-power](2026-10-13-gr4-hotshoe-power.md)
- [2026-10-13-gr4-hotshoe-recovery-v3](2026-10-13-gr4-hotshoe-recovery-v3.md)
- [2026-10-13-gr4-nikon-flash-bridge-feasibility](2026-10-13-gr4-nikon-flash-bridge-feasibility.md)

## Reproduction

```sh
python3 tools/audit_gr4_hotshoe_power.py /path/to/gr4_decoded.bin --output /tmp/gr4-power-audit.json
python3 tools/check_gr4_hotshoe_manual_power.py examples/probe-gr4-hotshoe-manual-power.ttl.example --output /tmp/gr4-v5-flow.json
```

Outputs must not already exist. Static auditing checks a pinned local sample; host flow checks use synthetic replies. Neither executes camera firmware. GF3 verification requires Capstone; optional ARM emulation requires Unicorn and was not used for publication verification. The superseded v2 probe is retained as failed-experiment evidence and must not be deployed. Firmware, extracted files and raw camera readbacks stay local.
