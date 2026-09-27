# Dataset sources and retrieval

## IoT-23

- Official page: <https://www.stratosphereips.org/datasets-iot23>
- Small labeled-flow archive: <https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/iot_23_datasets_small.tar.gz>
- Full archive: <https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/iot_23_datasets_full.tar.gz>
- Citation: see [IoT-23 dataset card](IOT23_DATASET_CARD.md).
- Required structure: scenario folders containing `bro/conn.log.labeled` or direct `conn.log.labeled` files.

The official page does not publish a SHA-256 checksum for the downloadable archive. The script computes and records the local SHA-256; this detects later local changes but does not authenticate the download. If an independently verified SHA-256 is available, set `IOT23_SHA256` before `--download` to require a match. Store the raw archive and extracted files outside the Git checkout.

```bash
cd iot-honeypot-ids
export IOT23_DATA_DIR="$HOME/datasets/iot23"
./scripts/research/prepare-iot23.sh --download
```

To use a previously downloaded and extracted copy, set `IOT23_DATA_DIR` to its root and omit `--download`. Preparation fails if files are missing or malformed. It writes canonical `flows.jsonl`, source checksums/provenance, audit JSON, manifest, and summary under `research/datasets/iot23/prepared/`, with a measured manifest and summary at `research/datasets/iot23/`. Generated data and manifests are gitignored.

## TRAPSIG controlled campaigns

Campaign data is generated only by controlled runs against the isolated Pi honeypot, using [attacker scenarios](../../../../attacker/README.md). The campaign/run identifiers and ground-truth provenance are kept separate from detector output. Physical campaigns have not been run in this execution environment; see the status in the final research baseline.
