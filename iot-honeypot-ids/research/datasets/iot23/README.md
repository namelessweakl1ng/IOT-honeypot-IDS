# IoT-23 local data workflow

This directory tracks the dataset contract and explicit label mapping only. Do not place raw archives or generated flows here. The preparer writes ignored local output under `prepared/` and a generated audit summary; raw data must be stored outside the checkout.

## Download and prepare

From the nested project root on Linux:

```bash
export IOT23_DATA_DIR="$HOME/datasets/iot23"
./scripts/research/prepare-iot23.sh --download
```

The `--download` switch is explicit because the small flow archive is large. The command verifies the external destination, downloads the official small archive, optionally checks it against `IOT23_SHA256`, extracts the scenarios, imports the labeled Zeek logs, and fails unless all 23 expected scenario folders are present. The source does not publish a checksum in its dataset metadata; a locally computed digest is integrity metadata, not an authenticity check.

For an archive already downloaded, set `IOT23_DATA_DIR` to an external directory containing extracted scenario folders and run `./scripts/research/prepare-iot23.sh`. To verify a locally held archive before preparation, also set `IOT23_ARCHIVE` and a trusted `IOT23_SHA256`.

## Validate

Run from the nested project root after preparation:

```bash
PYTHONPATH=model-lab python -m model_lab.datasets.validate_iot23 research/datasets/iot23/prepared/normalized/flows.jsonl
```

The validator prints measured counts, scenario and label distributions, timestamp range, missing values, duplicate counts, and invalid rows as JSON. It exits nonzero for malformed rows, missing data, or a scenario count other than 23. It accepts `--expected-scenarios 0` only for explicitly scoped diagnostic fixtures; that does not qualify as a full IoT-23 benchmark.

## Tracked contracts

- `mappings.yaml`: native-to-project label mapping. Native and mapped labels are preserved separately; unlisted values remain `UNMAPPED` / `UNKNOWN`.
- `schema.json`: normalized row contract and feature version.
- `manifest.schema.json`: minimum required metadata for a measured preparation manifest.
- `model-lab/model_lab/datasets/import_iot23.py`: canonical Zeek importer.
- `model-lab/model_lab/datasets/iot23_features.py`: feature and split contract.
- `model-lab/model_lab/datasets/validate_iot23.py`: canonical validator.
- `scripts/research/prepare_iot23.py`: manifest and measured audit generation.

Dataset citation and limitations are in [the dataset card](../../../docs/research/datasets/IOT23_DATASET_CARD.md); feature compatibility is in [the feature mapping](../../../docs/research/datasets/IOT23_FEATURE_MAPPING.md).
