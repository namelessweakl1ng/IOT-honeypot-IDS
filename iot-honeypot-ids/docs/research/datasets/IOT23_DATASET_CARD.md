# IoT-23 dataset card

## Identity and source

- **Name/version:** IoT-23, dataset release 1.0.0 (2020).
- **Source:** Stratosphere Laboratory, Aposemat / Avast AIC project; [official dataset page](https://www.stratosphereips.org/datasets-iot23) and [Zenodo record](https://zenodo.org/records/4743746).
- **Download:** [small flow-oriented archive](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/iot_23_datasets_small.tar.gz) or the [full archive](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/iot_23_datasets_full.tar.gz). Raw archives are not stored in Git.
- **Citation (source wording):** Sebastian Garcia, Agustin Parmisano, & Maria Jose Erquiaga. (2020). *IoT-23: A labeled dataset with malicious and benign IoT network traffic* (Version 1.0.0) [Data set]. Zenodo. https://doi.org/10.5281/zenodo.4743746.
- **License/usage:** The source FAQ says permission is not required when the dataset is cited, but the Zenodo record fields inspected here did not expose a license label. Cite the dataset, check the current source/Zenodo terms, and do not redistribute it from this repository.

## Contents and labels

The source describes 23 scenarios: 20 malware captures and 3 benign captures. Benign device captures include a Philips Hue lamp, Amazon Echo, and Somfy smart doorlock. The traffic was captured in a controlled laboratory environment during 2018–2019. Each scenario includes Zeek/Bro connection logs; `bro/conn.log.labeled` is the preferred labeled-flow input. The small archive omits PCAPs and focuses on logs/README material.

Labels are assigned by analyst inspection and labeling rules applied to flow characteristics. They are useful external benchmark annotations, but they are not TRAPSIG's independent campaign ground truth and are not detector predictions. Labels describe network behavior (for example `Benign`, `C&C`, `DDoS`, `PartOfAHorizontalPortScan`, and file-download behaviors); they do not consistently name one malware family.

Available Zeek fields depend on the source log header. Common fields include timestamp, UID, originator/responder addresses and ports, protocol, service, duration, byte/packet counts, connection state, history, and the two IoT-23 label columns. The adapter reads `#fields`; it does not assume every source file has an identical header.

## Mapping and transformations

`research/datasets/iot23/mappings.yaml` is applied by the importer as the explicit project taxonomy mapping. The normalized output keeps `original_label`, `original_detailed_label`, `project_label`, `binary_label`, `label_source`, `source_scenario`, and source-row/file provenance separately. Unknown labels stay `UNMAPPED` / `UNKNOWN`; mappings never infer a label from a scenario directory name. Zeek epoch timestamps are normalized to UTC ISO-8601. Missing numeric measurements remain null; model imputation is fit on training scenarios only. Source and destination fields preserve Zeek direction.

`model-lab/model_lab/datasets/iot23_features.py` is the compatibility contract. The initial shared numerical feature subset is flow duration, originator/responder bytes, and originator/responder packet counts. Identifiers, labels, scenario names, addresses, file paths, timestamps, ports, UIDs, and label-derived TRAPSIG features are excluded from the default cross-scenario feature vector. Unsupported honeypot features are marked unavailable instead of imputed or invented.

## Relevance and limits

IoT-23 is relevant for public evaluation of network-flow classification and behavior-oriented detection on real IoT device traffic. It supports Benchmark A only. TRAPSIG's Pi sensors produce honeypot events and reconstructed sessions, a different measurement domain. IoT-23 results do not validate Pi ingestion, honeypot behavior, deployment latency, or production performance.

The dataset has strong class/scenario imbalance, correlated flows within captures, historical capture conditions, and potentially scenario-specific artifacts. Treating every flow as independent or randomly splitting flows can inflate results. Use scenario-aware splits and disclose unseen labels/scenarios. Captured traffic does not represent all Internet IoT behavior. The source's flow labels arise from analysis rules and human review; they are imperfect annotations. The exact class distribution, missingness, duplicates, and timestamp range are generated from locally prepared data and are intentionally not asserted here.

## Citation and source links

Use the citation above and cite the [official source](https://www.stratosphereips.org/datasets-iot23). The source describes capture provenance, labels, archive options, and the labeling workflow. See [DATASET_SOURCES.md](DATASET_SOURCES.md) for repeatable retrieval and checksum steps.
