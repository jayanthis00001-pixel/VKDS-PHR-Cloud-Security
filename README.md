# VKDS PHR Cloud Security

This repository provides a reproducible implementation of the **Vigorous Key Distribution Strategy (VKDS)** for privacy-preserving Personal Health Record (PHR) encryption in cloud computing environments.

The implementation follows the manuscript workflow in which secure PHR storage and retrieval are achieved through:

* Diffie-Hellman based shared secret generation
* Quantum Key Distribution inspired key generation
* Fragment-level Non-Abelian Encryption based data protection
* Hash-based signature generation and verification
* Synthetic PHR generation for privacy-safe benchmarking
* Encryption, decryption, key-generation, and trust-level performance analysis

No real patient record, clinical identifier, or personally identifiable health information is used in this repository.

## Repository Structure

```text
VKDS-PHR-Cloud-Security/
│
├── README.md
├── requirements.txt
├── config.yaml
├── run_reproducibility.sh
├── .gitignore
├── .zenodo.json
│
└── src/
    ├── vkds_core.py
    ├── data_generator.py
    ├── run_experiments.py
    └── plots.py
```

## Method Overview

The VKDS workflow consists of five main stages.

First, synthetic PHR files are generated with structured health-record attributes such as patient identifier, age, gender, diagnosis code, laboratory values, prescription details, treatment status, and billing information. The generated records are stored only for experimental benchmarking.

Second, the administrator and user establish a shared secret using the Diffie-Hellman protocol. This shared secret represents the access-level secret required for secure communication and controlled record retrieval.

Third, a Quantum Key Distribution inspired module generates a qubit-derived encryption key. The key-generation process uses fixed random seeds for deterministic reproducibility while preserving the algorithmic behavior required for experimental analysis.

Fourth, each PHR file is divided into fixed-size fragments. Each fragment is encrypted using the VKDS encryption module, which combines the generated quantum key, shared secret, and Non-Abelian transformation logic. A hash-based signature is produced for each encrypted fragment.

Finally, the decryption stage verifies the fragment signature before reconstruction. If the verification fails, the fragment is rejected. If all signatures are valid, the encrypted fragments are decrypted and combined to reconstruct the original PHR file.

## Experimental Design

The experiments evaluate VKDS performance using synthetic PHR files of different sizes. The following metrics are reported:

* Encryption time
* Decryption time
* Key-generation time
* Computation time
* Signature verification status
* Trust-level score
* Scalability across different file sizes

The implementation uses repeated trials for each file size and reports average values to support stable benchmarking.

## Installation

Create a Python environment and install the required packages.

```bash
pip install -r requirements.txt
```

Recommended Python version:

```text
Python 3.10 or above
```

## Running the Complete Reproducibility Pipeline

Use the following command from the repository root:

```bash
bash run_reproducibility.sh
```

This command performs the full pipeline:

```text
1. Generate synthetic PHR records
2. Run VKDS encryption and decryption experiments
3. Measure encryption, decryption, key-generation, and computation time
4. Verify fragment-level signatures
5. Export result tables
6. Generate performance plots
```

## Manual Execution

The pipeline can also be executed step by step.

Generate the synthetic dataset:

```bash
python src/data_generator.py --config config.yaml
```

Run VKDS experiments:

```bash
python src/run_experiments.py --config config.yaml
```

Generate figures:

```bash
python src/plots.py --config config.yaml
```

## Expected Outputs

After successful execution, the following folders are generated automatically:

```text
data/
├── synthetic_phr/

results/
├── vkds_timing_results.csv
├── vkds_trust_results.csv
├── vkds_signature_results.csv

figures/
├── computation_time.png
├── encryption_decryption_time.png
├── key_generation_time.png
├── trust_level.png
```

The generated CSV files contain the numerical results used for performance reporting. The generated figures provide visual comparisons for computation time, encryption/decryption time, key-generation time, and trust-level analysis.

## Configuration

The experimental parameters are controlled through `config.yaml`.

Main configurable parameters include:

```text
dataset size
file-size range
number of independent runs
fragment size
random seed
Diffie-Hellman key size
QKD key length
number of users
role-based access settings
output directories
```

Keeping the same random seed reproduces the same synthetic dataset and deterministic experimental behavior.

## Data Availability

This repository uses only synthetic PHR data generated through the provided script. The dataset is generated locally during execution and does not contain real patient information, clinical identifiers, hospital records, or protected health information.

The synthetic dataset can be regenerated by running:

```bash
python src/data_generator.py --config config.yaml
```

The generated data are stored in:

```text
data/synthetic_phr/
```

## Code Availability

The custom code for the VKDS workflow is provided in this repository. It includes synthetic PHR generation, Diffie-Hellman secret generation, QKD-inspired key generation, Non-Abelian Encryption based fragment encryption, hash-based signature verification, experimental benchmarking, and figure generation.

After creating a stable GitHub release, the repository can be archived through Zenodo to obtain a DOI for the exact release version used in the manuscript.

## Reproducibility Notes

The implementation is designed for manuscript-level reproducibility and benchmarking. It does not require access to any external healthcare dataset. All experimental data are generated locally using the configuration file.

The results may vary slightly depending on processor speed, operating system, Python version, and available system resources. The default configuration fixes random seeds to support repeatable synthetic data generation and consistent VKDS execution behavior.

## Ethical and Privacy Considerations

No real patient data are included. The synthetic records are generated only for evaluating encryption, decryption, key-generation, and verification performance. The repository is intended for research reproducibility and should not be used as a clinical deployment system without independent security validation, compliance review, and production-level cryptographic auditing.

## Manuscript Title

Vigorous Key Distribution for Privacy Preserving Personal Health Record Encryption in Cloud Computing

## Repository Status

This repository supports the reproducibility requirements of the submitted manuscript. The code and generated data are intended to help readers verify the experimental workflow, reproduce the performance analysis, and inspect the implementation of the VKDS framework.
