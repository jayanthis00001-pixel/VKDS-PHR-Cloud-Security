#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo "VKDS PHR Cloud Security Reproducibility Pipeline"
echo "============================================================"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "[1/5] Checking Python installation..."
python --version

echo "[2/5] Creating output directories..."
mkdir -p data/synthetic_phr results figures

echo "[3/5] Generating synthetic PHR dataset..."
python src/data_generator.py --config config.yaml

echo "[4/5] Running VKDS encryption, decryption, and timing experiments..."
python src/run_experiments.py --config config.yaml

echo "[5/5] Generating performance figures..."
python src/plots.py --config config.yaml

echo "============================================================"
echo "Pipeline completed successfully."
echo "Generated outputs:"
echo "  - data/synthetic_phr/"
echo "  - results/vkds_timing_results.csv"
echo "  - results/vkds_trust_results.csv"
echo "  - results/vkds_signature_results.csv"
echo "  - figures/computation_time.png"
echo "  - figures/encryption_decryption_time.png"
echo "  - figures/key_generation_time.png"
echo "  - figures/trust_level.png"
echo "============================================================"
