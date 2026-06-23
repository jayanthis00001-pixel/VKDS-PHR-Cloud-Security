"""
Synthetic PHR data generator for the VKDS reproducibility package.

The generator creates privacy-safe synthetic Personal Health Record payloads
for encryption and timing experiments. No real patient data are used.

The output files are deterministic when the same random seed is used in
config.yaml. Each generated file is a byte-level JSON payload saved with a
.bin extension because the VKDS experiment encrypts the serialized record
stream exactly as stored.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml


DIAGNOSIS_CODES = [
    "I10", "E11", "J45", "N18", "K21", "M54", "E78", "D64", "J18", "R50",
    "B34", "G43", "L20", "H52", "A09", "F41", "C50", "Z00", "R07", "U07"
]

PRESCRIPTIONS = [
    "metformin", "amlodipine", "atorvastatin", "salbutamol", "omeprazole",
    "paracetamol", "cetirizine", "azithromycin", "ferrous_sulfate",
    "vitamin_d3"
]

DEPARTMENTS = [
    "general_medicine", "cardiology", "pulmonology", "nephrology",
    "orthopedics", "dermatology", "neurology", "endocrinology"
]

TREATMENT_STATUS = [
    "stable", "under_observation", "follow_up_required", "discharged",
    "referred", "medication_adjusted"
]

BLOOD_GROUPS = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
GENDERS = ["female", "male", "other"]
ADMISSION_TYPES = ["outpatient", "inpatient", "emergency", "teleconsultation"]
INSURANCE_STATUS = ["self_pay", "insured", "government_scheme", "corporate"]


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def target_size_bytes(size_kb: float) -> int:
    return max(1, int(round(float(size_kb) * 1024)))


def safe_size_label(size_kb: float) -> str:
    value = str(size_kb).replace(".", "p")
    return f"{value}kb"


def stable_patient_id(rng: random.Random, index: int) -> str:
    raw = f"VKDS-SYN-{index}-{rng.randint(10_000, 99_999)}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10].upper()
    return f"SYN{digest}"


def synthetic_record(
    rng: random.Random,
    index: int,
    roles: List[str],
    base_time: datetime,
) -> Dict[str, Any]:
    diagnosis = rng.choice(DIAGNOSIS_CODES)
    glucose = round(rng.uniform(70, 220), 2)
    hemoglobin = round(rng.uniform(9.5, 16.8), 2)
    creatinine = round(rng.uniform(0.5, 2.2), 2)
    systolic = rng.randint(95, 165)
    diastolic = rng.randint(60, 105)

    timestamp = base_time + timedelta(minutes=index * rng.randint(3, 17))

    return {
        "patient_id": stable_patient_id(rng, index),
        "age": rng.randint(18, 88),
        "gender": rng.choice(GENDERS),
        "blood_group": rng.choice(BLOOD_GROUPS),
        "diagnosis_code": diagnosis,
        "laboratory_result": {
            "glucose_mg_dl": glucose,
            "hemoglobin_g_dl": hemoglobin,
            "creatinine_mg_dl": creatinine,
            "blood_pressure": f"{systolic}/{diastolic}",
        },
        "prescription": rng.sample(PRESCRIPTIONS, k=rng.randint(1, 3)),
        "treatment_status": rng.choice(TREATMENT_STATUS),
        "admission_type": rng.choice(ADMISSION_TYPES),
        "department": rng.choice(DEPARTMENTS),
        "physician_id": f"DOC{rng.randint(1000, 9999)}",
        "insurance_status": rng.choice(INSURANCE_STATUS),
        "billing_amount": round(rng.uniform(250.0, 75000.0), 2),
        "access_role": rng.choice(roles) if roles else "physician",
        "timestamp": timestamp.replace(tzinfo=timezone.utc).isoformat(),
    }


def compact_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def build_payload_for_size(
    rng: random.Random,
    size_kb: float,
    records_per_file: int,
    roles: List[str],
    base_index: int,
) -> Tuple[bytes, int]:
    """Build a deterministic serialized PHR payload close to the target size.

    The payload is valid compact JSON. For small target files, metadata is kept
    minimal. For larger files, records are appended until the requested target
    size is reached, and a non-clinical padding field is used to make the byte
    length exact.
    """
    target = target_size_bytes(size_kb)
    base_time = datetime(2026, 1, 1, 8, 0, 0)

    records: List[Dict[str, Any]] = []
    max_records = max(1, records_per_file)

    # Start with a compact payload and add records until approaching the target.
    payload = {
        "dataset": "synthetic_phr",
        "size_kb": size_kb,
        "records": records,
        "padding": "",
    }

    for record_offset in range(max_records * 100):
        candidate_record = synthetic_record(
            rng=rng,
            index=base_index + record_offset,
            roles=roles,
            base_time=base_time,
        )
        trial_records = records + [candidate_record]
        trial_payload = dict(payload)
        trial_payload["records"] = trial_records
        trial_payload["record_count"] = len(trial_records)
        trial_payload["padding"] = ""
        trial_bytes = compact_json_bytes(trial_payload)

        # Leave space for the padding field and JSON delimiters.
        if len(trial_bytes) <= target:
            records.append(candidate_record)
            payload["records"] = records
            payload["record_count"] = len(records)
        else:
            break

    # If even one full record is too large, use a minimal synthetic record.
    if not records:
        minimal = {
            "patient_id": stable_patient_id(rng, base_index),
            "age": rng.randint(18, 88),
            "gender": rng.choice(GENDERS),
            "blood_group": rng.choice(BLOOD_GROUPS),
            "diagnosis_code": rng.choice(DIAGNOSIS_CODES),
            "laboratory_result": {"glucose_mg_dl": round(rng.uniform(70, 220), 2)},
            "prescription": [rng.choice(PRESCRIPTIONS)],
            "treatment_status": rng.choice(TREATMENT_STATUS),
            "admission_type": rng.choice(ADMISSION_TYPES),
            "department": rng.choice(DEPARTMENTS),
            "physician_id": f"DOC{rng.randint(1000, 9999)}",
            "insurance_status": rng.choice(INSURANCE_STATUS),
            "billing_amount": round(rng.uniform(250.0, 75000.0), 2),
            "access_role": rng.choice(roles) if roles else "physician",
            "timestamp": base_time.replace(tzinfo=timezone.utc).isoformat(),
        }
        records.append(minimal)
        payload["records"] = records
        payload["record_count"] = 1

    # Adjust payload to exact byte length using a non-clinical padding field.
    payload["padding"] = ""
    current = compact_json_bytes(payload)

    if len(current) < target:
        # Estimate padding length and refine until exact.
        missing = target - len(current)
        payload["padding"] = "X" * missing
        adjusted = compact_json_bytes(payload)

        # JSON encoding of the padding field changes total length. Refine.
        while len(adjusted) > target and payload["padding"]:
            payload["padding"] = payload["padding"][:-1]
            adjusted = compact_json_bytes(payload)

        while len(adjusted) < target:
            payload["padding"] += "X"
            adjusted = compact_json_bytes(payload)

        current = adjusted

    # In rare cases where a required small JSON payload exceeds the target,
    # keep it valid and report the actual byte size in the manifest.
    return current, len(records)


def write_payload(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def generate_dataset(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    project = config.get("project", {})
    dataset_cfg = config.get("dataset", {})
    user_cfg = config.get("users", {})
    path_cfg = config.get("paths", {})

    seed = int(project.get("random_seed", 42))
    rng = random.Random(seed)

    output_dir = Path(path_cfg.get("synthetic_phr_dir", "data/synthetic_phr"))
    output_dir.mkdir(parents=True, exist_ok=True)

    file_sizes = dataset_cfg.get("file_sizes_kb", [0.3, 1, 10, 30, 50, 100, 500])
    records_per_file = int(dataset_cfg.get("records_per_file", 128))
    roles = list(user_cfg.get("roles", ["physician", "nurse", "auditor"]))

    manifest: List[Dict[str, Any]] = []
    base_index = 0

    for idx, size_kb in enumerate(file_sizes):
        size_value = float(size_kb)
        payload, record_count = build_payload_for_size(
            rng=rng,
            size_kb=size_value,
            records_per_file=records_per_file,
            roles=roles,
            base_index=base_index,
        )
        base_index += max(1, record_count)

        label = safe_size_label(size_value)
        file_name = f"phr_{idx:02d}_{label}.bin"
        file_path = output_dir / file_name
        write_payload(file_path, payload)

        digest = hashlib.sha256(payload).hexdigest()
        manifest.append(
            {
                "file_index": idx,
                "file_name": file_name,
                "file_path": str(file_path),
                "target_size_kb": size_value,
                "target_size_bytes": target_size_bytes(size_value),
                "actual_size_bytes": len(payload),
                "actual_size_kb": round(len(payload) / 1024.0, 6),
                "record_count": record_count,
                "sha256": digest,
            }
        )

    write_manifest(output_dir / "manifest.csv", manifest)
    write_manifest_json(output_dir / "manifest.json", manifest)

    return manifest


def write_manifest(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_manifest_json(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.write_text(json.dumps(rows, indent=2), encoding="utf-8")


def print_summary(manifest: List[Dict[str, Any]]) -> None:
    print("Synthetic PHR dataset generated successfully.")
    print(f"Total files: {len(manifest)}")
    if manifest:
        print(f"Output directory: {Path(manifest[0]['file_path']).parent}")
    for row in manifest:
        print(
            f"  - {row['file_name']}: "
            f"{row['actual_size_bytes']} bytes, "
            f"{row['record_count']} records"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate synthetic PHR data for VKDS experiments.")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to the VKDS YAML configuration file.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    manifest = generate_dataset(config)
    print_summary(manifest)


if __name__ == "__main__":
    main()
