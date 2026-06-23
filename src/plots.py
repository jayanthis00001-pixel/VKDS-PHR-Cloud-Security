"""
Plot generation script for the VKDS reproducibility package.

This script reads the CSV files produced by src/run_experiments.py and creates
publication-ready performance figures for:

1. Computation time
2. Encryption and decryption time
3. Key-generation time
4. Cloud trust-level score

Run from the repository root:

    python src/plots.py --config config.yaml
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import matplotlib.pyplot as plt
import pandas as pd
import yaml


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def read_required_csv(path: Path, label: str) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(
            f"{label} file not found: {path}. "
            "Run `python src/run_experiments.py --config config.yaml` first."
        )
    df = pd.read_csv(path)
    if df.empty:
        raise ValueError(f"{label} file is empty: {path}")
    return df


def figure_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    plotting = config.get("plotting", {})
    return {
        "dpi": int(plotting.get("dpi", 300)),
        "width": float(plotting.get("figure_width", 8)),
        "height": float(plotting.get("figure_height", 5)),
        "grid": bool(plotting.get("grid", True)),
    }


def method_order(methods: Iterable[str]) -> List[str]:
    preferred = ["DAC-MACS", "NEDAC-MACS", "VKDS"]
    present = list(dict.fromkeys(str(m) for m in methods))
    ordered = [m for m in preferred if m in present]
    ordered.extend([m for m in present if m not in ordered])
    return ordered


def aggregate_timing(timing_df: pd.DataFrame) -> pd.DataFrame:
    required_columns = {
        "method",
        "file_size_kb",
        "key_generation_time_s",
        "encryption_time_s",
        "decryption_time_s",
        "computation_time_s",
    }
    missing = required_columns.difference(timing_df.columns)
    if missing:
        raise ValueError(f"Timing results are missing required columns: {sorted(missing)}")

    numeric_cols = [
        "file_size_kb",
        "key_generation_time_s",
        "encryption_time_s",
        "decryption_time_s",
        "computation_time_s",
    ]
    for col in numeric_cols:
        timing_df[col] = pd.to_numeric(timing_df[col], errors="coerce")

    timing_df = timing_df.dropna(subset=numeric_cols + ["method"])
    return (
        timing_df.groupby(["method", "file_size_kb"], as_index=False)
        .agg(
            key_generation_time_s=("key_generation_time_s", "mean"),
            encryption_time_s=("encryption_time_s", "mean"),
            decryption_time_s=("decryption_time_s", "mean"),
            computation_time_s=("computation_time_s", "mean"),
        )
        .sort_values(["file_size_kb", "method"])
    )


def aggregate_trust(trust_df: pd.DataFrame) -> pd.DataFrame:
    required_columns = {"file_size_kb", "trust_score"}
    missing = required_columns.difference(trust_df.columns)
    if missing:
        raise ValueError(f"Trust results are missing required columns: {sorted(missing)}")

    trust_df["file_size_kb"] = pd.to_numeric(trust_df["file_size_kb"], errors="coerce")
    trust_df["trust_score"] = pd.to_numeric(trust_df["trust_score"], errors="coerce")
    trust_df = trust_df.dropna(subset=["file_size_kb", "trust_score"])

    return (
        trust_df.groupby("file_size_kb", as_index=False)
        .agg(trust_score=("trust_score", "mean"))
        .sort_values("file_size_kb")
    )


def setup_axes(title: str, xlabel: str, ylabel: str, grid: bool) -> None:
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    if grid:
        plt.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)


def apply_size_axis() -> None:
    plt.xscale("log")
    plt.xticks(
        [0.3, 1, 10, 30, 50, 100, 500, 1000, 5000, 10000],
        ["0.3", "1", "10", "30", "50", "100", "500", "1000", "5000", "10000"],
        rotation=35,
    )


def save_current_figure(path: Path, dpi: int) -> None:
    ensure_parent(path)
    plt.tight_layout()
    plt.savefig(path, dpi=dpi, bbox_inches="tight")
    plt.close()


def plot_computation_time(
    summary_df: pd.DataFrame,
    output_path: Path,
    settings: Dict[str, Any],
) -> None:
    plt.figure(figsize=(settings["width"], settings["height"]))

    for method in method_order(summary_df["method"].unique()):
        group = summary_df[summary_df["method"] == method].sort_values("file_size_kb")
        plt.plot(
            group["file_size_kb"],
            group["computation_time_s"],
            marker="o",
            linewidth=2,
            label=method,
        )

    setup_axes(
        title="Computation Time Comparison",
        xlabel="PHR file size (KB)",
        ylabel="Computation time (s)",
        grid=settings["grid"],
    )
    apply_size_axis()
    plt.legend()
    save_current_figure(output_path, settings["dpi"])


def plot_encryption_decryption_time(
    summary_df: pd.DataFrame,
    output_path: Path,
    settings: Dict[str, Any],
) -> None:
    plt.figure(figsize=(settings["width"], settings["height"]))

    vkds = summary_df[summary_df["method"] == "VKDS"].sort_values("file_size_kb")
    if vkds.empty:
        vkds = summary_df.sort_values("file_size_kb")

    plt.plot(
        vkds["file_size_kb"],
        vkds["encryption_time_s"],
        marker="o",
        linewidth=2,
        label="Encryption time",
    )
    plt.plot(
        vkds["file_size_kb"],
        vkds["decryption_time_s"],
        marker="s",
        linewidth=2,
        label="Decryption time",
    )

    setup_axes(
        title="VKDS Encryption and Decryption Time",
        xlabel="PHR file size (KB)",
        ylabel="Time (s)",
        grid=settings["grid"],
    )
    apply_size_axis()
    plt.legend()
    save_current_figure(output_path, settings["dpi"])


def plot_key_generation_time(
    summary_df: pd.DataFrame,
    output_path: Path,
    settings: Dict[str, Any],
) -> None:
    plt.figure(figsize=(settings["width"], settings["height"]))

    for method in method_order(summary_df["method"].unique()):
        group = summary_df[summary_df["method"] == method].sort_values("file_size_kb")
        plt.plot(
            group["file_size_kb"],
            group["key_generation_time_s"],
            marker="o",
            linewidth=2,
            label=method,
        )

    setup_axes(
        title="Key-Generation Time Comparison",
        xlabel="PHR file size (KB)",
        ylabel="Key-generation time (s)",
        grid=settings["grid"],
    )
    apply_size_axis()
    plt.legend()
    save_current_figure(output_path, settings["dpi"])


def plot_trust_level(
    trust_summary: pd.DataFrame,
    output_path: Path,
    settings: Dict[str, Any],
) -> None:
    plt.figure(figsize=(settings["width"], settings["height"]))

    plt.plot(
        trust_summary["file_size_kb"],
        trust_summary["trust_score"],
        marker="o",
        linewidth=2,
        label="VKDS trust score",
    )

    setup_axes(
        title="VKDS Trust-Level Analysis",
        xlabel="PHR file size (KB)",
        ylabel="Trust score",
        grid=settings["grid"],
    )
    apply_size_axis()
    plt.ylim(0.0, 1.05)
    plt.legend()
    save_current_figure(output_path, settings["dpi"])


def create_all_plots(config: Dict[str, Any]) -> List[Path]:
    outputs = config.get("outputs", {})
    settings = figure_settings(config)

    timing_path = Path(outputs.get("timing_results_csv", "results/vkds_timing_results.csv"))
    trust_path = Path(outputs.get("trust_results_csv", "results/vkds_trust_results.csv"))

    computation_plot = Path(outputs.get("computation_time_plot", "figures/computation_time.png"))
    enc_dec_plot = Path(outputs.get("encryption_decryption_plot", "figures/encryption_decryption_time.png"))
    key_plot = Path(outputs.get("key_generation_plot", "figures/key_generation_time.png"))
    trust_plot = Path(outputs.get("trust_level_plot", "figures/trust_level.png"))

    timing_df = read_required_csv(timing_path, "Timing results")
    trust_df = read_required_csv(trust_path, "Trust results")

    timing_summary = aggregate_timing(timing_df)
    trust_summary = aggregate_trust(trust_df)

    plot_computation_time(timing_summary, computation_plot, settings)
    plot_encryption_decryption_time(timing_summary, enc_dec_plot, settings)
    plot_key_generation_time(timing_summary, key_plot, settings)
    plot_trust_level(trust_summary, trust_plot, settings)

    summary_output = timing_path.parent / "vkds_plot_summary.csv"
    ensure_parent(summary_output)
    timing_summary.to_csv(summary_output, index=False)

    return [computation_plot, enc_dec_plot, key_plot, trust_plot, summary_output]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate VKDS performance plots.")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to the VKDS YAML configuration file.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    generated = create_all_plots(config)

    print("VKDS figures generated successfully.")
    for path in generated:
        print(f"  - {path}")


if __name__ == "__main__":
    main()
