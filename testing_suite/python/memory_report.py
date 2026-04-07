#!/usr/bin/env python3
"""
memory_report.py — Flash + SRAM footprint comparison
=====================================================
Parses avr-size output from Arduino build artefacts and generates
a comparison chart + table (figure 07_memory_footprint.png).

USAGE
-----
  # Option A: point at a directory of .elf files (recommended)
  python memory_report.py --elf-dir /tmp/arduino_build_XXXXX/

  # Option B: pass a JSON file with the values
  python memory_report.py --json memory_data.json

  # Option C: enter values interactively
  python memory_report.py --manual

  # No arguments → demo with estimated values
  python memory_report.py

HOW TO GET BUILD SIZE VALUES
-----------------------------
  Arduino IDE: File > Preferences > Show verbose output during: Compilation
  After building, find the "avr-size" line in the output.
  The numbers are:  text  data  bss  dec  hex  filename
    Flash used = text + data
    SRAM used  = data + bss

MANUAL JSON FORMAT
------------------
[
  {"algo": "PLAIN",     "flash": 4230,  "sram": 312},
  {"algo": "XOR",       "flash": 4692,  "sram": 330},
  {"algo": "AES128",    "flash": 8104,  "sram": 542},
  {"algo": "AES128CBC", "flash": 8300,  "sram": 558},
  {"algo": "SPECK",     "flash": 5680,  "sram": 458},
  {"algo": "CHACHA20",  "flash": 7200,  "sram": 464}
]

ATmega328P limits: Flash 32,768 B  |  SRAM 2,048 B
"""

import argparse
import json
import os
import re
import subprocess
import sys

try:
    import pandas as pd
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError as e:
    print(f"ERROR: {e}\nRun: pip install pandas matplotlib numpy")
    sys.exit(1)

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

FIGURES_DIR = os.path.join(os.path.dirname(__file__), "..", "results", "figures")
FLASH_MAX   = 32_768
SRAM_MAX    =  2_048

COLORS = {
    "PLAIN":     "#6B7280",
    "XOR":       "#DC2626",
    "AES128":    "#2563EB",
    "AES128CBC": "#7C3AED",
    "SPECK":     "#16A34A",
    "CHACHA20":  "#B45309",
}
LABELS = {
    "PLAIN":     "Plaintext",
    "XOR":       "XOR",
    "AES128":    "AES-128 ECB",
    "AES128CBC": "AES-128 CBC",
    "SPECK":     "SPECK-64/128",
    "CHACHA20":  "ChaCha20",
}

# ---------------------------------------------------------------------------
# ELF parsing
# ---------------------------------------------------------------------------

AVR_RE = re.compile(r"\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+")

def size_from_elf(elf_path):
    try:
        result = subprocess.run(["avr-size", elf_path],
                                capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            m = AVR_RE.match(line)
            if m:
                text, data, bss = int(m.group(1)), int(m.group(2)), int(m.group(3))
                return text + data, data + bss
    except FileNotFoundError:
        print("WARNING: avr-size not found — install avr-gcc toolchain.")
    except subprocess.CalledProcessError as e:
        print(f"WARNING: avr-size error: {e}")
    return None, None

def load_from_elf_dir(elf_dir):
    rows = []
    for fn in os.listdir(elf_dir):
        if not fn.endswith(".elf"):
            continue
        algo = fn.split("_")[0].upper()
        flash, sram = size_from_elf(os.path.join(elf_dir, fn))
        if flash and sram:
            rows.append({"algo": algo, "flash": flash, "sram": sram})
    return rows

# ---------------------------------------------------------------------------
# Manual entry
# ---------------------------------------------------------------------------

def manual_entry():
    print("\nEnter memory figures (from Arduino IDE verbose build output).\n")
    rows = []
    for algo in ["PLAIN", "XOR", "AES128", "AES128CBC", "SPECK", "CHACHA20"]:
        try:
            flash = int(input(f"  {algo:8s} — Flash bytes used: "))
            sram  = int(input(f"  {algo:8s} — SRAM  bytes used: "))
            rows.append({"algo": algo, "flash": flash, "sram": sram})
        except (ValueError, EOFError):
            print(f"  (skipping {algo})")
    return rows

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_df(rows):
    df = pd.DataFrame(rows)
    df["label"]      = df["algo"].map(lambda a: LABELS.get(a, a))
    df["flash_pct"]  = df["flash"] / FLASH_MAX * 100
    df["sram_pct"]   = df["sram"]  / SRAM_MAX  * 100
    df["flash_free"] = FLASH_MAX - df["flash"]
    df["sram_free"]  = SRAM_MAX  - df["sram"]
    return df

def print_report(df):
    print("\n" + "="*65)
    print("  MEMORY FOOTPRINT — ATmega328P (TX sketches)")
    print(f"  Flash limit: {FLASH_MAX:,} B  |  SRAM limit: {SRAM_MAX:,} B")
    print("="*65)
    disp = df[["label","flash","flash_pct","flash_free","sram","sram_pct","sram_free"]].copy()
    disp.columns = ["Algorithm","Flash (B)","Flash %","Flash free","SRAM (B)","SRAM %","SRAM free"]
    for col in ["Flash %","SRAM %"]:
        disp[col] = disp[col].map(lambda x: f"{x:.1f}%")
    if HAS_TABULATE:
        print("\n" + tabulate(disp, headers="keys", tablefmt="rounded_outline", showindex=False))
    else:
        print(disp.to_string(index=False))
    print()

def plot_memory(df, outdir):
    os.makedirs(outdir, exist_ok=True)
    plt.rcParams.update({
        "figure.facecolor": "#FFFFFF", "axes.facecolor": "#FAFAFA",
        "axes.edgecolor": "#CCCCCC", "axes.labelcolor": "#1A1A1A",
        "axes.titlecolor": "#1A1A1A", "xtick.color": "#5A5A5A",
        "ytick.color": "#5A5A5A", "text.color": "#1A1A1A",
        "grid.color": "#E0E0E0", "grid.linestyle": "--", "grid.alpha": 0.8,
        "legend.facecolor": "#FFFFFF", "legend.edgecolor": "#CCCCCC",
        "font.family": "monospace",
    })

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.patch.set_facecolor("#FFFFFF")

    labels = [LABELS.get(a, a) for a in df["algo"]]
    clrs   = [COLORS.get(a, "#888") for a in df["algo"]]
    x      = np.arange(len(labels))

    # Flash
    b1 = ax1.bar(x, df["flash"], color=clrs, alpha=0.85)
    ax1.axhline(FLASH_MAX, color="#BC0031", linestyle="--", linewidth=1.5,
                label=f"Limit ({FLASH_MAX:,} B)")
    ax1.set_xticks(x); ax1.set_xticklabels(labels, fontsize=9, rotation=15, ha="right")
    ax1.set_ylabel("Bytes"); ax1.set_title("Flash Memory Usage", fontsize=12)
    ax1.yaxis.grid(True); ax1.set_axisbelow(True); ax1.legend(fontsize=8)
    for bar in b1:
        h = bar.get_height()
        ax1.text(bar.get_x()+bar.get_width()/2, h+80, f"{h:,}",
                 ha="center", fontsize=8, color="#1A1A1A")

    # SRAM
    b2 = ax2.bar(x, df["sram"], color=clrs, alpha=0.85)
    ax2.axhline(SRAM_MAX, color="#ef4444", linestyle="--", linewidth=1.5,
                label=f"Limit ({SRAM_MAX:,} B)")
    ax2.axhspan(SRAM_MAX * 0.85, SRAM_MAX, alpha=0.1, color="#ef4444",
                label="Danger zone (>85%)")
    ax2.set_xticks(x); ax2.set_xticklabels(labels, fontsize=9, rotation=15, ha="right")
    ax2.set_ylabel("Bytes"); ax2.set_title("SRAM Usage at Runtime", fontsize=12)
    ax2.yaxis.grid(True); ax2.set_axisbelow(True); ax2.legend(fontsize=8)
    for bar in b2:
        h = bar.get_height()
        ax2.text(bar.get_x()+bar.get_width()/2, h+5, f"{h:,}",
                 ha="center", fontsize=8, color="#1A1A1A")

    fig.suptitle("ATmega328P Memory Footprint by Algorithm (TX sketch)",
                 fontsize=13, color="#1A1A1A", y=1.02)
    plt.tight_layout()
    path = os.path.join(outdir, "07_memory_footprint.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Generate memory footprint chart")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--elf-dir", help="Directory containing .elf build artefacts")
    g.add_argument("--json",    help="JSON file with memory data")
    g.add_argument("--manual",  action="store_true", help="Interactive entry")
    p.add_argument("--outdir",  default=FIGURES_DIR,
                   help="Output directory for figures (default: ../results/figures/)")
    return p.parse_args()

def main():
    args = parse_args()

    if args.elf_dir:
        rows = load_from_elf_dir(args.elf_dir)
    elif args.json:
        with open(args.json) as f:
            rows = json.load(f)
    elif args.manual:
        rows = manual_entry()
    else:
        print("No data source given — using estimated placeholder values.")
        print("Use --elf-dir, --json, or --manual for real data.\n")
        rows = [
            {"algo": "PLAIN",     "flash": 4_230,  "sram": 312},
            {"algo": "XOR",       "flash": 4_692,  "sram": 330},
            {"algo": "AES128",    "flash": 8_104,  "sram": 542},
            {"algo": "AES128CBC", "flash": 8_300,  "sram": 558},
            {"algo": "SPECK",     "flash": 5_680,  "sram": 458},
            {"algo": "CHACHA20",  "flash": 7_200,  "sram": 464},
        ]

    if not rows:
        print("No data loaded.")
        sys.exit(1)

    df = build_df(rows)
    print_report(df)
    plot_memory(df, args.outdir)
    print("Done.")


if __name__ == "__main__":
    main()
