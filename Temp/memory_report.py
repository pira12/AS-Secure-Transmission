#!/usr/bin/env python3
"""
memory_report.py — Flash + SRAM footprint per algorithm
========================================================
Parses avr-size output from Arduino build artefacts and produces
a comparison table + bar chart.

USAGE
-----
  1. Build each sketch in Arduino IDE with verbose output enabled:
       File > Preferences > Show verbose output during: Compilation

  2. Copy the "avr-size" line from each build and paste it here,
     OR point --builddir at a directory containing .elf files.

  Direct ELF mode (recommended):
     python memory_report.py --elf-dir /tmp/arduino_builds/

  Manual entry mode:
     python memory_report.py --manual

  Manual JSON input file:
     python memory_report.py --json memory_data.json

MANUAL JSON FORMAT
------------------
[
  {"algo": "PLAIN",    "flash": 4230, "sram": 312},
  {"algo": "XOR",      "flash": 4556, "sram": 318},
  {"algo": "AES128",   "flash": 8104, "sram": 542},
  {"algo": "SPECK",    "flash": 5248, "sram": 346},
  {"algo": "CHACHA20", "flash": 6912, "sram": 398}
]

FLASH LIMIT:  32,768 bytes (ATmega328P)
SRAM LIMIT:    2,048 bytes (ATmega328P)
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

FLASH_MAX = 32_768
SRAM_MAX  =  2_048

ALGO_COLORS = {
    "PLAIN":    "#64748b",
    "XOR":      "#ef4444",
    "AES128":   "#3b82f6",
    "SPECK":    "#22c55e",
    "CHACHA20": "#f59e0b",
}
ALGO_LABELS = {
    "PLAIN":    "Plaintext",
    "XOR":      "XOR (Static)",
    "AES128":   "AES-128",
    "SPECK":    "SPECK-64/128",
    "CHACHA20": "ChaCha20",
}

# ---------------------------------------------------------------------------
# ELF parsing
# ---------------------------------------------------------------------------

AVR_SIZE_RE = re.compile(r"\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+")  # text data bss dec

def size_from_elf(elf_path):
    """Run avr-size on an ELF file and return (flash, sram)."""
    try:
        result = subprocess.run(["avr-size", elf_path],
                                capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            m = AVR_SIZE_RE.match(line)
            if m:
                text  = int(m.group(1))
                data  = int(m.group(2))
                bss   = int(m.group(3))
                flash = text + data       # Flash used
                sram  = data + bss        # SRAM used at runtime
                return flash, sram
    except FileNotFoundError:
        print("WARNING: avr-size not found. Install avr-gcc toolchain.")
    except subprocess.CalledProcessError as e:
        print(f"WARNING: avr-size failed: {e}")
    return None, None

def load_from_elf_dir(elf_dir):
    """Scan a directory for .elf files named <algo>*.elf."""
    rows = []
    for fn in os.listdir(elf_dir):
        if not fn.endswith(".elf"):
            continue
        algo = fn.split("_")[0].upper()
        path = os.path.join(elf_dir, fn)
        flash, sram = size_from_elf(path)
        if flash and sram:
            rows.append({"algo": algo, "flash": flash, "sram": sram})
    return rows

# ---------------------------------------------------------------------------
# Manual entry
# ---------------------------------------------------------------------------

def manual_entry():
    print("\nEnter memory figures for each algorithm.")
    print("(Get these from Arduino IDE verbose build output or avr-size)\n")
    rows = []
    algos = ["PLAIN", "XOR", "AES128", "SPECK", "CHACHA20"]
    for algo in algos:
        try:
            flash = int(input(f"  {algo} — Flash bytes used: "))
            sram  = int(input(f"  {algo} — SRAM bytes used : "))
            rows.append({"algo": algo, "flash": flash, "sram": sram})
        except (ValueError, EOFError):
            print(f"  (skipping {algo})")
    return rows

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_report(rows):
    df = pd.DataFrame(rows)
    df["label"]     = df["algo"].map(lambda a: ALGO_LABELS.get(a, a))
    df["flash_pct"] = df["flash"] / FLASH_MAX * 100
    df["sram_pct"]  = df["sram"]  / SRAM_MAX  * 100
    df["flash_free"] = FLASH_MAX - df["flash"]
    df["sram_free"]  = SRAM_MAX  - df["sram"]
    return df

def print_report(df):
    print("\n" + "="*65)
    print("  MEMORY FOOTPRINT REPORT — ATmega328P")
    print(f"  Flash limit: {FLASH_MAX:,} bytes  |  SRAM limit: {SRAM_MAX:,} bytes")
    print("="*65)

    disp = df[["label", "flash", "flash_pct", "flash_free", "sram", "sram_pct", "sram_free"]].copy()
    disp.columns = ["Algorithm", "Flash (B)", "Flash %", "Flash free", "SRAM (B)", "SRAM %", "SRAM free"]
    for col in ["Flash %", "SRAM %"]:
        disp[col] = disp[col].map(lambda x: f"{x:.1f}%")

    if HAS_TABULATE:
        print("\n" + tabulate(disp, headers="keys", tablefmt="rounded_outline", showindex=False))
    else:
        print(disp.to_string(index=False))
    print()

def plot_memory(df, outdir):
    os.makedirs(outdir, exist_ok=True)

    plt.rcParams.update({
        "figure.facecolor": "#0f172a",
        "axes.facecolor":   "#1e293b",
        "axes.edgecolor":   "#334155",
        "axes.labelcolor":  "#e2e8f0",
        "axes.titlecolor":  "#f8fafc",
        "xtick.color":      "#94a3b8",
        "ytick.color":      "#94a3b8",
        "text.color":       "#e2e8f0",
        "grid.color":       "#334155",
        "grid.linestyle":   "--",
        "grid.alpha":       0.5,
        "font.family":      "monospace",
    })

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.patch.set_facecolor("#0f172a")

    labels = [ALGO_LABELS.get(a, a) for a in df["algo"]]
    colors = [ALGO_COLORS.get(a, "#888") for a in df["algo"]]
    x = np.arange(len(labels))

    # Flash
    bars1 = ax1.bar(x, df["flash"], color=colors, alpha=0.85)
    ax1.axhline(FLASH_MAX, color="#f8fafc", linestyle="--", linewidth=1.5, label=f"Flash limit ({FLASH_MAX:,}B)")
    ax1.set_xticks(x); ax1.set_xticklabels(labels, fontsize=8, rotation=15, ha="right")
    ax1.set_ylabel("Bytes"); ax1.set_title("Flash Memory Usage", fontsize=12)
    ax1.yaxis.grid(True); ax1.set_axisbelow(True); ax1.legend(fontsize=8)
    for bar in bars1:
        h = bar.get_height()
        ax1.text(bar.get_x()+bar.get_width()/2, h+50, f"{h:,}B",
                 ha="center", fontsize=7, color="#f8fafc")

    # SRAM — with danger zone
    bars2 = ax2.bar(x, df["sram"], color=colors, alpha=0.85)
    ax2.axhline(SRAM_MAX, color="#ef4444", linestyle="--", linewidth=1.5, label=f"SRAM limit ({SRAM_MAX:,}B)")
    ax2.axhspan(SRAM_MAX * 0.85, SRAM_MAX, alpha=0.12, color="#ef4444", label="Danger zone (>85%)")
    ax2.set_xticks(x); ax2.set_xticklabels(labels, fontsize=8, rotation=15, ha="right")
    ax2.set_ylabel("Bytes"); ax2.set_title("SRAM Usage at Runtime", fontsize=12)
    ax2.yaxis.grid(True); ax2.set_axisbelow(True); ax2.legend(fontsize=8)
    for bar in bars2:
        h = bar.get_height()
        ax2.text(bar.get_x()+bar.get_width()/2, h+5, f"{h:,}B",
                 ha="center", fontsize=7, color="#f8fafc")

    fig.suptitle("ATmega328P Memory Footprint by Algorithm (TX sketch)",
                 fontsize=13, color="#f8fafc", y=1.02)
    plt.tight_layout()
    path = os.path.join(outdir, "07_memory_footprint.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Generate memory footprint report")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--elf-dir", help="Directory containing .elf build artefacts")
    g.add_argument("--json",    help="JSON file with manual memory data")
    g.add_argument("--manual",  action="store_true", help="Interactive manual entry")
    p.add_argument("--outdir",  default="results/figures", help="Output directory for figures")
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
        # Demo with placeholder data so you can test the script
        print("No data source specified. Running with example data.")
        print("Use --elf-dir, --json, or --manual in production.\n")
        rows = [
            {"algo": "PLAIN",    "flash": 4_230,  "sram": 312},
            {"algo": "XOR",      "flash": 4_556,  "sram": 318},
            {"algo": "AES128",   "flash": 8_104,  "sram": 542},
            {"algo": "SPECK",    "flash": 5_248,  "sram": 346},
            {"algo": "CHACHA20", "flash": 6_912,  "sram": 398},
        ]

    if not rows:
        print("No data loaded."); sys.exit(1)

    df = build_report(rows)
    print_report(df)
    plot_memory(df, args.outdir)
    print("Done.")

if __name__ == "__main__":
    main()
