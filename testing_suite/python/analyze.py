#!/usr/bin/env python3
"""
analyze.py — AS-Secure-Transmission results analyser
=====================================================
Reads all CSV files in results/ and produces:
  - Terminal summary tables (latency, reliability, throughput)
  - Matplotlib figures saved to results/figures/
  - results.json consumed by dashboard.html

USAGE
-----
  cd testing_suite
  python python/analyze.py
  python python/analyze.py --results results/ --outdir results/figures/

DEPENDENCIES
------------
  pip install pandas matplotlib numpy scipy tabulate
"""

import argparse
import glob
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

try:
    import pandas as pd
    import numpy as np
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError as e:
    print(f"ERROR: {e}\nRun: pip install pandas matplotlib numpy")
    sys.exit(1)

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
FIGURES_DIR = os.path.join(RESULTS_DIR, "figures")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGO_ORDER = ["PLAIN", "XOR", "AES128", "AES128CBC", "SPECK", "CHACHA20"]
ALGO_LABELS = {
    "PLAIN":     "Plaintext",
    "XOR":       "XOR (Static Key)",
    "AES128":    "AES-128 ECB",
    "AES128CBC": "AES-128 CBC",
    "SPECK":     "SPECK-64/128",
    "CHACHA20":  "ChaCha20",
}
COLORS = {
    "PLAIN":     "#6B7280",
    "XOR":       "#DC2626",
    "AES128":    "#2563EB",
    "AES128CBC": "#7C3AED",
    "SPECK":     "#16A34A",
    "CHACHA20":  "#B45309",
}

# UvA-styled light theme for matplotlib figures
LIGHT = {
    "figure.facecolor": "#FFFFFF",
    "axes.facecolor":   "#FAFAFA",
    "axes.edgecolor":   "#CCCCCC",
    "axes.labelcolor":  "#1A1A1A",
    "axes.titlecolor":  "#1A1A1A",
    "xtick.color":      "#5A5A5A",
    "ytick.color":      "#5A5A5A",
    "text.color":       "#1A1A1A",
    "grid.color":       "#E0E0E0",
    "grid.linestyle":   "--",
    "grid.alpha":       0.8,
    "legend.facecolor": "#FFFFFF",
    "legend.edgecolor": "#CCCCCC",
    "font.family":      "monospace",
    "font.size":        10,
}

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_csvs(results_dir):
    tx_frames, rx_frames = [], []

    for path in glob.glob(os.path.join(results_dir, "*_tx_*.csv")):
        algo = os.path.basename(path).split("_tx_")[0]
        df = pd.read_csv(path)
        df["algo"] = algo
        tx_frames.append(df)

    for path in glob.glob(os.path.join(results_dir, "*_rx_*.csv")):
        algo = os.path.basename(path).split("_rx_")[0]
        df = pd.read_csv(path)
        df["algo"] = algo
        rx_frames.append(df)

    tx = pd.concat(tx_frames, ignore_index=True) if tx_frames else pd.DataFrame()
    rx = pd.concat(rx_frames, ignore_index=True) if rx_frames else pd.DataFrame()
    return tx, rx

# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def build_stats(tx, rx):
    rows = []
    for algo in ALGO_ORDER:
        t = tx[tx["algo"] == algo] if not tx.empty else pd.DataFrame()
        r = rx[rx["algo"] == algo] if not rx.empty else pd.DataFrame()

        sent  = len(t)
        recvd = len(r)
        loss  = (1 - recvd / sent) * 100 if sent > 0 else None
        ok    = int(r["ok"].sum()) if not r.empty and "ok" in r.columns else 0
        integ = ok / recvd * 100 if recvd > 0 else None

        enc_mean = t["enc_us"].mean() if not t.empty and "enc_us" in t.columns else None
        enc_std  = t["enc_us"].std()  if not t.empty else None
        dec_mean = r["dec_us"].mean() if not r.empty and "dec_us" in r.columns else None
        dec_std  = r["dec_us"].std()  if not r.empty else None

        # Effective throughput: 128 bits / (enc overhead + 64 ms radio time)
        msg_bits = 16 * 8
        radio_s  = msg_bits / 2000.0
        enc_s    = (enc_mean or 0) / 1e6
        eff_tput = msg_bits / (enc_s + radio_s) if (enc_s + radio_s) > 0 else None

        rows.append({
            "algo":         algo,
            "label":        ALGO_LABELS.get(algo, algo),
            "sent":         sent,
            "recvd":        recvd,
            "loss_pct":     loss,
            "ok":           ok,
            "integrity_pct": integ,
            "enc_mean_us":  enc_mean,
            "enc_std_us":   enc_std,
            "dec_mean_us":  dec_mean,
            "dec_std_us":   dec_std,
            "eff_tput_bps": eff_tput,
        })
    return pd.DataFrame(rows)

# ---------------------------------------------------------------------------
# Terminal tables
# ---------------------------------------------------------------------------

def print_tables(stats):
    print("\n" + "="*70)
    print("  AS-SECURE-TRANSMISSION — RESULTS SUMMARY")
    print("="*70)

    def fmt(x, dec=1):
        return f"{x:.{dec}f}" if pd.notna(x) else "—"

    # Latency
    lat = stats[["label","enc_mean_us","enc_std_us","dec_mean_us","dec_std_us"]].copy()
    lat.columns = ["Algorithm", "Enc mean (µs)", "Enc σ", "Dec mean (µs)", "Dec σ"]
    lat = lat.dropna(subset=["Enc mean (µs)"])
    for col in lat.columns[1:]:
        lat[col] = lat[col].map(lambda x: fmt(x)).astype(str)  # ← add .astype(str)
    print("\nTable 1 — Enc/Dec latency (16-byte message)\n")
    if HAS_TABULATE:
        print(tabulate(lat, headers="keys", tablefmt="rounded_outline", showindex=False))
    else:
        print(lat.to_string(index=False))

    # Reliability
    rel = stats[["label","sent","recvd","loss_pct","integrity_pct"]].copy()
    rel.columns = ["Algorithm", "Sent", "Recv'd", "Loss %", "Integrity %"]
    for col in ["Loss %", "Integrity %"]:
        rel[col] = rel[col].map(lambda x: f"{x:.1f}%" if pd.notna(x) else "—").astype(str)  # ← add .astype(str)
    print("\nTable 2 — Transmission reliability\n")
    if HAS_TABULATE:
        print(tabulate(rel, headers="keys", tablefmt="rounded_outline", showindex=False))
    else:
        print(rel.to_string(index=False))

    # Throughput
    tput = stats[["label","eff_tput_bps"]].copy()
    tput.columns = ["Algorithm", "Effective throughput (bps)"]
    tput["Effective throughput (bps)"] = tput["Effective throughput (bps)"].map(
        lambda x: fmt(x, 0)).astype(str)  # ← use explicit column name + .astype(str)
    print("\nTable 3 — Effective throughput (2000 bps raw link)\n")
    if HAS_TABULATE:
        print(tabulate(tput, headers="keys", tablefmt="rounded_outline", showindex=False))
    else:
        print(tput.to_string(index=False))
    print()

# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------

def _style():
    plt.rcParams.update(LIGHT)

def fig_latency_bar(stats, outdir):
    _style()
    df = stats.dropna(subset=["enc_mean_us"])
    if df.empty:
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#FFFFFF")
    x     = np.arange(len(df))
    w     = 0.35
    clrs  = [COLORS[a] for a in df["algo"]]

    b1 = ax.bar(x - w/2, df["enc_mean_us"], w, yerr=df["enc_std_us"],
                color=clrs, alpha=0.85, label="Encrypt",
                capsize=5, error_kw={"ecolor":"#333333","elinewidth":1.5})
    b2 = ax.bar(x + w/2, df["dec_mean_us"], w, yerr=df["dec_std_us"],
                color=clrs, alpha=0.45, label="Decrypt",
                capsize=5, error_kw={"ecolor":"#333333","elinewidth":1.5})

    ax.set_xticks(x)
    ax.set_xticklabels([ALGO_LABELS[a] for a in df["algo"]], fontsize=9)
    ax.set_ylabel("Latency (µs)")
    ax.set_title("Encryption / Decryption Latency\n(16-byte message, ATmega328P @ 16 MHz)", fontsize=12)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.legend()

    for rect in list(b1) + list(b2):
        h = rect.get_height()
        if pd.notna(h) and h > 0:
            ax.annotate(f"{h:.0f}",
                        xy=(rect.get_x() + rect.get_width()/2, h),
                        xytext=(0, 4), textcoords="offset points",
                        ha="center", va="bottom", fontsize=8, color="#1A1A1A")

    plt.tight_layout()
    path = os.path.join(outdir, "01_latency_bar.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

def fig_latency_dist(tx, outdir):
    _style()
    algos = [a for a in ALGO_ORDER if a in tx["algo"].unique() and a != "PLAIN"]
    if not algos:
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#FFFFFF")
    data   = [tx[tx["algo"] == a]["enc_us"].dropna().values for a in algos]
    labels = [ALGO_LABELS[a] for a in algos]
    clrs   = [COLORS[a] for a in algos]

    parts = ax.violinplot(data, positions=range(len(data)),
                          showmedians=True, showextrema=True)
    for i, pc in enumerate(parts["bodies"]):
        pc.set_facecolor(clrs[i]); pc.set_alpha(0.7)
    for key in ("cmedians","cbars","cmins","cmaxes"):
        parts[key].set_color("#333333")

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylabel("Encrypt Time (µs)")
    ax.set_title("Encryption Latency Distribution (all samples)", fontsize=12)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)

    plt.tight_layout()
    path = os.path.join(outdir, "02_latency_distribution.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

def fig_packet_loss(stats, outdir):
    _style()
    df = stats.dropna(subset=["loss_pct"])
    if df.empty:
        return

    fig, ax = plt.subplots(figsize=(8, 4))
    fig.patch.set_facecolor("#FFFFFF")
    labels = [ALGO_LABELS[a] for a in df["algo"]]
    clrs   = [COLORS[a] for a in df["algo"]]

    bars = ax.barh(labels, df["loss_pct"], color=clrs, alpha=0.85)
    ax.set_xlabel("Packet Loss (%)")
    ax.set_title("Packet Loss Rate per Algorithm", fontsize=12)
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)

    for bar, val in zip(bars, df["loss_pct"]):
        ax.text(val + 0.15, bar.get_y() + bar.get_height()/2,
                f"{val:.1f}%", va="center", fontsize=9, color="#1A1A1A")

    plt.tight_layout()
    path = os.path.join(outdir, "03_packet_loss.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

def fig_throughput(stats, outdir):
    _style()
    df = stats.dropna(subset=["eff_tput_bps"])
    if df.empty:
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#FFFFFF")
    clrs = [COLORS[a] for a in df["algo"]]

    ax.barh([ALGO_LABELS[a] for a in df["algo"]], df["eff_tput_bps"],
            color=clrs, alpha=0.85)
    ax.axvline(2000, color="#BC0031", linestyle="--", linewidth=1.5,
               label="Raw link (2000 bps)")
    ax.set_xlabel("Effective Throughput (bps)")
    ax.set_title("Effective Throughput per Algorithm\n(enc overhead + radio transmission)", fontsize=12)
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.legend()

    for i, val in enumerate(df["eff_tput_bps"]):
        ax.text(val + 5, i, f"{val:.0f}", va="center", fontsize=9, color="#1A1A1A")

    plt.tight_layout()
    path = os.path.join(outdir, "04_throughput.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

def fig_timeseries(tx, outdir):
    _style()
    algos = [a for a in ALGO_ORDER if a in tx["algo"].unique()]
    if not algos:
        return

    fig, ax = plt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor("#FFFFFF")

    for algo in algos:
        sub = tx[tx["algo"] == algo].sort_values("wall_time_s")
        if "enc_us" not in sub.columns:
            continue
        rolling = sub["enc_us"].rolling(5, min_periods=1).mean()
        ax.plot(sub["wall_time_s"], rolling,
                label=ALGO_LABELS[algo], color=COLORS[algo],
                linewidth=1.8, alpha=0.9)

    ax.set_xlabel("Elapsed Time (s)")
    ax.set_ylabel("Encrypt Time (µs) — rolling avg")
    ax.set_title("Encryption Latency Over Test Window", fontsize=12)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.legend(loc="upper right")

    plt.tight_layout()
    path = os.path.join(outdir, "05_latency_timeseries.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

def fig_radar(stats, outdir):
    _style()
    df = stats.dropna(subset=["enc_mean_us", "loss_pct", "eff_tput_bps"]).copy()
    if len(df) < 2:
        return

    metrics = ["Encrypt\nSpeed", "Decrypt\nSpeed", "Throughput", "Reliability"]
    eps = 1e-9

    df["n_enc"]  = 1 - (df["enc_mean_us"] - df["enc_mean_us"].min()) / (df["enc_mean_us"].max() - df["enc_mean_us"].min() + eps)
    df["n_dec"]  = 1 - (df["dec_mean_us"] - df["dec_mean_us"].min()) / (df["dec_mean_us"].max() - df["dec_mean_us"].min() + eps)
    df["n_tput"] = (df["eff_tput_bps"] - df["eff_tput_bps"].min()) / (df["eff_tput_bps"].max() - df["eff_tput_bps"].min() + eps)
    df["n_rel"]  = df["integrity_pct"].fillna(100) / 100.0

    N = len(metrics)
    angles = [n / float(N) * 2 * np.pi for n in range(N)] + [0]

    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor("#FFFFFF")
    ax.set_facecolor("#FAFAFA")
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metrics, color="#1A1A1A", fontsize=10)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["25%","50%","75%","100%"], color="#888888", fontsize=8)
    ax.yaxis.grid(color="#E0E0E0", linestyle="--", alpha=0.8)
    ax.spines["polar"].set_color("#CCCCCC")

    for _, row in df.iterrows():
        vals = [row["n_enc"], row["n_dec"], row["n_tput"], row["n_rel"], row["n_enc"]]
        ax.plot(angles, vals, color=COLORS[row["algo"]], linewidth=2,
                label=ALGO_LABELS[row["algo"]])
        ax.fill(angles, vals, color=COLORS[row["algo"]], alpha=0.12)

    ax.legend(loc="lower right", bbox_to_anchor=(1.35, -0.1))
    ax.set_title("Algorithm Performance Radar\n(normalised — higher = better)", fontsize=12, pad=20)

    plt.tight_layout()
    path = os.path.join(outdir, "06_radar.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

# ---------------------------------------------------------------------------
# JSON export for dashboard
# ---------------------------------------------------------------------------

def export_json(stats, tx, rx, outdir):
    payload = {"algorithms": []}
    for _, row in stats.iterrows():
        algo = row["algo"]
        enc_samples = tx[tx["algo"] == algo]["enc_us"].dropna().tolist() if not tx.empty else []
        dec_samples = rx[rx["algo"] == algo]["dec_us"].dropna().tolist() if not rx.empty else []

        payload["algorithms"].append({
            "id":            algo,
            "label":         ALGO_LABELS.get(algo, algo),
            "color":         COLORS.get(algo, "#888"),
            "enc_mean_us":   round(row["enc_mean_us"], 2) if pd.notna(row["enc_mean_us"]) else None,
            "enc_std_us":    round(row["enc_std_us"],  2) if pd.notna(row["enc_std_us"])  else None,
            "dec_mean_us":   round(row["dec_mean_us"], 2) if pd.notna(row["dec_mean_us"]) else None,
            "dec_std_us":    round(row["dec_std_us"],  2) if pd.notna(row["dec_std_us"])  else None,
            "sent":          int(row["sent"]),
            "recvd":         int(row["recvd"]),
            "loss_pct":      round(row["loss_pct"],     2) if pd.notna(row["loss_pct"])      else None,
            "integrity_pct": round(row["integrity_pct"],2) if pd.notna(row["integrity_pct"]) else None,
            "eff_tput_bps":  round(row["eff_tput_bps"], 1) if pd.notna(row["eff_tput_bps"])  else None,
            "enc_samples":   enc_samples[:300],
            "dec_samples":   dec_samples[:300],
        })

    path = os.path.join(outdir, "results.json")
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n  Dashboard JSON → {path}")
    return path

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Analyse results and generate graphs")
    p.add_argument("--results", default=RESULTS_DIR,
                   help="Directory with CSV files (default: ../results/)")
    p.add_argument("--outdir",  default=FIGURES_DIR,
                   help="Output directory for figures (default: ../results/figures/)")
    return p.parse_args()

def main():
    args = parse_args()

    if not os.path.isdir(args.results):
        print(f"ERROR: '{args.results}' not found. Run collect_data.py first.")
        sys.exit(1)

    os.makedirs(args.outdir, exist_ok=True)

    print("\nLoading CSV files…")
    tx, rx = load_csvs(args.results)
    if tx.empty and rx.empty:
        print("No CSV data found. Run collect_data.py first.")
        sys.exit(1)
    print(f"  TX rows: {len(tx)}  |  RX rows: {len(rx)}")

    stats = build_stats(tx, rx)
    print_tables(stats)

    print("Generating figures…")
    fig_latency_bar(stats, args.outdir)
    fig_latency_dist(tx, args.outdir)
    fig_packet_loss(stats, args.outdir)
    fig_throughput(stats, args.outdir)
    fig_timeseries(tx, args.outdir)
    fig_radar(stats, args.outdir)
    export_json(stats, tx, rx, args.outdir)

    print(f"\nDone. Open testing_suite/dashboard.html in a browser.")


if __name__ == "__main__":
    main()
