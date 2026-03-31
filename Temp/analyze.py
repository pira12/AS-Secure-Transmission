#!/usr/bin/env python3
"""
analyze.py — AS-Secure-Transmission Analysis & Graph Generator
==============================================================
Reads all CSV files in results/ and produces:
  1. Terminal summary tables
  2. Publication-quality matplotlib figures saved to results/figures/
  3. A JSON summary file for the interactive HTML dashboard

USAGE
-----
  python analyze.py
  python analyze.py --results results/ --outdir results/figures/

DEPENDENCIES
------------
  pip install pandas matplotlib numpy scipy tabulate
"""

import argparse
import glob
import json
import os
import re
import sys
import warnings

warnings.filterwarnings("ignore")

try:
    import pandas as pd
    import numpy as np
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.gridspec import GridSpec
    from scipy import stats as sp_stats
except ImportError as e:
    print(f"ERROR: Missing dependency — {e}")
    print("Run:  pip install pandas matplotlib numpy scipy")
    sys.exit(1)

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False
    print("tip: pip install tabulate  for prettier terminal tables\n")

# ---------------------------------------------------------------------------
# Style
# ---------------------------------------------------------------------------

ALGO_ORDER  = ["PLAIN", "XOR", "AES128", "SPECK", "CHACHA20"]
ALGO_LABELS = {
    "PLAIN":    "Plaintext",
    "XOR":      "XOR (Static Key)",
    "AES128":   "AES-128 (ECB)",
    "SPECK":    "SPECK-64/128",
    "CHACHA20": "ChaCha20",
}
COLORS = {
    "PLAIN":    "#64748b",
    "XOR":      "#ef4444",
    "AES128":   "#3b82f6",
    "SPECK":    "#22c55e",
    "CHACHA20": "#f59e0b",
}

PLT_STYLE = {
    "figure.facecolor":     "#0f172a",
    "axes.facecolor":       "#1e293b",
    "axes.edgecolor":       "#334155",
    "axes.labelcolor":      "#e2e8f0",
    "axes.titlecolor":      "#f8fafc",
    "xtick.color":          "#94a3b8",
    "ytick.color":          "#94a3b8",
    "text.color":           "#e2e8f0",
    "grid.color":           "#334155",
    "grid.linestyle":       "--",
    "grid.alpha":           0.5,
    "legend.facecolor":     "#1e293b",
    "legend.edgecolor":     "#334155",
    "legend.labelcolor":    "#e2e8f0",
    "font.family":          "monospace",
    "font.size":            10,
}

def apply_style():
    plt.rcParams.update(PLT_STYLE)

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
# Statistics builder
# ---------------------------------------------------------------------------

def build_stats(tx, rx):
    rows = []
    for algo in ALGO_ORDER:
        t = tx[tx["algo"] == algo] if not tx.empty else pd.DataFrame()
        r = rx[rx["algo"] == algo] if not rx.empty else pd.DataFrame()

        sent  = len(t)
        recvd = len(r)
        loss  = (1 - recvd / sent) * 100 if sent > 0 else None
        ok    = r["ok"].sum() if not r.empty and "ok" in r.columns else 0
        integrity = ok / recvd * 100 if recvd > 0 else None

        enc_mean = t["enc_us"].mean() if not t.empty and "enc_us" in t.columns else None
        enc_std  = t["enc_us"].std()  if not t.empty and "enc_us" in t.columns else None
        dec_mean = r["dec_us"].mean() if not r.empty and "dec_us" in r.columns else None
        dec_std  = r["dec_us"].std()  if not r.empty and "dec_us" in r.columns else None

        # Effective throughput: msg_size_bytes * 8 bits / (enc_us / 1e6 + radio_overhead)
        # Radio at 2000 bps: 16 bytes = 128 bits → 64 ms radio time
        # Effective throughput = 128 / (enc_us/1e6 + 0.064) bps
        msg_bits    = 16 * 8
        radio_s     = msg_bits / 2000.0
        enc_s       = (enc_mean or 0) / 1e6
        eff_tput    = msg_bits / (enc_s + radio_s) if (enc_s + radio_s) > 0 else None

        rows.append({
            "algo":        algo,
            "label":       ALGO_LABELS.get(algo, algo),
            "sent":        sent,
            "recvd":       recvd,
            "loss_pct":    loss,
            "ok":          int(ok),
            "integrity_pct": integrity,
            "enc_mean_us": enc_mean,
            "enc_std_us":  enc_std,
            "dec_mean_us": dec_mean,
            "dec_std_us":  dec_std,
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

    # Table 1: Latency
    lat = stats[["label", "enc_mean_us", "enc_std_us", "dec_mean_us", "dec_std_us"]].copy()
    lat.columns = ["Algorithm", "Enc Mean (µs)", "Enc σ (µs)", "Dec Mean (µs)", "Dec σ (µs)"]
    lat = lat.dropna(subset=["Enc Mean (µs)"])
    for col in lat.columns[1:]:
        lat[col] = lat[col].map(lambda x: f"{x:.1f}" if pd.notna(x) else "—")

    print("\n📊 Table 1: Encryption/Decryption Latency (16-byte message)\n")
    if HAS_TABULATE:
        print(tabulate(lat, headers="keys", tablefmt="rounded_outline", showindex=False))
    else:
        print(lat.to_string(index=False))

    # Table 2: Packet metrics
    pkt = stats[["label", "sent", "recvd", "loss_pct", "integrity_pct"]].copy()
    pkt.columns = ["Algorithm", "Sent", "Recv'd", "Loss %", "Integrity %"]
    for col in ["Loss %", "Integrity %"]:
        pkt[col] = pkt[col].map(lambda x: f"{x:.1f}%" if pd.notna(x) else "—")

    print("\n📊 Table 2: Transmission Reliability\n")
    if HAS_TABULATE:
        print(tabulate(pkt, headers="keys", tablefmt="rounded_outline", showindex=False))
    else:
        print(pkt.to_string(index=False))

    # Table 3: Throughput
    tput = stats[["label", "eff_tput_bps"]].copy()
    tput.columns = ["Algorithm", "Effective Throughput (bps)"]
    tput["Effective Throughput (bps)"] = tput["Effective Throughput (bps)"].map(
        lambda x: f"{x:.1f}" if pd.notna(x) else "—"
    )
    print("\n📊 Table 3: Effective Application Throughput (16-byte msg over 2000 bps link)\n")
    if HAS_TABULATE:
        print(tabulate(tput, headers="keys", tablefmt="rounded_outline", showindex=False))
    else:
        print(tput.to_string(index=False))

    print()

# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------

def fig_latency_bar(stats, outdir):
    """Bar chart: enc+dec latency per algorithm with error bars."""
    apply_style()
    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#0f172a")

    df = stats.dropna(subset=["enc_mean_us"])
    algos  = [ALGO_LABELS[a] for a in df["algo"]]
    x      = np.arange(len(algos))
    width  = 0.35

    b1 = ax.bar(x - width/2, df["enc_mean_us"],      width, yerr=df["enc_std_us"],
                color=[COLORS[a] for a in df["algo"]],
                alpha=0.85, label="Encrypt", capsize=5, error_kw={"ecolor":"#f8fafc","elinewidth":1.5})
    b2 = ax.bar(x + width/2, df["dec_mean_us"],      width, yerr=df["dec_std_us"],
                color=[COLORS[a] for a in df["algo"]],
                alpha=0.45, label="Decrypt", capsize=5, error_kw={"ecolor":"#f8fafc","elinewidth":1.5})

    ax.set_xticks(x)
    ax.set_xticklabels(algos, fontsize=9)
    ax.set_ylabel("Latency (µs)", fontsize=11)
    ax.set_title("Encryption / Decryption Latency per Algorithm\n(16-byte message, ATmega328P @ 16 MHz)", fontsize=12)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.legend(loc="upper left")

    # Value labels on bars
    for rect in list(b1) + list(b2):
        h = rect.get_height()
        if pd.notna(h) and h > 0:
            ax.annotate(f"{h:.0f}", xy=(rect.get_x() + rect.get_width()/2, h),
                        xytext=(0, 4), textcoords="offset points",
                        ha="center", va="bottom", fontsize=8, color="#f8fafc")

    plt.tight_layout()
    path = os.path.join(outdir, "01_latency_bar.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

def fig_latency_dist(tx, outdir):
    """Violin / KDE: distribution of enc_us across algorithms."""
    apply_style()
    algos_present = [a for a in ALGO_ORDER if a in tx["algo"].unique() and a != "PLAIN"]
    if not algos_present:
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#0f172a")

    data = [tx[tx["algo"] == a]["enc_us"].dropna().values for a in algos_present]
    labels = [ALGO_LABELS[a] for a in algos_present]
    colors_list = [COLORS[a] for a in algos_present]

    parts = ax.violinplot(data, positions=range(len(data)), showmedians=True,
                          showextrema=True)

    for i, pc in enumerate(parts["bodies"]):
        pc.set_facecolor(colors_list[i])
        pc.set_alpha(0.7)
    parts["cmedians"].set_color("#f8fafc")
    parts["cbars"].set_color("#f8fafc")
    parts["cmins"].set_color("#f8fafc")
    parts["cmaxes"].set_color("#f8fafc")

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylabel("Encrypt Time (µs)", fontsize=11)
    ax.set_title("Encryption Latency Distribution\n(all samples, 16-byte message)", fontsize=12)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)

    plt.tight_layout()
    path = os.path.join(outdir, "02_latency_distribution.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

def fig_packet_loss(stats, outdir):
    """Horizontal bar: packet loss % per algorithm."""
    apply_style()
    df = stats.dropna(subset=["loss_pct"])
    if df.empty:
        return

    fig, ax = plt.subplots(figsize=(8, 4))
    fig.patch.set_facecolor("#0f172a")

    labels = [ALGO_LABELS[a] for a in df["algo"]]
    loss   = df["loss_pct"].values
    colors = [COLORS[a] for a in df["algo"]]

    bars = ax.barh(labels, loss, color=colors, alpha=0.85)
    ax.set_xlabel("Packet Loss (%)", fontsize=11)
    ax.set_title("Packet Loss Rate per Algorithm", fontsize=12)
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)

    for bar, val in zip(bars, loss):
        ax.text(val + 0.2, bar.get_y() + bar.get_height()/2,
                f"{val:.1f}%", va="center", fontsize=9, color="#f8fafc")

    plt.tight_layout()
    path = os.path.join(outdir, "03_packet_loss.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

def fig_throughput(stats, outdir):
    """Bar: effective throughput vs raw link rate."""
    apply_style()
    df = stats.dropna(subset=["eff_tput_bps"])
    if df.empty:
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#0f172a")

    labels = [ALGO_LABELS[a] for a in df["algo"]]
    tput   = df["eff_tput_bps"].values
    colors = [COLORS[a] for a in df["algo"]]

    ax.barh(labels, tput, color=colors, alpha=0.85)
    ax.axvline(2000, color="#f8fafc", linestyle="--", linewidth=1.5, label="Raw link (2000 bps)")

    ax.set_xlabel("Effective Throughput (bps)", fontsize=11)
    ax.set_title("Effective Application Throughput per Algorithm\n(overhead = encrypt latency + radio transmission)", fontsize=12)
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.legend()

    for i, val in enumerate(tput):
        ax.text(val + 10, i, f"{val:.0f} bps", va="center", fontsize=9, color="#f8fafc")

    plt.tight_layout()
    path = os.path.join(outdir, "04_throughput.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")

def fig_enc_timeseries(tx, outdir):
    """Time-series of enc_us over the test window."""
    apply_style()
    algos_present = [a for a in ALGO_ORDER if a in tx["algo"].unique()]
    if not algos_present:
        return

    fig, ax = plt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor("#0f172a")

    for algo in algos_present:
        sub = tx[tx["algo"] == algo].sort_values("wall_time_s")
        if "enc_us" not in sub.columns:
            continue
        # Rolling mean for readability
        rolling = sub["enc_us"].rolling(5, min_periods=1).mean()
        ax.plot(sub["wall_time_s"], rolling,
                label=ALGO_LABELS[algo], color=COLORS[algo], linewidth=1.8, alpha=0.9)

    ax.set_xlabel("Elapsed Time (s)", fontsize=11)
    ax.set_ylabel("Encrypt Time (µs) — rolling avg", fontsize=11)
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
    """Radar chart: normalised multi-metric comparison."""
    apply_style()
    df = stats.dropna(subset=["enc_mean_us", "loss_pct", "eff_tput_bps"]).copy()
    if len(df) < 2:
        return

    metrics = ["Encrypt Speed", "Decrypt Speed", "Throughput", "Reliability"]

    # Normalise 0–1 (higher = better for all)
    df["n_enc"]  = 1 - (df["enc_mean_us"] - df["enc_mean_us"].min()) / (df["enc_mean_us"].max() - df["enc_mean_us"].min() + 1e-9)
    df["n_dec"]  = 1 - (df["dec_mean_us"] - df["dec_mean_us"].min()) / (df["dec_mean_us"].max() - df["dec_mean_us"].min() + 1e-9)
    df["n_tput"] = (df["eff_tput_bps"] - df["eff_tput_bps"].min()) / (df["eff_tput_bps"].max() - df["eff_tput_bps"].min() + 1e-9)
    df["n_rel"]  = (df["integrity_pct"].fillna(100) - 0) / 100.0

    N = len(metrics)
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor("#0f172a")
    ax.set_facecolor("#1e293b")

    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metrics, color="#e2e8f0", fontsize=10)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["25%", "50%", "75%", "100%"], color="#64748b", fontsize=8)
    ax.yaxis.grid(color="#334155", linestyle="--", alpha=0.5)
    ax.spines["polar"].set_color("#334155")

    for _, row in df.iterrows():
        values = [row["n_enc"], row["n_dec"], row["n_tput"], row["n_rel"]]
        values += values[:1]
        ax.plot(angles, values, color=COLORS[row["algo"]], linewidth=2, label=ALGO_LABELS[row["algo"]])
        ax.fill(angles, values, color=COLORS[row["algo"]], alpha=0.15)

    ax.legend(loc="lower right", bbox_to_anchor=(1.3, -0.1))
    ax.set_title("Algorithm Performance Radar\n(normalised, higher = better)", fontsize=12, pad=20, color="#f8fafc")

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
        t = tx[tx["algo"] == algo]["enc_us"].dropna().tolist() if not tx.empty else []
        r_dec = rx[rx["algo"] == algo]["dec_us"].dropna().tolist() if not rx.empty else []

        payload["algorithms"].append({
            "id":             algo,
            "label":          ALGO_LABELS.get(algo, algo),
            "color":          COLORS.get(algo, "#888"),
            "enc_mean_us":    round(row["enc_mean_us"], 2) if pd.notna(row["enc_mean_us"]) else None,
            "enc_std_us":     round(row["enc_std_us"],  2) if pd.notna(row["enc_std_us"])  else None,
            "dec_mean_us":    round(row["dec_mean_us"], 2) if pd.notna(row["dec_mean_us"]) else None,
            "dec_std_us":     round(row["dec_std_us"],  2) if pd.notna(row["dec_std_us"])  else None,
            "sent":           int(row["sent"]),
            "recvd":          int(row["recvd"]),
            "loss_pct":       round(row["loss_pct"], 2)     if pd.notna(row["loss_pct"])     else None,
            "integrity_pct":  round(row["integrity_pct"],2) if pd.notna(row["integrity_pct"])else None,
            "eff_tput_bps":   round(row["eff_tput_bps"],1)  if pd.notna(row["eff_tput_bps"]) else None,
            "enc_samples":    t[:200],   # cap at 200 points for dashboard
            "dec_samples":    r_dec[:200],
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
    p = argparse.ArgumentParser(description="Analyse test results and generate graphs")
    p.add_argument("--results", default="results",         help="Directory with CSV files (default: results/)")
    p.add_argument("--outdir",  default="results/figures", help="Output directory for figures (default: results/figures/)")
    return p.parse_args()

def main():
    args = parse_args()

    if not os.path.isdir(args.results):
        print(f"ERROR: results directory '{args.results}' not found.")
        print("Run collect_data.py first, or point --results at your CSV folder.")
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

    print("\nGenerating figures…")
    fig_latency_bar(stats, args.outdir)
    fig_latency_dist(tx, args.outdir)
    fig_packet_loss(stats, args.outdir)
    fig_throughput(stats, args.outdir)
    fig_enc_timeseries(tx, args.outdir)
    fig_radar(stats, args.outdir)

    export_json(stats, tx, rx, args.outdir)

    print(f"\n✓ All done. Figures saved to: {args.outdir}/")

if __name__ == "__main__":
    main()
