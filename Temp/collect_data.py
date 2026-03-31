#!/usr/bin/env python3
"""
collect_data.py — AS-Secure-Transmission Test Suite
====================================================
Reads structured serial output from the TX and RX Arduinos and saves
raw data to CSV files in the results/ directory.

USAGE
-----
  python collect_data.py --tx COM3 --rx COM4 --duration 60 --algo AES128

  On Linux/macOS ports are typically /dev/ttyUSB0, /dev/ttyACM0, etc.

SERIAL PROTOCOL
---------------
TX lines:  TEST,<ALG>,<SIZE>,ENC_US:<t>,ITER:<n>
RX lines:  RECV,<ALG>,<SIZE>,DEC_US:<t>,OK:<0|1>,ITER:<n>

OUTPUT
------
results/<algo>_tx.csv   — TX timing data
results/<algo>_rx.csv   — RX timing + success data
"""

import argparse
import csv
import os
import re
import sys
import time
import threading
from datetime import datetime

try:
    import serial
except ImportError:
    print("ERROR: pyserial not installed. Run: pip install pyserial")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Collect serial data from TX/RX Arduinos")
    p.add_argument("--tx",       required=True,  help="Serial port for TX Arduino (e.g. COM3 or /dev/ttyUSB0)")
    p.add_argument("--rx",       required=True,  help="Serial port for RX Arduino (e.g. COM4 or /dev/ttyUSB1)")
    p.add_argument("--baud",     default=9600,   type=int, help="Baud rate (default: 9600)")
    p.add_argument("--duration", default=60,     type=int, help="Test duration in seconds (default: 60)")
    p.add_argument("--algo",     required=True,
                   choices=["PLAIN", "XOR", "AES128", "SPECK", "CHACHA20"],
                   help="Algorithm being tested (must match sketch output)")
    p.add_argument("--outdir",   default="results", help="Output directory (default: results/)")
    return p.parse_args()

# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------

def open_writers(outdir, algo):
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    tx_path = os.path.join(outdir, f"{algo}_tx_{ts}.csv")
    rx_path = os.path.join(outdir, f"{algo}_rx_{ts}.csv")

    tx_f = open(tx_path, "w", newline="")
    rx_f = open(rx_path, "w", newline="")

    tx_w = csv.writer(tx_f)
    rx_w = csv.writer(rx_f)

    tx_w.writerow(["wall_time_s", "algo", "msg_size_bytes", "enc_us", "iter"])
    rx_w.writerow(["wall_time_s", "algo", "msg_size_bytes", "dec_us", "ok", "iter"])

    print(f"  TX data → {tx_path}")
    print(f"  RX data → {rx_path}")
    return tx_f, tx_w, rx_f, rx_w, tx_path, rx_path

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

TX_RE = re.compile(
    r"TEST,(?P<algo>\w+),(?P<size>\d+),ENC_US:(?P<enc_us>\d+),ITER:(?P<iter>\d+)"
)
RX_RE = re.compile(
    r"RECV,(?P<algo>\w+),(?P<size>\d+),DEC_US:(?P<dec_us>\d+),OK:(?P<ok>[01]),ITER:(?P<iter>\d+)"
)

def parse_tx_line(line):
    m = TX_RE.search(line)
    if m:
        return {
            "algo":     m.group("algo"),
            "size":     int(m.group("size")),
            "enc_us":   int(m.group("enc_us")),
            "iter":     int(m.group("iter")),
        }
    return None

def parse_rx_line(line):
    m = RX_RE.search(line)
    if m:
        return {
            "algo":   m.group("algo"),
            "size":   int(m.group("size")),
            "dec_us": int(m.group("dec_us")),
            "ok":     int(m.group("ok")),
            "iter":   int(m.group("iter")),
        }
    return None

# ---------------------------------------------------------------------------
# Reader threads
# ---------------------------------------------------------------------------

stop_event = threading.Event()

def tx_reader(port, baud, writer, csv_file, start_time, stats):
    try:
        ser = serial.Serial(port, baud, timeout=1)
        print(f"[TX] Connected on {port}")
        while not stop_event.is_set():
            raw = ser.readline().decode("utf-8", errors="replace").strip()
            if not raw:
                continue
            elapsed = time.time() - start_time
            d = parse_tx_line(raw)
            if d:
                writer.writerow([f"{elapsed:.3f}", d["algo"], d["size"], d["enc_us"], d["iter"]])
                csv_file.flush()
                stats["tx_count"] += 1
                stats["enc_us_sum"] += d["enc_us"]
                if stats["tx_count"] % 10 == 0:
                    avg = stats["enc_us_sum"] / stats["tx_count"]
                    print(f"[TX] {stats['tx_count']} sent  |  avg enc: {avg:.1f} µs")
            else:
                print(f"[TX] {raw}")
        ser.close()
    except serial.SerialException as e:
        print(f"[TX] Serial error: {e}")
        stop_event.set()

def rx_reader(port, baud, writer, csv_file, start_time, stats):
    try:
        ser = serial.Serial(port, baud, timeout=1)
        print(f"[RX] Connected on {port}")
        while not stop_event.is_set():
            raw = ser.readline().decode("utf-8", errors="replace").strip()
            if not raw:
                continue
            elapsed = time.time() - start_time
            d = parse_rx_line(raw)
            if d:
                writer.writerow([f"{elapsed:.3f}", d["algo"], d["size"], d["dec_us"], d["ok"], d["iter"]])
                csv_file.flush()
                stats["rx_count"] += 1
                stats["ok_count"] += d["ok"]
                stats["dec_us_sum"] += d["dec_us"]
                if stats["rx_count"] % 10 == 0:
                    loss = 1 - (stats["rx_count"] / max(stats.get("tx_ref", stats["rx_count"]), 1))
                    avg  = stats["dec_us_sum"] / stats["rx_count"]
                    ok_r = stats["ok_count"] / stats["rx_count"] * 100
                    print(f"[RX] {stats['rx_count']} recv  |  avg dec: {avg:.1f} µs  |  ok: {ok_r:.1f}%")
            else:
                print(f"[RX] {raw}")
        ser.close()
    except serial.SerialException as e:
        print(f"[RX] Serial error: {e}")
        stop_event.set()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    print(f"\n{'='*55}")
    print(f"  AS-Secure-Transmission — Data Collector")
    print(f"  Algorithm : {args.algo}")
    print(f"  Duration  : {args.duration}s")
    print(f"  TX port   : {args.tx}  |  RX port: {args.rx}")
    print(f"{'='*55}\n")

    tx_f, tx_w, rx_f, rx_w, tx_path, rx_path = open_writers(args.outdir, args.algo)

    tx_stats = {"tx_count": 0, "enc_us_sum": 0}
    rx_stats = {"rx_count": 0, "ok_count": 0, "dec_us_sum": 0}

    start = time.time()

    t_tx = threading.Thread(target=tx_reader,
                            args=(args.tx, args.baud, tx_w, tx_f, start, tx_stats),
                            daemon=True)
    t_rx = threading.Thread(target=rx_reader,
                            args=(args.rx, args.baud, rx_w, rx_f, start, rx_stats),
                            daemon=True)

    t_tx.start()
    t_rx.start()

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")

    stop_event.set()
    t_tx.join(timeout=3)
    t_rx.join(timeout=3)
    tx_f.close()
    rx_f.close()

    # ---- Summary ----
    tx_n = tx_stats["tx_count"]
    rx_n = rx_stats["rx_count"]
    ok_n = rx_stats["ok_count"]

    print(f"\n{'='*55}")
    print(f"  SUMMARY — {args.algo}")
    print(f"  Packets sent          : {tx_n}")
    print(f"  Packets received      : {rx_n}")
    print(f"  Successful decrypts   : {ok_n}")
    if tx_n > 0:
        print(f"  Packet loss           : {(1-rx_n/tx_n)*100:.1f}%")
    if tx_n > 0:
        print(f"  Avg encrypt time      : {tx_stats['enc_us_sum']/tx_n:.1f} µs")
    if rx_n > 0:
        print(f"  Avg decrypt time      : {rx_stats['dec_us_sum']/rx_n:.1f} µs")
        print(f"  Integrity pass rate   : {ok_n/rx_n*100:.1f}%")
    print(f"{'='*55}\n")
    print(f"Saved: {tx_path}")
    print(f"Saved: {rx_path}")

if __name__ == "__main__":
    main()
