#!/usr/bin/env python3
"""
collect_data.py — AS-Secure-Transmission data collector
========================================================
Reads structured serial output from TX and RX Arduinos and saves
timing + reliability data to CSV files in testing_suite/results/.

USAGE
-----
  python collect_data.py --tx /dev/ttyUSB0 --rx /dev/ttyUSB1 --algo PLAIN
  python collect_data.py --tx /dev/ttyUSB0 --rx /dev/ttyUSB1 --algo XOR      --duration 60
  python collect_data.py --tx /dev/ttyUSB0 --rx /dev/ttyUSB1 --algo AES128
  python collect_data.py --tx /dev/ttyUSB0 --rx /dev/ttyUSB1 --algo SPECK
  python collect_data.py --tx /dev/ttyUSB0 --rx /dev/ttyUSB1 --algo CHACHA20

  On Windows ports look like COM3, COM4 etc.
  On Linux/macOS: /dev/ttyUSB0, /dev/ttyACM0, etc.

ARDUINO SERIAL PROTOCOL
-----------------------
TX lines:  TEST,<ALGO>,<SIZE>,ENC_US:<t>,ITER:<n>
RX lines:  RECV,<ALGO>,<SIZE>,DEC_US:<t>,OK:<0|1>,ITER:<n>

DEPENDENCIES
------------
  pip install pyserial
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
    print("ERROR: pyserial not installed.  Run:  pip install pyserial")
    sys.exit(1)

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Collect serial data from TX/RX Arduinos")
    p.add_argument("--tx",       required=True,
                   help="Serial port for TX Arduino (e.g. /dev/ttyUSB0 or COM3)")
    p.add_argument("--rx",       required=True,
                   help="Serial port for RX Arduino (e.g. /dev/ttyUSB1 or COM4)")
    p.add_argument("--baud",     default=9600, type=int,
                   help="Baud rate (default: 9600)")
    p.add_argument("--duration", default=60,   type=int,
                   help="Test duration in seconds (default: 60)")
    p.add_argument("--algo",     required=True,
                   choices=["PLAIN", "XOR", "AES128", "SPECK", "CHACHA20"],
                   help="Algorithm label — must match sketch output")
    p.add_argument("--outdir",   default=RESULTS_DIR,
                   help="Output directory for CSV files (default: ../results/)")
    return p.parse_args()

# ---------------------------------------------------------------------------
# CSV setup
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
# Line parsers
# ---------------------------------------------------------------------------

TX_RE = re.compile(
    r"TEST,(?P<algo>\w+),(?P<size>\d+),ENC_US:(?P<enc_us>\d+),ITER:(?P<iter>\d+)"
)
RX_RE = re.compile(
    r"RECV,(?P<algo>\w+),(?P<size>\d+),DEC_US:(?P<dec_us>\d+),OK:(?P<ok>[01]),ITER:(?P<iter>\d+)"
)

def parse_tx(line):
    m = TX_RE.search(line)
    if m:
        return {k: (int(v) if k != "algo" else v) for k, v in m.groupdict().items()}
    return None

def parse_rx(line):
    m = RX_RE.search(line)
    if m:
        return {k: (int(v) if k != "algo" else v) for k, v in m.groupdict().items()}
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
            d = parse_tx(raw)
            if d:
                writer.writerow([f"{elapsed:.3f}", d["algo"], d["size"], d["enc_us"], d["iter"]])
                csv_file.flush()
                stats["count"] += 1
                stats["enc_sum"] += d["enc_us"]
                if stats["count"] % 20 == 0:
                    avg = stats["enc_sum"] / stats["count"]
                    print(f"[TX] {stats['count']:4d} sent  |  avg enc: {avg:.1f} µs")
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
            d = parse_rx(raw)
            if d:
                writer.writerow([f"{elapsed:.3f}", d["algo"], d["size"], d["dec_us"], d["ok"], d["iter"]])
                csv_file.flush()
                stats["count"] += 1
                stats["ok_count"] += d["ok"]
                stats["dec_sum"] += d["dec_us"]
                if stats["count"] % 20 == 0:
                    avg = stats["dec_sum"] / stats["count"]
                    ok_r = stats["ok_count"] / stats["count"] * 100
                    print(f"[RX] {stats['count']:4d} recv  |  avg dec: {avg:.1f} µs  |  ok: {ok_r:.1f}%")
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

    tx_stats = {"count": 0, "enc_sum": 0}
    rx_stats = {"count": 0, "ok_count": 0, "dec_sum": 0}

    start = time.time()

    t_tx = threading.Thread(
        target=tx_reader,
        args=(args.tx, args.baud, tx_w, tx_f, start, tx_stats),
        daemon=True,
    )
    t_rx = threading.Thread(
        target=rx_reader,
        args=(args.rx, args.baud, rx_w, rx_f, start, rx_stats),
        daemon=True,
    )

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

    tx_n = tx_stats["count"]
    rx_n = rx_stats["count"]
    ok_n = rx_stats["ok_count"]

    print(f"\n{'='*55}")
    print(f"  SUMMARY — {args.algo}")
    print(f"  Packets sent        : {tx_n}")
    print(f"  Packets received    : {rx_n}")
    print(f"  Successful decrypts : {ok_n}")
    if tx_n > 0:
        print(f"  Packet loss         : {(1-rx_n/tx_n)*100:.1f}%")
        print(f"  Avg encrypt time    : {tx_stats['enc_sum']/tx_n:.1f} µs")
    if rx_n > 0:
        print(f"  Avg decrypt time    : {rx_stats['dec_sum']/rx_n:.1f} µs")
        print(f"  Integrity pass rate : {ok_n/rx_n*100:.1f}%")
    print(f"{'='*55}\n")
    print(f"Saved: {tx_path}")
    print(f"Saved: {rx_path}")


if __name__ == "__main__":
    main()
