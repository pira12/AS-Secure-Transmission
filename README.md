# AS-Secure-Transmission

Comparison of symmetric encryption algorithms on an Arduino Nano (ATmega328P) over a 433 MHz ASK RF link. Built for the Advanced Security course assignment on secure transmission.

---

## Overview

Five cipher variants are implemented and benchmarked:

| Algorithm | Type | Key size | Block/stream | Library |
|-----------|------|----------|--------------|---------|
| **Plaintext** | None (baseline) | — | — | RadioHead |
| **XOR** | Stream (broken baseline) | 128-bit repeating | Stream | None |
| **AES-128 ECB** | Block cipher | 128-bit | 16-byte block | AESLib |
| **AES-128 CBC** | Block cipher | 128-bit | 16-byte block | AESLib |
| **SPECK-64/128** | Lightweight block cipher | 128-bit | 8-byte block | None |
| **ChaCha20** | Stream cipher | 256-bit | Stream | None |

Hardware setup:
- Two Arduino Nano boards (ATmega328P @ 16 MHz)
- 433 MHz ASK RF modules (transmitter + receiver)
- RadioHead ASK driver at 2000 bps, TX pin 12, RX pin 11

---

## Repository Structure

```
AS-Secure-Transmission/
│
├── transmission_code/              Plaintext TX (demo)
├── receiver_code/                  Plaintext RX (demo)
│
├── aes_transmission_code/          AES-128 ECB TX (single block demo)
├── aes_receiver_code/              AES-128 ECB RX
│
├── aes_cbc_transmission_code/      AES-128 CBC TX (multi-packet, long message)
├── aes_cbc_receiver_code/          AES-128 CBC RX (reassembly + CBC decrypt)
│
├── xor_transmission_code/          XOR cipher TX (demo)
├── xor_receiver_code/              XOR cipher RX
│
├── speck_transmission_code/        SPECK-64/128 TX (demo)
├── speck_receiver_code/            SPECK-64/128 RX
│
├── chacha20_transmission_code/     ChaCha20 TX (demo)
├── chacha20_receiver_code/         ChaCha20 RX
│
└── testing_suite/                  Benchmarking suite (see below)
    ├── arduino/
    │   ├── test_plain/             tx_plain/ + rx_plain/
    │   ├── test_xor/               tx_xor/   + rx_xor/
    │   ├── test_aes128/            tx_aes128/ + rx_aes128/
    │   ├── test_speck/             tx_speck/ + rx_speck/
    │   └── test_chacha20/          tx_chacha20/ + rx_chacha20/
    ├── python/
    │   ├── collect_data.py         Serial data collector
    │   ├── analyze.py              Graph + table generator
    │   └── memory_report.py        Flash/SRAM footprint chart
    ├── results/                    CSV files land here (auto-created)
    │   └── figures/                PNG graphs + results.json (auto-created)
    └── dashboard.html              Interactive results dashboard
```

---

## Demo Sketches

The root-level sketch directories are for live demonstration — human-readable Serial output, designed to show the cipher working on screen during a presentation.

Each cipher has:
- **`*_transmission_code/`** — encrypts a message, sends it over RF, prints plaintext + ciphertext hex + encrypt time
- **`*_receiver_code/`** — receives the packet, decrypts, prints the recovered message + decrypt time

### AES-128 CBC (multi-packet demo)

The CBC variant handles messages longer than the 60-byte RF packet limit by splitting the ciphertext across multiple packets with a `[packet_index, total_packets]` header. The receiver reassembles before decrypting.

Features:
- PKCS7 padding
- 4-byte magic header (`0xDEADBEEF`) for integrity verification
- 3× retransmit per packet to reduce loss

---

## Testing Suite

The `testing_suite/` directory is a complete benchmarking infrastructure for comparing all five algorithms under identical conditions.

### Arduino library requirements

| Algorithm | Library |
|-----------|---------|
| PLAIN, XOR, SPECK, ChaCha20 | RadioHead only |
| AES-128 ECB | AESLib (DavyLandman) — Arduino Library Manager |

### Python dependencies

```bash
pip install pyserial pandas matplotlib numpy scipy tabulate
```

### Step-by-step workflow

#### 1. Flash the test sketches

Each algorithm has a dedicated TX and RX test sketch inside `testing_suite/arduino/`. These output structured CSV-compatible lines that the Python collector parses:

```
TX:  TEST,<ALGO>,<SIZE>,ENC_US:<t>,ITER:<n>
RX:  RECV,<ALGO>,<SIZE>,DEC_US:<t>,OK:<1|0>,ITER:<n>
```

Flash the TX sketch to the **transmitter Arduino** and the RX sketch to the **receiver Arduino**.

#### 2. Collect data

Run one algorithm at a time. Ports are typically `/dev/ttyUSB0` and `/dev/ttyUSB1` on Linux, `COM3`/`COM4` on Windows.

```bash
cd testing_suite

python python/collect_data.py --tx /dev/ttyUSB0 --rx /dev/ttyUSB1 --algo PLAIN    --duration 60
python python/collect_data.py --tx /dev/ttyUSB0 --rx /dev/ttyUSB1 --algo XOR      --duration 60
python python/collect_data.py --tx /dev/ttyUSB0 --rx /dev/ttyUSB1 --algo AES128   --duration 60
python python/collect_data.py --tx /dev/ttyUSB0 --rx /dev/ttyUSB1 --algo SPECK    --duration 60
python python/collect_data.py --tx /dev/ttyUSB0 --rx /dev/ttyUSB1 --algo CHACHA20 --duration 60
```

Each run saves two timestamped CSVs to `testing_suite/results/`.

#### 3. Analyse and generate graphs

```bash
python python/analyze.py
```

Produces in `testing_suite/results/figures/`:

| File | Content |
|------|---------|
| `01_latency_bar.png` | Encrypt + decrypt time per algorithm with σ error bars |
| `02_latency_distribution.png` | Violin plot — spread of all timing samples |
| `03_packet_loss.png` | Packet loss % per algorithm |
| `04_throughput.png` | Effective throughput vs raw 2000 bps link |
| `05_latency_timeseries.png` | Latency over the test window (rolling average) |
| `06_radar.png` | Multi-metric radar chart |
| `results.json` | Machine-readable summary consumed by the dashboard |

Also prints three formatted tables (latency, reliability, throughput) to the terminal.

#### 4. Open the dashboard

```bash
python -m http.server 80
```

Then navigate in the browser to: http://localhost/dashboard.html


The dashboard automatically loads `results/figures/results.json` via `fetch()`. If no real data is available yet, it falls back to sample data so you can preview the layout. A status pill in the top-right corner shows which mode is active.

Dashboard features:
- Per-algorithm toggle buttons to show/hide series on all charts
- KPI summary cards (fastest encrypt, lowest packet loss, best throughput, smallest flash)
- Charts: latency bar, packet loss, throughput, memory footprint, latency timeseries, performance radar
- Full results table with all metrics

#### 5. Memory footprint chart (optional)

Enable verbose compilation in Arduino IDE (`File > Preferences > Show verbose output during: Compilation`), build each TX sketch, then run:

```bash
# Option A: point at a directory of .elf build artefacts
python python/memory_report.py --elf-dir /tmp/arduino_build_XXXXX/

# Option B: enter values manually (prompts you for Flash + SRAM per algorithm)
python python/memory_report.py --manual

# Option C: JSON file
python python/memory_report.py --json my_memory_data.json
```

Produces `testing_suite/results/figures/07_memory_footprint.png`.

---

## Metrics Reference

| Metric | Formula | Where measured |
|--------|---------|----------------|
| Encrypt latency | `micros()` around encrypt call | TX Arduino |
| Decrypt latency | `micros()` around decrypt call | RX Arduino |
| Packet loss | `(sent − received) / sent × 100` | Python collector |
| Integrity | `ok_count / received × 100` | RX compares decrypted payload to expected |
| Effective throughput | `128 bits / (enc_us/1e6 + 128/2000)` | Computed in analyze.py |

The throughput formula accounts for both the cipher overhead and the fixed RF transmission time (128 bits at 2000 bps = 64 ms).

---

## Cipher Notes

### XOR (static key)
Intentionally weak baseline. A static repeating key means identical plaintext always produces identical ciphertext. Key recovery requires a single known-plaintext pair: `K = C XOR P`. Do not use for real data protection.

### AES-128 ECB
Standard AES in Electronic Codebook mode. Identical 16-byte plaintext blocks produce identical ciphertext blocks (ECB penguin problem). Useful for demonstrating why mode of operation matters.

### AES-128 CBC
Cipher Block Chaining — each block is XORed with the previous ciphertext block before encryption, breaking the block-to-block pattern. The static IV used here is acceptable for a demo but should be random and transmitted alongside the ciphertext in production.

### SPECK-64/128
NSA-designed lightweight block cipher optimised for software on 32-bit platforms. Very small code footprint with no external library. 64-bit block size, 128-bit key, 27 rounds.

### ChaCha20
Modern stream cipher designed by D. J. Bernstein. No block alignment or padding needed. 256-bit key, 96-bit nonce, 20 rounds. RFC 7539 compliant. The static nonce used here is suitable for a demo; production use must use a unique nonce per message.

---

## Hardware Wiring

```
Arduino Nano        433 MHz module
──────────────      ──────────────
5V          ──────  VCC
GND         ──────  GND
D12 (TX)    ──────  DATA  (transmitter board)
D11 (RX)    ──────  DATA  (receiver board)
```

Both Arduinos share the same pin assignment; only the flashed sketch differs.
