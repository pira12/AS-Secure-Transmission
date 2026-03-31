# AS-Secure-Transmission — Testing Suite

## Directory Layout

```
testing_suite/
├── arduino/
│   ├── test_plaintext/    tx_plaintext.ino  rx_plaintext.ino
│   ├── test_xor/          tx_xor.ino        rx_xor.ino
│   ├── test_aes128/       tx_aes128.ino     rx_aes128.ino
│   ├── test_speck/        tx_speck.ino      rx_speck.ino
│   └── test_chacha20/     tx_chacha20.ino   rx_chacha20.ino
├── python/
│   ├── collect_data.py    Serial reader — saves CSV per algorithm
│   ├── analyze.py         Analysis + matplotlib graph generator
│   └── memory_report.py   Flash/SRAM footprint comparison
└── results/               CSV files land here (auto-created)
    └── figures/           PNG graphs land here (auto-created)
```

---

## Python Setup

```bash
pip install pyserial pandas matplotlib numpy scipy tabulate
```

---

## Step-by-Step Workflow

### 1. Flash the Sketches

Each algorithm has a TX sketch and an RX sketch.
- Flash the TX sketch to your **transmitter Arduino**
- Flash the RX sketch to your **receiver Arduino**

Arduino library requirements:
| Algorithm | Library                                  |
|-----------|------------------------------------------|
| PLAIN     | RadioHead (built-in via Library Manager) |
| XOR       | RadioHead                                |
| AES128    | AESLib (DavyLandman) via Library Manager |
| SPECK     | None — pure C, self-contained            |
| ChaCha20  | None — pure C, self-contained            |

### 2. Run the Data Collector

Open **two terminal windows** (or use two USB ports).

```bash
# Run one test at a time — 60 seconds per algorithm
python python/collect_data.py --tx COM3 --rx COM4 --algo PLAIN    --duration 60
python python/collect_data.py --tx COM3 --rx COM4 --algo XOR      --duration 60
python python/collect_data.py --tx COM3 --rx COM4 --algo AES128   --duration 60
python python/collect_data.py --tx COM3 --rx COM4 --algo SPECK    --duration 60
python python/collect_data.py --tx COM3 --rx COM4 --algo CHACHA20 --duration 60
```

On Linux/macOS, ports are typically `/dev/ttyUSB0` and `/dev/ttyUSB1`.

Each run saves:
- `results/<ALGO>_tx_<timestamp>.csv`
- `results/<ALGO>_rx_<timestamp>.csv`

### 3. Generate Graphs and Tables

```bash
python python/analyze.py
```

Produces in `results/figures/`:
| File | Content |
|------|---------|
| `01_latency_bar.png`       | Encrypt + decrypt time, per algorithm, with σ error bars |
| `02_latency_distribution.png` | Violin plot — spread of all timing samples           |
| `03_packet_loss.png`       | Packet loss % per algorithm                              |
| `04_throughput.png`        | Effective application throughput vs raw 2000 bps link    |
| `05_latency_timeseries.png`| Latency over the test window (rolling average)           |
| `06_radar.png`             | Multi-metric radar chart for presentation summary slide  |
| `results.json`             | Machine-readable summary for the HTML dashboard          |

Also prints three formatted tables to the terminal.

### 4. Memory Footprint

Enable verbose compilation in Arduino IDE:  
`File > Preferences > Show verbose output during: ☑ Compilation`

Build each sketch, find the `avr-size` line in the output.  
Then either:

```bash
# Option A: Auto-scan ELF files from build temp dir
python python/memory_report.py --elf-dir /tmp/arduino_build_XXXXX/

# Option B: Manual entry (prompts you for each value)
python python/memory_report.py --manual

# Option C: JSON file
python python/memory_report.py --json my_memory_data.json
```

Produces `results/figures/07_memory_footprint.png`.

---

## Serial Protocol Reference

All sketches output structured CSV-compatible lines that the collector parses:

**TX line format:**
```
TEST,<ALGO>,<SIZE_BYTES>,ENC_US:<micros>,ITER:<n>
```

**RX line format:**
```
RECV,<ALGO>,<SIZE_BYTES>,DEC_US:<micros>,OK:<1|0>,ITER:<n>
```

Example:
```
TEST,AES128,16,ENC_US:312,ITER:47
RECV,AES128,16,DEC_US:298,OK:1,ITER:47
```

`OK:1` = decrypted payload matches expected plaintext (integrity check).  
`OK:0` = decryption failed or payload corrupted.

---

## Metrics Explained

| Metric | Formula | Notes |
|--------|---------|-------|
| Encrypt latency | `micros()` around encrypt call | TX Arduino |
| Decrypt latency | `micros()` around decrypt call | RX Arduino |
| Packet loss | `(sent − received) / sent × 100` | Collector correlation |
| Integrity | `ok_count / received × 100` | Payload match |
| Effective throughput | `128 bits / (enc_s + radio_s)` | radio = 128b / 2000bps = 64ms |

---

## Tips

- Run each algorithm test for at least **60 seconds** to get stable statistics (≥100 samples).
- Keep both Arduinos within 1–2 m during testing for consistent RF conditions.
- For the IV-reuse demo, deliberately send two messages that differ by one byte and compare ciphertext — AES-ECB will produce different ciphertext for different plaintexts, but *identical* ciphertext for identical 16-byte blocks. Use this to show the ECB penguin problem live.
- SPECK and XOR sketches need no external libraries — they compile fastest and use the least Flash. Good for your presentation narrative about lightweight crypto.
