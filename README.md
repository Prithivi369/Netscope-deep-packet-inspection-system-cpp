# Netscope — Packet Deep Inspection System in C++

A packet deep inspection system that reads PCAP captures, classifies traffic by application (YouTube, Facebook, etc.) via SNI extraction, applies blocking rules, and writes filtered output.

---

## How It Works

```
input.pcap → Parse Ethernet/IP/TCP → Extract SNI from TLS Client Hello
           → Classify App → Check Rules → Forward or Drop → output.pcap
```

**SNI (Server Name Indication)** is the domain name sent in plaintext during the TLS handshake — before encryption begins. This is how HTTPS traffic is identified despite being encrypted.

**Flow tracking** via 5-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)` ensures all packets of a connection are blocked once the app is identified, not just the packet containing the SNI.

---

## Two Versions

| Version | File | Use Case |
|---|---|---|
| Simple (single-threaded) | `src/main_working.cpp` | Learning, small captures |
| Multi-threaded | `src/dpi_mt.cpp` | High-performance, large captures |

**Multi-threaded architecture:**
```
Reader → LB Threads (hash by 5-tuple) → FP Threads (DPI + blocking) → Output Writer
```
Consistent hashing ensures all packets of the same connection always go to the same Fast Path thread.

---

## File Structure

```
packet_analyzer/
├── include/
│   ├── types.h               # FiveTuple, AppType, data structures
│   ├── pcap_reader.h         # PCAP file I/O
│   ├── packet_parser.h       # Ethernet/IP/TCP parsing
│   ├── sni_extractor.h       # TLS SNI + HTTP Host extraction
│   ├── rule_manager.h        # Blocking rules
│   ├── connection_tracker.h  # Flow state tracking
│   ├── load_balancer.h       # LB thread (multi-threaded)
│   ├── fast_path.h           # FP thread (multi-threaded)
│   └── thread_safe_queue.h   # Producer-consumer queue
├── src/
│   ├── main_working.cpp      # ★ Simple version
│   ├── dpi_mt.cpp            # ★ Multi-threaded version
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   └── types.cpp
├── generate_test_pcap.py     # Creates sample test data
└── test_dpi.pcap
```

---

## Build

**Simple version:**
```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp src/pcap_reader.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

**Multi-threaded version:**
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp src/pcap_reader.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

No external libraries required. C++17, macOS/Linux.

---

## Run

```bash
# Basic
./dpi_engine test_dpi.pcap output.pcap

# With blocking rules
./dpi_engine input.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook

# Configure threads (multi-threaded only)
./dpi_engine input.pcap output.pcap --lbs 2 --fps 4

# Generate test data
python3 generate_test_pcap.py
```

---

## Blocking Rules

| Rule Type | Flag | Effect |
|---|---|---|
| IP | `--block-ip <ip>` | Drops all traffic from that source IP |
| App | `--block-app <app>` | Drops all connections classified as that app |
| Domain | `--block-domain <str>` | Drops any connection whose SNI contains the string |

Blocking is flow-based: once a flow is identified as blocked (on the Client Hello packet), all subsequent packets of that connection are dropped.

---

## Sample Output

```
Total Packets:   77     Forwarded: 69     Dropped: 8

APPLICATION BREAKDOWN
  HTTPS      39  50.6%
  Unknown    16  20.8%
  YouTube     4   5.2%  (BLOCKED)
  DNS         4   5.2%
  Facebook    3   3.9%

DETECTED SNIs
  www.youtube.com  → YouTube
  www.facebook.com → Facebook
  www.google.com   → Google
```

---

## Extending

- **Add app signatures** — edit `sniToAppType()` in `types.cpp`
- **Add QUIC/HTTP3** — UDP port 443, different SNI encoding
- **Throttling instead of dropping** — delay packets in Fast Path instead of discarding
- **Persistent rules** — load/save rule file on startup

---

## License

MIT
