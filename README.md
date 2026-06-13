# Netscope — Packet Deep Inspection System in C++

A deep packet inspection engine built from scratch in C++. Reads raw PCAP captures, parses every protocol layer at the byte level, reconstructs TCP flows, extracts application identity from TLS handshakes and HTTP headers, enforces blocking rules, and writes a filtered output PCAP with a full traffic report.

Built to understand how ISP-level filtering, enterprise firewalls, and parental controls actually work — not by wrapping libpcap or any inspection library, but by manually walking Ethernet frames, IP headers, TCP segments, and TLS records byte by byte.

---

## Why This Matters for ML-Based Network Security

Rule-based DPI (what Netscope does) and ML-based traffic classification are complementary layers in production network security systems. Rule-based systems are fast and interpretable but brittle — they break the moment an app changes its CDN domain or migrates to QUIC. ML-based classifiers (flow-level models like FLOWPRINT, or sequence models over packet inter-arrival times) are more robust to such changes but require structured, labeled flow features to train and evaluate on.

Building Netscope from scratch made concrete what those features actually are and where they come from:

- **5-tuple flows** `(src_ip, dst_ip, src_port, dst_port, protocol)` — the primary key for per-flow ML models
- **SNI / HTTP Host** — application-layer identity signal, available only in early handshake packets
- **Flow state** `(NEW → ESTABLISHED → CLASSIFIED → BLOCKED → CLOSED)` — temporal structure that sequence models operate over
- **Packet timing and count per flow** — the features that remain available when payload inspection fails (e.g. QUIC with encrypted SNI)

The `20% Unknown` flows in Netscope's output — traffic it can't classify by SNI substring match — are exactly the distribution where an ML classifier trained on flow-level features would provide value. Rule-based systems produce their own hardest training examples.

---

## How It Works

```
input.pcap
    │
    ▼
PcapReader — validates magic number (0xa1b2c3d4), handles byte-swap for big-endian files
    │
    ▼
PacketParser — Ethernet (14B) → IP (IHL×4 bytes) → TCP (data offset×4) / UDP (8B)
    │
    ▼
Payload extracted at computed offset
    │
    ├─ Port 443 → SNIExtractor: walk TLS record → handshake → extensions → type 0x0000
    ├─ Port 80  → HTTPHostExtractor: scan for "Host:" → read to \r\n
    └─ Port 53  → DNSExtractor: parse label-length encoded domain
    │
    ▼
sniToAppType() — substring match against 22 known services (YouTube, TikTok, Discord, ...)
    │
    ▼
RuleManager — IP → Port → App → Domain (first match wins)
    │
    ▼
Flow marked BLOCKED or FORWARD for all future packets on that 5-tuple
    │
    ▼
output.pcap + traffic report
```

---

## The SNI Insight

HTTPS encrypts application data, but the TLS handshake starts with a **Client Hello in plaintext**. This message contains the **Server Name Indication (SNI)** — the domain the client wants to reach — so the server knows which certificate to serve before encryption begins.

Extracting it requires navigating a layered structure. After verifying content type `0x16` (Handshake) and handshake type `0x01` (Client Hello), the parser skips 2 bytes of client version, 32 bytes of random, a variable-length session ID, variable-length cipher suites, and compression methods — all with explicit offset arithmetic. Then it walks each extension by type (2 bytes) and length (2 bytes) until it finds `0x0000` (SNI), then reads the hostname. Every length field is big-endian; the codebase uses a portable `PortableNet::netToHost16/32` rather than POSIX `ntohs/ntohl` for cross-platform support. Getting any offset wrong produces silently garbage output — which happened more than once.

For HTTP, `HTTPHostExtractor` scans for `Host:` case-insensitively, skips whitespace, and reads until `\r\n`, stripping any port suffix.

SNI is also the feature that highlights a core limitation of rule-based DPI: as TLS Encrypted Client Hello (ECH) adoption grows, SNI will no longer be available in plaintext. Traffic classification will need to fall back to flow-level statistical features — packet sizes, inter-arrival times, byte distributions — which is where ML models operate.

---

## Flow-Based Blocking

Blocking a single packet doesn't end a TCP connection — the sender retransmits. Netscope tracks **flows** by 5-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)`. The `Connection` struct tracks state across `NEW → ESTABLISHED → CLASSIFIED → BLOCKED → CLOSED`, driven by TCP flag inspection (SYN, SYN-ACK, FIN, RST).

The early packets of an HTTPS connection (SYN, SYN-ACK, ACK) arrive before the Client Hello, so the flow stays `ESTABLISHED` and packets are forwarded. The moment SNI is extracted and a rule matches, the `Connection` is marked `BLOCKED` — and every subsequent packet on that flow is dropped without re-inspecting the payload. The connection stalls and times out on the client.

This deferred classification pattern — where a decision is made on the first informative packet and propagated to all subsequent packets in the same flow — is the same temporal structure that makes network traffic a natural fit for sequence classification models.

---

## Architecture

### Simple Version (`main_working.cpp`)

Single-threaded pipeline. One packet at a time: parse → look up flow in `std::unordered_map<FiveTuple, Flow, FiveTupleHash>` → extract SNI → classify → check rules → write or drop. The right place to read first.

### Multi-Threaded Version (`dpi_mt.cpp`)

Two-stage thread pool for throughput:

```
Reader (main thread)
    │
    └─ hash(5-tuple) % num_lbs ──► LoadBalancer threads
                                         │
                                         └─ hash(5-tuple) % fps_per_lb ──► FastPath threads
                                                                                  │
                                                                           TSQueue<Packet>
                                                                                  │
                                                                           Output writer thread
                                                                                  │
                                                                           output.pcap
```

**Why consistent hashing at both stages, not round-robin?** Each `FastPath` thread owns its own `FlowEntry` map — no shared locking on the hot path. For this to be correct, all packets of the same TCP connection must always land on the same FP thread. Round-robin would scatter them. The same `FiveTupleHash` is applied at both the LB dispatch and the FP dispatch, so `192.168.1.5:54321→142.250.1.1:443` always routes to the same FP regardless of which LB received it.

**TSQueue** between stages uses `std::mutex` + `std::condition_variable` with both a `not_empty_` and `not_full_` condvar. Producers block when the queue hits `max_size` (10,000 packets); consumers block when empty. No busy-spinning. The `shutdown()` method sets a flag and broadcasts on both condvars so all waiting threads wake and exit cleanly.

**Packet ownership:** `Packet` structs own their data via `std::vector<uint8_t>` — no raw pointer sharing across threads. The payload pointer inside `PacketJob` is recalculated from the owned buffer at each stage.

### Full Engine Version (`dpi_engine.cpp` + `DPIEngine` class)

Wraps the above into a proper class hierarchy with `FPManager`, `LBManager`, `ConnectionTracker` per FP, `GlobalConnectionTable` for aggregated stats, and `RuleManager` with `std::shared_mutex` for concurrent reads from all FP threads against a single rule set. Rules support IP, app, domain (with `*.example.com` wildcard patterns), and port. The rule file format is section-based (`[BLOCKED_IPS]`, `[BLOCKED_APPS]`, etc.) and can be loaded at startup or saved at runtime.

---

## File Structure

```
netscope/
├── include/
│   ├── types.h               # FiveTuple, FiveTupleHash, AppType, Connection, PacketJob, DPIStats
│   ├── platform.h            # Portable byte-order conversion (no POSIX dependency)
│   ├── pcap_reader.h         # PCAP global header + per-packet header, byte-swap detection
│   ├── packet_parser.h       # Ethernet / IP / TCP / UDP parsing with offset tracking
│   ├── sni_extractor.h       # TLS SNI, HTTP Host, DNS query, QUIC (partial) extractors
│   ├── rule_manager.h        # IP/app/domain/port blocking, shared_mutex, wildcard support
│   ├── connection_tracker.h  # Per-FP flow table, state machine, LRU eviction at 100k entries
│   ├── thread_safe_queue.h   # mutex + dual condvar bounded queue, shutdown broadcast
│   ├── load_balancer.h       # LB thread: consistent hash dispatch to FP queues
│   ├── fast_path.h           # FP thread: DPI, TCP state, rule check, output callback
│   └── dpi_engine.h          # Orchestrator: owns all managers, reader thread, output thread
├── src/
│   ├── main_working.cpp      # ★ Single-threaded version — start here
│   ├── dpi_mt.cpp            # ★ Self-contained multi-threaded version
│   ├── main_dpi.cpp          # Entry point for full DPIEngine version
│   ├── dpi_engine.cpp        # DPIEngine implementation
│   ├── fast_path.cpp         # FastPathProcessor implementation
│   ├── load_balancer.cpp     # LoadBalancer implementation
│   ├── connection_tracker.cpp# ConnectionTracker + GlobalConnectionTable
│   ├── rule_manager.cpp      # RuleManager implementation
│   ├── packet_parser.cpp     # Protocol parsing
│   ├── pcap_reader.cpp       # PCAP file I/O
│   ├── sni_extractor.cpp     # TLS/HTTP/DNS/QUIC extraction
│   └── types.cpp             # appTypeToString, sniToAppType (22 services)
├── generate_test_pcap.py     # Generates test PCAP: 16 TLS flows, 2 HTTP, 4 DNS, blocked-IP traffic
└── test_dpi.pcap
```

---

## Key Engineering Decisions

**Portable byte order handling.** Rather than using POSIX `ntohs`/`ntohl` (unavailable on Windows without Winsock), `platform.h` implements `PortableNet::netToHost16/32` using runtime endianness detection and manual byte swapping. `pcap_reader.cpp` also handles byte-swapped PCAP files (magic `0xd4c3b2a1`) by swapping the global header fields on open.

**Per-FP flow tables, no shared state on the hot path.** The `ConnectionTracker` in each `FastPath` is never shared — it's only ever accessed by that one thread. This makes the classification and blocking decision entirely lock-free. The only shared mutable state is `RuleManager`, which uses `std::shared_mutex` to allow all FP threads to read concurrently and only block on writes (rule changes).

**Flow classification is sticky but deferred.** A flow is not marked `classified` until SNI is successfully extracted. If the Client Hello hasn't arrived yet (early SYN/ACK packets), the flow stays `ESTABLISHED` and packets pass through. Once classified, the `classified` flag prevents re-inspection of every subsequent packet — the app type is fixed for the lifetime of the flow.

**`ConnectionTracker` has an LRU eviction policy at 100,000 entries.** Rather than growing unboundedly on long captures, it scans for the entry with the oldest `last_seen` timestamp and evicts it when the table is full. Not O(1), but acceptable for the eviction rate at normal traffic volumes.

**Two separate versions were built deliberately.** `main_working.cpp` exists as a standalone readable version — understanding the multi-threaded version without it would mean reasoning about concurrency and packet inspection simultaneously. The single-threaded version also served as the correctness baseline when debugging the MT version.

**The test PCAP is generated, not captured.** `generate_test_pcap.py` constructs valid PCAP frames from scratch using Python's `struct` module — Ethernet headers, IP headers with correct length fields, TCP handshakes, and real TLS Client Hello structures with properly encoded SNI extensions. This means the test data is deterministic and covers all 22 classification targets, plus a blocked-IP scenario with 5 packets from `192.168.1.50`.

---

## Build

**Simple version:**
```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp src/pcap_reader.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

**Multi-threaded version (self-contained):**
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_mt \
    src/dpi_mt.cpp src/pcap_reader.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

**Full engine version:**
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/main_dpi.cpp src/dpi_engine.cpp src/fast_path.cpp \
    src/load_balancer.cpp src/connection_tracker.cpp \
    src/rule_manager.cpp src/packet_parser.cpp \
    src/pcap_reader.cpp src/sni_extractor.cpp src/types.cpp
```

Or via CMake:
```bash
mkdir build && cd build && cmake .. && make
```

No external dependencies. C++17, macOS/Linux.

---

## Run

```bash
# Generate test data
python3 generate_test_pcap.py

# Basic run
./dpi_mt test_dpi.pcap output.pcap

# With blocking rules
./dpi_mt input.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook

# Configure thread pool
./dpi_mt input.pcap output.pcap --lbs 2 --fps 4

# Full engine with rule file
./dpi_engine input.pcap output.pcap --rules rules.txt
```

---

## Blocking Rules

| Rule Type | Flag | Matches On |
|---|---|---|
| IP | `--block-ip <ip>` | Source IP (exact match) |
| App | `--block-app <name>` | Classified application type |
| Domain | `--block-domain <str>` | Substring match on extracted SNI |
| Port | rule file only | Destination port |

Rules are checked in order: IP → Port → App → Domain. First match drops the packet and marks the entire flow blocked. Wildcard domain patterns (`*.facebook.com`) are supported in the full engine via `RuleManager`.

**Rule file format:**
```
[BLOCKED_IPS]
192.168.1.50

[BLOCKED_APPS]
YouTube
TikTok

[BLOCKED_DOMAINS]
*.facebook.com
tiktok.com

[BLOCKED_PORTS]
6881
```

---

## Recognized Applications

`sniToAppType()` in `types.cpp` matches SNI strings against 22 services including subdomains and CDN domains:

Google, YouTube (`ytimg`, `youtu.be`), Facebook (`fbcdn`, `fbsbx`), Instagram (`cdninstagram`), WhatsApp (`wa.me`), Twitter/X (`twimg`, `t.co`), Netflix (`nflxvideo`), Amazon (`amazonaws`, `cloudfront`), Microsoft (`azure`, `outlook`, `bing`), Apple (`icloud`, `mzstatic`), Telegram (`t.me`), TikTok (`tiktokcdn`, `bytedance`, `musical.ly`), Spotify (`scdn.co`), Zoom, Discord (`discordapp`), GitHub (`githubusercontent`), Cloudflare (`cf-`)

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:              77                                ║
║ TCP Packets:                73    UDP Packets:   4            ║
║ Forwarded:                  69    Dropped:       8            ║
╠══════════════════════════════════════════════════════════════╣
║   LB0 dispatched:           53    LB1 dispatched:  24        ║
║   FP0 processed:            53    FP2 processed:   24        ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS          39  50.6% ##########                           ║
║ Unknown        16  20.8% ####                                 ║
║ YouTube         4   5.2% # (BLOCKED)                         ║
║ DNS             4   5.2% #                                    ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com  → YouTube  (BLOCKED)
  - www.facebook.com → Facebook
  - github.com       → GitHub
```

The `Unknown` bucket — 20.8% of traffic in this capture — represents flows where SNI was unavailable or didn't match any rule pattern. In a production system, this is where an ML classifier operating on flow-level statistical features (packet size distribution, inter-arrival times, byte entropy) would take over from the rule engine.

---

## What's Next

**QUIC / HTTP3.** `QUICSNIExtractor` is stubbed — it detects QUIC Initial packets by the long-header form bit and does a naive scan for a Client Hello handshake type byte. Proper implementation requires parsing QUIC frames, finding the `CRYPTO` frame type (`0x06`), and reassembling the TLS Client Hello from potentially fragmented CRYPTO data. QUIC v1 also uses AEAD with a well-known per-version salt for the Initial packet, making the SNI technically recoverable — but significantly more involved than TLS over TCP. As QUIC adoption grows (already dominant for YouTube and Google), this also makes SNI-based classification increasingly unreliable, strengthening the case for flow-statistical ML approaches.

**Live capture.** The reader thread currently opens a file. Replacing it with a raw socket (`AF_PACKET` on Linux, `BPF` on macOS) would make Netscope a real-time inspector. The thread architecture already supports this — the reader thread is the only piece that changes.

**ML-based classification for Unknown flows.** The current `sniToAppType()` is a 22-entry substring lookup. A natural extension is exporting per-flow features (packet count, byte count, flow duration, packet size mean/variance, inter-arrival time statistics) for flows that remain `Unknown` after SNI extraction, and training a flow-level classifier on labeled PCAP datasets (ISCX, CICIDS). The existing flow tracking infrastructure produces exactly the data that such a model would need.

**Throttling instead of dropping.** The current `PacketAction` enum has `LOG_ONLY` defined but not wired up. Adding a `THROTTLE` action that delays forwarding in the output queue rather than dropping would enable rate-limiting rather than hard blocking — more realistic for ISP scenarios.

**Connection timeout tuning.** `cleanupStale()` is called in the FP thread on each 100ms timeout with a default of 300 seconds. For high-throughput use, this becomes expensive as the table grows. A proper timer wheel would handle this in O(1).

---

## License

MIT
