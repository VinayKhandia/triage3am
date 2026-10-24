# triage3am

A dependency-free incident triage tool. It reads raw log files, groups similar lines into templates using a Drain-inspired clustering method, and reports the earliest likely trigger, the order in which services failed, and suggested next steps. It uses only the Python standard library and makes no calls to external services or language models.

## Quick start

Requires Python 3 (standard library only; no `pip install` step).

```bash
python3 server.py
# Dashboard and API at http://localhost:8000
```

Analyze a log file from the command line:

```bash
curl -X POST http://localhost:8000/api/v2/analyze/upload \
  -F "file=@datasets/ecommerce_cascade_10k.log" \
  -F "threshold=0.55"
```

Run the tests and regenerate the bundled datasets:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
python3 generate_datasets.py
```

## Example output

<img width="1470" height="956" alt="Screenshot 2026-10-24 at 10 33 49 AM" src="https://github.com/user-attachments/assets/6c80ea48-5910-4a3f-bed9-300f27982d5e" />



## What it does

- **Template clustering.** Variable tokens (UUIDs, IP addresses, memory addresses, timestamps, numeric IDs) are masked so structurally identical lines collapse into one template. This needs no per-format parsing rules. A 10,000-line outage typically reduces to a handful of ranked incident cards.
- **Likely trigger ("patient zero").** In a large outage most lines are downstream symptoms such as timeouts, retries, and 504s. Instead of ranking by frequency, the tool looks for the earliest anomalous failure and reports its timestamp, line number, service, and event.
- **Priority scoring.** Incidents are ranked by a multi-factor score: how early the failure appeared, burst frequency, cross-service blast radius, and stack trace severity. This keeps high-volume retry loops from outranking the root cause.
- **Cascade timeline.** Service failure order and propagation delays (`T0 -> T1 -> T2`) are reconstructed from event timing, then shown as a chain and a dependency graph separating root services from downstream degraded ones.
- **Error-rate spikes.** Severity counts are binned into 10-second buckets to show baseline versus peak and the second the spike began.
- **Diagnostic runbooks.** A set of deterministic, rule-based runbooks (see below) maps recognized patterns to concrete suggested commands such as `kubectl rollout undo` or `kubectl scale`.
- **Exports.** Reports can be exported as Slack Markdown, GitHub/Jira post-mortem Markdown, a CSV summary, or structured JSON.
- **Offline fallback.** If the backend is unreachable, the web UI falls back to an in-browser triage implementation.

### Built-in runbooks

1. Database connection pool and lock starvation
2. JVM / container OOM eviction and CrashLoopBackOff
3. Redis / cache eviction storm and thundering herd
4. Payment gateway and remote RPC timeout storm
5. Upstream microservice unresponsiveness (502/504)
6. Message queue / Kafka consumer lag and rebalance storm
7. Disk volume exhaustion (ENOSPC / read-only filesystem)
8. TLS / SSL certificate expiration
9. Rate limiting / 429 quota exhaustion
10. Thread starvation and deadlock
11. DNS resolution failure and CoreDNS saturation

## Backend and ingestion

- **Threaded server.** Long-running ingestion does not block health checks, metrics, or other users.
- **Streaming parser.** Logs are read as lazy iterators, so memory use during ingestion does not grow with file size. Gzip input is detected by its magic bytes (`0x1f 0x8b`) and decompressed on the fly without extracting to disk.
- **Multipart uploads.** A pure-Python parser accepts `.log`, `.txt`, `.json`, and `.gz` files.
- **Payload limit.** Requests larger than 100 MB are rejected with HTTP 413 before the body is read.
- **Response compression.** JSON responses over 1 KB are gzip-compressed when the client sends `Accept-Encoding: gzip`.
- **Path validation.** `SafePathManager` rejects directory traversal attempts (`../`, `%2f`, null bytes) on file endpoints.
- **Dataset discovery.** Files in `datasets/` are listed automatically with title, line count, size, and affected services.

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/health` | Service health, version, uptime, and capabilities |
| GET | `/api/v2/metrics` | Active threads, runtime counters, and memory status |
| GET | `/api/v2/presets` | Available preset scenarios with line counts and sizes |
| GET | `/api/load-preset?name=...&limit=...&offset=...` | Stream preset log content with optional pagination |
| GET | `/api/v2/download?file=...` | Download a single dataset file |
| GET | `/api/v2/download/bundle` | Download all datasets as a `.zip` |
| POST | `/api/v2/analyze` | Triage a raw text or JSON log payload |
| POST | `/api/v2/analyze/upload` | Triage an uploaded `.log`, `.txt`, `.json`, or `.gz` file |
| POST | `/api/v2/export` | Format a triage report as `slack`, `markdown`, `csv`, or `json` |
| POST | `/api/v2/export/download` | Generate a report and return it as a file download |
| POST | `/api/export-slack` | Backward-compatible v1 Slack export |
| GET | `/` | Web dashboard (`static/index.html`) |

### Examples

Analyze raw logs:

```bash
curl -X POST http://localhost:8000/api/v2/analyze \
  -H "Content-Type: application/json" \
  -d '{"logs": "2026-10-10T03:02:11Z [postgres-cluster] FATAL remaining connection slots are reserved (max_connections=100)\n2026-10-10T03:02:12Z [order-service] ERROR HikariPool-1 - Connection is not available"}'
```

Export a report as post-mortem Markdown:

```bash
curl -X POST http://localhost:8000/api/v2/export \
  -H "Content-Type: application/json" \
  -d '{"format": "markdown", "report": { ... }}'
```

Download a dataset file, or all datasets as a ZIP:

```bash
curl -O -J "http://localhost:8000/api/v2/download?file=ecommerce_cascade_10k.log"
curl -O -J http://localhost:8000/api/v2/download/bundle
```

Download a report as a file:

```bash
curl -X POST http://localhost:8000/api/v2/export/download \
  -H "Content-Type: application/json" \
  -d '{"format": "markdown", "filename": "postmortem.md", "report": { ... }}' \
  -o postmortem.md
```

## Benchmarks

Triage of a 10,000-line bundled dataset completes in roughly 0.18 s on the author's machine.

<!-- TODO before publishing: fill in the details below and confirm the figure.
Machine / CPU:
Python version:
Dataset:
Method: median of N runs, command used:
Reproduce with: <command>
Only keep any other performance claims (noise reduction, comparison
overhead from the Trie index, response compression ratio) if you
measure them and list the method here. -->

## Design decisions and trade-offs

**Deterministic clustering instead of an LLM.** Logs are not sent to an external model. An LLM call over 10,000 lines would add seconds of latency, token limits, API cost, and the risk of invented output. The heuristic approach runs locally and gives the same output for the same input. It will not understand a log line the way a model might, which is an accepted cost.

**Timing-based cascade inference instead of distributed tracing.** The cascade is reconstructed from event order and timing rather than trace IDs, because tracing is often missing or incomplete during real incidents and this works on a plain text dump. The trade-off is that clock skew or missing lines can produce a wrong order, so treat it as a lead to check, not a verdict.

**10-second buckets instead of finer windows.** Coarser buckets keep the spike view readable under pressure, at the cost of temporal precision.

**Single-pass variable masking instead of full grammar parsing.** Masking keeps per-line cost low across mixed formats (Syslog, Spring Boot, JSON, Kubernetes) without a heavy parser. Unusual formats may cluster less cleanly.

**Standard library only.** No installation friction and easy portability to a local CLI, Docker, or serverless environment.

## Limitations

- The bundled datasets (database pool starvation, Kubernetes OOM CrashLoopBackOff, Redis thundering herd) are synthetic and generated by `generate_datasets.py`. Behavior on real production logs has been tested less.
- "Likely trigger" is a timing heuristic. It can be wrong with clock skew, dropped lines, or incidents with several independent causes.
- Runbook recommendations are pattern-based suggestions. Review commands before running them against a real system.
- The server has no authentication or TLS. It is intended for local or trusted-network use only.
