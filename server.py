"""
Triage3AM Web Server: Ultra-fast, zero-dependency HTTP server with REST API
for raw log ingestion, instant clustering, and interactive UI.
"""

import os
import json
import time
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from triage_engine import TriageEngine

PORT = 8000
HOST = os.environ.get('TRIAGE_HOST', '127.0.0.1')
MAX_REQUEST_BYTES = int(os.environ.get('TRIAGE_MAX_REQUEST_BYTES', 10 * 1024 * 1024))
MAX_LOG_LINES = int(os.environ.get('TRIAGE_MAX_LOG_LINES', 100_000))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')

class TriageRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == '/api/presets':
            self._handle_get_presets()
        elif path == '/api/load-preset':
            preset_name = query.get('name', [''])[0]
            self._handle_load_preset(preset_name)
        elif path == '/api/health':
            self._send_json({'status': 'ok', 'server': 'Triage3AM v1.0'})
        else:
            # Fallback to serving static files
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == '/api/analyze':
            try:
                post_data = self._read_body().decode('utf-8-sig')
                raw_logs = self._extract_logs(
                    post_data,
                    self.headers.get('Content-Type', '').split(';', 1)[0].strip().lower() == 'application/json'
                )
                line_count = len(raw_logs.splitlines())
                if line_count > MAX_LOG_LINES:
                    self._send_json({
                        'error': f'Log upload contains {line_count} lines; maximum is {MAX_LOG_LINES}.'
                    }, status=413)
                    return

                t0 = time.perf_counter()
                engine = TriageEngine()
                report = engine.ingest_logs(raw_logs)
                elapsed = round(time.perf_counter() - t0, 3)
                report['summary']['time_to_triage_seconds'] = elapsed
                self._send_json(report)
            except UnicodeDecodeError:
                self._send_json({'error': 'Request body must contain valid UTF-8 text.'}, status=400)
            except ValueError as exc:
                self._send_json({'error': str(exc)}, status=400)
            except OverflowError as exc:
                self._send_json({'error': str(exc)}, status=413)
            except Exception:
                self._send_json({'error': 'The log analysis request could not be processed.'}, status=500)

        elif path == '/api/export-slack':
            try:
                post_data = self._read_body().decode('utf-8-sig')
                data = json.loads(post_data)
                if not isinstance(data, dict):
                    raise ValueError('Request body must be a JSON object.')
                slack_msg = self._generate_slack_markdown(data)
                self._send_json({'markdown': slack_msg})
            except UnicodeDecodeError:
                self._send_json({'error': 'Request body must contain valid UTF-8 text.'}, status=400)
            except ValueError as exc:
                self._send_json({'error': str(exc)}, status=400)
            except OverflowError as exc:
                self._send_json({'error': str(exc)}, status=413)
            except Exception:
                self._send_json({'error': 'The export request could not be processed.'}, status=500)
        else:
            self._send_json({'error': 'Endpoint not found.'}, status=404)

    def _read_body(self) -> bytes:
        """Read a bounded request body and reject unsupported framing."""
        if self.headers.get('Transfer-Encoding'):
            raise ValueError('Transfer-Encoding is not supported; send a Content-Length header.')
        raw_length = self.headers.get('Content-Length')
        if raw_length is None:
            raise ValueError('Content-Length header is required.')
        try:
            content_length = int(raw_length)
        except (TypeError, ValueError):
            raise ValueError('Content-Length must be a non-negative integer.')
        if content_length < 0:
            raise ValueError('Content-Length must be a non-negative integer.')
        if content_length > MAX_REQUEST_BYTES:
            raise OverflowError(f'Request body exceeds the {MAX_REQUEST_BYTES}-byte limit.')
        body = self.rfile.read(content_length)
        if len(body) != content_length:
            raise ValueError('Request body ended before Content-Length bytes were received.')
        return body

    @staticmethod
    def _extract_logs(post_data: str, is_json: bool = False) -> str:
        """Accept the dashboard's JSON contract and plain-text log uploads."""
        if not is_json and not post_data.strip().startswith('{'):
            return post_data
        try:
            body = json.loads(post_data)
        except json.JSONDecodeError as exc:
            if not is_json:
                return post_data
            raise ValueError(f'Invalid JSON body: {exc.msg}.')
        if not isinstance(body, dict):
            raise ValueError('JSON request body must be an object containing a string "logs" field.')
        raw_logs = body.get('logs', '')
        if not isinstance(raw_logs, str):
            raise ValueError('The "logs" field must be a string.')
        return raw_logs

    def _handle_get_presets(self):
        presets = [
            {
                'id': 'ecommerce_cascade_10k.log',
                'title': 'Scenario 1: Black Friday Checkout Cascade (10,000 Lines)',
                'description': 'PostgreSQL pool exhaustion cascades into Hikari pool timeout, payment retry storm, and 504 Gateway Timeouts.',
                'services': ['postgres-cluster', 'order-service', 'payment-gateway', 'api-gateway'],
                'lines': 10000,
                'type': 'Database Starvation'
            },
            {
                'id': 'k8s_oom_cascade_10k.log',
                'title': 'Scenario 2: Kubernetes OOMKilled & CrashLoop (10,000 Lines)',
                'description': 'Java Heap OOM kills auth-service pod; kernel oom-killer evicts container, cascading auth failures through API gateway.',
                'services': ['auth-service', 'kubelet', 'user-service', 'api-gateway'],
                'lines': 10000,
                'type': 'Memory Exhaustion'
            }
        ]
        self._send_json({'presets': presets})

    def _handle_load_preset(self, name: str):
        # Prevent directory traversal
        safe_name = os.path.basename(name)
        preset_path = os.path.join(DATASETS_DIR, safe_name)
        if not os.path.exists(preset_path):
            self._send_json({'error': 'Preset not found'}, status=404)
            return

        with open(preset_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self._send_json({
            'name': safe_name,
            'lines_count': len(content.splitlines()),
            'content': content
        })

    def _generate_slack_markdown(self, report: dict) -> str:
        s = report.get('summary', {})
        incidents = report.get('incidents', [])
        p0 = incidents[0] if incidents else {}
        elapsed = s.get('time_to_triage_seconds', 'not measured')

        md = f"""🚨 *[INCIDENT ALERT: SEV-{p0.get('priority', 'P0')}] - {s.get('root_cause_summary', 'Service Outage')}*
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• *Trigger Detected:* `{s.get('outage_started_at') or 'No timestamp available'}`
• *Noise Reduction:* `{s.get('total_lines_ingested', 'unknown')} lines` ➔ `{s.get('actionable_incidents', len(incidents))} incident cards` ({s.get('noise_reduction_percentage', 'not measured')}% by card-count reduction in {elapsed}s)
• *Blast Radius:* {len(s.get('services_impacted', []))} services affected: `{', '.join(s.get('services_impacted', [])[:5])}`

*Root Cause Hypothesis:*
> {p0.get('diagnosis', {}).get('trigger', 'Underlying dependency failure')}

*Patient Zero (First Anomaly):*
```{p0.get('patient_zero', {}).get('raw', 'N/A')[:200]}```

*Recommended Immediate Action:*
```{p0.get('diagnosis', {}).get('command', 'kubectl get pods -A')}```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_Generated automatically by Triage3AM in {elapsed}s_"""
        return md

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def run(port=PORT):
    server = ThreadingHTTPServer((HOST, port), TriageRequestHandler)
    print(f"🔥 Triage3AM Server running at http://{HOST}:{port}")
    print(f"📁 Serving static files from {STATIC_DIR}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.server_close()

if __name__ == '__main__':
    run()
