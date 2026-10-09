"""
Unit and Integration Tests for Triage3AM.
Verifies Drain clustering, Patient Zero detection, impact scoring, and Slack export.
"""

import unittest
import os
import json
import http.client
import threading
from http.server import ThreadingHTTPServer
from triage_engine import LogLine, TriageEngine
import server
from server import TriageRequestHandler

class TestTriage3AM(unittest.TestCase):
    def setUp(self):
        self.engine = TriageEngine()
        self.ecommerce_log_path = 'datasets/ecommerce_cascade_10k.log'
        self.k8s_log_path = 'datasets/k8s_oom_cascade_10k.log'

    @classmethod
    def setUpClass(cls):
        cls.http_server = ThreadingHTTPServer(('127.0.0.1', 0), TriageRequestHandler)
        cls.http_thread = threading.Thread(target=cls.http_server.serve_forever, daemon=True)
        cls.http_thread.start()
        cls.server_address = cls.http_server.server_address

    @classmethod
    def tearDownClass(cls):
        cls.http_server.shutdown()
        cls.http_server.server_close()
        cls.http_thread.join(timeout=2)

    def post(self, path, payload, content_type='application/json'):
        conn = http.client.HTTPConnection(*self.server_address, timeout=5)
        conn.request('POST', path, body=payload, headers={'Content-Type': content_type})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return response.status, json.loads(body)

    def test_ecommerce_scenario(self):
        self.assertTrue(os.path.exists(self.ecommerce_log_path))
        with open(self.ecommerce_log_path, 'r') as f:
            raw = f.read()
        
        report = self.engine.ingest_logs(raw)
        summary = report['summary']
        
        self.assertEqual(summary['total_lines_ingested'], 10000)
        self.assertGreater(summary['noise_reduction_percentage'], 99.0)
        self.assertIn('Database Connection Pool Starvation', summary['root_cause_summary'])
        self.assertIn('postgres-cluster', summary['services_impacted'])
        self.assertIn('order-service', summary['services_impacted'])
        
        # Verify top incident is P0
        p0 = report['incidents'][0]
        self.assertEqual(p0['priority'], 'P0')
        self.assertTrue(len(p0['diagnosis']['command']) > 0)
        self.assertAlmostEqual(sum(p0['impact_breakdown'].values()), p0['impact_score'])
        self.assertFalse(p0['diagnosis']['causality_confirmed'])
        self.assertTrue(p0['diagnosis']['evidence']['supporting_log_lines'])

    def test_k8s_oom_scenario(self):
        self.assertTrue(os.path.exists(self.k8s_log_path))
        with open(self.k8s_log_path, 'r') as f:
            raw = f.read()

        report = self.engine.ingest_logs(raw)
        summary = report['summary']

        self.assertEqual(summary['total_lines_ingested'], 10000)
        self.assertGreater(summary['noise_reduction_percentage'], 99.0)
        self.assertIn('OOM', summary['root_cause_summary'])
        self.assertIn('auth-service', summary['services_impacted'])

    def test_slack_markdown_generation(self):
        with open(self.ecommerce_log_path, 'r') as f:
            raw = f.read()
        report = self.engine.ingest_logs(raw)
        handler = TriageRequestHandler
        slack_md = handler._generate_slack_markdown(None, report)
        self.assertIn('INCIDENT ALERT', slack_md)
        self.assertIn('Root Cause Hypothesis', slack_md)
        self.assertIn('Patient Zero', slack_md)

    def test_api_rejects_invalid_json_and_log_types(self):
        status, body = self.post('/api/analyze', '{"logs":', 'application/json')
        self.assertEqual(status, 400)
        self.assertIn('Invalid JSON', body['error'])

        status, body = self.post('/api/analyze', '{"logs": ["not", "text"]}')
        self.assertEqual(status, 400)
        self.assertIn('must be a string', body['error'])

    def test_api_preserves_unstructured_text_and_reports_measured_duration(self):
        status, report = self.post('/api/analyze', '{not-json but valid log content', 'text/plain')
        self.assertEqual(status, 200)
        self.assertEqual(report['summary']['total_lines_ingested'], 1)
        self.assertGreaterEqual(report['summary']['time_to_triage_seconds'], 0)

    def test_api_rejects_invalid_utf8_and_oversized_uploads(self):
        status, body = self.post('/api/analyze', b'\xff', 'text/plain')
        self.assertEqual(status, 400)
        self.assertIn('UTF-8', body['error'])

        original_limit = server.MAX_REQUEST_BYTES
        try:
            server.MAX_REQUEST_BYTES = 8
            status, body = self.post('/api/analyze', b'x' * 9, 'text/plain')
        finally:
            server.MAX_REQUEST_BYTES = original_limit
        self.assertEqual(status, 413)
        self.assertIn('byte limit', body['error'])

    def test_api_enforces_line_limit(self):
        original_limit = server.MAX_LOG_LINES
        try:
            server.MAX_LOG_LINES = 1
            status, body = self.post('/api/analyze', '{"logs":"one\\ntwo"}')
        finally:
            server.MAX_LOG_LINES = original_limit
        self.assertEqual(status, 413)
        self.assertIn('maximum is 1', body['error'])

    def test_mixed_timezone_logs_are_comparable(self):
        report = self.engine.ingest_logs(
            '2026-10-10T03:00:00Z [api-service] ERROR database timeout\n'
            '2026-10-10 03:00:01 [api-service] ERROR database timeout'
        )
        self.assertEqual(report['summary']['total_lines_ingested'], 2)
        parsed = [LogLine('2026-10-10T03:00:00Z [api-service] INFO ok', 1),
                  LogLine('2026-10-10 03:00:00 [api-service] INFO ok', 2)]
        self.assertEqual(parsed[0].timestamp, parsed[1].timestamp)

    def test_http_status_codes_remain_distinct_templates(self):
        self.engine.ingest_logs(
            '2026-10-10T03:00:00Z [api-service] ERROR HTTP 500 Internal Server Error\n'
            '2026-10-10 03:00:01 [api-service] ERROR HTTP 503 Service Unavailable'
        )
        status_templates = [
            cluster.get_template_str() for cluster in self.engine.clusters
            if '<HTTP_STATUS_' in cluster.get_template_str()
        ]
        self.assertEqual(len(status_templates), 2)

    def test_missing_timestamps_do_not_invent_a_cascade_trigger(self):
        report = self.engine.ingest_logs(
            '[api-service] ERROR database timeout\n'
            '[payment-service] ERROR upstream request failed'
        )
        self.assertIsNone(report['summary']['outage_started_at'])
        self.assertFalse(any(item['is_cascade_trigger'] for item in report['incidents']))
        self.assertIsNone(report['incidents'][0]['first_seen'])

if __name__ == '__main__':
    unittest.main()
