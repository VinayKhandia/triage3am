"""
Triage3AM Core Engine: Rule-free log ingestion, dynamic template clustering,
temporal cascade analysis, blast radius calculation, and root cause diagnosis.
"""

import re
import math
import json
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional

# Generalized token patterns for dynamic masking (universal, not specific to any one app)
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')
HEX_REGEX = re.compile(r'\b(?:0x)?[0-9a-fA-F]{7,}\b')
UUID_REGEX = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
TIMESTAMP_REGEX = re.compile(r'\b(?:\d{4}[-/.]\d{2}[-/.]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b')
NUMBER_REGEX = re.compile(r'\b\d+(?:\.\d+)?\b')
HTTP_STATUS_REGEX = re.compile(
    r'\b(HTTP(?:/\d(?:\.\d)?)?\s+|status(?:\s*(?:code)?\s*[=:]?\s*)|response\s+)([1-5]\d{2})\b',
    re.IGNORECASE
)
URL_REGEX = re.compile(r'https?://[^\s]+|/[a-zA-Z0-9_\-\./]+(?:\?[a-zA-Z0-9_\-=&]+)?')
SERVICE_BRACKET_REGEX = re.compile(r'\[([a-zA-Z0-9_\-]+(?:-service|-api|-worker|-db|-app|-gateway|svc|pod|cluster)?)\]')
_DIGIT_WORDS = ('ZERO', 'ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE')

SEVERITY_WEIGHTS = {
    'PANIC': 100,
    'FATAL': 95,
    'CRITICAL': 90,
    'SEVERE': 85,
    'ERROR': 70,
    'ERR': 70,
    'EXCEPTION': 65,
    'WARN': 30,
    'WARNING': 30,
    'INFO': 5,
    'DEBUG': 1,
}

class LogLine:
    def __init__(self, raw: str, line_no: int):
        self.raw = raw.strip()
        self.line_no = line_no
        self.timestamp_str = ""
        self.timestamp: Optional[datetime] = None
        self.service = "system"
        self.severity = "INFO"
        self.message = self.raw
        self.masked_tokens: List[str] = []
        self._parse()

    def _parse(self):
        # 1. Try parsing JSON log format
        if self.raw.startswith('{') and self.raw.endswith('}'):
            try:
                data = json.loads(self.raw)
                self.message = str(data.get('message') or data.get('msg') or data.get('log') or self.raw)
                self.service = str(data.get('service') or data.get('app') or data.get('container') or data.get('component') or "system")
                self.severity = str(data.get('level') or data.get('severity') or "INFO").upper()
                time_val = data.get('timestamp') or data.get('time') or data.get('@timestamp') or data.get('ts')
                if time_val:
                    self.timestamp_str = str(time_val)
                    self._parse_time(self.timestamp_str)
                return
            except Exception:
                pass

        # 2. Extract timestamp from standard log strings
        ts_match = TIMESTAMP_REGEX.search(self.raw)
        if ts_match:
            self.timestamp_str = ts_match.group(0)
            self._parse_time(self.timestamp_str)

        # 3. Extract severity
        upper_line = self.raw.upper()
        for sev in ['PANIC', 'FATAL', 'CRITICAL', 'SEVERE', 'ERROR', 'WARN', 'WARNING', 'INFO', 'DEBUG']:
            if re.search(r'\b' + sev + r'\b', upper_line):
                self.severity = 'ERROR' if sev in ('SEVERE', 'ERR') else ('WARN' if sev == 'WARNING' else sev)
                break

        # 4. Extract service name
        svc_match = SERVICE_BRACKET_REGEX.search(self.raw)
        if svc_match:
            self.service = svc_match.group(1).lower()
        else:
            tag_match = re.search(r'([a-zA-Z0-9_\-]+(?:-service|-gateway|-worker|-db|-api|-cluster|[0-9a-f]{5,}))[:\s]', self.raw)
            if tag_match:
                self.service = tag_match.group(1).lower()

    def _parse_time(self, ts_str: str):
        cleaned = ts_str.strip()
        # Handle ISO strings with Z
        try:
            iso_str = cleaned.replace('Z', '+00:00')
            self.timestamp = datetime.fromisoformat(iso_str)
            if self.timestamp.tzinfo is None:
                self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
            else:
                self.timestamp = self.timestamp.astimezone(timezone.utc)
            return
        except Exception:
            pass

        formats = [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%H:%M:%S.%f",
            "%H:%M:%S",
        ]
        for fmt in formats:
            try:
                base = cleaned.split('+')[0].rstrip('Z')
                self.timestamp = datetime.strptime(base, fmt)
                self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
                return
            except ValueError:
                continue

    def get_tier(self) -> str:
        if self.severity in ['PANIC', 'FATAL', 'CRITICAL', 'SEVERE', 'ERROR', 'ERR']:
            return 'ERROR'
        elif self.severity in ['WARN', 'WARNING']:
            return 'WARN'
        return 'INFO'

    def tokenize_and_mask(self) -> List[str]:
        # Strip timestamps, brackets, metadata before masking
        clean_text = self.message
        if self.timestamp_str:
            clean_text = clean_text.replace(self.timestamp_str, '')

        # Preserve response codes as meaning-bearing tokens before masking other numbers.
        clean_text = HTTP_STATUS_REGEX.sub(
            lambda match: match.group(1) + '<HTTP_STATUS_' + ''.join(
                _DIGIT_WORDS[int(digit)] for digit in match.group(2)
            ) + '>',
            clean_text
        )
        
        # Replace variable tokens with generic markers
        clean_text = UUID_REGEX.sub('<UUID>', clean_text)
        clean_text = IP_REGEX.sub('<IP>', clean_text)
        clean_text = HEX_REGEX.sub('<HEX>', clean_text)
        clean_text = URL_REGEX.sub('<URL>', clean_text)
        clean_text = NUMBER_REGEX.sub('<NUM>', clean_text)
        
        # Tokenize by whitespace and non-alphanumeric punctuation
        tokens = [t for t in re.split(r'[\s,;:|]+', clean_text) if t]
        self.masked_tokens = tokens
        return tokens


class DrainCluster:
    def __init__(self, template_tokens: List[str], first_line: LogLine):
        self.template_tokens = template_tokens
        self.cluster_id = f"inc-{first_line.line_no}"
        self.log_lines: List[LogLine] = [first_line]
        self.services = Counter({first_line.service: 1})
        self.severities = Counter({first_line.severity: 1})
        self.first_seen = first_line.timestamp
        self.last_seen = first_line.timestamp
        self.patient_zero = first_line
        self.has_stacktrace = False

    def get_template_str(self) -> str:
        return " ".join(self.template_tokens)

    def similarity(self, tokens: List[str]) -> float:
        """Computes structural similarity without hand-written rules"""
        if len(self.template_tokens) == 0 or len(tokens) == 0:
            return 0.0
        len_ratio = min(len(self.template_tokens), len(tokens)) / max(len(self.template_tokens), len(tokens))
        if len_ratio < 0.6:
            return 0.0

        matches = 0
        min_len = min(len(self.template_tokens), len(tokens))
        for i in range(min_len):
            t1 = self.template_tokens[i]
            t2 = tokens[i]
            if (t1.startswith('<HTTP_STATUS_') or t2.startswith('<HTTP_STATUS_')) and t1 != t2:
                return 0.0
            if t1 == t2:
                matches += 1
            elif t1 == '<*>' or t2 == '<*>':
                matches += 0.8
            elif (t1.startswith('<') and t1.endswith('>')) and (t2.startswith('<') and t2.endswith('>')):
                matches += 0.9

        return (matches / max(len(self.template_tokens), len(tokens)))

    def update_with(self, tokens: List[str], line: LogLine):
        self.log_lines.append(line)
        self.services[line.service] += 1
        self.severities[line.severity] += 1
        
        if line.timestamp:
            if not self.first_seen or line.timestamp < self.first_seen:
                self.first_seen = line.timestamp
                self.patient_zero = line
            if not self.last_seen or line.timestamp > self.last_seen:
                self.last_seen = line.timestamp

        if any(term in line.raw for term in ['at ', 'Traceback', 'Caused by:', 'goroutine', 'Exception in thread']):
            self.has_stacktrace = True

        # Refine template tokens: differing positions turn into wildcards <*>
        min_len = min(len(self.template_tokens), len(tokens))
        new_template = []
        for i in range(min_len):
            if self.template_tokens[i] == tokens[i]:
                new_template.append(self.template_tokens[i])
            else:
                new_template.append('<*>')
        self.template_tokens = new_template


class TriageEngine:
    def __init__(self, similarity_threshold: float = 0.55):
        self.similarity_threshold = similarity_threshold
        self.clusters: List[DrainCluster] = []
        self.total_lines = 0
        self.error_lines = 0

    def ingest_logs(self, raw_text: str) -> Dict[str, Any]:
        """Ingests raw logs, groups similar errors without hand-written rules, and ranks by impact."""
        lines = raw_text.splitlines()
        self.total_lines = len(lines)
        self.clusters = []
        self.error_lines = 0

        cluster_groups: Dict[Tuple[str, int], List[DrainCluster]] = defaultdict(list)

        for line_no, raw in enumerate(lines, start=1):
            if not raw.strip():
                continue

            log = LogLine(raw, line_no)
            is_error_grade = log.severity in ['PANIC', 'FATAL', 'CRITICAL', 'SEVERE', 'ERROR', 'WARN']
            if is_error_grade:
                self.error_lines += 1

            tier = log.get_tier()
            tokens = log.tokenize_and_mask()
            token_len = len(tokens)

            # Check similar clusters in same tier with nearby token lengths
            best_match: Optional[DrainCluster] = None
            best_sim = 0.0

            candidates = (
                cluster_groups[(tier, token_len)] +
                cluster_groups[(tier, token_len - 1)] +
                cluster_groups[(tier, token_len + 1)]
            )

            for cluster in candidates:
                sim = cluster.similarity(tokens)
                if sim > best_sim and sim >= self.similarity_threshold:
                    best_sim = sim
                    best_match = cluster

            if best_match:
                best_match.update_with(tokens, log)
            else:
                new_cluster = DrainCluster(tokens, log)
                cluster_groups[(tier, token_len)].append(new_cluster)
                self.clusters.append(new_cluster)

        return self._build_incident_report()

    def _build_incident_report(self) -> Dict[str, Any]:
        # Filter clusters to notable incidents (primarily errors and high-frequency warnings)
        incident_clusters = [
            c for c in self.clusters
            if any(c.severities.get(sev, 0) > 0 for sev in ['PANIC', 'FATAL', 'CRITICAL', 'SEVERE', 'ERROR'])
            or (c.severities.get('WARN', 0) >= 3 and len(c.services) >= 1)
        ]

        if not incident_clusters and self.clusters:
            incident_clusters = sorted(self.clusters, key=lambda c: len(c.log_lines), reverse=True)[:5]

        # Identify global Patient Zero (earliest critical anomaly across all incident clusters)
        all_patient_zeros = []
        for c in incident_clusters:
            if c.patient_zero and c.patient_zero.timestamp:
                all_patient_zeros.append((c.patient_zero.timestamp, c))

        all_patient_zeros.sort(key=lambda x: x[0])
        global_trigger_cluster = all_patient_zeros[0][1] if all_patient_zeros else None

        scored_incidents = []
        all_services = set()

        for c in incident_clusters:
            count = len(c.log_lines)
            num_services = len(c.services)
            all_services.update(c.services.keys())

            max_sev = 'INFO'
            for sev in ['PANIC', 'FATAL', 'CRITICAL', 'SEVERE', 'ERROR', 'WARN', 'INFO']:
                if c.severities.get(sev, 0) > 0:
                    max_sev = sev
                    break
            
            sev_weight = SEVERITY_WEIGHTS.get(max_sev, 10)
            is_global_root = (c == global_trigger_cluster)
            
            score_breakdown = {
                'severity': round(sev_weight * 0.35, 1),
                'frequency': round(min(count * 0.05, 30), 1),
                'service_breadth': round(min(num_services, 5) * 6, 1),
                'earliest_incident_bonus': 35 if is_global_root else 0,
                'stacktrace_evidence': 15 if c.has_stacktrace else 0,
            }
            impact_score = round(sum(score_breakdown.values()), 1)

            # Classify Priority: P0 (Critical Outage), P1 (High Impact), P2 (Degradation)
            if impact_score >= 60 or max_sev in ['FATAL', 'PANIC', 'CRITICAL']:
                priority = 'P0'
                priority_label = 'CRITICAL OUTAGE'
            elif impact_score >= 40 or max_sev == 'ERROR':
                priority = 'P1'
                priority_label = 'HIGH IMPACT'
            else:
                priority = 'P2'
                priority_label = 'DEGRADATION'

            scored_incidents.append({
                'cluster': c,
                'impact_score': round(impact_score, 1),
                'impact_breakdown': score_breakdown,
                'priority': priority,
                'priority_label': priority_label,
                'max_sev': max_sev,
                'is_global_root': is_global_root
            })

        # Sort descending by impact score (P0 root triggers surface first)
        scored_incidents.sort(key=lambda x: (x['is_global_root'], x['impact_score']), reverse=True)

        formatted_incidents = []
        for rank, item in enumerate(scored_incidents, start=1):
            c: DrainCluster = item['cluster']
            is_cascade_root = item['is_global_root']

            diagnosis = self._diagnose_incident(c, is_cascade_root)
            diagnosis['confidence'] = 'heuristic'
            diagnosis['causality_confirmed'] = False
            diagnosis['evidence'] = {
                'basis': 'The candidate label comes from message text patterns. The examples below support the match but do not prove causation.',
                'supporting_log_lines': [line.raw for line in c.log_lines[:3]],
                'observed_services': list(c.services.keys()),
                'first_seen': c.first_seen.isoformat() if isinstance(c.first_seen, datetime) else None,
            }

            formatted_incidents.append({
                'rank': rank,
                'id': c.cluster_id,
                'priority': item['priority'],
                'priority_label': item['priority_label'],
                'impact_score': item['impact_score'],
                'impact_breakdown': item['impact_breakdown'],
                'template': c.get_template_str(),
                'line_count': len(c.log_lines),
                'percentage_of_total': round((len(c.log_lines) / max(self.total_lines, 1)) * 100, 2),
                'first_seen': c.first_seen.isoformat() if isinstance(c.first_seen, datetime) else None,
                'last_seen': c.last_seen.isoformat() if isinstance(c.last_seen, datetime) else None,
                'services_affected': list(c.services.keys()),
                'primary_service': c.services.most_common(1)[0][0] if c.services else "system",
                'severities': dict(c.severities),
                'patient_zero': {
                    'line_no': c.patient_zero.line_no,
                    'raw': c.patient_zero.raw,
                    'timestamp': c.patient_zero.timestamp.isoformat() if c.patient_zero.timestamp else None,
                    'service': c.patient_zero.service,
                },
                'is_cascade_trigger': is_cascade_root,
                'diagnosis': diagnosis,
                'sample_lines': [line.raw for line in c.log_lines[:5]]
            })

        incident_count = len(formatted_incidents)
        noise_reduction_pct = round(((self.total_lines - incident_count) / max(self.total_lines, 1)) * 100, 2)

        outage_start_str = None
        if global_trigger_cluster and global_trigger_cluster.first_seen and isinstance(global_trigger_cluster.first_seen, datetime):
            outage_start_str = global_trigger_cluster.first_seen.isoformat()

        return {
            'summary': {
                'total_lines_ingested': self.total_lines,
                'total_error_lines': self.error_lines,
                'raw_clusters_formed': len(self.clusters),
                'actionable_incidents': incident_count,
                'noise_reduction_percentage': noise_reduction_pct,
                'services_impacted': list(all_services),
                'total_services_impacted': len(all_services),
                'outage_started_at': outage_start_str,
                'root_cause_summary': formatted_incidents[0]['diagnosis']['root_cause'] if formatted_incidents else "Multiple microservice faults"
            },
            'incidents': formatted_incidents,
            'cascade_chain': self._build_cascade_chain(formatted_incidents)
        }

    def _diagnose_incident(self, cluster: DrainCluster, is_cascade_root: bool) -> Dict[str, Any]:
        """Synthesizes deterministic root-cause diagnosis, trigger hypothesis, and runbook fix."""
        sample_text = (cluster.patient_zero.raw + " " + cluster.get_template_str()).lower()

        # Database / Connection Pool Starvation
        if any(w in sample_text for w in [
            'connection pool', 'timeout waiting for pool', 'max_connections', 'postgres', 'mysql',
            'sqlalchemy', 'hikaripool', 'db-primary', 'connectionclosedexception', 'database lock',
            'cannot obtain lock', 'relation \'inventory_items\''
        ]):
            return {
                'root_cause': "Database Connection Pool Starvation",
                'trigger': "Spike in concurrent traffic or long-running transaction held all DB connection slots (max_connections reached).",
                'impact_narrative': "Downstream APIs cannot acquire database handles, backing up request queues across checkout and worker pods.",
                'recommended_fix': "1. Bump `max_connections` or connection pool size:\n   `ALTER SYSTEM SET max_connections = 300;`\n2. Terminate stuck transactions:\n   `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle in transaction';`\n3. Scale PgBouncer pooler replicas.",
                'command': "kubectl scale deployment/db-pool-proxy --replicas=3"
            }

        # Out Of Memory / Memory Leak / OOMKilled
        elif any(w in sample_text for w in ['oomkilled', 'outofmemoryerror', 'heap space', 'memory cgroup', 'oom-killer', 'crashloopbackoff', 'failed liveness probe']):
            return {
                'root_cause': "JVM / Container OOM Eviction & CrashLoopBackOff",
                'trigger': "Memory leak triggered by unclosed streaming buffers or bulk payload ingestion, hitting Kubernetes memory cgroup quota.",
                'impact_narrative': "Container kernel killed the pod; cascading failover caused continuous restart loops across auth pods.",
                'recommended_fix': "1. Roll back recent canary release:\n   `kubectl rollout undo deployment/auth-service`\n2. Increase pod memory limits from 512Mi to 2Gi:\n   `kubectl patch deployment auth-service -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"auth\",\"resources\":{\"limits\":{\"memory\":\"2Gi\"}}}]}}}}'`",
                'command': "kubectl rollout undo deployment/auth-service"
            }

        # Redis / Cache Starvation & Thundering Herd
        elif any(w in sample_text for w in ['redis', 'ioredis', '6379', 'timeout connecting to redis', 'cache miss']):
            return {
                'root_cause': "Cache Layer Saturation / Thundering Herd",
                'trigger': "Key eviction storm or Redis cluster failover timed out, causing hundreds of workers to stampede DB simultaneously.",
                'impact_narrative': "Cache unavailability amplified latency by 40x across customer-facing gateways.",
                'recommended_fix': "1. Verify Redis cluster health and shard replication:\n   `redis-cli -h cache-cluster info replication`\n2. Enable circuit breaker to return stale cached values during re-warming.",
                'command': "redis-cli cluster failover takeover"
            }

        # Payment Gateway & Remote RPC
        elif any(w in sample_text for w in ['paymentintent', 'payment-gateway', 'payment', 'stripe', 'transaction rollback']):
            return {
                'root_cause': "Cascading Payment RPC Timeout & Retry Storm",
                'trigger': "Upstream database latency stalled checkout transactions, triggering client-side retry storms.",
                'impact_narrative': "Payment transactions rejected; orders aborted mid-flight.",
                'recommended_fix': "1. Enable exponential backoff and jitter on payment client.\n2. Enable circuit breaker for non-critical checkout services.",
                'command': "kubectl rollout restart deployment/payment-gateway"
            }

        # Network / DNS / Gateway 502 / 504
        elif any(w in sample_text for w in ['502 bad gateway', '504 gateway timeout', 'econnrefused', 'dns resolution failed', 'no route to host', 'gateway timeout']):
            return {
                'root_cause': "Upstream Microservice Unresponsiveness / Gateway Timeout (504)",
                'trigger': "Upstream dependencies failed health checks or exceeded ingress read timeout threshold (30s).",
                'impact_narrative': "Ingress proxies dropped incoming user traffic with HTTP 504 Gateway Timeout.",
                'recommended_fix': "1. Inspect upstream endpoints in Kubernetes:\n   `kubectl get endpoints <service-name>`\n2. Check Envoy / Nginx ingress error logs:\n   `kubectl logs -l app=ingress-nginx --tail=100`",
                'command': "kubectl get pods -A | grep -v Running"
            }

        # Kafka / Message Queue Partition Lag
        elif any(w in sample_text for w in ['kafka', 'consumer lag', 'rebalance', 'commitfailedexception', 'amqp']):
            return {
                'root_cause': "Event Queue Consumer Rebalance Storm",
                'trigger': "Slow batch processing caused consumer heartbeats to expire, triggering continuous partition rebalances.",
                'impact_narrative': "Event ingestion halted; async orders and notifications are stalled in topic partitions.",
                'recommended_fix': "1. Increase `max.poll.interval.ms` from 300000 to 600000.\n2. Scale consumer worker replicas:\n   `kubectl scale deployment/order-worker --replicas=6`",
                'command': "kafka-consumer-groups.sh --bootstrap-server broker:9092 --describe --group order-processors"
            }

        # Default generalized heuristic
        else:
            svc_name = cluster.services.most_common(1)[0][0] if cluster.services else 'primary service'
            return {
                'root_cause': f"Systemic Degradation in {svc_name}",
                'trigger': "Unexpected anomaly burst triggering cascading retries across microservice boundaries.",
                'impact_narrative': f"{len(cluster.log_lines)} events recorded across {len(cluster.services)} services starting at {cluster.first_seen}.",
                'recommended_fix': "1. Check recent deployments and feature flag changes.\n2. Isolate offending service traffic with ingress throttling.\n3. Capture thread dump and heap profiling.",
                'command': "kubectl get events --sort-by='.metadata.creationTimestamp' | tail -n 20"
            }

    def _build_cascade_chain(self, incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Constructs the timeline dependency chain of how the incident cascaded."""
        chain = []
        for inc in incidents:
            chain.append({
                'time': inc['patient_zero']['timestamp'],
                'service': inc['primary_service'],
                'event': inc['diagnosis']['root_cause'],
                'severity': inc['priority'],
                'impact': f"{inc['line_count']} errors across {', '.join(inc['services_affected'][:3])}",
                'is_trigger': inc.get('is_cascade_trigger', False)
            })
        return chain
