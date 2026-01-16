# Logstash Pipelines – Log Ingestion Layer

Logstash is used to collect, parse, and forward system logs to Elasticsearch
for insider threat analysis.

## Pipelines Used

### 1. Authentication Logs (authlog.conf)
- Source: /var/log/auth.log
- Captures:
  - User logins
  - sudo usage
  - session open/close events
- Purpose:
  - Detect unauthorized logins
  - Track privilege escalation

### 2. Audit Logs (auditlog.conf)
- Source: /var/log/audit/audit.log
- Captures:
  - File access
  - Command execution
  - USB device activity
- Purpose:
  - Detect insider misuse at OS level

## Output
- All logs are sent to Elasticsearch
- Indexed as:
  - auth-logs
  - audit-logs

Logstash acts as the central data processing engine
between Linux security logs and the analytics layer.
