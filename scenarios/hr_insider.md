# Scenario 1: HR Insider Accessing Sensitive Files

## User
- Username: hr_alice
- Role: Human Resources

## Suspicious Activity
The HR user accessed internal system directories
and viewed command history files.

### Actions Performed
- Listed all employee home directories
- Accessed `.bash_history` file

## Why This Is Suspicious
HR users are not expected to:
- Explore other users’ directories
- Inspect command history files

This behavior may indicate reconnaissance
or attempt to hide activity.

## Detection Method
- Auditd captured file access events
- Logstash parsed audit logs
- Elasticsearch stored events in `audit-logs`
- UEBA detected deviation from baseline behavior

## Evidence
- User identified as `hr_alice`
- File accessed: `/home/hr_alice/.bash_history`
- Timestamped audit records available

