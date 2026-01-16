# UEBA Module – Insider Threat Detection Logic

This module implements User and Entity Behavior Analytics (UEBA)
to detect insider threats based on real Linux user activity.

## Components

### Baseline Modeling (ueba_baseline.py)
Defines normal user behavior such as:
- Typical login frequency
- Command execution patterns
- File access behavior

### User Mapping (ueba_real_users.py)
Maps real Linux system users to monitored entities.

### Detection Engine (ueba_detect.py)
Compares real-time activity against baseline
to identify anomalies and suspicious actions.

### Risk Scoring (ueba_score.py)
Assigns a numerical risk score to each user
based on detected anomalies.

### Alerting (email_alert.py)
Triggers alerts when a user exceeds
a defined risk threshold.

## Approach
This project uses rule-based UEBA,
which is suitable for real-time monitoring
and academic evaluation.
