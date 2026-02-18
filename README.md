# AWS Cloud Security Monitoring System

A cloud-based security monitoring project built on AWS to detect suspicious authentication and API activity using log analysis and rule-based detection. The system correlates events across cloud and host layers to detect suspicious behavior such as brute-force login attempts and overlapping API activity from the same source IP.

## Architecture
```
             ┌────────────────────┐
             │   AWS CloudTrail   │
             └──────────┬─────────┘
                        │
                        ▼
              CloudTrail JSON Logs
                        │
                        ▼
 ┌─────────────────────────────────────────────┐
 │           Python Detection Pipeline         │
 │  - Log Parsing                              │
 │  - SSH Brute-Force Detection                │
 │  - Cross-Source Correlation                 │
 │  - Severity Scoring                         │
 └─────────────────────────────────────────────┘
                        │
                        ▼
        Alert Output + Visual Reports
```

## Features
### SSH Brute-Force Detection
Detects repeated failed login attempts exceeding a configurable threshold.  

Example:
```bash
SSH ALERT: {'alert': 'Brute-force login attempt suspected',
            'count': 3,
            'severity': 'high'}
```

### Cloud + Host Correlation
Identifies source IPs observed in both:  
- SSH authentication activity  
- AWS CloudTrail API activity  

Example:
```bash
CORRELATION ALERT: {'alert': 'IP seen in both SSH and CloudTrail activity',
                    'sourceIP': '130.127.xxx.xxx',
                    'severity': 'medium'}
```

### Security Visualizations
- SSH success vs failure distribution
- Top CloudTrail API events (Top 10, horizontal view)  
  
Examples:  
<img width="1000" height="600" alt="cloudtrail_activity" src="https://github.com/user-attachments/assets/fea9ab4b-d8ca-4d4f-b2ef-015198f2f7eb" />  
<img width="640" height="480" alt="ssh_activity" src="https://github.com/user-attachments/assets/fee686f8-a52d-4324-bf1f-773e0a52cc9f" />  

## Tech Stack
- AWS (EC2, IAM, CloudTrail)  
    - Environment: Ubuntu Server 24.04 LTS on AWS EC2 (Free Tier)  
    - IAM: IAM user with MFA (least privilege practices)
- Python
- Pandas, Matplotlib
- GitHub Actions

## Project Stucture
```bash
aws-cloud-security-monitoring/
├── data/
│   └── raw/
│       ├── sample_auth.log
│       └── sample_cloudtrail.json
├── src/
│   ├── detection/
│       ├── correlation_rules.py
│       └── ssh_rules.py
│   ├── parsers/
│       ├── auth_log_parser.py
│       └── cloudtrail_parser.py
│   ├── visualization/
│       └── plots.py
│   └── main.py
├── .gitignore
├── .project-root-hook
├── README.md
└── requirements.txt
```
## How To Run
1. Install dependencies:  
`pip install -r requirements.txt`
2. Run detection and generate visualizations:  
`python src/main.py`  
  
Output:  
- Concise alert summary
- Generated visualization images
