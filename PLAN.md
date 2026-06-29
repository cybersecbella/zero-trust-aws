zero-trust-aws/
│
├── README.md                          # overview, quickstart, IAM requirements
├── plan.md                            # this file
├── requirements.txt                   # Python deps (boto3, pandas, scipy)
├── requirements.yml                   # Ansible Galaxy deps (ansible-lockdown)
│
├── ansible/
│   ├── site.yml                       # orchestrates full hardening sequence
│   ├── inventory/
│   │   ├── hosts.yml
│   │   └── group_vars/
│   │       ├── all.yml                # global CIS overrides + skip list
│   │       └── ec2_ubuntu.yml
│   └── playbooks/
│       ├── harden.yml                 # CIS Level 2 hardening run
│       ├── scan_pre.yml               # OpenSCAP baseline before
│       ├── scan_post.yml              # OpenSCAP scan after
│       └── ai_review.yml             # triggers sg_diff.py post-run
│
├── auditor/
│   ├── sg_auditor.py                  # SG auditor — 0.0.0.0/0 on 22/3389
│   └── tests/
│       └── test_sg_auditor.py
│
├── reviewer/
│   ├── sg_diff.py                     # AI firewall rule reviewer (Claude API)
│   └── tests/
│       └── test_sg_diff.py
│
├── zeek/
│   ├── analyzer.py                    # conn.log + dns.log lateral movement detection
│   ├── detections.py
│   │   ├── lateral_movement.py        # internal SSH/RDP/SMB fan-out
│   │   ├── data_staging.py            # high-volume internal transfers
│   │   └── dns_entropy.py             # DGA/C2 beacon detection
│   └── tests/
│       ├── fixtures/                  # sample conn.log and dns.log snippets
│       └── test_analyzer.py
│
├── gap_analyzer/
│   ├── nist_800_207.py                # zero-trust gap scorer + AI narrative
│   ├── controls/
│   │   └── aws_controls_map.py        # NIST tenet → AWS control mapping
│   └── tests/
│       └── test_gap_analyzer.py
│
├── scripts/
│   └── setup_iam.sh                   # creates least-priv IAM policy for CI
│
└── .github/
    └── workflows/
        ├── audit.yml                  # scheduled SG audit (daily)
        └── test.yml                   # pytest on PR