visit this to setup the models locally https://chatgpt.com/share/68fe98f7-1158-800f-90e1-6c828da722c2

---

```bash
your-project/
├── Jenkinsfile                # Jenkins pipeline
├── parsers/
│   ├──stats/
│       ├── parser_input.py        # Parse different SAST formats
│       ├── parsast.py     # Converts SAST to LLM-readable TXT
│       └── generate_policies.py   # Generate policies using AI
├── security-reports/          # Auto-generated reports
│   ├── sast-report.json       # Raw SAST scan
│   ├── sast-findings.txt      # Parsed findings for LLM
│   └── security-policies.json # AI-generated policies
├── FetchingData/src           # Application source code
│  
└── requirements.txt           # Python dependencies
```

```bash
pip install requests openai anthropic
```


## Setup Sonar Qube

```bash
# Run in Docker
docker run -d --name sonarqube -p 9000:9000 sonarqube:latest

# Access: http://localhost:9000
# Default: admin/admin

```
