visit this to setup the models locally https://chatgpt.com/share/68fe98f7-1158-800f-90e1-6c828da722c2

---

```bash
your-project/
├── README.md                       # Project overview and setup instructions
├── requirements.txt                # Python dependencies
├── Jenkinsfile                     # Jenkins CI/CD pipeline
│
├── src/
│   ├── app/                        # Sample vulnerable application
│   │   └── [your code to scan]
│   │
│   ├── parsers/
│   │   ├── sast_parser.py          # Parse SAST reports (SonarQube)
│   │   ├── sca_parser.py           # Parse SCA reports (OWASP Dependency-Check)
│   │   ├── dast_parser.py          # Parse DAST reports (OWASP ZAP)
│   │   └── unified_parser.py       # Combine all reports into structured format
│   │
│   ├── policy_generation/
│   │   ├── prompt_templates.py     # Prompt engineering templates
│   │   ├── hf_api_client.py        # Hugging Face API integration
│   │   └── policy_generator.py     # Main policy generation logic
│   │
│   └── evaluation/
│       ├── metrics.py              # BLEU, ROUGE-L calculations
│       └── compare_policies.py     # Compare with NIST/ISO templates
│
├── security-reports/               # Generated reports (gitignored)
│   ├── raw/
│   │   ├── sast-report.json
│   │   ├── sca-report.json
│   │   └── dast-report.xml
│   ├── parsed/
│   │   └── unified-findings.json   # Preprocessed for LLM
│   └── policies/
│       └── generated-policies.json # AI-generated policies
│
├── reference-policies/             # NIST CSF & ISO 27001 templates
│   ├── nist-csf-templates.json
│   └── iso27001-templates.json
│
├── tests/
│   ├── test_parsers.py
│   ├── test_llm_generation.py
│   └── test_evaluation.py
│
└── config/
    ├── hf_config.yaml              # Hugging Face API key & model names
    └── tools_config.yaml           # SAST/SCA/DAST tool configurations
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
