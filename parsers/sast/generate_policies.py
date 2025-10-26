#!/usr/bin/env python3
"""
generate_policies.py
Generate security policies from parsed SAST findings using LLM
"""

import json
import argparse
import os
from datetime import datetime

# Choose your LLM implementation
# Uncomment the one you want to use:

# Option 1: Local Ollama
import requests

# # Option 2: OpenAI
# from openai import OpenAI

# # Option 3: Anthropic Claude
# from anthropic import Anthropic


def call_llm(prompt: str, model: str = "llama3.3") -> str:
    """
    Call LLM to generate policy.
    Modify this function based on your chosen LLM.
    """

    # === OPTION 1: OLLAMA (Local) ===
    try:
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                'model': model,
                'prompt': prompt,
                'stream': False
            },
            timeout=120
        )
        if response.status_code == 200:
            return response.json().get('response', '')
    except Exception as e:
        print(f" Ollama error: {e}")
        return generate_fallback_policy()

    # === OPTION 2: OPENAI ===
    # try:
    #     client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
    #     response = client.chat.completions.create(
    #         model="gpt-4",
    #         messages=[
    #             {"role": "system", "content": "You are a cybersecurity policy expert."},
    #             {"role": "user", "content": prompt}
    #         ],
    #         max_tokens=2000
    #     )
    #     return response.choices[0].message.content
    # except Exception as e:
    #     print(f"⚠️  OpenAI error: {e}")
    #     return generate_fallback_policy()

    # === OPTION 3: ANTHROPIC CLAUDE ===
    # try:
    #     client = Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
    #     response = client.messages.create(
    #         model="claude-3-sonnet-20240229",
    #         max_tokens=2000,
    #         messages=[{"role": "user", "content": prompt}]
    #     )
    #     return response.content[0].text
    # except Exception as e:
    #     print(f"⚠️  Claude error: {e}")
    #     return generate_fallback_policy()


def generate_fallback_policy() -> str:
    """Fallback policy if LLM fails"""
    return """
**POLICY STATEMENT**
Security vulnerabilities have been identified and must be addressed.

**SCOPE**
All affected systems and components.

**REQUIREMENTS**
- Remediate identified vulnerabilities
- Follow secure coding practices
- Implement proper input validation

**IMPLEMENTATION**
Development team to review and fix issues within SLA.
"""


def create_policy_prompt(sast_findings: str, framework: str) -> str:

    prompt = f"""You are a cybersecurity compliance expert. Based on the SAST security findings below, generate comprehensive security policies aligned with {framework.upper()}.

{sast_findings}

Generate 3-5 security policies that address these vulnerabilities. For EACH policy, provide:

1. **Policy ID**: Unique identifier (e.g., POL-SEC-001)
2. **Title**: Clear policy title
3. **Policy Statement**: Formal statement of the security requirement
4. **{framework.upper()} Control Mapping**: Which control category (e.g., PR.DS for NIST CSF)
5. **Scope**: What systems/components this applies to
6. **Requirements**: Specific technical requirements (bullet points)
7. **Implementation Guidelines**: How developers should implement (concrete steps)
8. **Compliance Verification**: How to verify compliance
9. **Responsibilities**: Who implements and monitors

Format the response as a JSON array of policy objects.

Example format:
[
  {{
    "policy_id": "POL-SEC-001",
    "title": "Input Validation Policy",
    "statement": "All user inputs must be validated...",
    "nist_control": "PR.DS-5",
    "scope": "Web applications",
    "requirements": ["Validate all inputs", "Sanitize data"],
    "implementation": "Use framework validation...",
    "verification": "Code review + automated testing",
    "responsibilities": "Dev team implements, Security reviews"
  }}
]
"""

    return prompt


def parse_findings(txt_path: str) -> str:
    with open(txt_path, 'r', encoding='utf-8') as f:
        content = f.read()

    finding_count = content.count("--- Finding #")
    print(f"Found {finding_count} vulnerabilities in report")

    if len(content) > 4000:
        lines = content.split('\n')
        truncated = '\n'.join(lines[:100])
        truncated += f"\n\n[... {len(lines) - 100} additional lines truncated for brevity]"
        return truncated

    return content


def generate_policies(sast_findings: str, model: str, framework: str) -> list:

    print(f"Calling {model} to generate policies...")

    prompt = create_policy_prompt(sast_findings, framework)

    response = call_llm(prompt, model)

    try:
        start = response.find('[')
        end = response.rfind(']') + 1

        if start != -1 and end > start:
            json_str = response[start:end]
            policies = json.loads(json_str)
            print(f"Generated {len(policies)} policies")
            return policies
        else:
            raise ValueError("No JSON array found in response")

    except Exception as e:
        print(f"Could not parse as JSON: {e}")
        policies = [{
            'policy_id': 'POL-SEC-001',
            'title': 'Security Policy',
            'statement': response,
            'nist_control': 'PR.DS',
            'scope': 'All systems',
            'requirements': ['Review findings', 'Implement fixes'],
            'implementation': 'Development team to address',
            'verification': 'Security review',
            'responsibilities': 'Development and Security teams'
        }]
        return policies


def main():
    parser = argparse.ArgumentParser(
        description='Generate security policies from SAST findings using LLM'
    )
    parser.add_argument('--input', required=True, help='Input TXT file (from parser_sast_llm.py)')
    parser.add_argument('--output', required=True, help='Output JSON file for policies')
    parser.add_argument('--model', default='llama3.3', help='LLM model name')
    parser.add_argument('--framework', default='nist-csf',
                        choices=['nist-csf', 'iso-27001'],
                        help='Security framework to align with')

    args = parser.parse_args()

    print("=" * 70)
    print("AI-POWERED SECURITY POLICY GENERATOR")
    print("=" * 70)
    print(f"Model: {args.model}")
    print(f"Framework: {args.framework.upper()}")
    print(f"Input: {args.input}")
    print("=" * 70)

    print(f"\n Loading SAST findings from {args.input}...")
    sast_findings = parse_findings(args.input)

    policies = generate_policies(sast_findings, args.model, args.framework)

    output_data = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'model': args.model,
            'framework': args.framework,
            'source': args.input
        },
        'total_policies': len(policies),
        'policies': policies
    }

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Generated {len(policies)} policies")
    print(f"Saved to: {args.output}")
    print("=" * 70)


if __name__ == '__main__':
    main()