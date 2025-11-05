from email import policy
import json
import sys
from pathlib import Path
import logging

from prompt_templates import SYSTEM_PROMPT, build_prompt
from hf_client_api import HuggingFaceClient
from policy_models import SecurityPolicy

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def load_findings_from_txt(report_path):
    """Load vulnerability findings from text report"""
    logger.info(f"Loading report from {report_path}...")
    
    with open(report_path, 'r') as f:
        content = f.read()
    
    # Parse text content to extract findings
    # This is a simple parser - adjust based on your actual report format
    findings = []
    lines = content.split('\n')
    
    current_finding = {}
    for line in lines:
        line = line.strip()
        if not line:
            if current_finding:
                findings.append(current_finding)
                current_finding = {}
            continue
        
        # Look for common patterns in security reports
        if line.startswith('Severity:') or 'CRITICAL' in line or 'HIGH' in line or 'MEDIUM' in line or 'LOW' in line:
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if sev in line.upper():
                    current_finding['severity'] = sev
                    break
        elif line.startswith('Title:') or line.startswith('Vulnerability:'):
            current_finding['title'] = line.split(':', 1)[1].strip() if ':' in line else line
        elif line.startswith('Description:'):
            current_finding['description'] = line.split(':', 1)[1].strip() if ':' in line else line
        elif line.startswith('CWE'):
            current_finding['cwe'] = line
        elif line.startswith('File:') or line.startswith('Location:'):
            current_finding['location'] = line.split(':', 1)[1].strip() if ':' in line else line
    
    # Add last finding if exists
    if current_finding:
        findings.append(current_finding)
    
    # If parsing failed, return raw content as single finding
    if not findings:
        logger.warning("Could not parse structured findings, using raw content")
        findings = [{
            'severity': 'UNKNOWN',
            'title': 'Security Report Analysis',
            'description': content[:500],  # First 500 chars
            'raw_content': content
        }]
    
    return findings


def generate_policy(report_path, policy_type, output_path, api_key=None, model=None, provider=None):
    """Generate security policy from text report"""
    
    # Load findings from text file
    findings = load_findings_from_txt(report_path)
    logger.info(f"Extracted {len(findings)} findings/sections from report")
    
    # Setup client
    logger.info("Connecting to Hugging Face API...")
    client = HuggingFaceClient(
        api_key=api_key,
        model=model or "openai/gpt-oss-120b",
        provider=provider or "groq"
    )
    
    # Build prompt
    logger.info(f"Generating {policy_type} policy...")
    user_prompt = build_prompt(findings, policy_type)
    
    # Generate with system + user prompt
    result = client.generate(user_prompt, SYSTEM_PROMPT)
    
    if not result['success']:
        logger.error(f"Generation failed: {result.get('error')}")
        sys.exit(1)
    
    # Validate with Pydantic
    try:
        if result['json']:
            policy = SecurityPolicy(**result['json'])
            logger.info("✓ Policy validated successfully")
        else:
            raise ValueError("No JSON in response")
    except Exception as e:
        logger.warning(f"Validation failed: {e}")
        logger.info("Creating fallback policy...")
        
        # Count severities for fallback
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            sev = f.get('severity', '').upper()
            if sev in counts:
                counts[sev] += 1
        
        from datetime import datetime, timedelta
        now = datetime.now()
        
        policy = SecurityPolicy(
            metadata={
                "policy_id": f"POL-{policy_type}-{now.strftime('%Y-%m-%d')}",
                "policy_name": f"{policy_type} Security Policy",
                "version": "1.0",
                "status": "Draft",
                "created_date": now.isoformat(),
                "last_updated": now.isoformat(),
                "next_review_date": (now + timedelta(days=90)).strftime('%Y-%m-%d'),
                "author": "Automated Policy Generator",
                "department": "Information Security",
                "classification": "Internal"
            },
            policy_statement={
                "purpose": f"To address security vulnerabilities identified in {policy_type} scanning",
                "description": "This policy was auto-generated and requires manual review",
                "applicability": "All relevant systems and teams",
                "enforcement": "Manual review required"
            },
            policy_type=policy_type,
            executive_summary="Manual review required - automated generation failed",
            scope=f"{policy_type} security",
            objectives=["Review findings", "Implement controls"],
            risk_assessment={
                "overall_risk_level": "High" if counts['CRITICAL'] > 0 else "Medium",
                "critical_count": counts['CRITICAL'],
                "high_count": counts['HIGH'],
                "medium_count": counts['MEDIUM'],
                "low_count": counts['LOW'],
                "business_impact": "To be assessed",
                "likelihood": "To be assessed"
            },
            total_findings=len(findings),
            vulnerability_categories=["Review manually"],
            security_controls=[],
            remediation_actions=[],
            compliance_mapping={
                "nist_csf_categories": [],
                "iso27001_controls": []
            },
            monitoring_requirements=["Manual review required"],
            review_schedule="Quarterly"
        )
    
    # Save
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(policy.model_dump_json(indent=2))
    
    logger.info(f"✓ Policy saved to {output_path}")
    
    # Summary
    print("\n" + "="*60)
    print(f"POLICY GENERATED: {policy.policy_type}")
    print(f"Total Findings: {policy.total_findings}")
    print(f"Critical: {policy.risk_assessment.critical_count} | High: {policy.risk_assessment.high_count} | Medium: {policy.risk_assessment.medium_count} | Low: {policy.risk_assessment.low_count}")
    print("="*60)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate security policies from vulnerability reports")
    parser.add_argument('--api-key', help='HF API key (or set HF_TOKEN env var)')
    parser.add_argument('--report', required=True, help='Path to text report file')
    parser.add_argument('--type', default='SAST', choices=['SAST', 'SCA', 'DAST'], help='Policy type')
    parser.add_argument('--output', default='policy.json', help='Output path')
    parser.add_argument('--model', help='Model name (default: openai/gpt-oss-120b)')
    parser.add_argument('--provider', default='groq', choices=['together', 'groq', 'huggingface'], help='Provider')
    
    args = parser.parse_args()
    
    generate_policy(
        report_path=args.report,
        policy_type=args.type,
        output_path=args.output,
        api_key=args.api_key,
        model=args.model,
        provider=args.provider
    )


if __name__ == "__main__":
    main()