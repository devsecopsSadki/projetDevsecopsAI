"""
prompt_templates.py
Hybrid NIST CSF + ISO 27001 policy templates
"""

SYSTEM_PROMPT = """You are a cybersecurity expert specialized in NIST Cybersecurity Framework and ISO 27001 standards.
Generate comprehensive security policies that combine the best of both frameworks:
- NIST CSF's 5 functions (Identify, Protect, Detect, Respond, Recover)
- ISO 27001's risk-based approach and control domains

Output valid JSON only. Be specific and actionable."""

SAST_TEMPLATE = """Generate a comprehensive SAST security policy using NIST CSF + ISO 27001 approach.

FINDINGS SUMMARY:
- Total: {findings_count}
- Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}

TOP CODE VULNERABILITIES:
{findings_list}

OUTPUT JSON STRUCTURE (MUST INCLUDE ALL FIELDS):
{{
  "metadata": {{
    "policy_id": "POL-SAST-2025-001",
    "policy_name": "Static Application Security Testing (SAST) Policy",
    "version": "1.0",
    "status": "Draft",
    "created_date": "2025-11-05T00:00:00",
    "last_updated": "2025-11-05T00:00:00",
    "next_review_date": "2026-02-05",
    "author": "Security Policy Generator",
    "approved_by": null,
    "department": "Information Security",
    "classification": "Internal"
  }},
  
  "policy_statement": {{
    "purpose": "To establish standards for identifying and remediating source code vulnerabilities through static analysis",
    "description": "This policy defines requirements for SAST implementation, vulnerability management, and secure code development practices",
    "applicability": "All development teams and applications with custom source code",
    "enforcement": "Mandatory SAST scans in CI/CD pipeline with quality gates",
    "exceptions": "Legacy applications may request temporary exemptions through security review board"
  }},
  
  "policy_type": "SAST",
  "executive_summary": "2-3 sentences on overall code security posture and key risks",
  "scope": "Application source code security analysis",
  "objectives": ["objective 1", "objective 2", "objective 3"],
  
  "risk_assessment": {{
    "overall_risk_level": "Critical|High|Medium|Low",
    "critical_count": {critical},
    "high_count": {high},
    "medium_count": {medium},
    "low_count": {low},
    "business_impact": "Description of potential business impact",
    "likelihood": "High|Medium|Low - likelihood of exploitation"
  }},
  
  "total_findings": {findings_count},
  "vulnerability_categories": ["SQL Injection", "XSS", "Hardcoded Secrets", "..."],
  
  "security_controls": [
    {{
      "control_id": "SC-001",
      "nist_function": "Protect",
      "iso_domain": "A.14 System Development",
      "title": "Input Validation Framework",
      "description": "Implement comprehensive input validation",
      "implementation_steps": ["step 1", "step 2", "step 3"]
    }}
  ],
  
  "remediation_actions": [
    {{
      "priority": "P0",
      "title": "Fix critical SQL injection vulnerabilities",
      "affected_assets": ["auth module", "user API"],
      "timeline": "Immediate (0-7 days)",
      "owner": "Backend Team",
      "success_criteria": "All SQL queries use parameterized statements"
    }}
  ],
  
  "compliance_mapping": {{
    "nist_csf_categories": ["PR.DS-5", "PR.IP-1", "DE.CM-4"],
    "iso27001_controls": ["A.14.2.1", "A.14.2.5", "A.12.6.1"]
  }},
  
  "monitoring_requirements": ["Code scanning in CI/CD", "Weekly SAST scans", "Security code reviews"],
  "review_schedule": "Quarterly policy review and annual audit"
}}"""

SCA_TEMPLATE = """Generate a comprehensive SCA security policy using NIST CSF + ISO 27001 approach.

DEPENDENCY VULNERABILITIES:
- Total: {findings_count}
- Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}

VULNERABLE DEPENDENCIES:
{findings_list}

OUTPUT JSON STRUCTURE (MUST INCLUDE ALL FIELDS):
{{
  "metadata": {{
    "policy_id": "POL-SCA-2025-001",
    "policy_name": "Software Composition Analysis (SCA) Policy",
    "version": "1.0",
    "status": "Draft",
    "created_date": "2025-11-05T00:00:00",
    "last_updated": "2025-11-05T00:00:00",
    "next_review_date": "2026-02-05",
    "author": "Security Policy Generator",
    "approved_by": null,
    "department": "Information Security",
    "classification": "Internal"
  }},
  
  "policy_statement": {{
    "purpose": "To manage third-party dependency security risks and ensure supply chain integrity",
    "description": "This policy establishes requirements for dependency scanning, vulnerability management, and SBOM maintenance",
    "applicability": "All applications using third-party libraries, packages, or open-source components",
    "enforcement": "Automated SCA scans with blocking of high-risk dependencies",
    "exceptions": "Critical dependencies with no alternatives may be approved with compensating controls"
  }},
  
  "policy_type": "SCA",
  "executive_summary": "2-3 sentences on dependency security posture and supply chain risks",
  "scope": "Third-party dependency and supply chain security",
  "objectives": ["objective 1", "objective 2", "objective 3"],
  
  "risk_assessment": {{
    "overall_risk_level": "Critical|High|Medium|Low",
    "critical_count": {critical},
    "high_count": {high},
    "medium_count": {medium},
    "low_count": {low},
    "business_impact": "Impact of vulnerable dependencies",
    "likelihood": "High|Medium|Low"
  }},
  
  "total_findings": {findings_count},
  "vulnerability_categories": ["Outdated packages with CVEs", "Known malicious packages", "..."],
  
  "security_controls": [
    {{
      "control_id": "SC-SCA-001",
      "nist_function": "Identify",
      "iso_domain": "A.15 Supplier Relationships",
      "title": "Dependency Inventory Management",
      "description": "Maintain comprehensive SBOM",
      "implementation_steps": ["step 1", "step 2", "step 3"]
    }}
  ],
  
  "remediation_actions": [
    {{
      "priority": "P0",
      "title": "Update critical vulnerable dependencies",
      "affected_assets": ["package1@version", "package2@version"],
      "timeline": "Immediate (0-7 days)",
      "owner": "DevOps Team",
      "success_criteria": "All critical CVEs patched"
    }}
  ],
  
  "compliance_mapping": {{
    "nist_csf_categories": ["ID.AM-2", "PR.IP-12", "DE.CM-8"],
    "iso27001_controls": ["A.15.1.1", "A.15.1.2", "A.12.6.1"]
  }},
  
  "monitoring_requirements": ["Daily dependency scanning", "CVE monitoring", "License compliance checks"],
  "review_schedule": "Monthly dependency review and quarterly audit"
}}"""

DAST_TEMPLATE = """Generate a comprehensive DAST security policy using NIST CSF + ISO 27001 approach.

RUNTIME VULNERABILITIES:
- Total: {findings_count}
- Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}

RUNTIME SECURITY ISSUES:
{findings_list}

OUTPUT JSON STRUCTURE (MUST INCLUDE ALL FIELDS):
{{
  "metadata": {{
    "policy_id": "POL-DAST-2025-001",
    "policy_name": "Dynamic Application Security Testing (DAST) Policy",
    "version": "1.0",
    "status": "Draft",
    "created_date": "2025-11-05T00:00:00",
    "last_updated": "2025-11-05T00:00:00",
    "next_review_date": "2026-02-05",
    "author": "Security Policy Generator",
    "approved_by": null,
    "department": "Information Security",
    "classification": "Internal"
  }},
  
  "policy_statement": {{
    "purpose": "To identify and remediate runtime security vulnerabilities through dynamic testing",
    "description": "This policy defines requirements for DAST implementation, runtime security monitoring, and production security hardening",
    "applicability": "All web applications, APIs, and internet-facing services",
    "enforcement": "Pre-production DAST scans required before deployment to production",
    "exceptions": "Internal-only applications may use reduced scan frequency with approval"
  }},
  
  "policy_type": "DAST",
  "executive_summary": "2-3 sentences on runtime security posture and exposure risks",
  "scope": "Runtime application security and infrastructure",
  "objectives": ["objective 1", "objective 2", "objective 3"],
  
  "risk_assessment": {{
    "overall_risk_level": "Critical|High|Medium|Low",
    "critical_count": {critical},
    "high_count": {high},
    "medium_count": {medium},
    "low_count": {low},
    "business_impact": "Impact of runtime vulnerabilities if exploited",
    "likelihood": "High|Medium|Low"
  }},
  
  "total_findings": {findings_count},
  "vulnerability_categories": ["Missing security headers", "Authentication flaws", "OWASP Top 10 issues", "..."],
  
  "security_controls": [
    {{
      "control_id": "SC-DAST-001",
      "nist_function": "Protect",
      "iso_domain": "A.13 Communications Security",
      "title": "Security Headers Implementation",
      "description": "Implement all required HTTP security headers",
      "implementation_steps": ["step 1", "step 2", "step 3"]
    }}
  ],
  
  "remediation_actions": [
    {{
      "priority": "P0",
      "title": "Fix critical authentication bypass",
      "affected_assets": ["/api/admin", "/api/user"],
      "timeline": "Immediate (0-7 days)",
      "owner": "Security Team",
      "success_criteria": "Authentication required for all protected endpoints"
    }}
  ],
  
  "compliance_mapping": {{
    "nist_csf_categories": ["PR.AC-1", "PR.DS-2", "DE.CM-1"],
    "iso27001_controls": ["A.9.1.1", "A.13.1.1", "A.18.1.3"]
  }},
  
  "monitoring_requirements": ["Runtime security monitoring", "Weekly DAST scans", "WAF rule updates"],
  "review_schedule": "Monthly review and quarterly penetration testing"
}}"""


def build_prompt(findings, policy_type):
    """Build hybrid NIST + ISO policy prompt"""
    
    # Count severities
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for f in findings:
        sev = f.get('severity', '').upper()
        if sev == 'CRITICAL':
            counts['critical'] += 1
        elif sev == 'HIGH':
            counts['high'] += 1
        elif sev == 'MEDIUM':
            counts['medium'] += 1
        elif sev == 'LOW':
            counts['low'] += 1
    
    # Format top findings
    findings_list = []
    for i, f in enumerate(findings[:15], 1):
        findings_list.append(
            f"{i}. [{f.get('severity', 'N/A')}] {f.get('title', 'Unknown')}\n"
            f"   Location: {f.get('location', 'N/A')}\n"
            f"   Recommendation: {f.get('recommendation', 'Review and fix')}"
        )
    
    # Select template
    templates = {
        'SAST': SAST_TEMPLATE,
        'SCA': SCA_TEMPLATE,
        'DAST': DAST_TEMPLATE
    }
    
    template = templates.get(policy_type, SAST_TEMPLATE)
    
    return template.format(
        findings_count=len(findings),
        critical=counts['critical'],
        high=counts['high'],
        medium=counts['medium'],
        low=counts['low'],
        findings_list='\n\n'.join(findings_list)
    )