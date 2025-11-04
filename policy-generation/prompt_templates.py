from typing import List, Dict, Any


class PromptTemplates:
    """Templates for generating security policies from vulnerability reports"""
    
    @staticmethod
    def get_system_prompt() -> str:
        """Base system prompt for the LLM"""
        return """You are a cybersecurity expert specialized in writing security policies and remediation guidelines. 
Your task is to analyze vulnerability reports and generate clear, actionable security policies that align with 
industry standards like NIST Cybersecurity Framework and ISO 27001.

Generate policies that are:
- Clear and actionable
- Aligned with security best practices
- Specific to the identified vulnerabilities
- Include severity-based prioritization
- Provide concrete remediation steps"""

    @staticmethod
    def generate_sast_policy_prompt(findings: List[Dict[str, Any]]) -> str:
        """Generate prompt for SAST findings"""
        findings_summary = PromptTemplates._summarize_findings(findings, "SAST")
        
        return f"""Based on the following Static Application Security Testing (SAST) findings, generate a comprehensive security policy document:

{findings_summary}

Generate a security policy that includes:
1. Executive Summary: Overview of code security posture
2. Risk Assessment: Categorize findings by severity (Critical, High, Medium, Low)
3. Security Controls: Specific controls to address each vulnerability type
4. Remediation Guidelines: Step-by-step fixes for each issue category
5. Timeline: Prioritized remediation schedule based on severity
6. Compliance Mapping: Map findings to NIST CSF or ISO 27001 controls where applicable

Format the policy in JSON with the following structure:
{{
  "policy_type": "SAST Security Policy",
  "generated_date": "YYYY-MM-DD",
  "executive_summary": "...",
  "risk_assessment": {{
    "critical": [...],
    "high": [...],
    "medium": [...],
    "low": [...]
  }},
  "security_controls": [...],
  "remediation_guidelines": [...],
  "timeline": {{...}},
  "compliance_mapping": {{...}}
}}"""

    @staticmethod
    def generate_sca_policy_prompt(findings: List[Dict[str, Any]]) -> str:
        """Generate prompt for SCA findings"""
        findings_summary = PromptTemplates._summarize_findings(findings, "SCA")
        
        return f"""Based on the following Software Composition Analysis (SCA) findings, generate a comprehensive dependency security policy:

{findings_summary}

Generate a security policy that includes:
1. Executive Summary: Overview of dependency security risks
2. Vulnerable Dependencies: List of packages with known vulnerabilities (CVE, CVSS scores)
3. Risk Assessment: Impact analysis of each vulnerable dependency
4. Update Strategy: Prioritized plan for updating or replacing dependencies
5. Patch Management: Process for ongoing dependency monitoring
6. Supply Chain Security: Guidelines for vetting new dependencies
7. Compliance Requirements: Align with NIST CSF or ISO 27001 standards

Format the policy in JSON with clear sections for each component."""

    @staticmethod
    def generate_dast_policy_prompt(findings: List[Dict[str, Any]]) -> str:
        """Generate prompt for DAST findings"""
        findings_summary = PromptTemplates._summarize_findings(findings, "DAST")
        
        return f"""Based on the following Dynamic Application Security Testing (DAST) findings, generate a comprehensive runtime security policy:

{findings_summary}

Generate a security policy that includes:
1. Executive Summary: Overview of runtime vulnerabilities
2. Vulnerability Assessment: Analysis of each finding (OWASP Top 10 mapping)
3. Configuration Hardening: Server and application configuration recommendations
4. Security Headers: Required HTTP security headers
5. Input Validation: Recommendations for preventing injection attacks
6. Authentication & Authorization: Access control improvements
7. Monitoring & Detection: Runtime security monitoring requirements
8. Incident Response: Steps for addressing exploited vulnerabilities

Format the policy in JSON with actionable recommendations for each finding."""

    @staticmethod
    def generate_unified_policy_prompt(
        sast_findings: List[Dict[str, Any]],
        sca_findings: List[Dict[str, Any]],
        dast_findings: List[Dict[str, Any]]
    ) -> str:
        """Generate comprehensive policy from all scan types"""
        
        sast_summary = PromptTemplates._summarize_findings(sast_findings, "SAST") if sast_findings else "No SAST findings."
        sca_summary = PromptTemplates._summarize_findings(sca_findings, "SCA") if sca_findings else "No SCA findings."
        dast_summary = PromptTemplates._summarize_findings(dast_findings, "DAST") if dast_findings else "No DAST findings."
        
        return f"""Based on comprehensive security testing results (SAST, SCA, DAST), generate a unified application security policy:

=== STATIC CODE ANALYSIS (SAST) ===
{sast_summary}

=== DEPENDENCY ANALYSIS (SCA) ===
{sca_summary}

=== RUNTIME TESTING (DAST) ===
{dast_summary}

Generate a comprehensive, unified security policy that includes:

1. EXECUTIVE SUMMARY
   - Overall security posture
   - Critical risks requiring immediate attention
   - High-level remediation roadmap

2. RISK ASSESSMENT
   - Consolidated risk ranking across all scan types
   - Attack surface analysis
   - Business impact assessment

3. SECURITY CONTROLS (organized by NIST CSF functions)
   - Identify: Asset management, risk assessment
   - Protect: Access control, data security, protective technology
   - Detect: Continuous monitoring, detection processes
   - Respond: Incident response planning
   - Recover: Recovery planning, improvements

4. REMEDIATION ROADMAP
   - Phase 1 (Immediate - 0-30 days): Critical and high severity
   - Phase 2 (Short-term - 30-90 days): Medium severity
   - Phase 3 (Long-term - 90+ days): Low severity, technical debt

5. COMPLIANCE MAPPING
   - Map findings to NIST CSF categories
   - Map findings to ISO 27001 controls
   - Identify compliance gaps

6. ONGOING SECURITY PRACTICES
   - Secure development lifecycle integration
   - Continuous monitoring and scanning
   - Security training requirements
   - Dependency management process

Format as a well-structured JSON document with clear, actionable guidance."""

    @staticmethod
    def _summarize_findings(findings: List[Dict[str, Any]], scan_type: str) -> str:
        """Create a concise summary of findings for the prompt"""
        if not findings:
            return f"No {scan_type} findings detected."
        
        summary_lines = [f"Total {scan_type} Findings: {len(findings)}\n"]
        
        # Group by severity
        by_severity = {}
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN').upper()
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        # Summarize each severity level
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            if severity in by_severity:
                items = by_severity[severity]
                summary_lines.append(f"\n{severity} Severity ({len(items)} findings):")
                
                # Show first 5 of each severity
                for i, item in enumerate(items[:5], 1):
                    title = item.get('title', 'Unknown')
                    location = item.get('location', 'N/A')
                    summary_lines.append(f"  {i}. {title}")
                    summary_lines.append(f"     Location: {location}")
                    
                    if scan_type == "SCA":
                        cve = item.get('cve', 'N/A')
                        cvss = item.get('cvss', 'N/A')
                        summary_lines.append(f"     CVE: {cve}, CVSS: {cvss}")
                
                if len(items) > 5:
                    summary_lines.append(f"  ... and {len(items) - 5} more {severity} findings")
        
        return "\n".join(summary_lines)

    @staticmethod
    def get_refinement_prompt(initial_policy: str, feedback: str) -> str:
        """Generate prompt for refining/improving a policy based on feedback"""
        return f"""Review and refine the following security policy based on the feedback provided:

=== CURRENT POLICY ===
{initial_policy}

=== FEEDBACK/REQUIREMENTS ===
{feedback}

Generate an improved version of the policy that addresses the feedback while maintaining:
- Technical accuracy
- Actionable recommendations
- Alignment with security standards
- Clear structure and readability

Return the refined policy in the same JSON format."""