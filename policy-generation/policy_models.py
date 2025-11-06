from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class PolicyMetadata(BaseModel):
    """Policy metadata and governance information"""
    policy_id: str  # e.g., "POL-SAST-2024-001"
    policy_name: str
    status: str  # Draft, Active, Under Review, Archived
    created_date: datetime
    last_updated: datetime
    author: str


class PolicyStatement(BaseModel):
    """Core policy statement and purpose"""
    purpose: str  # Why this policy exists
    description: str  # Detailed policy description
    applicability: str  # Who/what this policy applies to
    enforcement: str  # How policy will be enforced
    exceptions: Optional[str] = None  # Any exceptions to the policy


class RiskAssessment(BaseModel):
    """ISO 27001 inspired risk assessment"""
    overall_risk_level: str  # Critical, High, Medium, Low
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    business_impact: str
    likelihood: str  # High, Medium, Low


class SecurityControl(BaseModel):
    """Hybrid NIST + ISO control"""
    control_id: str
    nist_function: str  # Identify, Protect, Detect, Respond, Recover
    iso_domain: str  # Access Control, Cryptography, Physical Security, etc.
    title: str
    description: str
    implementation_steps: List[str]


class RemediationAction(BaseModel):
    """Prioritized remediation with timeline"""
    priority: str  # P0 (Critical), P1 (High), P2 (Medium), P3 (Low)
    title: str
    affected_assets: List[str]
    timeline: str  # "Immediate (0-7 days)", "Short-term (7-30 days)", etc.
    owner: str  # Team/role responsible
    success_criteria: str


class ComplianceMapping(BaseModel):
    """Map to both frameworks"""
    nist_csf_categories: List[str]  # e.g., ["PR.AC-1", "DE.CM-1"]
    iso27001_controls: List[str]  # e.g., ["A.9.2.1", "A.12.6.1"]


class SecurityPolicy(BaseModel):
    """Hybrid NIST CSF + ISO 27001 Security Policy"""
    
    # Policy Metadata (Governance)
    metadata: PolicyMetadata
    
    # Policy Statement (Core Purpose)
    policy_statement: PolicyStatement
    
    # Policy Details
    policy_type: str
    
    # Executive Overview (ISO 27001 style)
    executive_summary: str
    scope: str
    objectives: List[str]
    
    # Risk Assessment (ISO 27001 Annex A inspired)
    risk_assessment: RiskAssessment
    
    # Findings Summary
    total_findings: int
    vulnerability_categories: List[str]  # Top 5-10 vuln types
    
    # Security Controls (NIST CSF Functions + ISO Domains)
    security_controls: List[SecurityControl]
    
    # Remediation Roadmap (Prioritized)
    remediation_actions: List[RemediationAction]
    
    # Compliance Mapping
    compliance_mapping: ComplianceMapping
    
    # Continuous Improvement (NIST Recover + ISO PDCA)
    monitoring_requirements: List[str]
    review_schedule: str
    
    def __init__(self, **data):
        super().__init__(**data)