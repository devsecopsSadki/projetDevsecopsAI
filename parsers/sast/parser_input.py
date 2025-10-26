#!/usr/bin/env python3
"""
parser_input.py
Parses various SAST report formats (SARIF, SonarQube JSON, etc.) into a unified structure
"""

import json
from pathlib import Path
from typing import List, Dict, Any


def parse_report(report_path: str) -> List[Dict[str, Any]]:

    report_path = Path(report_path)

    if not report_path.exists():
        raise FileNotFoundError(f"Report not found: {report_path}")

    with open(report_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if 'issues' in data:
        return parse_sonarqube(data)
    elif '$schema' in data and 'sarif' in data.get('$schema', ''):
        return parse_sarif(data)
    elif 'runs' in data:
        return parse_sarif(data)
    else:
        return parse_generic(data)


def parse_sonarqube(data: Dict) -> List[Dict[str, Any]]:
    vulnerabilities = []

    for issue in data.get('issues', []):
        component = issue.get('component', '')
        file_path = component.split(':')[-1] if ':' in component else component
        line = issue.get('line', 0)
        location = f"{file_path}:{line}" if line else file_path

        vuln = {
            'type': 'SAST',
            'id': issue.get('key', 'N/A'),
            'title': issue.get('message', 'No title'),
            'description': issue.get('message', 'No description'),
            'severity': issue.get('severity', 'UNKNOWN'),
            'location': location,
            'file': file_path,
            'line': line,
            'rule': issue.get('rule', 'N/A'),
            'recommendation': f"Fix {issue.get('rule', 'this issue')} - Refer to SonarQube documentation"
        }
        vulnerabilities.append(vuln)

    return vulnerabilities


def parse_sarif(data: Dict) -> List[Dict[str, Any]]:
    vulnerabilities = []

    for run in data.get('runs', []):
        for result in run.get('results', []):
            locations = result.get('locations', [{}])
            if locations:
                physical = locations[0].get('physicalLocation', {})
                artifact = physical.get('artifactLocation', {})
                region = physical.get('region', {})

                file_path = artifact.get('uri', 'Unknown')
                line = region.get('startLine', 0)
                location = f"{file_path}:{line}" if line else file_path
            else:
                location = "Unknown"
                file_path = "Unknown"
                line = 0

            message = result.get('message', {})
            title = message.get('text', 'No title')

            rule_id = result.get('ruleId', 'N/A')

            vuln = {
                'type': 'SAST',
                'id': result.get('ruleId', 'N/A'),
                'title': title,
                'description': title,
                'severity': result.get('level', 'warning').upper(),
                'location': location,
                'file': file_path,
                'line': line,
                'rule': rule_id,
                'recommendation': f"Review and fix {rule_id}"
            }
            vulnerabilities.append(vuln)

    return vulnerabilities


def parse_generic(data: Dict) -> List[Dict[str, Any]]:
    vulnerabilities = []

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        vuln = {
                            'type': 'SAST',
                            'id': item.get('id', 'N/A'),
                            'title': item.get('title') or item.get('message', 'No title'),
                            'description': item.get('description') or item.get('message', 'No description'),
                            'severity': item.get('severity', 'UNKNOWN'),
                            'location': item.get('location') or item.get('file', 'Unknown'),
                            'recommendation': item.get('recommendation', 'Review and fix this issue')
                        }
                        vulnerabilities.append(vuln)

    return vulnerabilities


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python parser_input.py <report.json>")
        sys.exit(1)

    vulns = parse_report(sys.argv[1])
    print(f"Parsed {len(vulns)} vulnerabilities")

    for i, v in enumerate(vulns[:5], 1):
        print(f"\n{i}. {v['title']}")
        print(f"   Location: {v['location']}")
        print(f"   Severity: {v['severity']}")