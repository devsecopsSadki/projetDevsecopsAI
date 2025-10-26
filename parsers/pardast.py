# parser_dast_llm.py
"""
Prépare un .txt lisible par LLM depuis un rapport DAST (OWASP ZAP, etc.).
Usage:
    python parser_dast_llm.py <report.json> <out.txt>
"""
import sys
from pathlib import Path
from parser_input import parse_report

MAX_CHARS_PER_ITEM = 5000

def format_dast(v, idx):
    title = v.get("title") or v.get("id") or "DAST finding"
    desc = (v.get("description") or "").strip()
    uri = v.get("location") or "N/A"
    rec = v.get("recommendation") or "Vérifier la configuration et corriger la vulnérabilité."
    text = (
        f"--- DAST Finding #{idx} ---\n"
        f"Vulnerability: {title}\n"
        f"Target (URL/Endpoint): {uri}\n"
        f"Description: {desc}\n"
        f"Recommendation: {rec}\n"
    )
    if len(text) > MAX_CHARS_PER_ITEM:
        text = text[:MAX_CHARS_PER_ITEM-12] + "\n[...truncated]\n"
    return text

def prepare_dast_text(report_path: str, out_path: str):
    vulns = parse_report(report_path)
    dast = [v for v in vulns if v.get("type") == "DAST"]
    header = "Résumé DAST — tests dynamiques (formaté pour LLM)\n\n"
    parts = [header]
    if not dast:
        parts.append("Aucune vulnérabilité DAST trouvée.\n")
    else:
        for i, v in enumerate(dast, 1):
            parts.append(format_dast(v, i))
            parts.append("\n")
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text("".join(parts), encoding="utf-8")
    print(f"[OK] DAST .txt généré: {out_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python parser_dast_llm.py <dast_report> <out.txt>")
        sys.exit(1)
    prepare_dast_text(sys.argv[1], sys.argv[2])
