# parser_sca_llm.py
"""
Prépare un .txt lisible par LLM depuis un rapport SCA (dépendances).
Usage:
    python parser_sca_llm.py <report.json> <out.txt>
"""
import sys
from pathlib import Path
from parser_input import parse_report

MAX_CHARS_PER_ITEM = 5000

def format_sca(v, idx):
    pkg_loc = v.get("location") or "package@version"
    title = v.get("title") or pkg_loc
    desc = (v.get("description") or "").strip()
    cve = v.get("cve") or "N/A"
    cvss = v.get("cvss")
    cvss_str = str(cvss) if cvss is not None else "N/A"
    rec = v.get("recommendation") or "Mettre à jour le package ou appliquer le correctif recommandé."
    text = (
        f"--- Dependency Finding #{idx} ---\n"
        f"Package: {pkg_loc}\n"
        f"Title: {title}\n"
        f"CVE: {cve}\n"
        f"CVSS: {cvss_str}\n"
        f"Description: {desc}\n"
        f"Recommendation: {rec}\n"
    )
    if len(text) > MAX_CHARS_PER_ITEM:
        text = text[:MAX_CHARS_PER_ITEM-12] + "\n[...truncated]\n"
    return text

def prepare_sca_text(report_path: str, out_path: str):
    vulns = parse_report(report_path)
    sca = [v for v in vulns if v.get("type") == "SCA"]
    header = "Résumé SCA — vulnérabilités de dépendances (formaté pour LLM)\n\n"
    parts = [header]
    if not sca:
        parts.append("Aucune vulnérabilité SCA trouvée.\n")
    else:
        for i, v in enumerate(sca, 1):
            parts.append(format_sca(v, i))
            parts.append("\n")
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text("".join(parts), encoding="utf-8")
    print(f"[OK] SCA .txt généré: {out_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python parser_sca_llm.py <sca_report> <out.txt>")
        sys.exit(1)
    prepare_sca_text(sys.argv[1], sys.argv[2])
