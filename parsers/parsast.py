# parser_sast_llm.py
"""
Prépare un .txt lisible par LLM depuis un rapport SAST (SARIF/JSON).
Usage:
    python parser_sast_llm.py <report.json> <out.txt>
"""
import sys
from pathlib import Path
from parser_input import parse_report

MAX_CHARS_PER_ITEM = 5000

def format_sast(v, idx):
    title = v.get("title") or v.get("id") or "SAST finding"
    desc = (v.get("description") or "").strip()
    loc = v.get("location") or "N/A"
    rec = v.get("recommendation") or "Aucune recommandation fournie."
    text = (
        f"--- Finding #{idx} ---\n"
        f"Titre: {title}\n"
        f"Emplacement: {loc}\n"
        f"Description: {desc}\n"
        f"Recommandation: {rec}\n"
    )
    if len(text) > MAX_CHARS_PER_ITEM:
        text = text[:MAX_CHARS_PER_ITEM-12] + "\n[...truncated]\n"
    return text

def prepare_sast_text(report_path: str, out_path: str):
    vulns = parse_report(report_path)
    sast = [v for v in vulns if v.get("type") == "SAST"]
    header = "Résumé SAST — formaté pour LLM\nChaque entrée: Title, Location, Description, Recommendation\n\n"
    parts = [header]
    if not sast:
        parts.append("Aucune vulnérabilité SAST trouvée.\n")
    else:
        for i, v in enumerate(sast, 1):
            parts.append(format_sast(v, i))
            parts.append("\n")
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text("".join(parts), encoding="utf-8")
    print(f"[OK] SAST .txt généré: {out_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python parser_sast_llm.py <sast_report> <out.txt>")
        sys.exit(1)
    prepare_sast_text(sys.argv[1], sys.argv[2])
