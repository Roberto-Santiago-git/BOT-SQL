#!/usr/bin/env python3
# validator.py — reporte de estándares Oracle (solo reporta, NO corrige)

import sys, os, re, json, pathlib
from typing import List, Dict, Any

# ---------- Utilidades ----------

def read_text_utf8_nobom(path: str) -> str:
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        return f.read()

def file_exists(path: str) -> bool:
    try:
        return pathlib.Path(path).exists()
    except Exception:
        return False

def line_no(text: str, idx: int) -> int:
    return text.count("\n", 0, max(0, idx)) + 1

# ---------- Carga de policy ----------

def load_policy(policy_path: str) -> Dict[str, Any]:
    raw = read_text_utf8_nobom(policy_path)
    return json.loads(raw)

# ---------- Reglas ----------

def check_insert_columns(text: str, require: bool) -> List[Dict[str, Any]]:
    """
    INSERT INTO <obj> (...)  -> exige lista de columnas.
    """
    if not require:
        return []
    issues = []
    for m in re.finditer(r"\binsert\s+into\s+([\"A-Z0-9_.]+)", text, flags=re.I):
        j = m.end()
        while j < len(text) and text[j] in " \t\r\n":
            j += 1
        if j >= len(text) or text[j] != "(":
            ln1 = line_no(text, m.start())
            tail = text[m.start(): m.start() + 400]
            mv = re.search(r"\b(values|select)\b", tail, flags=re.I)
            ln2 = line_no(text, m.start() + (mv.end() if mv else 0))
            issues.append({
                "code": "INSERT-COLS",
                "desc": "INSERT debe declarar columnas destino",
                "ls": ln1, "le": ln2 if ln2 >= ln1 else ln1
            })
    return issues

def check_exception_prefix(text: str, prefix: str) -> List[Dict[str, Any]]:
    """
    Excepciones declaradas deben iniciar con un prefijo (p.ej. EXC_).
    """
    if not prefix:
        return []
    issues = []
    for m in re.finditer(r"^\s*([A-Z][A-Z0-9_]*)\s+EXCEPTION\s*;", text, flags=re.M):
        name = m.group(1)
        if not name.startswith(prefix):
            issues.append({
                "code": "EXC-PREFIX",
                "desc": f"Excepciones deben iniciar con {prefix}",
                "ls": line_no(text, m.start()),
                "le": line_no(text, m.start())
            })
    return issues

def check_select_star(text: str, forbid: bool) -> List[Dict[str, Any]]:
    """
    Prohíbe SELECT *.
    """
    if not forbid:
        return []
    issues = []
    for m in re.finditer(r"\bselect\s*(?:/\*.*?\*/\s*)*\*\s*from\b", text, flags=re.I|re.S):
        ln = line_no(text, m.start())
        issues.append({
            "code": "SELECT-STAR",
            "desc": "Evitar SELECT *; lista columnas explícitas",
            "ls": ln, "le": ln
        })
    return issues

def check_forbidden_keywords(text: str, keywords: List[str]) -> List[Dict[str, Any]]:
    """
    Palabras clave prohibidas (simples).
    """
    issues = []
    for kw in (keywords or []):
        kw = kw.strip()
        if not kw:
            continue
        pat = r"\b" + re.escape(kw) + r"\b"
        for m in re.finditer(pat, text, flags=re.I):
            ln = line_no(text, m.start())
            issues.append({
                "code": "KW-FORBIDDEN",
                "desc": f"Keyword prohibido: {kw}",
                "ls": ln, "le": ln
            })
    return issues

def check_bitacora(text: str, cfg: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Exige llamadas a bitácora corporativa: start / finish_ok / finish_err.
    """
    if not cfg:
        return []
    reqs = [
        ("BITACORA", cfg.get("start", "")),
        ("BITACORA", cfg.get("finish_ok", "")),
        ("BITACORA", cfg.get("finish_err", "")),
    ]
    issues = []
    for code, needle in reqs:
        if needle and re.search(re.escape(needle), text, flags=re.I) is None:
            issues.append({
                "code": code,
                "desc": f"Falta llamada requerida: {needle}",
                "ls": 1, "le": 1
            })
    return issues

def check_order_by_position(text: str, forbid: bool) -> List[Dict[str, Any]]:
    if not forbid:
        return []
    issues = []
    for m in re.finditer(r"\border\s+by\s+\d+(?:\s*,\s*\d+)*\b", text, flags=re.I):
        ln = line_no(text, m.start())
        issues.append({
            "code": "ORD-BY-NUM",
            "desc": "Evita ORDER BY por posición; usa columnas explícitas",
            "ls": ln, "le": ln
        })
    return issues

def check_update_delete_where(text: str, enforce_update: bool, enforce_delete: bool) -> List[Dict[str, Any]]:
    issues = []
    if enforce_update:
        for m in re.finditer(r"\bupdate\b[\s\S]*?;", text, flags=re.I):
            frag = text[m.start():m.end()]
            if re.search(r"\bwhere\b", frag, flags=re.I) is None:
                ln = line_no(text, m.start())
                issues.append({
                    "code": "UPDATE-WHERE",
                    "desc": "UPDATE sin WHERE",
                    "ls": ln, "le": ln
                })
    if enforce_delete:
        for m in re.finditer(r"\bdelete\b[\s\S]*?;", text, flags=re.I):
            frag = text[m.start():m.end()]
            if re.search(r"\bwhere\b", frag, flags=re.I) is None and re.search(r"\btruncate\b", frag, flags=re.I) is None:
                ln = line_no(text, m.start())
                issues.append({
                    "code": "DELETE-WHERE",
                    "desc": "DELETE sin WHERE",
                    "ls": ln, "le": ln
                })
    return issues

# ---------- Reporte ----------

def emit_report(all_issues: Dict[str, List[Dict[str, Any]]], policy: Dict[str, Any]) -> int:
    total = sum(len(v) for v in all_issues.values())
    prefix = (policy.get("output") or {}).get("prefix", "Veredicto: ")
    if total == 0:
        print(prefix + "CUMPLE")
        return 0

    print(f"{prefix}NO CUMPLE [{total} hallazgos]")

    doc_refs = policy.get("doc_refs", {}) or {}
    notes = policy.get("remediation_notes", {}) or {}

    for fname, items in all_issues.items():
        print(f"\n[{fname}]")
        for it in items:
            rng = f"L{it['ls']}" + (f"–{it['le']}" if it['le'] != it['ls'] else "")
            print(f"- Ubicación: {rng}")
            print(f"  Regla: {it['code']} — {it['desc']}")
            ref = doc_refs.get(it["code"]) or doc_refs.get(it["code"].split(":")[0])
            if isinstance(ref, dict):
                page = ref.get("page")
                section = ref.get("section")
                if page or section:
                    print(f"  Sustento: Estándares Oracle, p.{page or '?'} (\"{section or ''}\")")
            note = notes.get(it["code"]) or notes.get(it["code"].split(":")[0])
            if note:
                print(f"  Cómo corregir: {note}")
    return 1

# ---------- MAIN ----------

def main():
    if len(sys.argv) < 3:
        print("Veredicto: NO CUMPLE")
        print("- [error] Uso: validator.py <policy.json> <archivo1.sql> [archivo2.sql ...]")
        sys.exit(2)

    policy_path = sys.argv[1]
    targets = sys.argv[2:]

    if not file_exists(policy_path):
        print("Veredicto: NO CUMPLE")
        print(f"- [error] Policy no encontrada: {policy_path}")
        sys.exit(2)

    try:
        policy = load_policy(policy_path)
    except Exception as e:
        print("Veredicto: NO CUMPLE")
        print(f"- [error] Policy inválida: {e}")
        sys.exit(2)

    # Exclusiones opcionales por regex
    skip_patterns = policy.get("skip_patterns", [])
    skip_res = [re.compile(p, flags=re.I) for p in skip_patterns] if skip_patterns else []

    all_issues: Dict[str, List[Dict[str, Any]]] = {}

    for target in targets:
        if not file_exists(target):
            print(f"- [warn] archivo no encontrado: {target}")
            continue

        # saltar por patrón si aplica
        if skip_res and any(r.search(target) for r in skip_res):
            continue

        try:
            text = read_text_utf8_nobom(target)
        except Exception as e:
            print(f"- [warn] no se pudo leer {target}: {e}")
            continue

        issues: List[Dict[str, Any]] = []

        # Parámetros de policy (opcionales)
        require_insert_cols = policy.get("require_insert_column_list", False)
        exc_prefix          = policy.get("require_exception_prefix", "")
        forbid_star         = policy.get("forbid_select_star", False)
        forbid_kws          = policy.get("forbid_keywords") or []
        bitacora_cfg        = policy.get("require_bitacora_calls", {}) or {}
        forbid_ord_pos      = policy.get("forbid_order_by_position", False)
        enforce_upd_where   = policy.get("require_where_update", False)
        enforce_del_where   = policy.get("require_where_delete", False)

        # Aplicar reglas
        issues += check_insert_columns(text, require_insert_cols)
        issues += check_exception_prefix(text, exc_prefix)
        issues += check_select_star(text, forbid_star)
        if forbid_kws:
            issues += check_forbidden_keywords(text, forbid_kws)
        issues += check_bitacora(text, bitacora_cfg)
        issues += check_order_by_position(text, forbid_ord_pos)
        issues += check_update_delete_where(text, enforce_upd_where, enforce_del_where)

        if issues:
            all_issues[os.path.basename(target)] = issues

    exit_code = emit_report(all_issues, policy)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()

