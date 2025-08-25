# validator_integration.py
import subprocess, os, tempfile
from pathlib import Path

# Rutas relativas al repositorio
ROOT = Path(__file__).resolve().parent
# Ajusta si tu JSON está en otro sitio
POLICY_CANDIDATES = [
    ROOT / "policy_oracle" / "policy_oracle.json",
    ROOT / "policy_oracle.json",
    ROOT / "policy_ip.json",
]
SCRIPT_CANDIDATES = [
    ROOT / "validator" / "src" / "validator.py",
    ROOT / "validator.py",
]

def _first_existing(paths):
    for p in paths:
        if p and Path(p).exists():
            return str(p)
    # último fallback aunque no exista (para que falle claro)
    return str(paths[0])

POLICY = _first_existing(POLICY_CANDIDATES)
SCRIPT = _first_existing(SCRIPT_CANDIDATES)

def validar_sql_por_ruta(ruta_sql: str, timeout=30):
    p = subprocess.run(["py", SCRIPT, POLICY, ruta_sql],
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def validar_sql_por_texto(sql_text: str, timeout=30):
    p = subprocess.run(["py", SCRIPT, POLICY, "-"],
                       input=sql_text, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def handle_mensaje(usuario_texto: str = None, adjunto_bytes: bytes = None, adjunto_nombre: str = None):
    if adjunto_bytes:
        ext = (os.path.splitext(adjunto_nombre or "")[1] or "").lower()
        if ext not in {".sql", ".pkb", ".pks", ".pkg", ".ddl", ".txt"}:
            return "Formato no soportado."
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
            f.write(adjunto_bytes)
            tmp = f.name
        try:
            code, out, err = validar_sql_por_ruta(tmp)
        finally:
            try: os.unlink(tmp)
            except: pass
    else:
        code, out, err = validar_sql_por_texto(usuario_texto or "")

    return out if out else f"Error:\n{err}"
