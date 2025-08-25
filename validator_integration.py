# validator_integration.py
import subprocess, os, tempfile

POLICY = r"E:\Users\10055372\Downloads\validator_policies\policy_oracle.json"
SCRIPT = r"E:\Users\10055372\Downloads\validator.py"

def validar_sql_por_ruta(ruta_sql:str, timeout=30):
    p = subprocess.run(["py", SCRIPT, POLICY, ruta_sql],
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def validar_sql_por_texto(sql_text:str, timeout=30):
    p = subprocess.run(["py", SCRIPT, POLICY, "-"],
                       input=sql_text, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def handle_mensaje(usuario_texto:str=None, adjunto_bytes:bytes=None, adjunto_nombre:str=None):
    if adjunto_bytes:
        ext = os.path.splitext(adjunto_nombre or "")[1].lower()
        if ext not in {".sql",".pkb",".pks",".pkg",".ddl",".txt"}:
            return "Formato no soportado."
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
            f.write(adjunto_bytes)
            tmp = f.name
        code, out, err = validar_sql_por_ruta(tmp)
        os.unlink(tmp)
    else:
        code, out, err = validar_sql_por_texto(usuario_texto or "")
    return out if out else f"Error:\n{err}"
