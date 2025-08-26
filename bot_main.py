import os, glob, subprocess, tempfile

POLICY_PATH = "policy_oracle"  # ajusta si cambiaste la ruta/nombre

def run_validator(files):
    if not os.path.isfile(POLICY_PATH):
        return f"⚠️ Policy no encontrada: {POLICY_PATH}"
    if not files:
        return "✅ No hay archivos a validar."
    cmd = ["python", "validator/src/validator.py", POLICY_PATH] + files
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = (p.stdout or "") + (("\n"+p.stderr) if p.stderr else "")
    return ("✅ CUMPLE\n\n" + out.strip()) if p.returncode == 0 else ("❌ NO CUMPLE\n\n" + out.strip())

def handle_validate_message(text:str, attachments:list):
    # 1) Si hay adjuntos, valida solo esos
    saved = []
    for att in attachments or []:
        # att: bytes + filename según tu bot (ajusta a tu SDK)
        content = att["bytes"]
        name = att["filename"]
        if not name.lower().endswith((".sql",".pkb",".pks",".pls",".txt")):
            continue
        fd, path = tempfile.mkstemp(suffix=os.path.splitext(name)[1])
        os.close(fd)
        with open(path, "wb") as f: f.write(content)
        saved.append(path)

    if saved:
        res = run_validator(saved)
        # limpia tmp
        for pth in saved:
            try: os.remove(pth)
            except: pass
        return res

    # 2) Sin adjuntos: valida todo el repo o una carpeta
    files = [f for f in glob.glob("**/*", recursive=True)
             if f.lower().endswith((".sql",".pkb",".pks",".pls",".txt"))]
    return run_validator(files)

# Ejemplo de uso en tu handler principal:
# if user_message.startswith(("validar","valida","/validate")) or attachments:
#     reply = handle_validate_message(user_message, attachments)
#     send_message(reply)
