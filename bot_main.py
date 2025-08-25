# bot_main.py
import argparse
from validator_integration import handle_mensaje

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--text", help="SQL pegado por el usuario")
    ap.add_argument("--file", help="Ruta a un .sql adjunto")
    args = ap.parse_args()

    if args.file:
        with open(args.file, "rb") as f:
            contenido = f.read()
        resp = handle_mensaje(adjunto_bytes=contenido, adjunto_nombre=args.file)
    else:
        resp = handle_mensaje(usuario_texto=args.text or "")

    print(resp)
