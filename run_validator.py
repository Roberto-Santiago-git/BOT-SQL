from validator_integration import handle_mensaje
import os
p = os.path.join(os.environ["ATTACHMENTS_DIR"], r"INSERT TBL_REF_PROC 6.sql")
print(handle_mensaje(adjunto_bytes=open(p,"rb").read(),
                     adjunto_nombre="INSERT TBL_REF_PROC 6.sql"))
