
import os
import hmac
import time
import sqlite3
from datetime import datetime, timezone
from flask import Flask, request, jsonify, session, redirect, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "")
TOKEN = os.environ.get("SYNC_TOKEN", "")
DB = os.environ.get("DB_PATH", "/tmp/vigia_alertas.sqlite3")
intentos = {}

def conexion():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE IF NOT EXISTS usuarios
        (nombre TEXT PRIMARY KEY, pin_hash TEXT, activo INTEGER)""")
    db.execute("""CREATE TABLE IF NOT EXISTS alertas
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
         fecha TEXT, camara TEXT, tipo TEXT, detalle TEXT)""")
    db.commit()
    return db

def autorizado():
    recibido = request.headers.get("X-Vigia-Token", "")
    return bool(TOKEN) and hmac.compare_digest(recibido, TOKEN)

@app.get("/health")
def health():
    return jsonify(estado="activo", servicio="VIGIA ALERTAS")

@app.post("/api/usuarios")
def guardar_usuario():
    if not autorizado():
        return jsonify(error="No autorizado"), 401
    datos = request.get_json(silent=True) or {}
    nombre = str(datos.get("nombre", "")).strip()[:100]
    pin = str(datos.get("pin", ""))
    activo = bool(datos.get("activo", True))
    if not nombre or not (pin.isdigit() and len(pin) == 4):
        return jsonify(error="Nombre y PIN de 4 digitos requeridos"), 400
    db = conexion()
    db.execute("INSERT OR REPLACE INTO usuarios VALUES (?, ?, ?)",
               (nombre, generate_password_hash(pin), int(activo)))
    db.commit()
    db.close()
    return jsonify(ok=True)

@app.post("/api/revocar")
def revocar():
    if not autorizado():
        return jsonify(error="No autorizado"), 401
    nombre = str((request.get_json(silent=True) or {}).get("nombre", ""))
    db = conexion()
    db.execute("UPDATE usuarios SET activo=0 WHERE nombre=?", (nombre,))
    db.commit()
    db.close()
    return jsonify(ok=True)

@app.post("/api/alertas")
def recibir_alerta():
    if not autorizado():
        return jsonify(error="No autorizado"), 401
    datos = request.get_json(silent=True) or {}
    camara = str(datos.get("camara", ""))[:100]
    tipo = str(datos.get("tipo", "Alerta"))[:100]
    detalle = str(datos.get("detalle", ""))[:500]
    db = conexion()
    db.execute("INSERT INTO alertas(fecha,camara,tipo,detalle) VALUES(?,?,?,?)",
               (datetime.now(timezone.utc).isoformat(), camara, tipo, detalle))
    db.commit()
    db.close()
    return jsonify(ok=True), 201

ESTILO = """
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VIGIA ALERTAS</title>
<style>
body{font-family:Arial;background:#101b2b;color:white;margin:0;padding:24px}
main{max-width:750px;margin:45px auto;background:#23354c;padding:28px;border-radius:16px}
h1{margin-top:0}
input,button{display:block;width:100%;padding:14px;margin:12px 0;
box-sizing:border-box;border:0;border-radius:8px;font-size:17px}
button{background:#2fb7aa;cursor:pointer;font-weight:bold}
.alerta{background:#142438;padding:16px;border-radius:10px;margin:12px 0}
small{color:#b8c9db}
</style>
"""

@app.route("/", methods=["GET", "POST"])
def inicio():
    if session.get("usuario"):
        return redirect("/alertas")
    error = ""
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        pin = request.form.get("pin", "")
        ip = request.remote_addr or "desconocida"
        ahora = time.time()
        registro = intentos.get(ip, [])
        registro = [t for t in registro if ahora - t < 900]
        if len(registro) >= 5:
            error = "Demasiados intentos. Proba nuevamente en 15 minutos."
        else:
            db = conexion()
            usuario = db.execute(
                "SELECT * FROM usuarios WHERE nombre=?", (nombre,)
            ).fetchone()
            db.close()
            if usuario and usuario["activo"] and check_password_hash(
                    usuario["pin_hash"], pin):
                intentos.pop(ip, None)
                session.clear()
                session["usuario"] = nombre
                return redirect("/alertas")
            registro.append(ahora)
            intentos[ip] = registro
            error = "Nombre o PIN incorrecto."
    return render_template_string(ESTILO + """
    <main><h1>🔔 VIGÍA ALERTAS</h1>
    <p>Acceso autorizado. Solo alertas, sin cámaras.</p>
    <form method="post">
      <input name="nombre" placeholder="Nombre" required autocomplete="username">
      <input name="pin" type="password" inputmode="numeric"
             maxlength="4" placeholder="PIN de 4 dígitos" required>
      <button>Ingresar</button>
    </form><p>{{error}}</p></main>
    """, error=error)

@app.get("/alertas")
def mostrar_alertas():
    if not session.get("usuario"):
        return redirect("/")
    db = conexion()
    usuario = db.execute("SELECT activo FROM usuarios WHERE nombre=?",
                         (session["usuario"],)).fetchone()
    db.close()
    if not usuario or not usuario["activo"]:
        session.clear()
        return redirect("/")
    return render_template_string(ESTILO + """
    <main><h1>🔔 VIGÍA ALERTAS</h1>
    <p>Usuario: {{nombre}} · <a href="/salir" style="color:#2fb7aa">Salir</a></p>
    <button onclick="activar()">Activar sonido</button>
    <div id="lista">Consultando alertas...</div></main>
    <script>
    let audio=null, ultimo=0, iniciado=false;
    function activar(){
      audio=new (window.AudioContext||window.webkitAudioContext)();
      audio.resume();
    }
    function sonar(){
      if(!audio)return;
      const o=audio.createOscillator(),g=audio.createGain();
      o.connect(g);g.connect(audio.destination);
      o.frequency.value=880;g.gain.value=0.12;
      o.start();o.stop(audio.currentTime+0.2);
    }
    function limpiar(n){
      return String(n??"").replace(/[&<>"']/g,c=>
        ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
    }
    async function actualizar(){
      try{
        const r=await fetch("/api/mis-alertas",{cache:"no-store"});
        if(r.status===401){location.href="/";return}
        if(!r.ok)throw Error("Sin conexión");
        const a=await r.json();
        const nuevo=a.length?a[0].id:0;
        if(iniciado&&nuevo>ultimo)sonar();
        ultimo=nuevo;iniciado=true;
        document.getElementById("lista").innerHTML=a.length?
          a.map(x=>`<div class="alerta"><b>${limpiar(x.tipo)}</b>
          <p>${limpiar(x.detalle)}</p>
          <small>${limpiar(x.camara)} · ${limpiar(x.fecha)}</small></div>`).join(""):
          "<p>No hay alertas registradas todavía.</p>";
      }catch(e){
        document.getElementById("lista").textContent=
          "No se pudo conectar al servidor.";
      }
    }
    actualizar();setInterval(actualizar,5000);
    </script>""", nombre=session["usuario"])

@app.get("/api/mis-alertas")
def mis_alertas():
    if not session.get("usuario"):
        return jsonify(error="No autorizado"), 401
    db = conexion()
    usuario = db.execute("SELECT activo FROM usuarios WHERE nombre=?",
                         (session["usuario"],)).fetchone()
    if not usuario or not usuario["activo"]:
        db.close()
        session.clear()
        return jsonify(error="Acceso revocado"), 401
    datos = db.execute("SELECT * FROM alertas ORDER BY id DESC LIMIT 100").fetchall()
    resultado = [dict(x) for x in datos]
    db.close()
    return jsonify(resultado)

@app.get("/salir")
def salir():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
