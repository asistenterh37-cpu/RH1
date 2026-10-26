"""VIGIA ALERTAS. Solo metadatos: autenticacion y alertas; sin imagenes ni camaras.
Render gratis: SQLite local temporal; sincronizacion desde PC restablece usuarios y alertas.
"""
import os, hmac, time, secrets, sqlite3, threading
from pathlib import Path
from datetime import timedelta
from flask import Flask, request, session, redirect, jsonify, render_template_string
from werkzeug.security import check_password_hash

app=Flask(__name__)
app.secret_key=os.getenv('SESSION_SECRET') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', PERMANENT_SESSION_LIFETIME=timedelta(hours=8),MAX_CONTENT_LENGTH=150000)
DATA=Path(os.getenv('VIGIA_DB_PATH','/tmp/vigia_alertas_publicas.sqlite3'))
LOCK=threading.RLock(); FAIL={}
STYLE='''<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>VIGÍA ALERTAS</title><style>*{box-sizing:border-box}body{background:#101b2b;color:#eff6ff;font:18px system-ui;margin:0;padding:16px}main{background:#23364e;border-radius:16px;padding:25px;max-width:720px;margin:6vh auto}input,button{width:100%;padding:14px;margin:8px 0;font-size:18px;border:0;border-radius:9px}button{background:#35b7a9;font-weight:700;cursor:pointer}article{background:#17283c;margin:12px 0;padding:15px;border-radius:10px}a{color:#8be7db}.muted{color:#c2d3e0}</style>'''
def db():
 c=sqlite3.connect(str(DATA),timeout=15);c.row_factory=sqlite3.Row
 c.execute('CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY,pin_hash TEXT,active INTEGER,version INTEGER)')
 c.execute('CREATE TABLE IF NOT EXISTS alerts(instance TEXT,source_id INTEGER,ts TEXT,camera INTEGER,event TEXT,detail TEXT,severity TEXT,PRIMARY KEY(instance,source_id))')
 c.commit();return c

def current_user():
 name=session.get('name')
 if not name:return None
 with LOCK:
  with db() as c:r=c.execute('SELECT * FROM users WHERE name=?',(name,)).fetchone()
 return r if r and r['active'] and r['version']==session.get('version') else None

@app.after_request
def security(r):
 r.headers['Cache-Control']='no-store';r.headers['X-Frame-Options']='DENY';r.headers['X-Content-Type-Options']='nosniff';r.headers['Content-Security-Policy']="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
 return r
@app.get('/health')
def health():return jsonify(status='online',service='VIGIA solo alertas')
@app.post('/ingest')
def ingest():
 token=os.getenv('VIGIA_SYNC_TOKEN','')
 if len(token)<32 or not hmac.compare_digest(request.headers.get('Authorization',''), 'Bearer '+token):return jsonify(error='token invalido o no configurado en Render'),403
 data=request.get_json(silent=True) or {};inst=str(data.get('instance',''));users=data.get('users',[]);alerts=data.get('alerts',[])
 if len(inst)!=32 or not isinstance(users,list) or not isinstance(alerts,list) or len(users)>250 or len(alerts)>100:return jsonify(error='datos invalidos'),400
 with LOCK:
  with db() as c:
   for u in users:
    if not isinstance(u,dict):continue
    name=str(u.get('name',''))[:80];ph=str(u.get('pin_hash',''))[:220]
    if not name or not ph.startswith('pbkdf2:sha256:'):continue
    c.execute('INSERT INTO users(name,pin_hash,active,version) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET pin_hash=excluded.pin_hash,active=excluded.active,version=excluded.version',(name,ph,int(bool(u.get('active'))),int(u.get('version',1))))
   for a in alerts:
    if not isinstance(a,dict):continue
    c.execute('INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?,?)',(inst,int(a['id']),str(a['time'])[:50],int(a['camera']),str(a['event'])[:150],str(a.get('detail',''))[:500],str(a.get('severity','info'))[:30]))
   c.commit()
 return jsonify(ok=True,users=len(users),alerts=len(alerts))
@app.route('/',methods=['GET','POST'])
def login():
 if current_user():return redirect('/alertas')
 err=''
 if request.method=='POST':
  name=request.form.get('name','').strip()[:80];pin=request.form.get('pin','');ip=request.remote_addr or 'unknown';now=time.monotonic()
  with LOCK:
   checks=[t for t in FAIL.get(ip,[]) if now-t<900];FAIL[ip]=checks
   blocked=len(checks)>=5
  if blocked:err='Demasiados intentos. Intentá más tarde.'
  else:
   with LOCK:
    with db() as c:u=c.execute('SELECT * FROM users WHERE name=?',(name,)).fetchone()
   valid=u is not None and bool(u['active']) and len(pin)==4 and pin.isdigit() and check_password_hash(u['pin_hash'],pin)
   if valid:
    with LOCK:FAIL.pop(ip,None)
    session.clear();session.permanent=True;session['name']=u['name'];session['version']=u['version'];return redirect('/alertas')
   with LOCK:FAIL.setdefault(ip,[]).append(now)
   err='Nombre o PIN incorrecto. Si el usuario existe solo en la PC, sincronizá VIGÍA con Render.'
 return render_template_string('<!doctype html><html lang="es">'+STYLE+'''<main><h1>🔔 VIGÍA ALERTAS</h1><p>Acceso autorizado. Solo alertas, sin cámaras.</p><form method="post"><input name="name" autocomplete="username" placeholder="Nombre" required maxlength="80"><input name="pin" type="password" autocomplete="current-password" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" placeholder="PIN de 4 dígitos" required><button>Ingresar</button></form><p>{{err}}</p></main></html>''',err=err)
@app.get('/alertas')
def alerts_page():
 u=current_user()
 if not u:return redirect('/')
 return render_template_string('<!doctype html><html lang="es">'+STYLE+'''<main><h1>🔔 VIGÍA ALERTAS</h1><p>Sesión: {{name}} · <a href="/salir">Salir</a></p><button onclick="sonido()">Activar sonido de alertas</button><p class="muted">Mostrando únicamente alertas. Para recibir sonido, mantené abierta esta página.</p><section id="items">Cargando alertas...</section></main><script>let last=null,audio=null;function sonido(){audio=new(window.AudioContext||window.webkitAudioContext)();audio.resume()}function beep(){if(!audio)return;const o=audio.createOscillator(),g=audio.createGain();o.connect(g);g.connect(audio.destination);g.gain.value=.09;o.frequency.value=800;o.start();o.stop(audio.currentTime+.2)}async function refresh(){try{let r=await fetch('/api/alertas',{cache:'no-store'});if(r.status===401){location.href='/';return}if(!r.ok)throw Error();let a=await r.json(),mx=a.length?a[0].key:null;if(last&&mx&&mx!==last)beep();last=mx;let d=document.getElementById('items');d.replaceChildren();if(!a.length){let p=document.createElement('article');p.textContent='No hay alertas registradas todavía.';d.append(p)}for(let x of a){let box=document.createElement('article'),h=document.createElement('h3'),p=document.createElement('p'),sub=document.createElement('small');h.textContent=x.event;sub.textContent=x.ts.replace('T',' ')+' · Cámara '+x.camera;p.textContent=x.detail||'';box.append(h,sub,p);d.append(box)}}catch(e){document.getElementById('items').textContent='Sin conexión con el servidor de alertas.'}}refresh();setInterval(refresh,6000)</script></html>''',name=u['name'])
@app.get('/api/alertas')
def api_alerts():
 if not current_user():return jsonify(error='no autorizado'),401
 with LOCK:
  with db() as c:rows=c.execute('SELECT instance,source_id,ts,camera,event,detail FROM alerts ORDER BY ts DESC,source_id DESC LIMIT 100').fetchall()
 return jsonify([{'key':r['instance']+':'+str(r['source_id']),'ts':r['ts'],'camera':r['camera'],'event':r['event'],'detail':r['detail']} for r in rows])
@app.get('/salir')
def salir():session.clear();return redirect('/')
