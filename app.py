import os, sqlite3, secrets, csv, io, json
from datetime import datetime, date
from functools import wraps
from flask import Flask, request, session, redirect, url_for, flash, render_template, Response, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '')
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE','0')=='1', MAX_CONTENT_LENGTH=12*1024*1024)
DB = os.environ.get('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'saba.sqlite3'))
ROLES = {'admin':'Administrateur', 'coordinateur':'Coordinateur général', 'securite':'Responsable sécurité', 'dga':'DGA', 'controleur':'Contrôleur', 'lecture':'Consultation'}
APPROVERS = ('coordinateur','securite','dga')

def conn():
    c=sqlite3.connect(DB, timeout=20)
    c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('PRAGMA journal_mode=WAL')
    return c

def init_db():
    os.makedirs(os.path.dirname(os.path.abspath(DB)), exist_ok=True)
    with conn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS zones(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, responsable TEXT DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE, name TEXT NOT NULL, quartier TEXT DEFAULT '', responsable TEXT DEFAULT '', client TEXT DEFAULT '', situation TEXT DEFAULT 'ACTIF', observations TEXT DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS visits(id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id), visit_date TEXT NOT NULL, controleur TEXT NOT NULL, effected INTEGER NOT NULL DEFAULT 1, observations TEXT DEFAULT '', created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'EN ATTENTE', approved_by INTEGER REFERENCES users(id), approved_at TEXT, approval_note TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS visit_messages(id INTEGER PRIMARY KEY, visit_id INTEGER NOT NULL REFERENCES visits(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id), message TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS visit_messages_visit_idx ON visit_messages(visit_id);
        CREATE INDEX IF NOT EXISTS visits_date_idx ON visits(visit_date);
        CREATE INDEX IF NOT EXISTS visits_site_idx ON visits(site_id);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, entity TEXT, entity_id INTEGER, created_at TEXT, details TEXT);
        CREATE TABLE IF NOT EXISTS notifications(
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            actor_id INTEGER REFERENCES users(id),
            visit_id INTEGER NOT NULL REFERENCES visits(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read_at TEXT
        );
        CREATE INDEX IF NOT EXISTS notifications_user_unread_idx ON notifications(user_id,read_at,id);
        CREATE INDEX IF NOT EXISTS notifications_visit_idx ON notifications(visit_id);

        ''')
        existing={r['name'] for r in c.execute('PRAGMA table_info(sites)')}
        if 'zone_id' not in existing:c.execute('ALTER TABLE sites ADD COLUMN zone_id INTEGER REFERENCES zones(id)')

def all_zones():return many('SELECT id,name FROM zones ORDER BY name')

def selected_zone(value):
    if not value:return None
    if not str(value).isdigit() or not one('SELECT id FROM zones WHERE id=?',(value,)):abort(400,'Zone invalide')
    return int(value)

def log(c,action,entity,entity_id,details=''):
    c.execute('INSERT INTO audit(user_id,action,entity,entity_id,created_at,details) VALUES(?,?,?,?,?,?)', (session.get('uid'),action,entity,entity_id,datetime.now().isoformat(timespec='seconds'),details))

def notify(c, visit_id, event_type, title, message, creator_id=None, include_responsables=True):
    """Enregistre des notifications pour les utilisateurs actifs concernés.
    La fonction est appelée dans la même transaction que l'événement d'origine.
    """
    actor_id=session.get('uid')
    recipients=set()
    if creator_id is not None:
        recipients.add(creator_id)
    if include_responsables:
        recipients.update(r['id'] for r in c.execute(
            "SELECT id FROM users WHERE active=1 AND role IN ('admin','coordinateur','securite','dga')"))
    if actor_id is not None:
        recipients.discard(actor_id)
    now=datetime.now().isoformat(timespec='seconds')
    for recipient_id in recipients:
        # Ne pas notifier les anciens utilisateurs inactifs.
        active=c.execute('SELECT 1 FROM users WHERE id=? AND active=1',(recipient_id,)).fetchone()
        if active:
            c.execute('''INSERT INTO notifications(user_id,actor_id,visit_id,event_type,title,message,created_at)
                         VALUES(?,?,?,?,?,?,?)''',
                      (recipient_id,actor_id,visit_id,event_type,title,message,now))

def unread_notifications(uid):
    return one('SELECT COUNT(*) AS n FROM notifications WHERE user_id=? AND read_at IS NULL',(uid,))['n']

def one(query,args=()):
    with conn() as c:return c.execute(query,args).fetchone()

def many(query,args=()):
    with conn() as c:return c.execute(query,args).fetchall()

def current():
    if not session.get('uid'):return None
    return one('SELECT id,username,role FROM users WHERE id=? AND active=1',(session['uid'],))

def login_required(fn):
    @wraps(fn)
    def wrapper(*args,**kwargs):
        if not current():return redirect(url_for('login'))
        return fn(*args,**kwargs)
    return wrapper

def role_required(*roles):
    def decorate(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args,**kwargs):
            if current()['role'] not in roles:abort(403)
            return fn(*args,**kwargs)
        return wrapper
    return decorate

def token():
    if 'csrf' not in session:session['csrf']=secrets.token_urlsafe(24)
    return session['csrf']

@app.before_request
def check_csrf():
    if request.method=='POST' and not secrets.compare_digest(request.form.get('csrf',''),token()):abort(400,'Jeton de sécurité invalide. Actualisez la page.')

@app.context_processor
def context():
    me=current()
    return {'me':me,'csrf_token':token,'roles':ROLES,'today':date.today().isoformat(),
            'unread_count': unread_notifications(me['id']) if me else 0}

@app.route('/notifications')
@login_required
def notifications_page():
    rows=many('''SELECT n.*,u.username actor_name,s.code,s.name site_name
                 FROM notifications n
                 LEFT JOIN users u ON u.id=n.actor_id
                 JOIN visits v ON v.id=n.visit_id
                 JOIN sites s ON s.id=v.site_id
                 WHERE n.user_id=? ORDER BY n.id DESC LIMIT 100''',(current()['id'],))
    return render_template('notifications.html',notifications=rows)

@app.route('/notifications/count')
@login_required
def notifications_count():
    response=jsonify({'unread':unread_notifications(current()['id'])})
    response.headers['Cache-Control']='no-store'
    return response

@app.post('/notifications/<int:nid>/read')
@login_required
def notification_read(nid):
    with conn() as c:
        row=c.execute('SELECT visit_id FROM notifications WHERE id=? AND user_id=?',(nid,current()['id'])).fetchone()
        if not row:abort(404)
        c.execute('UPDATE notifications SET read_at=COALESCE(read_at,?) WHERE id=? AND user_id=?',
                  (datetime.now().isoformat(timespec='seconds'),nid,current()['id']))
    return redirect(url_for('visit_detail',vid=row['visit_id']))

@app.post('/notifications/read-all')
@login_required
def notifications_read_all():
    with conn() as c:
        c.execute('UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL',
                  (datetime.now().isoformat(timespec='seconds'),current()['id']))
    flash('Toutes les notifications ont été marquées comme lues.','success')
    return redirect(url_for('notifications_page'))

@app.route('/setup',methods=['GET','POST'])
def setup():
    if one('SELECT COUNT(*) AS n FROM users')['n']>0:abort(404)
    if request.method=='POST':
        if request.form.get('setup_key')!=os.environ.get('SETUP_KEY') or not os.environ.get('SETUP_KEY'):
            flash('Code d’installation incorrect ou non configuré.','danger')
        elif len(request.form.get('password',''))<12:flash('Le mot de passe doit comporter au moins 12 caractères.','danger')
        else:
            with conn() as c:c.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',(request.form['username'].strip(),generate_password_hash(request.form['password']),'admin'))
            flash('Compte administrateur créé. Connectez-vous.','success');return redirect(url_for('login'))
    return render_template('setup.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if one('SELECT COUNT(*) AS n FROM users')['n']==0:return redirect(url_for('setup'))
    if request.method=='POST':
        u=one('SELECT * FROM users WHERE username=? AND active=1',(request.form.get('username','').strip(),))
        if u and check_password_hash(u['password_hash'],request.form.get('password','')):
            session.clear();session['uid']=u['id'];token();return redirect(url_for('dashboard'))
        flash('Identifiants incorrects.','danger')
    return render_template('login.html')

@app.post('/logout')
@login_required
def logout():session.clear();return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    year=request.args.get('year',str(date.today().year))
    if not year.isdigit() or len(year)!=4:year=str(date.today().year)
    stats=one('''SELECT (SELECT COUNT(*) FROM sites) sites,(SELECT COUNT(*) FROM visits WHERE substr(visit_date,1,4)=?) total,(SELECT COUNT(*) FROM visits WHERE substr(visit_date,1,4)=? AND status='VALIDÉE') validated,(SELECT COUNT(*) FROM visits WHERE status='EN ATTENTE') pending,(SELECT COUNT(DISTINCT site_id) FROM visits WHERE substr(visit_date,1,4)=? AND status='VALIDÉE') covered''',(year,year,year))
    monthly=many('''SELECT substr(visit_date,6,2) month, COUNT(*) total, SUM(CASE WHEN status='VALIDÉE' THEN 1 ELSE 0 END) valid FROM visits WHERE substr(visit_date,1,4)=? GROUP BY month ORDER BY month''',(year,))
    recent=many('''SELECT v.*,s.code,s.name,u.username approver FROM visits v JOIN sites s ON s.id=v.site_id LEFT JOIN users u ON u.id=v.approved_by ORDER BY v.id DESC LIMIT 12''')
    return render_template('dashboard.html',stats=stats,monthly={int(r['month']):r for r in monthly},recent=recent,year=year)

@app.route('/zones',methods=['GET','POST'])
@login_required
def zones():
    if request.method=='POST':
        if current()['role'] not in ('admin','coordinateur','securite'):abort(403)
        name=request.form.get('name','').strip();responsable=request.form.get('responsable','').strip()
        if not name:flash('Le nom de la zone est obligatoire.','danger')
        else:
            try:
                with conn() as c:
                    cur=c.execute('INSERT INTO zones(name,responsable,created_at) VALUES(?,?,?)',(name,responsable,datetime.now().isoformat(timespec='seconds')))
                    log(c,'CREATE','zone',cur.lastrowid)
                flash('Zone créée.','success');return redirect(url_for('zones'))
            except sqlite3.IntegrityError:flash('Cette zone existe déjà.','danger')
    rows=many('SELECT z.*,COUNT(s.id) AS count_sites FROM zones z LEFT JOIN sites s ON s.zone_id=z.id GROUP BY z.id ORDER BY z.name')
    return render_template('zones.html',zones=rows)

@app.route('/zones/<int:zid>/edit',methods=['GET','POST'])
@role_required('admin','coordinateur','securite')
def zone_edit(zid):
    z=one('SELECT * FROM zones WHERE id=?',(zid,))
    if not z:abort(404)
    if request.method=='POST':
        name=request.form.get('name','').strip()
        if not name:flash('Nom obligatoire.','danger')
        else:
            try:
                with conn() as c:
                    c.execute('UPDATE zones SET name=?,responsable=? WHERE id=?',(name,request.form.get('responsable','').strip(),zid))
                    log(c,'UPDATE','zone',zid)
                flash('Zone modifiée.','success');return redirect(url_for('zones'))
            except sqlite3.IntegrityError:flash('Cette zone existe déjà.','danger')
    return render_template('zone_edit.html',z=z)

@app.route('/visits/<int:vid>',methods=['GET'])
@login_required
def visit_detail(vid):
    v=one('''SELECT v.*,s.code,s.name,s.zone_id,z.name zone_name,u.username approver
             FROM visits v JOIN sites s ON s.id=v.site_id LEFT JOIN zones z ON z.id=s.zone_id
             LEFT JOIN users u ON u.id=v.approved_by WHERE v.id=?''',(vid,))
    if not v:abort(404)
    if current()['role']=='controleur' and v['created_by']!=current()['id']:abort(403)
    messages=many('''SELECT m.*,u.username,u.role FROM visit_messages m JOIN users u ON u.id=m.user_id WHERE m.visit_id=? ORDER BY m.id''',(vid,))
    history=many('''SELECT a.action,a.created_at,a.details,u.username
                    FROM audit a LEFT JOIN users u ON u.id=a.user_id
                    WHERE a.entity='visit' AND a.entity_id=?
                    AND a.action IN ('VALIDÉE','REJETÉE','ANNULATION_VALIDATION')
                    ORDER BY a.id DESC''',(vid,))
    history_items=[]
    for item in history:
        row=dict(item)
        row['reason']=''
        if row['action']=='ANNULATION_VALIDATION':
            try:row['reason']=json.loads(row['details']).get('motif','')
            except (TypeError,ValueError,AttributeError):row['reason']='Motif conservé dans le journal'
        history_items.append(row)
    return render_template('visit_detail.html',v=v,messages=messages,history=history_items)

@app.post('/visits/<int:vid>/messages')
@login_required
def visit_message(vid):
    v=one('SELECT id,created_by FROM visits WHERE id=?',(vid,))
    if not v:abort(404)
    if current()['role']=='lecture' or (current()['role']=='controleur' and v['created_by']!=current()['id']):abort(403)
    message=request.form.get('message','').strip()
    if not message or len(message)>4000:flash('Message obligatoire (4 000 caractères maximum).','danger')
    else:
        with conn() as c:
            cur=c.execute('INSERT INTO visit_messages(visit_id,user_id,message,created_at) VALUES(?,?,?,?)',(vid,current()['id'],message,datetime.now().isoformat(timespec='seconds')))
            log(c,'MESSAGE','visit',vid,str(cur.lastrowid))
            site=c.execute('''SELECT s.code,s.name FROM visits v JOIN sites s ON s.id=v.site_id WHERE v.id=?''',(vid,)).fetchone()
            notify(c,vid,'MESSAGE','Nouvelle réponse sur une visite',
                   f"{current()['username']} a répondu au rapport du site {site['code']} · {site['name']}.",
                   creator_id=v['created_by'])
        flash('Réponse enregistrée.','success')
    return redirect(url_for('visit_detail',vid=vid))

@app.route('/sites',methods=['GET','POST'])
@login_required
def sites():
    if request.method=='POST':
        if current()['role'] not in ('admin','coordinateur','securite'):abort(403)
        code=request.form.get('code','').strip().upper();name=request.form.get('name','').strip()
        if not code or not name:flash('Code et nom obligatoires.','danger')
        else:
            try:
                with conn() as c:
                    cur=c.execute('INSERT INTO sites(code,name,quartier,responsable,client,situation,observations,created_at,zone_id) VALUES(?,?,?,?,?,?,?,?,?)',(code,name,request.form.get('quartier','').strip(),request.form.get('responsable','').strip(),request.form.get('client','').strip(),request.form.get('situation','ACTIF'),request.form.get('observations','').strip(),datetime.now().isoformat(timespec='seconds'),selected_zone(request.form.get('zone_id',''))))
                    log(c,'CREATE','site',cur.lastrowid)
                flash('Site enregistré.','success');return redirect(url_for('sites'))
            except sqlite3.IntegrityError:flash('Ce code site existe déjà.','danger')
    q=request.args.get('q','').strip()
    rows=many('SELECT s.*,z.name zone_name FROM sites s LEFT JOIN zones z ON z.id=s.zone_id WHERE s.code LIKE ? OR s.name LIKE ? ORDER BY s.code LIMIT 1000',(f'%{q}%',f'%{q}%'))
    return render_template('sites.html',sites=rows,q=q,zones=all_zones())

@app.route('/sites/<int:sid>/edit',methods=['GET','POST'])
@role_required('admin','coordinateur','securite')
def site_edit(sid):
    s=one('SELECT * FROM sites WHERE id=?',(sid,))
    if not s:abort(404)
    if request.method=='POST':
        try:
            with conn() as c:
                c.execute('UPDATE sites SET code=?,name=?,quartier=?,responsable=?,client=?,situation=?,observations=?,zone_id=? WHERE id=?',(request.form['code'].strip().upper(),request.form['name'].strip(),request.form.get('quartier',''),request.form.get('responsable',''),request.form.get('client',''),request.form.get('situation','ACTIF'),request.form.get('observations',''),selected_zone(request.form.get('zone_id','')),sid))
                log(c,'UPDATE','site',sid)
            flash('Site mis à jour.','success');return redirect(url_for('sites'))
        except sqlite3.IntegrityError:flash('Code déjà utilisé.','danger')
    return render_template('site_edit.html',s=s,zones=all_zones())

def create_visit_records(form):
    site_ids=form.getlist('site_ids') or [form.get('site_id','')]
    if not 1<=len(site_ids)<=100 or any(not x.isdigit() for x in site_ids):
        raise ValueError('Sélectionnez de 1 à 100 sites valides.')
    ids=list(dict.fromkeys(map(int,site_ids)))
    if len(ids)!=len(site_ids):raise ValueError('Un site est coché plusieurs fois.')
    try:date.fromisoformat(form.get('visit_date',''))
    except ValueError:raise ValueError('Date invalide.')
    effected=form.get('effected','1')
    if effected not in ('0','1'):raise ValueError('État de visite invalide.')
    obs=form.get('observations','').strip()
    ctl=form.get('controleur','').strip() or current()['username']
    if len(obs)>10000 or len(ctl)>200:raise ValueError('Texte trop long.')
    with conn() as c:
        ph=','.join('?' for _ in ids)
        n=c.execute(f"SELECT COUNT(*) FROM sites WHERE id IN ({ph}) AND situation='ACTIF'",ids).fetchone()[0]
        if n!=len(ids):raise ValueError('Site inconnu ou inactif.')
        for sid in ids:
            cur=c.execute('INSERT INTO visits(site_id,visit_date,controleur,effected,observations,created_by,created_at) VALUES(?,?,?,?,?,?,?)',
                (sid,form['visit_date'],ctl,int(effected),obs,current()['id'],datetime.now().isoformat(timespec='seconds')))
            log(c,'CREATE','visit',cur.lastrowid,'Déclaration multiple' if len(ids)>1 else '')
            site=c.execute('SELECT code,name FROM sites WHERE id=?',(sid,)).fetchone()
            notify(c,cur.lastrowid,'NEW_VISIT','Nouveau rapport de visite',
                   f"{current()['username']} a déclaré une visite pour {site['code']} · {site['name']}.")
    return len(ids)

@app.route('/visits',methods=['GET','POST'])
@login_required
def visits():
    if request.method=='POST':
        if current()['role']=='lecture':abort(403)
        try:
            count=create_visit_records(request.form)
        except ValueError as e:flash(str(e),'danger')
        else:
            flash(f'{count} visite(s) indépendante(s) enregistrée(s).','success')
            return redirect(url_for('visits'))
    status=request.args.get('status','');day=request.args.get('date','');site=request.args.get('site','')
    where=['1=1'];params=[]
    if current()['role']=='controleur':where.append('v.created_by=?');params.append(current()['id'])
    if status in ('EN ATTENTE','VALIDÉE','REJETÉE'):where.append('v.status=?');params.append(status)
    if day:where.append('v.visit_date=?');params.append(day)
    if site:where.append('(s.code LIKE ? OR s.name LIKE ?)');params.extend([f'%{site}%',f'%{site}%'])
    rows=many('''SELECT v.*,s.code,s.name,u.username approver FROM visits v JOIN sites s ON s.id=v.site_id LEFT JOIN users u ON u.id=v.approved_by WHERE '''+' AND '.join(where)+' ORDER BY v.visit_date DESC,v.id DESC LIMIT 1000',params)
    return render_template('visits.html',visits=rows,sites=many("SELECT id,code,name FROM sites WHERE situation='ACTIF' ORDER BY code"),filters={'status':status,'date':day,'site':site})

@app.route('/visits/declarer-plusieurs',methods=['GET','POST'])
@role_required('admin','coordinateur','securite','dga','controleur')
def visit_multiple():
    if request.method=='POST':
        try:n=create_visit_records(request.form)
        except ValueError as e:flash(str(e),'danger')
        else:
            flash(f'{n} visites distinctes enregistrées.','success')
            return redirect(url_for('visits'))
    sites_list=many("SELECT s.id,s.code,s.name,z.name zone_name FROM sites s LEFT JOIN zones z ON z.id=s.zone_id WHERE s.situation='ACTIF' ORDER BY z.name,s.code")
    return render_template('visit_multiple.html',sites=sites_list)

@app.route('/visits/<int:vid>/edit',methods=['GET','POST'])
@role_required('controleur')
def visit_edit(vid):
    v=one('SELECT v.*,s.code,s.name FROM visits v JOIN sites s ON s.id=v.site_id WHERE v.id=?',(vid,))
    if not v:abort(404)
    if v['created_by']!=current()['id']:abort(403)
    if v['status']!='EN ATTENTE':abort(409,'Visite déjà traitée.')
    if request.method=='POST':
        sid=request.form.get('site_id','')
        when=request.form.get('visit_date','')
        eff=request.form.get('effected','1')
        obs=request.form.get('observations','').strip()
        if not sid.isdigit() or not one("SELECT id FROM sites WHERE id=? AND situation='ACTIF'",(sid,)):
            flash('Site invalide.','danger')
        elif eff not in ('0','1') or len(obs)>10000:
            flash('Saisie invalide.','danger')
        else:
            try:date.fromisoformat(when)
            except ValueError:flash('Date invalide.','danger')
            else:
                with conn() as c:
                    result=c.execute("UPDATE visits SET site_id=?,visit_date=?,effected=?,observations=? WHERE id=? AND status='EN ATTENTE' AND created_by=?",
                        (int(sid),when,int(eff),obs,vid,current()['id']))
                    if result.rowcount:log(c,'UPDATE','visit',vid,'Modification avant validation')
                if not result.rowcount:abort(409,'Visite devenue non modifiable.')
                flash('Visite modifiée.','success')
                return redirect(url_for('visit_detail',vid=vid))
    sites_list=many("SELECT id,code,name FROM sites WHERE situation='ACTIF' OR id=? ORDER BY code",(v['site_id'],))
    return render_template('visit_edit.html',v=v,sites=sites_list)

@app.post('/visits/<int:vid>/delete')
@role_required('admin','coordinateur','securite','dga')
def visit_delete(vid):
    if request.form.get('confirm')!='SUPPRIMER':abort(400,'Confirmation obligatoire.')
    motif=request.form.get('motif','').strip()
    if not motif or len(motif)>500:abort(400,'Motif obligatoire (500 caractères maximum).')
    with conn() as c:
        v=c.execute('SELECT * FROM visits WHERE id=?',(vid,)).fetchone()
        if not v:abort(404)
        if v['status']!='EN ATTENTE':abort(409,'Visite déjà traitée.')
        messages=[dict(r) for r in c.execute('SELECT user_id,message,created_at FROM visit_messages WHERE visit_id=?',(vid,)).fetchall()]
        snapshot={'visite':dict(v),'messages':messages,'motif':motif,'deleted_by':current()['username']}
        result=c.execute("DELETE FROM visits WHERE id=? AND status='EN ATTENTE'",(vid,))
        if not result.rowcount:abort(409,'Impossible de supprimer la visite.')
        log(c,'DELETE','visit',vid,json.dumps(snapshot,ensure_ascii=False))
    flash('Visite supprimée et opération journalisée.','success')
    return redirect(url_for('visits'))

@app.post('/visits/<int:vid>/decision')
@role_required(*APPROVERS)
def decision(vid):
    status=request.form.get('status')
    if status not in ('VALIDÉE','REJETÉE'):abort(400)
    with conn() as c:
        r=c.execute('SELECT * FROM visits WHERE id=?',(vid,)).fetchone()
        if not r:abort(404)
        if r['status']!='EN ATTENTE':flash('Cette visite a déjà reçu une décision.','danger')
        elif not r['effected'] and status=='VALIDÉE':flash('Une visite non effectuée ne peut pas être validée.','danger')
        else:
            note=request.form.get('note','').strip()[:1000]
            updated=c.execute("UPDATE visits SET status=?,approved_by=?,approved_at=?,approval_note=? WHERE id=? AND status='EN ATTENTE'",
                (status,current()['id'],datetime.now().isoformat(timespec='seconds'),note,vid))
            if not updated.rowcount:abort(409,"Cette visite vient d'être traitée.")
            log(c,status,'visit',vid,note)
            site=c.execute('''SELECT s.code,s.name FROM visits v JOIN sites s ON s.id=v.site_id WHERE v.id=?''',(vid,)).fetchone()
            notify(c,vid,'DECISION','Visite '+status.lower(),
                   f"{current()['username']} a marqué {site['code']} · {site['name']} comme {status.lower()}.",
                   creator_id=r['created_by'])
            flash('Décision enregistrée.','success')
    return redirect(url_for('visit_detail',vid=vid))

@app.post('/visits/<int:vid>/undo-validation')
@role_required(*APPROVERS)
def undo_validation(vid):
    motif=request.form.get('motif','').strip()
    if not motif or len(motif)>500:
        flash('Le motif d’annulation est obligatoire (500 caractères maximum).','danger')
        return redirect(url_for('visit_detail',vid=vid))
    with conn() as c:
        visit=c.execute('SELECT * FROM visits WHERE id=?',(vid,)).fetchone()
        if not visit:abort(404)
        if visit['status']!='VALIDÉE':
            flash('Seules les visites validées peuvent être remises en attente.','danger')
            return redirect(url_for('visit_detail',vid=vid))
        previous={key:visit[key] for key in ('status','approved_by','approved_at','approval_note')}
        changed=c.execute("UPDATE visits SET status='EN ATTENTE',approved_by=NULL,approved_at=NULL,approval_note='' WHERE id=? AND status='VALIDÉE'",(vid,))
        if not changed.rowcount:abort(409,'Cette validation a déjà été annulée.')
        log(c,'ANNULATION_VALIDATION','visit',vid,
            json.dumps({'motif':motif,'previous':previous},ensure_ascii=False))
        site=c.execute('''SELECT s.code,s.name FROM visits v JOIN sites s ON s.id=v.site_id WHERE v.id=?''',(vid,)).fetchone()
        notify(c,vid,'UNDO_VALIDATION','Validation annulée',
               f"{current()['username']} a annulé la validation du site {site['code']} · {site['name']}. Motif : {motif}",
               creator_id=visit['created_by'])
    flash('Validation annulée : la visite est de nouveau EN ATTENTE.','success')
    return redirect(url_for('visit_detail',vid=vid))

@app.route('/reports')
@login_required
def reports():
    start=request.args.get('start',date.today().replace(day=1).isoformat());end=request.args.get('end',date.today().isoformat())
    try:date.fromisoformat(start);date.fromisoformat(end)
    except ValueError:abort(400)
    rows=many('''SELECT v.visit_date,s.code,s.name,v.controleur,v.effected,v.observations,v.status,u.username approver,v.approved_at FROM visits v JOIN sites s ON s.id=v.site_id LEFT JOIN users u ON u.id=v.approved_by WHERE v.visit_date BETWEEN ? AND ? ORDER BY v.visit_date DESC,s.code''',(start,end))
    if request.args.get('export')=='csv':
        out=io.StringIO();w=csv.writer(out,delimiter=';');w.writerow(['Date','Code site','Nom site','Contrôleur','Effectuée','Observations','Statut','Validateur','Date validation'])
        for r in rows:w.writerow([r[k] for k in r.keys()])
        content='\ufeff'+out.getvalue()
        return Response(content,mimetype='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename=rapport_saba.csv'})
    return render_template('reports.html',rows=rows,start=start,end=end)

@app.route('/users',methods=['GET','POST'])
@role_required('admin')
def users():
    if request.method=='POST':
        username=request.form.get('username','').strip();pwd=request.form.get('password','');role=request.form.get('role','')
        if role not in ROLES or len(pwd)<12 or not username:flash('Nom, rôle et mot de passe de 12 caractères minimum obligatoires.','danger')
        else:
            try:
                with conn() as c:
                    cur=c.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',(username,generate_password_hash(pwd),role));log(c,'CREATE','user',cur.lastrowid)
                flash('Utilisateur créé.','success');return redirect(url_for('users'))
            except sqlite3.IntegrityError:flash('Identifiant déjà utilisé.','danger')
    return render_template('users.html',users=many('SELECT id,username,role,active FROM users ORDER BY id'))

@app.route('/password',methods=['GET','POST'])
@login_required
def password():
    if request.method=='POST':
        u=one('SELECT password_hash FROM users WHERE id=?',(current()['id'],))
        if not check_password_hash(u['password_hash'],request.form.get('old','')):flash('Ancien mot de passe incorrect.','danger')
        elif len(request.form.get('new',''))<12:flash('12 caractères minimum.','danger')
        else:
            with conn() as c:c.execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(request.form['new']),current()['id']))
            flash('Mot de passe modifié.','success');return redirect(url_for('dashboard'))
    return render_template('password.html')

@app.route('/import',methods=['GET','POST'])
@role_required('admin')
def import_sites():
    if request.method=='POST':
        f=request.files.get('file');count=0;skipped=0
        if not f or not f.filename.lower().endswith('.csv'):flash('Utilisez un fichier CSV UTF-8.','danger')
        else:
            try:
                content=f.read().decode('utf-8-sig');sample=content[:4096]
                dialect=csv.Sniffer().sniff(sample,delimiters=';,\t')
                reader=csv.DictReader(io.StringIO(content),dialect=dialect)
                if not {'code','nom'}.issubset(set(reader.fieldnames or [])):raise ValueError('Colonnes obligatoires : code, nom')
                with conn() as c:
                    for row in reader:
                        code=row.get('code','').strip().upper();name=row.get('nom','').strip()
                        if not code or not name:skipped+=1;continue
                        c.execute('''INSERT INTO sites(code,name,quartier,responsable,client,situation,observations,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(code) DO UPDATE SET name=excluded.name,quartier=excluded.quartier,responsable=excluded.responsable,client=excluded.client,situation=excluded.situation,observations=excluded.observations''',(code,name,row.get('quartier',''),row.get('responsable',''),row.get('client',''),row.get('situation','ACTIF') or 'ACTIF',row.get('observations',''),datetime.now().isoformat(timespec='seconds')))
                        count+=1
                    log(c,'IMPORT','sites',0,f'{count} lignes')
                flash(f'{count} sites importés ou mis à jour ; {skipped} lignes ignorées.','success')
            except Exception as e:flash(f'Import impossible : {str(e)[:150]}','danger')
    return render_template('import.html')

@app.route('/health')
def health():return {'status':'ok'}

init_db()
if __name__=='__main__':app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')),debug=False)
