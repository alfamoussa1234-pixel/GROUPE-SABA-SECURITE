import os, sqlite3, secrets, csv, io, json, re, unicodedata, zipfile
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
from decimal import Decimal, InvalidOperation
from datetime import datetime, date
from functools import wraps
from flask import Flask, request, session, redirect, url_for, flash, render_template, render_template_string, Response, abort, jsonify
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

# Version autonome de la page Sites : evite qu'un ancien fichier templates/sites.html
# sur le serveur masque la nouvelle interface de gestion des effectifs.
SITES_INLINE_TEMPLATE = r'''{% extends 'base.html' %}
{% block body %}
<div class="headrow">
  <div><h1>Sites et effectifs</h1><p class="muted">Effectifs gérés par l’administrateur, le coordinateur général, le responsable sécurité et le DGA. Les sites supprimés sont conservés dans les archives.</p></div>
  <div class="actions">
  {% if not archived and me.role in ('admin','coordinateur','securite','dga') %}<a class="btn secondary" href="{{url_for('export_sites',format='xlsx')}}">Exporter Excel (avec agents)</a>{% endif %}
  {% if not archived and me.role=='admin' %}<a class="btn secondary" href="{{url_for('import_sites')}}">Importer des sites</a>{% endif %}
  {% if me.role=='admin' %}<a class="btn secondary" href="{{url_for('sites',archived='0' if archived else '1')}}">{{'Voir les sites actifs' if archived else 'Voir les sites supprimés'}}</a>{% endif %}
  </div>
</div>
{% if me.role in ('admin','coordinateur','securite') and not archived %}
<section class="card"><h2>Ajouter un site</h2>
<form method="post"><input type="hidden" name="csrf" value="{{csrf_token()}}">
<div class="formgrid">
  <div class="field"><label>Code site *</label><input name="code" placeholder="S001" required maxlength="80"></div>
  <div class="field"><label>Nom du site *</label><input name="name" required maxlength="200"></div>
  <div class="field"><label>Zone affectée</label><select name="zone_id"><option value="">Sans zone</option>{% for z in zones %}<option value="{{z.id}}">{{z.name}}</option>{% endfor %}</select></div>
  <div class="field"><label>Quartier / localisation</label><input name="quartier"></div>
  <div class="field"><label>Responsable</label><input name="responsable"></div>
  <div class="field"><label>Client / contrat</label><input name="client"></div>
  <div class="field"><label>Situation</label><select name="situation"><option>ACTIF</option><option>INACTIF</option></select></div>
  <div class="field"><label>Observations</label><input name="observations"></div>
</div><div class="actions"><button class="btn">Enregistrer le site</button></div></form></section>
{% endif %}
<section class="card">
<div class="headrow"><h2>{{'Sites supprimés' if archived else 'Répertoire des sites'}} ({{sites|length}} affichés)</h2>
  <form method="get" class="actions"><input type="hidden" name="archived" value="{{'1' if archived else '0'}}"><input name="q" value="{{q}}" placeholder="Rechercher code ou nom"><button class="btn small">Rechercher</button></form>
</div>
{% if not archived %}<p class="hint">Le nombre d'agents correspond à l'effectif affecté au site. « Non renseigné » signifie que l’effectif n’a pas encore été saisi par une personne habilitée.</p>{% endif %}
<div class="tablewrap"><table>
<thead><tr><th>Code</th><th>Site</th><th>Zone</th><th>Quartier</th><th>Client</th><th>Situation</th><th>Agents affectés</th><th>Dernière saisie</th><th>Actions</th></tr></thead>
<tbody>{% for s in sites %}<tr>
<td><strong>{{s.code}}</strong></td><td>{{s.name}}</td><td>{{s.zone_name or 'Non affecté'}}</td><td>{{s.quartier}}</td><td>{{s.client}}</td><td>{{s.situation}}</td>
<td>
  {% if not archived and me.role in ('admin','coordinateur','securite','dga') %}
    <form method="post" action="{{url_for('update_site_agents',sid=s.id)}}" class="agent-form">
    <input type="hidden" name="csrf" value="{{csrf_token()}}">
    <input aria-label="Nombre d'agents affectés à {{s.code}}" type="number" name="agent_count" min="0" max="10000" step="1" value="{{s.agent_count if s.agent_count is not none else ''}}" placeholder="Nombre" required>
    <button class="btn small" title="Enregistrer l'effectif">Enregistrer</button></form>
  {% else %}<strong>{{s.agent_count if s.agent_count is not none else 'Non renseigné'}}</strong>{% endif %}
</td>
<td>{% if s.agent_count_updated_at %}{{s.agents_updated_by or 'Utilisateur'}}<br><small class="muted">{{s.agent_count_updated_at[:16].replace('T',' ')}}</small>{% else %}—{% endif %}</td>
<td class="site-actions">
  {% if archived %}
    {% if me.role=='admin' %}
    <form method="post" action="{{url_for('site_restore',sid=s.id)}}"><input type="hidden" name="csrf" value="{{csrf_token()}}"><button class="btn small ok">Restaurer</button></form>
    {% if s.visits_count==0 %}
    <form method="post" action="{{url_for('site_delete_permanently',sid=s.id)}}" onsubmit="return confirm('Effacer définitivement ce site sans rapport ? Cette action ne peut pas être annulée.')"><input type="hidden" name="csrf" value="{{csrf_token()}}"><input type="hidden" name="confirm" value="EFFACER"><button class="btn small bad">Effacer définitivement</button></form>
    {% endif %}
    {% endif %}
  {% else %}
    {% if me.role in ('admin','coordinateur','securite') %}<a class="btn small secondary" href="{{url_for('site_edit',sid=s.id)}}">Modifier</a>{% endif %}
    {% if me.role=='admin' %}
      <details><summary class="danger-text">Supprimer</summary>
      <form method="post" action="{{url_for('site_archive',sid=s.id)}}" class="delete-form">
        <input type="hidden" name="csrf" value="{{csrf_token()}}"><input type="hidden" name="confirm" value="SUPPRIMER">
        <label>Motif de suppression</label><input name="motif" maxlength="500" required placeholder="Motif obligatoire">
        <p class="hint">Le site disparaîtra du répertoire, mais ses visites seront conservées.</p>
        <button class="btn small bad" onclick="return confirm('Supprimer ce site du répertoire actif ?')">Confirmer</button>
      </form></details>
    {% endif %}
  {% endif %}
</td>
</tr>{% else %}<tr><td colspan="9">Aucun site trouvé.</td></tr>{% endfor %}</tbody>
</table></div></section>
{% endblock %}
'''


# Rapport filtrable, autonome pour ne pas dépendre d'un ancien reports.html sur Render.
REPORTS_INLINE_TEMPLATE = r'''{% extends 'base.html' %}{% block body %}
<div class="headrow"><div><h1>Rapports des sites visités</h1>
<p class="muted">Consultez les rapports des contrôleurs par date, site, contrôleur et statut. Cliquez sur « Voir le rapport » pour lire les échanges et la validation.</p></div></div>
<section class="card"><form method="get" class="formgrid" style="align-items:end">
<div class="field"><label>Date du</label><input type="date" name="start" value="{{start}}"></div>
<div class="field"><label>Au</label><input type="date" name="end" value="{{end}}"></div>
<div class="field"><label>Contrôleur</label><select name="controleur"><option value="">Tous les contrôleurs</option>{% for c in controllers %}<option value="{{c}}" {% if filtre_controleur==c %}selected{% endif %}>{{c}}</option>{% endfor %}</select></div>
<div class="field"><label>Site / code</label><input name="site" value="{{filtre_site}}" placeholder="Nom ou code du site"></div>
<div class="field"><label>Visite</label><select name="effected"><option value="1" {% if effected=='1' %}selected{% endif %}>Sites visités</option><option value="0" {% if effected=='0' %}selected{% endif %}>Non visités</option><option value="all" {% if effected=='all' %}selected{% endif %}>Toutes les déclarations</option></select></div>
<div class="field"><label>Statut</label><select name="status"><option value="">Tous les statuts</option>{% for st in ['EN ATTENTE','VALIDÉE','REJETÉE'] %}<option value="{{st}}" {% if status==st %}selected{% endif %}>{{st}}</option>{% endfor %}</select></div>
<div class="actions"><button class="btn">Afficher</button><button class="btn secondary" name="export" value="csv">Exporter les rapports CSV</button></div>
</form></section>
<div class="grid"><div class="stat"><span>Rapports affichés</span><strong>{{rows|length}}</strong></div><div class="stat"><span>Sites distincts</span><strong>{{rows|map(attribute='code')|unique|list|length}}</strong></div><div class="stat"><span>Validés</span><strong>{{rows|selectattr('status','equalto','VALIDÉE')|list|length}}</strong></div><div class="stat"><span>En attente</span><strong>{{rows|selectattr('status','equalto','EN ATTENTE')|list|length}}</strong></div></div>
<section class="card"><h2>Rapports des contrôleurs</h2><p class="hint">L'effectif indiqué est l'effectif actuel du site, et non l'effectif à la date de visite. Les sites archivés restent présents dans l'historique. Maximum 5 000 résultats.</p>
<div class="tablewrap"><table><thead><tr><th>Date</th><th>Code</th><th>Site</th><th>Agents actuels</th><th>Contrôleur</th><th>Saisi par</th><th>Visité</th><th>Observations</th><th>Statut</th><th>Validateur</th><th>Rapport</th></tr></thead><tbody>
{% for r in rows %}<tr><td>{{r.visit_date}}</td><td><strong>{{r.code}}</strong></td><td>{{r.name}}</td><td>{{r.agents_actuels if r.agents_actuels is not none else '—'}}</td><td>{{r.controleur}}</td><td>{{r.saisi_par or '—'}}</td><td>{{'Oui' if r.effected else 'Non'}}</td><td class="wrap">{{r.observations}}</td><td>{{r.status}}</td><td>{{r.approver or '—'}}</td><td><a class="btn small secondary" href="{{url_for('visit_detail',vid=r.id)}}">Voir le rapport</a></td></tr>
{% else %}<tr><td colspan="11">Aucun rapport ne correspond à ces filtres.</td></tr>{% endfor %}</tbody></table></div>
</section>{% endblock %}'''

IMPORT_INLINE_TEMPLATE = r'''{% extends 'base.html' %}{% block body %}
<h1>Importer et exporter les sites avec leurs effectifs</h1>
<p class="muted">Gérez les sites et le nombre d'agents dans un fichier Excel (.xlsx) ou CSV. L'import est réservé à l'administrateur.</p>
<section class="card"><h2>1. Télécharger vos sites</h2><p>Export des sites actifs avec les codes, noms, zones, quartiers, responsables, clients, situations, nombres d'agents et observations.</p>
<div class="actions"><a class="btn" href="{{url_for('export_sites',format='xlsx')}}">Exporter Excel (.xlsx)</a><a class="btn secondary" href="{{url_for('export_sites',format='csv')}}">Exporter CSV</a><a class="btn secondary" href="{{url_for('site_import_model')}}">Modèle CSV vierge</a></div></section>
<section class="card"><h2>2. Importer les sites et effectifs</h2>
<p>Modifiez le fichier exporté dans Excel, en conservant la colonne <strong>code</strong> (identifiant unique), la colonne <strong>nom</strong> et la colonne <strong>nombre_agents</strong>. Enregistrez et importez.</p>
<form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="{{csrf_token()}}"><div class="field"><label>Fichier Excel ou CSV (12 Mo maximum)</label><input type="file" name="file" accept=".xlsx,.csv,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" required></div><div class="actions"><button class="btn">Importer et mettre à jour</button></div></form>
<p class="hint">Un même code met à jour le site existant, sans dupliquer ses rapports. Une cellule d'effectif vide conserve l'effectif déjà enregistré. L'import ne supprime aucun site et ne réactive pas les sites archivés. Les modifications sont tracées.</p></section>{% endblock %}'''

# Pages autonomes : utilisables même si les modèles du dépôt GitHub sont anciens.
USERS_INLINE_TEMPLATE = r'''{% extends 'base.html' %}
{% block body %}
<h1>Gestion des utilisateurs</h1>
<p class="muted">Chaque personne dispose de son propre accès. L'administrateur peut réinitialiser un mot de passe oublié sans consulter l'ancien.</p>
{% if temporary_secret is defined %}
<section class="card temp-password" role="status"><h2>Nouveau mot de passe provisoire</h2>
<p>Compte concerné : <strong>{{reset_username}}</strong></p>
<p class="secret-code">{{temporary_secret}}</p>
<p><strong>Copiez ce mot de passe maintenant.</strong> Il ne sera plus affiché après avoir quitté cette page. Communiquez-le uniquement à son titulaire par un canal privé. Il devra le changer dès sa connexion.</p>
<button type="button" class="btn secondary" onclick="navigator.clipboard.writeText(document.querySelector('.secret-code').textContent)">Copier le mot de passe</button>
</section>
{% endif %}
<section class="card"><h2>Créer un utilisateur</h2>
<form method="post"><input type="hidden" name="csrf" value="{{csrf_token()}}"><div class="formgrid">
<div class="field"><label>Identifiant</label><input name="username" required></div>
<div class="field"><label>Mot de passe (12 caractères minimum)</label><input name="password" type="password" minlength="12" required autocomplete="new-password"></div>
<div class="field"><label>Rôle</label><select name="role">{% for value,label in roles.items() %}<option value="{{value}}">{{label}}</option>{% endfor %}</select></div>
</div><div class="actions"><button class="btn">Créer le compte</button></div></form></section>
<section class="card"><h2>Comptes existants</h2>
<div class="tablewrap"><table><thead><tr><th>Identifiant</th><th>Rôle</th><th>Statut</th><th>Accès</th><th>Action</th></tr></thead><tbody>
{% for u in users %}<tr><td><strong>{{u.username}}</strong></td><td>{{roles[u.role]}}</td><td>{{'Actif' if u.active else 'Inactif'}}</td>
<td>{{'Changement obligatoire' if u.must_change_password else 'Normal'}}</td>
<td>{% if u.active and u.id!=me.id %}<form method="post" action="{{url_for('user_reset_password',uid=u.id)}}" onsubmit="return confirm('Réinitialiser le mot de passe de {{u.username}} ?')"><input type="hidden" name="csrf" value="{{csrf_token()}}"><button class="btn small secondary">Réinitialiser le mot de passe</button></form>{% else %}—{% endif %}</td></tr>
{% endfor %}</tbody></table></div></section>
{% endblock %}
'''

LOGIN_INLINE_TEMPLATE = r'''{% extends 'base.html' %}{% block body %}<section class="card login">
  <div style="text-align:center; margin-bottom:20px;">
    <img
      src="{{ url_for('static', filename='SABA O.png') }}"
      alt="Logo GROUPE SABA SÉCURITÉ"
      style="width:220px; max-width:100%; height:auto;"
    >
  </div>
  <h1>Connexion sécurisée</h1><p class="muted">Accédez aux visites et rapports de GROUPE SABA SÉCURITÉ.</p><form method="post"><input type="hidden" name="csrf" value="{{csrf_token()}}"><div class="field"><label>Identifiant</label><input name="username" autocomplete="username" required autofocus></div><div class="field"><label>Mot de passe</label><input name="password" type="password" autocomplete="current-password" required></div><button class="btn">Se connecter</button></form><p class="hint" style="text-align:center;margin-top:18px"><a href="{{url_for('forgot_password')}}">Mot de passe oublié ?</a></p></section>{% endblock %}
'''

FORGOT_PASSWORD_INLINE_TEMPLATE = r'''{% extends 'base.html' %}{% block body %}
<section class="card login"><h1>Mot de passe oublié ?</h1>
<p>Contactez l'administrateur de GROUPE SABA SÉCURITÉ et demandez une <strong>réinitialisation de votre mot de passe</strong>.</p>
<p class="muted">L'administrateur ouvrira « Utilisateurs » et vous remettra un mot de passe provisoire. À votre prochaine connexion, vous devrez le modifier.</p>
{% if recovery_enabled %}<p>Vous êtes l'administrateur et avez perdu votre accès ? <a href="{{url_for('admin_emergency_recovery')}}">Utiliser la clé de secours</a>.</p>{% endif %}
<p><a class="btn secondary" href="{{url_for('login')}}">Retour à la connexion</a></p></section>
{% endblock %}
'''

ADMIN_RECOVERY_INLINE_TEMPLATE = r'''{% extends 'base.html' %}{% block body %}
<section class="card login"><h1>Récupération administrateur</h1><p class="muted">Cette procédure nécessite la clé secrète ADMIN_RECOVERY_KEY configurée sur Render. Ne la communiquez jamais à un tiers.</p>
<form method="post"><input type="hidden" name="csrf" value="{{csrf_token()}}">
<div class="field"><label>Identifiant administrateur</label><input name="username" required></div>
<div class="field"><label>Clé de secours</label><input name="recovery_key" type="password" required autocomplete="off"></div>
<div class="field"><label>Nouveau mot de passe (12 caractères minimum)</label><input name="new_password" type="password" minlength="12" required autocomplete="new-password"></div>
<div class="field"><label>Confirmer le mot de passe</label><input name="confirm_password" type="password" minlength="12" required autocomplete="new-password"></div>
<button class="btn">Réinitialiser mon accès administrateur</button></form></section>
{% endblock %}
'''

PASSWORD_INLINE_TEMPLATE = r'''{% extends 'base.html' %}
{% block body %}
<section class="card login"><h1>{{'Définir mon nouveau mot de passe' if forced else 'Changer mon mot de passe'}}</h1>
{% if forced %}<p class="muted">Votre mot de passe provisoire doit être remplacé avant de poursuivre.</p>{% endif %}
<form method="post"><input type="hidden" name="csrf" value="{{csrf_token()}}">
{% if not forced %}<div class="field"><label>Ancien mot de passe</label><input name="old" type="password" autocomplete="current-password" required></div>{% endif %}
<div class="field"><label>Nouveau mot de passe (12 caractères minimum)</label><input name="new" type="password" minlength="12" autocomplete="new-password" required></div>
<div class="field"><label>Confirmer le nouveau mot de passe</label><input name="confirm" type="password" minlength="12" autocomplete="new-password" required></div>
<button class="btn">Enregistrer le nouveau mot de passe</button></form></section>
{% endblock %}
'''

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
        # Migration additive, sans écraser la base utilisée sur Render.
        for col,definition in (
            ('agent_count','INTEGER'),
            ('agent_count_updated_at','TEXT'),
            ('agent_count_updated_by','INTEGER'),
            ('archived_at','TEXT'),
            ('archived_by','INTEGER'),
            ('archive_reason','TEXT')
        ):
            if col not in existing:c.execute(f'ALTER TABLE sites ADD COLUMN {col} {definition}')
        user_columns={r['name'] for r in c.execute('PRAGMA table_info(users)')}
        if 'must_change_password' not in user_columns:
            c.execute('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0')
        if 'password_changed_at' not in user_columns:
            c.execute('ALTER TABLE users ADD COLUMN password_changed_at TEXT')

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
    return one('SELECT id,username,role,must_change_password FROM users WHERE id=? AND active=1',(session['uid'],))

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

@app.before_request
def require_new_password():
    # Un mot de passe temporaire doit être remplacé avant toute autre action.
    if request.endpoint in ('static','password','logout','login','setup','forgot_password','admin_emergency_recovery'):
        return None
    if session.get('uid'):
        user=current()
        if user and user['must_change_password']:
            return redirect(url_for('password'))

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
            session.clear();session['uid']=u['id'];token();return redirect(url_for('password' if u['must_change_password'] else 'dashboard'))
        flash('Identifiants incorrects.','danger')
    return render_template_string(LOGIN_INLINE_TEMPLATE)

@app.post('/logout')
@login_required
def logout():session.clear();return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    year=request.args.get('year',str(date.today().year))
    if not year.isdigit() or len(year)!=4:year=str(date.today().year)
    stats=one('''SELECT (SELECT COUNT(*) FROM sites WHERE archived_at IS NULL) sites, (SELECT COALESCE(SUM(agent_count),0) FROM sites WHERE archived_at IS NULL AND situation='ACTIF') agents, (SELECT COUNT(*) FROM sites WHERE archived_at IS NULL AND agent_count IS NULL) sites_sans_effectif,(SELECT COUNT(*) FROM visits WHERE substr(visit_date,1,4)=?) total,(SELECT COUNT(*) FROM visits WHERE substr(visit_date,1,4)=? AND status='VALIDÉE') validated,(SELECT COUNT(*) FROM visits WHERE status='EN ATTENTE') pending,(SELECT COUNT(DISTINCT site_id) FROM visits WHERE substr(visit_date,1,4)=? AND status='VALIDÉE') covered''',(year,year,year))
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
    archived=request.args.get('archived')=='1' and current()['role']=='admin'
    rows=many('''SELECT s.*,z.name zone_name,u.username agents_updated_by,
                    (SELECT COUNT(*) FROM visits v WHERE v.site_id=s.id) visits_count
                 FROM sites s LEFT JOIN zones z ON z.id=s.zone_id
                 LEFT JOIN users u ON u.id=s.agent_count_updated_by
                 WHERE (s.code LIKE ? OR s.name LIKE ?) AND s.archived_at IS '''+('NOT NULL' if archived else 'NULL')+
               ' ORDER BY s.code LIMIT 1000',(f'%{q}%',f'%{q}%'))
    return render_template_string(SITES_INLINE_TEMPLATE,sites=rows,q=q,zones=all_zones(),archived=archived)

@app.route('/sites/<int:sid>/edit',methods=['GET','POST'])
@role_required('admin','coordinateur','securite')
def site_edit(sid):
    s=one('SELECT * FROM sites WHERE id=?',(sid,))
    if not s:abort(404)
    if s['archived_at']:abort(409,'Ce site est archivé. Restaurez-le avant modification.')
    if request.method=='POST':
        try:
            with conn() as c:
                c.execute('UPDATE sites SET code=?,name=?,quartier=?,responsable=?,client=?,situation=?,observations=?,zone_id=? WHERE id=?',(request.form['code'].strip().upper(),request.form['name'].strip(),request.form.get('quartier',''),request.form.get('responsable',''),request.form.get('client',''),request.form.get('situation','ACTIF'),request.form.get('observations',''),selected_zone(request.form.get('zone_id','')),sid))
                log(c,'UPDATE','site',sid)
            flash('Site mis à jour.','success');return redirect(url_for('sites'))
        except sqlite3.IntegrityError:flash('Code déjà utilisé.','danger')
    return render_template('site_edit.html',s=s,zones=all_zones())


@app.post('/sites/<int:sid>/agents')
@role_required('admin', *APPROVERS)
def update_site_agents(sid):
    value=request.form.get('agent_count','').strip()
    if not value.isdecimal() or len(value)>5 or int(value)>10000:
        flash('Indiquez un nombre d’agents compris entre 0 et 10 000.','danger')
        return redirect(url_for('sites'))
    with conn() as c:
        site=c.execute('SELECT code,agent_count,archived_at FROM sites WHERE id=?',(sid,)).fetchone()
        if not site:abort(404)
        if site['archived_at']:abort(409,'Ce site est archivé.')
        new_value=int(value)
        c.execute('''UPDATE sites SET agent_count=?,agent_count_updated_by=?,agent_count_updated_at=?
                     WHERE id=? AND archived_at IS NULL''',
                  (new_value,current()['id'],datetime.now().isoformat(timespec='seconds'),sid))
        log(c,'EFFECTIF','site',sid,json.dumps({'avant':site['agent_count'],'apres':new_value},ensure_ascii=False))
    flash(f'Effectif du site {site["code"]} enregistré : {new_value} agent(s).','success')
    return redirect(url_for('sites'))

@app.post('/sites/<int:sid>/archive')
@role_required('admin')
def site_archive(sid):
    if request.form.get('confirm')!='SUPPRIMER':abort(400,'Confirmation obligatoire.')
    motif=request.form.get('motif','').strip()
    if not motif or len(motif)>500:abort(400,'Indiquez un motif (500 caractères maximum).')
    with conn() as c:
        site=c.execute('SELECT * FROM sites WHERE id=?',(sid,)).fetchone()
        if not site:abort(404)
        if site['archived_at']:abort(409,'Site déjà retiré du répertoire actif.')
        c.execute('''UPDATE sites SET archived_at=?,archived_by=?,archive_reason=? WHERE id=?''',
                  (datetime.now().isoformat(timespec='seconds'),current()['id'],motif,sid))
        log(c,'ARCHIVE','site',sid,json.dumps({'site':dict(site),'motif':motif},ensure_ascii=False))
    flash('Site supprimé du répertoire actif. Les rapports sont préservés et le site peut être restauré.','success')
    return redirect(url_for('sites'))

@app.post('/sites/<int:sid>/restore')
@role_required('admin')
def site_restore(sid):
    with conn() as c:
        site=c.execute('SELECT code,archived_at FROM sites WHERE id=?',(sid,)).fetchone()
        if not site:abort(404)
        if not site['archived_at']:abort(409,'Site non archivé.')
        c.execute('UPDATE sites SET archived_at=NULL,archived_by=NULL,archive_reason=NULL WHERE id=?',(sid,))
        log(c,'RESTORE','site',sid)
    flash('Site restauré.','success')
    return redirect(url_for('sites',archived='1'))

@app.post('/sites/<int:sid>/delete-permanently')
@role_required('admin')
def site_delete_permanently(sid):
    if request.form.get('confirm')!='EFFACER':abort(400,'Confirmation obligatoire.')
    with conn() as c:
        site=c.execute('SELECT * FROM sites WHERE id=?',(sid,)).fetchone()
        if not site:abort(404)
        if not site['archived_at']:abort(409,'Archivez d’abord le site.')
        visits=c.execute('SELECT COUNT(*) AS n FROM visits WHERE site_id=?',(sid,)).fetchone()['n']
        if visits:abort(409,'Ce site possède des rapports de visite : suppression définitive interdite.')
        log(c,'DELETE','site',sid,json.dumps(dict(site),ensure_ascii=False))
        c.execute('DELETE FROM sites WHERE id=?',(sid,))
    flash('Site définitivement supprimé : aucun rapport de visite n’était lié.','success')
    return redirect(url_for('sites',archived='1'))

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
        n=c.execute(f"SELECT COUNT(*) FROM sites WHERE id IN ({ph}) AND situation='ACTIF' AND archived_at IS NULL",ids).fetchone()[0]
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
    return render_template('visits.html',visits=rows,sites=many("SELECT id,code,name FROM sites WHERE situation='ACTIF' AND archived_at IS NULL ORDER BY code"),filters={'status':status,'date':day,'site':site})

@app.route('/visits/declarer-plusieurs',methods=['GET','POST'])
@role_required('admin','coordinateur','securite','dga','controleur')
def visit_multiple():
    if request.method=='POST':
        try:n=create_visit_records(request.form)
        except ValueError as e:flash(str(e),'danger')
        else:
            flash(f'{n} visites distinctes enregistrées.','success')
            return redirect(url_for('visits'))
    sites_list=many("SELECT s.id,s.code,s.name,z.name zone_name FROM sites s LEFT JOIN zones z ON z.id=s.zone_id WHERE s.situation='ACTIF' AND s.archived_at IS NULL ORDER BY z.name,s.code")
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
        if not sid.isdigit() or not one("SELECT id FROM sites WHERE id=? AND situation='ACTIF' AND archived_at IS NULL",(sid,)):
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
    sites_list=many("SELECT id,code,name FROM sites WHERE (situation='ACTIF' AND archived_at IS NULL) OR id=? ORDER BY code",(v['site_id'],))
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
    start=request.args.get('start',date.today().replace(day=1).isoformat())
    end=request.args.get('end',date.today().isoformat())
    try:
        if date.fromisoformat(start)>date.fromisoformat(end):raise ValueError('Dates inversées')
    except ValueError:abort(400,'Période invalide.')
    ctl=request.args.get('controleur','').strip()
    site=request.args.get('site','').strip()
    status=request.args.get('status','').strip()
    effected=request.args.get('effected','1')
    if effected not in ('0','1','all'):effected='1'
    if status not in ('','EN ATTENTE','VALIDÉE','REJETÉE'):status=''
    if len(ctl)>200 or len(site)>200:abort(400,'Filtre trop long.')
    filters=['v.visit_date BETWEEN ? AND ?'];params=[start,end]
    if current()['role']=='controleur':
        filters.append('v.created_by=?');params.append(current()['id'])
    if ctl:filters.append('v.controleur=?');params.append(ctl)
    if site:
        filters.append('(s.code LIKE ? OR s.name LIKE ?)')
        params.extend([f'%{site}%',f'%{site}%'])
    if status:filters.append('v.status=?');params.append(status)
    if effected!='all':filters.append('v.effected=?');params.append(int(effected))
    rows=many('''SELECT v.id,v.visit_date,s.code,s.name,s.agent_count agents_actuels,
                       v.controleur,v.effected,v.observations,v.status,
                       u.username approver,v.approved_at,creator.username saisi_par
                FROM visits v JOIN sites s ON s.id=v.site_id
                LEFT JOIN users u ON u.id=v.approved_by
                LEFT JOIN users creator ON creator.id=v.created_by
                WHERE '''+' AND '.join(filters)+''' ORDER BY v.visit_date DESC,v.id DESC LIMIT 5000''',params)
    if request.args.get('export')=='csv':
        out=io.StringIO();w=csv.writer(out,delimiter=';')
        w.writerow(['Date','Code site','Nom site','Effectif actuel','Contrôleur','Saisi par','Visité','Observations','Statut','Validateur','Date validation','N° rapport'])
        for r in rows:
            w.writerow([csv_safe(r[k]) for k in ('visit_date','code','name','agents_actuels','controleur','saisi_par','effected','observations','status','approver','approved_at','id')])
        return Response('\ufeff'+out.getvalue(),mimetype='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename=rapports_controleurs_saba.csv','Cache-Control':'no-store'})
    controller_filter = 'WHERE v.created_by=?' if current()['role']=='controleur' else ''
    controller_params = (current()['id'],) if current()['role']=='controleur' else ()
    controllers=[r['controleur'] for r in many('SELECT DISTINCT v.controleur FROM visits v '+controller_filter+' ORDER BY v.controleur',controller_params) if r['controleur']]
    return render_template_string(REPORTS_INLINE_TEMPLATE,rows=rows,start=start,end=end,controllers=controllers,
                                  filtre_controleur=ctl,filtre_site=site,effected=effected,status=status)

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
    return render_template_string(USERS_INLINE_TEMPLATE,users=many('SELECT id,username,role,active,must_change_password FROM users ORDER BY id'))


@app.post('/users/<int:uid>/reset-password')
@role_required('admin')
def user_reset_password(uid):
    if uid==current()['id']:
        flash('Pour votre propre compte, utilisez « Mot de passe ».','danger')
        return redirect(url_for('users'))
    temporary=secrets.token_urlsafe(18)
    with conn() as c:
        user=c.execute('SELECT username,active FROM users WHERE id=?',(uid,)).fetchone()
        if not user:abort(404)
        if not user['active']:abort(409,'Compte inactif.')
        c.execute('''UPDATE users SET password_hash=?,must_change_password=1
                     WHERE id=?''',(generate_password_hash(temporary),uid))
        log(c,'RESET_PASSWORD','user',uid,'Réinitialisation par un administrateur')
    response=app.make_response(render_template_string(USERS_INLINE_TEMPLATE,users=many('SELECT id,username,role,active,must_change_password FROM users ORDER BY id'),
                     temporary_secret=temporary,reset_username=user['username']))
    response.headers['Cache-Control']='no-store, private'
    return response

@app.route('/mot-de-passe-oublie')
def forgot_password():
    return render_template_string(FORGOT_PASSWORD_INLINE_TEMPLATE,recovery_enabled=len(os.environ.get('ADMIN_RECOVERY_KEY',''))>=32)

@app.route('/recuperation-admin',methods=['GET','POST'])
def admin_emergency_recovery():
    recovery_key=os.environ.get('ADMIN_RECOVERY_KEY','')
    if len(recovery_key)<32:abort(404,'Récupération administrateur non configurée.')
    if request.method=='POST':
        username=request.form.get('username','').strip()
        provided=request.form.get('recovery_key','')
        pwd=request.form.get('new_password','')
        # Même message pour éviter de divulguer l'existence d'un compte administrateur.
        user=one("SELECT id FROM users WHERE username=? AND role='admin' AND active=1",(username,))
        if not secrets.compare_digest(provided,recovery_key) or not user:
            flash('Informations de récupération incorrectes.','danger')
        elif len(pwd)<12 or pwd!=request.form.get('confirm_password',''):
            flash('Mot de passe de 12 caractères minimum et confirmation identique obligatoires.','danger')
        else:
            with conn() as c:
                c.execute('UPDATE users SET password_hash=?,must_change_password=0,password_changed_at=? WHERE id=?',
                          (generate_password_hash(pwd),datetime.now().isoformat(timespec='seconds'),user['id']))
                log(c,'RECOVERY_PASSWORD','user',user['id'],'Clé de secours administrateur')
            session.clear()
            flash('Mot de passe administrateur remplacé. Connectez-vous.','success')
            return redirect(url_for('login'))
    response=app.make_response(render_template_string(ADMIN_RECOVERY_INLINE_TEMPLATE))
    response.headers['Cache-Control']='no-store, private'
    return response

@app.route('/password',methods=['GET','POST'])
@login_required
def password():
    me=current()
    forced=bool(me['must_change_password'])
    if request.method=='POST':
        u=one('SELECT password_hash FROM users WHERE id=?',(me['id'],))
        new=request.form.get('new','')
        if not forced and not check_password_hash(u['password_hash'],request.form.get('old','')):
            flash('Ancien mot de passe incorrect.','danger')
        elif len(new)<12 or new!=request.form.get('confirm',''):
            flash('Choisissez 12 caractères minimum et confirmez le nouveau mot de passe.','danger')
        else:
            with conn() as c:
                c.execute('''UPDATE users SET password_hash=?,must_change_password=0,password_changed_at=? WHERE id=?''',
                          (generate_password_hash(new),datetime.now().isoformat(timespec='seconds'),me['id']))
                log(c,'CHANGE_PASSWORD','user',me['id'])
            flash('Mot de passe modifié.','success')
            return redirect(url_for('dashboard'))
    return render_template_string(PASSWORD_INLINE_TEMPLATE,forced=forced)

# CSV et XLSX sans dépendance supplémentaire : compatibles avec Excel.
SITE_COLUMNS=['code','nom','zone','quartier','responsable','client','situation','nombre_agents','observations']

def csv_safe(value):
    # Protéger les colonnes textuelles des formules CSV.
    value='' if value is None else str(value)
    if value.lstrip().startswith(('=','+','-','@','\t','\r','\n')):
        return "'"+value
    return value

def site_export_rows():
    rows=many('''SELECT s.code,s.name nom,z.name zone,s.quartier,s.responsable,s.client,
                       s.situation,s.agent_count nombre_agents,s.observations
                FROM sites s LEFT JOIN zones z ON z.id=s.zone_id
                WHERE s.archived_at IS NULL ORDER BY s.code''')
    return [[r[k] if r[k] is not None else '' for k in SITE_COLUMNS] for r in rows]

def make_xlsx(headers,rows):
    # Fichier xlsx autonome sans bibliothèque supplémentaire.
    table=[headers]+rows
    xrows=[]
    for rownum,row in enumerate(table,1):
        cells=[]
        for colnum,val in enumerate(row):
            col='';n=colnum+1
            while n: n,rem=divmod(n-1,26);col=chr(65+rem)+col
            address=f'{col}{rownum}'
            if val is None:val=''
            if isinstance(val,int) and not isinstance(val,bool):
                cells.append(f'<c r="{address}"><v>{val}</v></c>')
            else:
                cells.append(f'<c r="{address}" t="inlineStr"><is><t xml:space="preserve">{xml_escape(str(val))}</t></is></c>')
        xrows.append(f'<row r="{rownum}">'+''.join(cells)+'</row>')
    lastcol='';n=len(headers)
    while n:n,rem=divmod(n-1,26);lastcol=chr(65+rem)+lastcol
    sheet='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
    <sheetFormatPr defaultRowHeight="16"/><cols><col min="1" max="2" width="23" customWidth="1"/><col min="3" max="9" width="20" customWidth="1"/></cols>
    <sheetData>'''+''.join(xrows)+f'</sheetData><autoFilter ref="A1:{lastcol}{len(table)}"/></worksheet>'
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml','''<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>''')
        z.writestr('_rels/.rels','''<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>''')
        z.writestr('xl/workbook.xml','''<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sites" sheetId="1" r:id="rId1"/></sheets></workbook>''')
        z.writestr('xl/_rels/workbook.xml.rels','''<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>''')
        z.writestr('xl/worksheets/sheet1.xml',sheet)
    return out.getvalue()

def parse_xlsx_rows(data):
    ns={'m':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names=z.namelist()
        if len(names)>250 or sum(x.file_size for x in z.infolist())>35*1024*1024:
            raise ValueError('Fichier Excel trop volumineux.')
        sheets=sorted(x for x in names if re.fullmatch(r'xl/worksheets/sheet\d+\.xml',x))
        if not sheets:raise ValueError('Onglet Excel introuvable.')
        strings=[]
        if 'xl/sharedStrings.xml' in names:
            shared=ET.fromstring(z.read('xl/sharedStrings.xml'))
            strings=[''.join(t.text or '' for t in si.findall('.//m:t',ns)) for si in shared.findall('m:si',ns)]
        root=ET.fromstring(z.read(sheets[0]))
        result=[]
        for row in root.findall('.//m:sheetData/m:row',ns):
            values={}
            for cell in row.findall('m:c',ns):
                cellref=cell.get('r','');match=re.match(r'([A-Z]+)',cellref)
                if not match:continue
                index=0
                for char in match.group(1):index=index*26+ord(char)-64
                index-=1
                t=cell.get('t','');v=cell.find('m:v',ns)
                if t=='inlineStr':
                    value=''.join(x.text or '' for x in cell.findall('.//m:t',ns))
                elif t=='s':
                    pos=int(v.text) if v is not None and v.text else -1
                    value=strings[pos] if 0<=pos<len(strings) else ''
                else:value=v.text if v is not None and v.text else ''
                values[index]=value
            if values:
                result.append([values.get(k,'') for k in range(min(max(values)+1,40))])
            if len(result)>10002:raise ValueError('Maximum 10 000 lignes par import.')
        return result

def normalize_header(raw):
    txt=unicodedata.normalize('NFKD',str(raw or '')).encode('ascii','ignore').decode().lower()
    key=re.sub(r'[^a-z0-9]','',txt)
    aliases={'code':'code','codesite':'code','nom':'nom','name':'nom','nomsite':'nom','nomdusite':'nom',
             'zone':'zone','quartier':'quartier','localisation':'quartier',
             'responsable':'responsable','client':'client','situation':'situation',
             'agents':'nombre_agents','nombreagents':'nombre_agents','nombreagent':'nombre_agents',
             'nombredagents':'nombre_agents','agentsaffectes':'nombre_agents',
             'effectif':'nombre_agents','effectifs':'nombre_agents','agentcount':'nombre_agents',
             'observations':'observations','observation':'observations'}
    return aliases.get(key)

def import_table(data,filename):
    if filename.lower().endswith('.xlsx'):
        raw=parse_xlsx_rows(data)
    else:
        try:content=data.decode('utf-8-sig')
        except UnicodeDecodeError:content=data.decode('cp1252')
        try:dialect=csv.Sniffer().sniff(content[:4096],delimiters=';,\t')
        except csv.Error:dialect=csv.excel
        raw=list(csv.reader(io.StringIO(content),dialect=dialect))
    if not raw:raise ValueError('Le fichier est vide.')
    headers=[normalize_header(x) for x in raw[0]]
    valid_headers=[x for x in headers if x]
    if 'code' not in valid_headers or 'nom' not in valid_headers:
        raise ValueError('Colonnes obligatoires : code et nom.')
    if len(valid_headers)!=len(set(valid_headers)):
        raise ValueError('Colonnes en double dans le fichier.')
    parsed=[];seen=set();skipped=0
    for line,values in enumerate(raw[1:],2):
        if line>10002:raise ValueError('Maximum 10 000 lignes par import.')
        fields={h:str(values[i]).strip() for i,h in enumerate(headers) if h and i<len(values)}
        if not any(fields.values()):skipped+=1;continue
        code=fields.get('code','').upper();name=fields.get('nom','')
        if not code or not name or len(code)>80 or len(name)>200:
            raise ValueError(f'Ligne {line} : code et nom obligatoires (80 et 200 caractères maximum).')
        if code in seen:raise ValueError(f'Ligne {line} : code {code} présent plusieurs fois.')
        seen.add(code);fields['code']=code
        if 'nombre_agents' in fields and fields['nombre_agents']!='':
            try:n=Decimal(fields['nombre_agents'].replace(',','.'))
            except InvalidOperation:raise ValueError(f'Ligne {line} : nombre d’agents invalide.')
            if not n.is_finite() or n!=n.to_integral_value() or n<0 or n>10000:
                raise ValueError(f'Ligne {line} : effectif de 0 à 10 000 requis.')
            fields['nombre_agents']=int(n)
        if 'situation' in fields and fields['situation'] and fields['situation'] not in ('ACTIF','INACTIF'):
            raise ValueError(f'Ligne {line} : situation doit être ACTIF ou INACTIF.')
        parsed.append(fields)
    with conn() as c:
        added=0;updated=0;agents_changed=0
        now=datetime.now().isoformat(timespec='seconds')
        for data in parsed:
            code=data['code'];existing=c.execute('SELECT * FROM sites WHERE code=?',(code,)).fetchone()
            if existing and existing['archived_at']:
                raise ValueError(f'Site {code} archivé : restaurez-le manuellement avant import.')
            zone_id=None
            if data.get('zone'):
                zone=c.execute('SELECT id FROM zones WHERE name=?',(data['zone'],)).fetchone()
                if not zone:
                    cur=c.execute('INSERT INTO zones(name,created_at) VALUES(?,?)',(data['zone'],now))
                    zone_id=cur.lastrowid
                    log(c,'CREATE','zone',zone_id,'Création lors de l’import des sites')
                else:zone_id=zone['id']
            if existing:
                updates={'name':data['nom']}
                for col in ('quartier','responsable','client','situation','observations'):
                    if data.get(col):updates[col]=data[col]
                if zone_id is not None:updates['zone_id']=zone_id
                if isinstance(data.get('nombre_agents'),int):
                    if data['nombre_agents']!=existing['agent_count']:
                        updates.update(agent_count=data['nombre_agents'],agent_count_updated_at=now,agent_count_updated_by=current()['id'])
                        agents_changed+=1
                        log(c,'EFFECTIF','site',existing['id'],json.dumps({'avant':existing['agent_count'],'apres':data['nombre_agents'],'source':'import'},ensure_ascii=False))
                columns=','.join(f'{x}=?' for x in updates)
                c.execute(f'UPDATE sites SET {columns} WHERE id=?',[*updates.values(),existing['id']])
                updated+=1
            else:
                values={'code':code,'name':data['nom'],'zone_id':zone_id,
                        'quartier':data.get('quartier',''),'responsable':data.get('responsable',''),
                        'client':data.get('client',''),'situation':data.get('situation') or 'ACTIF',
                        'observations':data.get('observations',''),'created_at':now}
                if isinstance(data.get('nombre_agents'),int):
                    values.update(agent_count=data['nombre_agents'],agent_count_updated_by=current()['id'],agent_count_updated_at=now)
                    agents_changed+=1
                cols=','.join(values);ph=','.join('?' for _ in values)
                cursor=c.execute(f'INSERT INTO sites({cols}) VALUES({ph})',list(values.values()))
                log(c,'CREATE','site',cursor.lastrowid,'Import de sites')
                added+=1
        log(c,'IMPORT','sites',0,json.dumps({'ajoutes':added,'actualises':updated,'effectifs':agents_changed},ensure_ascii=False))
    return added,updated,agents_changed,skipped

@app.get('/sites/export')
@role_required('admin','coordinateur','securite','dga')
def export_sites():
    fmt=request.args.get('format','xlsx')
    if fmt not in ('xlsx','csv'):abort(400,'Format inconnu.')
    rows=site_export_rows()
    if fmt=='xlsx':
        content=make_xlsx(SITE_COLUMNS,rows)
        return Response(content,mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        headers={'Content-Disposition':'attachment; filename=sites_effectifs_groupe_saba.xlsx','Cache-Control':'no-store'})
    out=io.StringIO();writer=csv.writer(out,delimiter=';');writer.writerow(SITE_COLUMNS)
    for row in rows:writer.writerow([csv_safe(x) for x in row])
    return Response('\ufeff'+out.getvalue(),mimetype='text/csv; charset=utf-8',
                    headers={'Content-Disposition':'attachment; filename=sites_effectifs_groupe_saba.csv','Cache-Control':'no-store'})

@app.get('/sites/modele-import')
@role_required('admin')
def site_import_model():
    return Response('\ufeff'+';'.join(SITE_COLUMNS)+'\r\n',mimetype='text/csv; charset=utf-8',
                    headers={'Content-Disposition':'attachment; filename=modele_import_sites_saba.csv','Cache-Control':'no-store'})

@app.route('/import',methods=['GET','POST'])
@role_required('admin')
def import_sites():
    if request.method=='POST':
        f=request.files.get('file')
        if not f or not f.filename or not f.filename.lower().endswith(('.csv','.xlsx')):
            flash('Veuillez sélectionner un fichier Excel (.xlsx) ou CSV (.csv).','danger')
        else:
            try:
                added,updated,agents,skipped=import_table(f.read(),f.filename)
                flash(f'Import réussi : {added} site(s) ajouté(s), {updated} site(s) mis à jour, {agents} effectif(s) modifié(s), {skipped} ligne(s) vide(s) ignorée(s).','success')
                return redirect(url_for('import_sites'))
            except (ValueError,UnicodeError,zipfile.BadZipFile,ET.ParseError,sqlite3.Error) as e:
                flash(f'Import refusé sans modification : {str(e)[:230]}','danger')
    return render_template_string(IMPORT_INLINE_TEMPLATE)

@app.route('/health')
def health():return {'status':'ok'}

init_db()
if __name__=='__main__':app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')),debug=False)
