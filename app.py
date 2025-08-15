import os
import uuid
import datetime as dt

from flask import (Flask, render_template, request, redirect, url_for, session,
                   flash, jsonify, abort, send_file, Response)
from markupsafe import Markup
from flask_sqlalchemy import SQLAlchemy
from models import db, User, Preference, Location, Container, Item, History, Relation
from utils import (current_user, generate_code, qr_path, generate_qr, generate_pdf, generate_images, parse_custom_data, maybe_title, create_items_from_spec, reassign_code, save_image, log_action)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_, and_
from sqlalchemy.orm import foreign
import qrcode
import glob
import json
import zipfile
from PIL import Image
import math
import shutil
from difflib import SequenceMatcher
import io
import csv


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join('static', 'qr'), exist_ok=True)
app.secret_key = 'inventory-secret'
db.init_app(app)





@app.context_processor
def inject_user():
    return {'current_user': current_user()}


@app.before_request
@app.before_request
def enforce_https():
    if (not request.is_secure and
            request.headers.get('X-Forwarded-Proto', 'http') != 'https' and
            request.host.split(':')[0] not in ('localhost', '127.0.0.1')):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)


@app.before_request
def require_login():
    allowed = {'login', 'register', 'static', 'change_password'}
    if request.endpoint not in allowed and not current_user():
        return redirect(url_for('login'))


@app.route('/prefs/<key>', methods=['GET', 'POST'])
def user_pref(key):
    user = current_user()
    if not user:
        abort(403)
    pref = Preference.query.filter_by(user_id=user.id, key=key).first()
    if request.method == 'POST':
        data = request.get_json() or {}
        val = data.get('value', '')
        if pref:
            pref.value = val
        else:
            pref = Preference(user_id=user.id, key=key, value=val)
            db.session.add(pref)
        db.session.commit()
        return jsonify(success=True)
    return jsonify(value=pref.value if pref else None)

def ensure_admin():
    if not User.query.filter_by(is_admin=True).first():
        admin = User(username='admin', must_change=True,
                     theme_light='#800080', theme_dark='#ffeb3b',
                     is_admin=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()


def migrate_sqlite(path, models, bind=None):
    db.session.remove()
    engine = db.get_engine(app, bind=bind) if bind else db.engine
    if not os.path.exists(path):
        db.create_all(bind_key=bind)
        return
    import sqlite3
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    for model in models:
        table = model.__tablename__
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
        if not cur.fetchone():
            model.__table__.create(bind=engine, checkfirst=True)
            continue
        cur.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cur.fetchall()}
        for col in model.__table__.columns:
            if col.name not in existing:
                coltype = col.type.compile(engine.dialect)
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {col.name} {coltype}")
    conn.commit()
    conn.close()
    db.create_all(bind_key=bind)

def setup_database():
    db.create_all()
    inventory_models = (Location, Container, Item, History, Relation)
    user_models = (User, Preference)
    for model in inventory_models:
        try:
            db.session.query(model).first()
        except Exception:
            migrate_sqlite('inventory.db', inventory_models)
            break
    for model in user_models:
        try:
            db.session.query(model).first()
        except Exception:
            migrate_sqlite('users.db', user_models, bind='users')
            break
    ensure_admin()


with app.app_context():
    setup_database()


@app.route('/')
def index():
    q = request.args.get('q', '')

    def apply_filters(base_query):
        if request.args.get('name'):
            base_query = base_query.filter(Item.name.contains(request.args['name']))
        if request.args.get('type'):
            base_query = base_query.filter(Item.type.contains(request.args['type']))
        if request.args.get('location'):
            base_query = base_query.filter_by(location_id=request.args['location'])
        if request.args.get('container'):
            base_query = base_query.filter_by(container_id=request.args['container'])
        if request.args.get('quantity'):
            base_query = base_query.filter_by(quantity=request.args['quantity'])
        return base_query

    items = apply_filters(Item.query).all()

    all_containers = Container.query.all()
    all_locations = Location.query.all()
    containers = all_containers
    locations = all_locations

    unaccounted = apply_filters(Item.query.filter_by(container_id=None, location_id=None, missing=False)).all()
    missing_items = apply_filters(Item.query.filter_by(missing=True)).all()
    missing_containers = Container.query.filter_by(missing=True).all()

    def item_match(i, needle):
        data = ''
        if i.custom_data:
            try:
                data = json.dumps(json.loads(i.custom_data))
            except Exception:
                data = i.custom_data
        fields = [i.name or '', i.type or '', str(i.quantity), i.code, data]
        if i.location:
            fields.append(i.location.full_path())
        if i.container and i.container.name:
            fields.append(i.container.name)
        return any(_fuzzy_match(f, needle) for f in fields)

    def container_match(c, needle):
        data = ''
        if c.custom_data:
            try:
                data = json.dumps(json.loads(c.custom_data))
            except Exception:
                data = c.custom_data
        fields = [c.name or '', c.size or '', c.color or '', c.code, data]
        return any(_fuzzy_match(f, needle) for f in fields)

    def location_match(l, needle):
        data = ''
        if l.custom_data:
            try:
                data = json.dumps(json.loads(l.custom_data))
            except Exception:
                data = l.custom_data
        fields = [l.full_path(), l.code, data]
        return any(_fuzzy_match(f, needle) for f in fields)

    if q:
        ql = q.lower()
        items = [i for i in items if item_match(i, ql)]
        containers = [c for c in containers if container_match(c, ql)]
        locations = [l for l in locations if location_match(l, ql)]
        unaccounted = [i for i in unaccounted if item_match(i, ql)]
        missing_items = [i for i in missing_items if item_match(i, ql)]
        missing_containers = [c for c in missing_containers if container_match(c, ql)]

    return render_template('index.html', items=items, containers=containers,
                           locations=locations, unaccounted=unaccounted,
                           missing_items=missing_items,
                           missing_containers=missing_containers,
                           all_locations=all_locations, all_containers=all_containers,
                           request=request)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username exists')
        else:
            u = User(username=username)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash('Registered, please login')
            log_action('user registered', None, None, None)
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Logged in')
            log_action('user logged in')
            if user.must_change:
                return redirect(url_for('change_password'))
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out')
    return redirect(url_for('index'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if request.method == 'POST':
        new = request.form['password']
        user.set_password(new)
        user.must_change = False
        db.session.commit()
        flash('Password changed')
        return redirect(url_for('index'))
    return render_template('change_password.html')


@app.route('/account', methods=['GET', 'POST'])
def account():
    user = current_user()
    if request.method == 'POST':
        user.username = request.form['username']
        if request.form.get('password'):
            user.set_password(request.form['password'])
        light = request.form.get('theme_light')
        dark = request.form.get('theme_dark')
        if light:
            user.theme_light = light
        if dark:
            user.theme_dark = dark
        img = save_image(request.files.get('image'), f'user_{user.id}')
        if img:
            user.image = img
        db.session.commit()
        flash('Account updated')
        log_action('updated account')
    return render_template('account.html', user=user)


@app.route('/logs')
def logs():
    user = current_user()
    q = History.query.outerjoin(Item).outerjoin(Container).outerjoin(Location)
    if not user.is_admin:
        q = q.filter(History.user_id == user.id)

    start = request.args.get('start')
    end = request.args.get('end')
    period = request.args.get('period')
    action = request.args.get('action')
    search = request.args.get('q')

    if period:
        now = dt.datetime.utcnow()
        if period == 'day':
            start = (now - dt.timedelta(days=1)).date().isoformat()
        elif period == 'week':
            start = (now - dt.timedelta(weeks=1)).date().isoformat()
        elif period == 'month':
            start = (now - dt.timedelta(days=30)).date().isoformat()

    if start:
        try:
            q = q.filter(History.timestamp >= dt.datetime.fromisoformat(start))
        except ValueError:
            pass
    if end:
        try:
            q = q.filter(History.timestamp <= dt.datetime.fromisoformat(end))
        except ValueError:
            pass
    if action:
        q = q.filter(History.action.contains(action))
    if search:
        q = q.filter(db.or_(History.description.contains(search),
                             Item.name.contains(search),
                             Item.type.contains(search),
                             Container.name.contains(search),
                             Location.name.contains(search)))

    logs = q.order_by(History.timestamp.desc()).all()
    return render_template('admin_log.html', logs=logs)


@app.route('/admin/summary')
def admin_summary():
    user = current_user()
    if not user or not user.is_admin:
        abort(403)
    items_count = Item.query.count()
    containers_count = Container.query.count()
    locations_count = Location.query.count()
    range_key = request.args.get('range')
    start = request.args.get('start')
    end = request.args.get('end')
    today = dt.date.today()
    if range_key:
        if range_key == 'today':
            start = end = today.isoformat()
        elif range_key == 'yesterday':
            d = today - dt.timedelta(days=1)
            start = end = d.isoformat()
        elif range_key == 'this_week':
            start = (today - dt.timedelta(days=today.weekday())).isoformat()
            end = today.isoformat()
        elif range_key == 'last_week':
            end_date = today - dt.timedelta(days=today.weekday() + 1)
            start_date = end_date - dt.timedelta(days=6)
            start, end = start_date.isoformat(), end_date.isoformat()
        elif range_key == 'this_month':
            start = today.replace(day=1).isoformat()
            end = today.isoformat()
        elif range_key == 'last_month':
            first_this = today.replace(day=1)
            last_month_end = first_this - dt.timedelta(days=1)
            start = last_month_end.replace(day=1).isoformat()
            end = last_month_end.isoformat()
        elif range_key == 'this_year':
            start = today.replace(month=1, day=1).isoformat()
            end = today.isoformat()
        elif range_key == 'last_year':
            last_year = today.year - 1
            start = dt.date(last_year, 1, 1).isoformat()
            end = dt.date(last_year, 12, 31).isoformat()
        elif range_key == 'all':
            start = end = None

    start_dt = dt.datetime.fromisoformat(start) if start else None
    end_dt = dt.datetime.fromisoformat(end) if end else None
    if end_dt:
        end_dt = end_dt.replace(hour=23, minute=59, second=59)

    def in_range(query):
        if start_dt:
            query = query.filter(History.timestamp >= start_dt)
        if end_dt:
            query = query.filter(History.timestamp <= end_dt)
        return query

    items_by_location = (db.session.query(Location, db.func.count(Item.id))
                         .outerjoin(Item)
                         .group_by(Location.id).all())
    items_by_type = db.session.query(Item.type, db.func.count(Item.id)).group_by(Item.type).all()
    moves = (in_range(History.query.filter(History.action.in_([
                'item to container', 'item to location', 'container to location'])))
             .order_by(History.timestamp.desc()).limit(20).all())
    activities = in_range(History.query).order_by(History.timestamp.desc()).limit(20).all()
    logins = (in_range(History.query.filter_by(action='user logged in'))
              .order_by(History.timestamp.desc()).limit(20).all())
    return render_template('admin_summary.html', items_count=items_count,
                           containers_count=containers_count,
                           locations_count=locations_count,
                           items_by_location=items_by_location,
                           items_by_type=items_by_type,
                           moves=moves, activities=activities, logins=logins,
                           start=start, end=end)


@app.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    user = current_user()
    if not user or not user.is_admin:
        abort(403)
    if request.method == 'POST':
        if request.form.get('add'):
            username = request.form['username']
            password = request.form['password']
            is_admin = bool(request.form.get('is_admin'))
            new_user = User(username=username, is_admin=is_admin)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('User added', 'info')
        else:
            target = User.query.get_or_404(int(request.form['user_id']))
            if request.form.get('delete'):
                if target.is_admin and User.query.filter(User.is_admin, User.id != target.id).count() == 0:
                    flash('Must have at least one admin', 'danger')
                else:
                    db.session.delete(target)
                    db.session.commit()
                    flash('User deleted', 'info')
            else:
                target.username = request.form['username']
                if request.form.get('password'):
                    target.set_password(request.form['password'])
                new_admin = bool(request.form.get('is_admin'))
                if not new_admin and target.is_admin and User.query.filter(User.is_admin, User.id != target.id).count() == 0:
                    flash('Must have at least one admin', 'danger')
                else:
                    target.is_admin = new_admin
                    db.session.commit()
                    flash('User updated', 'info')
        return redirect(url_for('admin_users'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/ssl', methods=['GET', 'POST'])
def admin_ssl():
    user = current_user()
    if not user or not user.is_admin:
        abort(403)
    if request.method == 'POST':
        cert = request.files.get('cert')
        key = request.files.get('key')
        os.makedirs('ssl', exist_ok=True)
        if cert and cert.filename:
            cext = os.path.splitext(cert.filename)[1] or '.pem'
            for f in glob.glob(os.path.join('ssl', 'cert.*')):
                os.remove(f)
            cert.save(os.path.join('ssl', f'cert{cext}'))
        if key and key.filename:
            kext = os.path.splitext(key.filename)[1] or '.pem'
            for f in glob.glob(os.path.join('ssl', 'key.*')):
                os.remove(f)
            key.save(os.path.join('ssl', f'key{kext}'))
        flash('SSL files uploaded. Configure your server accordingly.', 'info')
        return redirect(url_for('admin_ssl'))
    return render_template('admin_ssl.html')


@app.route('/admin/upload', methods=['GET', 'POST'])
def admin_upload_db():
    user = current_user()
    if not user or not user.is_admin:
        abort(403)
    if request.method == 'POST':
        file = request.files.get('dbfile')
        if file and file.filename:
            filename = secure_filename(file.filename)
            temp = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(temp)
            shutil.move(temp, 'inventory.db')
            migrate_sqlite('inventory.db', (Location, Container, Item, History, Relation))
            flash('Database uploaded and migrated', 'info')
            return redirect(url_for('index'))
    return render_template('upload_db.html')


@app.route('/admin/download/db')
def admin_download_db():
    user = current_user()
    if not user or not user.is_admin:
        abort(403)
    db_path = db.engine.url.database
    return send_file(db_path, as_attachment=True)


@app.route('/admin/download/csv')
def admin_download_csv():
    user = current_user()
    if not user or not user.is_admin:
        abort(403)
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w') as z:
        s = io.StringIO(); w = csv.writer(s)
        w.writerow(['code', 'name', 'quantity', 'type', 'image', 'missing', 'custom_data', 'container_code', 'location_code'])
        for i in Item.query.all():
            w.writerow([
                i.code,
                i.name,
                i.quantity,
                i.type or '',
                i.image or '',
                'true' if i.missing else 'false',
                i.custom_data or '',
                i.container.code if i.container else '',
                i.location.code if i.location else ''
            ])
        z.writestr('items.csv', s.getvalue())
        s = io.StringIO(); w = csv.writer(s)
        w.writerow(['code', 'name', 'size', 'color', 'image', 'missing', 'custom_data', 'location_code', 'parent_code'])
        for c in Container.query.all():
            w.writerow([
                c.code,
                c.name or '',
                c.size or '',
                c.color or '',
                c.image or '',
                'true' if c.missing else 'false',
                c.custom_data or '',
                c.location.code if c.location else '',
                c.parent.code if c.parent else ''
            ])
        z.writestr('containers.csv', s.getvalue())
        s = io.StringIO(); w = csv.writer(s)
        w.writerow(['code', 'name', 'image', 'custom_data', 'parent_code'])
        for l in Location.query.all():
            w.writerow([
                l.code,
                l.name,
                l.image or '',
                l.custom_data or '',
                l.parent.code if l.parent else ''
            ])
        z.writestr('locations.csv', s.getvalue())
        for folder in ('static/uploads', 'static/qr'):
            if os.path.exists(folder):
                for root, _, files in os.walk(folder):
                    for f in files:
                        arc = os.path.relpath(os.path.join(root, f), 'static')
                        z.write(os.path.join(root, f), arcname=arc)
    mem.seek(0)
    return send_file(mem, mimetype='application/zip', as_attachment=True,
                     download_name='inventory_export.zip')


@app.route('/admin/template/<kind>')
def admin_template(kind):
    user = current_user()
    if not user or not user.is_admin:
        abort(403)
    templates = {
        'items': 'code,name,quantity,type,image,missing,custom_data,container_code,location_code\n',
        'containers': 'code,name,size,color,image,missing,custom_data,location_code,parent_code\n',
        'locations': 'code,name,image,custom_data,parent_code\n'
    }
    if kind not in templates:
        abort(404)
    return Response(templates[kind], mimetype='text/csv',
                    headers={'Content-Disposition':
                             f'attachment; filename={kind}_template.csv'})


@app.route('/admin/import', methods=['GET', 'POST'])
def admin_import_csv():
    user = current_user()
    if not user or not user.is_admin:
        abort(403)
    if request.method == 'POST':
        kind = request.form.get('kind')
        file = request.files.get('csv')
        if kind and file and file.filename:
            stream = io.StringIO(file.stream.read().decode('utf-8'))
            reader = csv.DictReader(stream)
            def parse_bool(v):
                return str(v).strip().lower() in ('1', 'true', 'yes', 'y') if v else False
            if kind == 'items':
                for row in reader:
                    name = row.get('name')
                    if not name:
                        continue
                    quantity = int(row.get('quantity') or 1)
                    type_ = row.get('type') or None
                    image = row.get('image') or None
                    missing = parse_bool(row.get('missing'))
                    custom_data = row.get('custom_data') or None
                    loc_code = row.get('location_code')
                    container_code = row.get('container_code')
                    location = Location.query.filter_by(code=loc_code).first() if loc_code else None
                    container = Container.query.filter_by(code=container_code).first() if container_code else None
                    code = row.get('code') or generate_code('IT')
                    item = Item(name=name, quantity=quantity, type=type_, image=image,
                                missing=missing, custom_data=custom_data, code=code,
                                location=location, container=container,
                                created_by=user, updated_by=user)
                    db.session.add(item)
                    generate_qr(code)
                db.session.commit()
                flash('Items imported', 'info')
            elif kind == 'containers':
                for row in reader:
                    name = row.get('name')
                    if not name:
                        continue
                    size = row.get('size') or None
                    color = row.get('color') or None
                    image = row.get('image') or None
                    missing = parse_bool(row.get('missing'))
                    custom_data = row.get('custom_data') or None
                    loc_code = row.get('location_code')
                    location = Location.query.filter_by(code=loc_code).first() if loc_code else None
                    parent_code = row.get('parent_code')
                    parent = Container.query.filter_by(code=parent_code).first() if parent_code else None
                    code = row.get('code') or generate_code('CT')
                    cont = Container(name=name, size=size, color=color, image=image,
                                     missing=missing, custom_data=custom_data,
                                     code=code, location=location, parent=parent,
                                     created_by=user, updated_by=user)
                    db.session.add(cont)
                    generate_qr(code)
                db.session.commit()
                flash('Containers imported', 'info')
            elif kind == 'locations':
                for row in reader:
                    name = row.get('name')
                    if not name:
                        continue
                    image = row.get('image') or None
                    custom_data = row.get('custom_data') or None
                    parent_code = row.get('parent_code')
                    parent = Location.query.filter_by(code=parent_code).first() if parent_code else None
                    code = row.get('code') or generate_code('LC')
                    loc = Location(name=name, image=image, custom_data=custom_data,
                                   code=code, parent=parent,
                                   created_by=user, updated_by=user)
                    db.session.add(loc)
                    generate_qr(code)
                db.session.commit()
                flash('Locations imported', 'info')
        return redirect(url_for('admin_import_csv'))
    return render_template('import_csv.html')


@app.route('/item/<code>')
def item_detail(code):
    item = Item.query.filter_by(code=code).first_or_404()
    rels = Relation.query.filter(or_(and_(Relation.first_type == 'item',
                                         Relation.first_id == item.id),
                                    and_(Relation.second_type == 'item',
                                         Relation.second_id == item.id))).all()
    related = []
    for r in rels:
        if r.first_type == 'item' and r.first_id == item.id:
            ttype, tid = r.second_type, r.second_id
        else:
            ttype, tid = r.first_type, r.first_id
        if ttype == 'item':
            t = Item.query.get(tid)
            related.append({'name': t.name, 'url': url_for('item_detail', code=t.code)})
        elif ttype == 'container':
            t = Container.query.get(tid)
            related.append({'name': t.name or t.code, 'url': url_for('container_detail', code=t.code)})
        else:
            t = Location.query.get(tid)
            related.append({'name': t.full_path(), 'url': url_for('location_detail', code=t.code)})
    data = json.loads(item.custom_data) if item.custom_data else {}
    return render_template('item_detail.html', item=item, related=related, custom_data=data)


@app.route('/container/<code>')
def container_detail(code):
    container = Container.query.filter_by(code=code).first_or_404()
    rels = Relation.query.filter(or_(and_(Relation.first_type == 'container',
                                         Relation.first_id == container.id),
                                    and_(Relation.second_type == 'container',
                                         Relation.second_id == container.id))).all()
    related = []
    for r in rels:
        if r.first_type == 'container' and r.first_id == container.id:
            ttype, tid = r.second_type, r.second_id
        else:
            ttype, tid = r.first_type, r.first_id
        if ttype == 'item':
            t = Item.query.get(tid)
            related.append({'name': t.name, 'url': url_for('item_detail', code=t.code)})
        elif ttype == 'container':
            t = Container.query.get(tid)
            related.append({'name': t.name or t.code, 'url': url_for('container_detail', code=t.code)})
        else:
            t = Location.query.get(tid)
            related.append({'name': t.full_path(), 'url': url_for('location_detail', code=t.code)})
    data = json.loads(container.custom_data) if container.custom_data else {}
    return render_template('container_detail.html', container=container, related=related, custom_data=data)


@app.route('/location/<code>')
def location_detail(code):
    location = Location.query.filter_by(code=code).first_or_404()
    rels = Relation.query.filter(or_(and_(Relation.first_type == 'location',
                                         Relation.first_id == location.id),
                                    and_(Relation.second_type == 'location',
                                         Relation.second_id == location.id))).all()
    related = []
    for r in rels:
        if r.first_type == 'location' and r.first_id == location.id:
            ttype, tid = r.second_type, r.second_id
        else:
            ttype, tid = r.first_type, r.first_id
        if ttype == 'item':
            t = Item.query.get(tid)
            related.append({'name': t.name, 'url': url_for('item_detail', code=t.code)})
        elif ttype == 'container':
            t = Container.query.get(tid)
            related.append({'name': t.name or t.code, 'url': url_for('container_detail', code=t.code)})
        else:
            t = Location.query.get(tid)
            related.append({'name': t.full_path(), 'url': url_for('location_detail', code=t.code)})
    data = json.loads(location.custom_data) if location.custom_data else {}
    return render_template('location_detail.html', location=location, related=related, custom_data=data)


@app.route('/add/item', methods=['GET', 'POST'])
def add_item():
    if request.method == 'POST':
        name = maybe_title(request.form['name'])
        type_ = maybe_title(request.form['type'])
        quantity = int(request.form['quantity'])
        code = request.form.get('code') or generate_code('IT')
        if request.form.get('code'):
            reassign_code(code)
        img = save_image(request.files.get('image'), code)
        custom_data = parse_custom_data(request.form.get('custom_data'))
        location_id = request.form.get('location')
        location = Location.query.get(location_id) if location_id else None
        existing = Item.query.filter(db.func.lower(Item.name) == name.lower()).first()
        item = Item(name=name, type=type_, quantity=quantity, code=code, image=img,
                    custom_data=custom_data, location=location,
                    created_by=current_user(), updated_by=current_user())
        db.session.add(item)
        db.session.commit()
        generate_qr(code)
        log_action('created item', item=item)
        if existing:
            undo_url = url_for('delete_item', code=code)
            msg = Markup(
                f"Warning: <a href='{url_for('item_detail', code=existing.code)}'><b>{existing.name}</b></a> already exists with quantity {existing.quantity}. "
                f"<a class='btn btn-sm btn-danger ms-2' href='{undo_url}'>Undo</a>"
            )
            flash(msg, 'warning')
        return redirect(url_for('item_detail', code=code))
    names = [n[0] for n in db.session.query(Item.name).distinct()]
    types = [t[0] for t in db.session.query(Item.type).distinct()]
    locations = Location.query.all()
    return render_template('add_item.html', names=names, types=types,
                           locations=locations, edit=False,
                           code=request.args.get('code'))


@app.route('/add/container', methods=['GET', 'POST'])
def add_container():
    if request.method == 'POST':
        name = maybe_title(request.form['name'])
        size = maybe_title(request.form['size'])
        color = maybe_title(request.form['color'])
        code = request.form.get('code') or generate_code('CT')
        if request.form.get('code'):
            reassign_code(code)
        img = save_image(request.files.get('image'), code)
        custom_data = parse_custom_data(request.form.get('custom_data'))
        location_id = request.form.get('location')
        location = Location.query.get(location_id) if location_id else None
        container = Container(name=name, size=size, color=color,
                              code=code, image=img,
                              custom_data=custom_data, location=location,
                              created_by=current_user(), updated_by=current_user())
        db.session.add(container)
        db.session.commit()
        items_spec = request.form.get('items', '').strip()
        if items_spec:
            create_items_from_spec(container, items_spec)
            db.session.commit()
        generate_qr(code)
        log_action('created container', container=container)
        return redirect(url_for('container_detail', code=code))
    sizes = [s[0] for s in db.session.query(Container.size).filter(Container.size != None).distinct()]
    colors = [c[0] for c in db.session.query(Container.color).filter(Container.color != None).distinct()]
    locations = Location.query.all()
    return render_template('add_container.html', sizes=sizes, colors=colors,
                           locations=locations, edit=False,
                           code=request.args.get('code'))


@app.route('/add/location', methods=['GET', 'POST'])
def add_location():
    parents = Location.query.all()
    if request.method == 'POST':
        name = maybe_title(request.form['name'])
        parent_id = request.form.get('parent_id') or None
        code = request.form.get('code') or generate_code('LC')
        if request.form.get('code'):
            reassign_code(code)
        img = save_image(request.files.get('image'), code)
        custom_data = parse_custom_data(request.form.get('custom_data'))
        location = Location(name=name, parent_id=parent_id, code=code, image=img,
                             custom_data=custom_data,
                             created_by=current_user(), updated_by=current_user())
        db.session.add(location)
        db.session.commit()
        generate_qr(code)
        log_action('created location', location=location)
        return redirect(url_for('location_detail', code=code))
    names = [n[0] for n in db.session.query(Location.name).distinct()]
    return render_template('add_location.html', locations=parents, names=names,
                           edit=False, code=request.args.get('code'))


@app.route('/item/<code>/edit', methods=['GET', 'POST'])
def edit_item(code):
    item = Item.query.filter_by(code=code).first_or_404()
    if request.method == 'POST':
        item.name = maybe_title(request.form['name'])
        item.type = maybe_title(request.form['type'])
        item.quantity = int(request.form['quantity'])
        img = save_image(request.files.get('image'), item.code)
        if img:
            item.image = img
        item.custom_data = parse_custom_data(request.form.get('custom_data'))
        item.updated_by = current_user()
        db.session.commit()
        log_action('edited item', item=item)
        return redirect(url_for('item_detail', code=code))
    names = [n[0] for n in db.session.query(Item.name).distinct()]
    types = [t[0] for t in db.session.query(Item.type).distinct()]
    locations = Location.query.all()
    return render_template('add_item.html', item=item, edit=True,
                           names=names, types=types, locations=locations)


@app.route('/item/<code>/delete')
def delete_item(code):
    item = Item.query.filter_by(code=code).first_or_404()
    log_action('deleted item', item=item)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/container/<code>/edit', methods=['GET', 'POST'])
def edit_container(code):
    container = Container.query.filter_by(code=code).first_or_404()
    if request.method == 'POST':
        container.name = maybe_title(request.form['name'])
        container.size = maybe_title(request.form['size'])
        container.color = maybe_title(request.form['color'])
        img = save_image(request.files.get('image'), container.code)
        if img:
            container.image = img
        container.custom_data = parse_custom_data(request.form.get('custom_data'))
        container.updated_by = current_user()
        db.session.commit()
        items_spec = request.form.get('items', '').strip()
        if items_spec:
            create_items_from_spec(container, items_spec)
            db.session.commit()
        log_action('edited container', container=container)
        return redirect(url_for('container_detail', code=code))
    sizes = [s[0] for s in db.session.query(Container.size).filter(Container.size != None).distinct()]
    colors = [c[0] for c in db.session.query(Container.color).filter(Container.color != None).distinct()]
    locations = Location.query.all()
    return render_template('add_container.html', container=container, edit=True,
                           sizes=sizes, colors=colors, locations=locations)


@app.route('/container/<code>/delete')
def delete_container(code):
    container = Container.query.filter_by(code=code).first_or_404()
    log_action('deleted container', container=container)
    db.session.delete(container)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/container/<code>/remove')
def remove_container_location(code):
    container = Container.query.filter_by(code=code).first_or_404()
    container.location = None
    container.updated_by = current_user()
    db.session.add(History(container=container, action='removed from location', user=current_user()))
    for it in container.items:
        it.location = None
        it.updated_by = current_user()
        db.session.add(History(item=it, action='removed from location', user=current_user()))
    db.session.commit()
    log_action('removed container from location', container=container)
    return redirect(url_for('container_detail', code=code))


@app.route('/container/<code>/missing', methods=['POST'])
def report_container_missing(code):
    container = Container.query.filter_by(code=code).first_or_404()
    container.missing = True
    container.updated_by = current_user()
    db.session.commit()
    log_action('reported missing container', container=container)
    return redirect(url_for('container_detail', code=code))


@app.route('/container/<code>/found', methods=['POST'])
def report_container_found(code):
    container = Container.query.filter_by(code=code).first_or_404()
    container.missing = False
    container.updated_by = current_user()
    db.session.commit()
    log_action('reported found container', container=container)
    return redirect(url_for('container_detail', code=code))


@app.route('/container/<code>/regen', methods=['POST'])
def regenerate_container_code(code):
    container = Container.query.filter_by(code=code).first_or_404()
    new_code = generate_code('CT')
    if container.image:
        ext = os.path.splitext(container.image)[1]
        old_path = os.path.join('static', container.image)
        new_rel = os.path.join('uploads', f'{new_code}{ext}')
        new_path = os.path.join('static', new_rel)
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
        container.image = new_rel
    old_qr = qr_path(container.code)
    if os.path.exists(old_qr):
        os.remove(old_qr)
    container.code = new_code
    db.session.commit()
    generate_qr(new_code)
    log_action('regenerated container code', container=container)
    return redirect(url_for('container_detail', code=new_code))


@app.route('/container/<code>/assign', methods=['POST'])
def assign_container_code(code):
    container = Container.query.filter_by(code=code).first_or_404()
    data = request.get_json() or {}
    new_code = data.get('code')
    if not new_code:
        abort(400)
    existing = (Item.query.filter_by(code=new_code).first() or
                Container.query.filter_by(code=new_code).first() or
                Location.query.filter_by(code=new_code).first())
    if existing and existing != container:
        if not data.get('confirm'):
            return jsonify({'conflict': True}), 409
        reassign_code(new_code)
    old_code = container.code
    if container.image:
        ext = os.path.splitext(container.image)[1]
        old_path = os.path.join('static', container.image)
        new_rel = os.path.join('uploads', f'{new_code}{ext}')
        new_path = os.path.join('static', new_rel)
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
        container.image = new_rel
    old_qr = qr_path(container.code)
    if os.path.exists(old_qr):
        os.remove(old_qr)
    container.code = new_code
    db.session.commit()
    generate_qr(new_code)
    log_action('code reassigned', container=container,
               description=f'{old_code} -> {new_code}')
    return jsonify({'ok': True})


@app.route('/location/<code>/edit', methods=['GET', 'POST'])
def edit_location(code):
    location = Location.query.filter_by(code=code).first_or_404()
    parents = Location.query.filter(Location.id != location.id).all()
    if request.method == 'POST':
        location.name = maybe_title(request.form['name'])
        parent_id = request.form.get('parent_id') or None
        location.parent_id = parent_id
        img = save_image(request.files.get('image'), location.code)
        if img:
            location.image = img
        location.custom_data = parse_custom_data(request.form.get('custom_data'))
        location.updated_by = current_user()
        db.session.commit()
        log_action('edited location', location=location)
        return redirect(url_for('location_detail', code=code))
    names = [n[0] for n in db.session.query(Location.name).distinct()]
    return render_template('add_location.html', location=location,
                           locations=parents, names=names, edit=True)


@app.route('/location/<code>/delete')
def delete_location(code):
    location = Location.query.filter_by(code=code).first_or_404()
    if location.children:
        abort(400)
    log_action('deleted location', location=location)
    db.session.delete(location)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/location/<code>/regen', methods=['POST'])
def regenerate_location_code(code):
    location = Location.query.filter_by(code=code).first_or_404()
    new_code = generate_code('LC')
    if location.image:
        ext = os.path.splitext(location.image)[1]
        old_path = os.path.join('static', location.image)
        new_rel = os.path.join('uploads', f'{new_code}{ext}')
        new_path = os.path.join('static', new_rel)
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
        location.image = new_rel
    old_qr = qr_path(location.code)
    if os.path.exists(old_qr):
        os.remove(old_qr)
    location.code = new_code
    db.session.commit()
    generate_qr(new_code)
    log_action('regenerated location code', location=location)
    return redirect(url_for('location_detail', code=new_code))


@app.route('/location/<code>/assign', methods=['POST'])
def assign_location_code(code):
    location = Location.query.filter_by(code=code).first_or_404()
    data = request.get_json() or {}
    new_code = data.get('code')
    if not new_code:
        abort(400)
    existing = (Item.query.filter_by(code=new_code).first() or
                Container.query.filter_by(code=new_code).first() or
                Location.query.filter_by(code=new_code).first())
    if existing and existing != location:
        if not data.get('confirm'):
            return jsonify({'conflict': True}), 409
        reassign_code(new_code)
    old_code = location.code
    if location.image:
        ext = os.path.splitext(location.image)[1]
        old_path = os.path.join('static', location.image)
        new_rel = os.path.join('uploads', f'{new_code}{ext}')
        new_path = os.path.join('static', new_rel)
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
        location.image = new_rel
    old_qr = qr_path(location.code)
    if os.path.exists(old_qr):
        os.remove(old_qr)
    location.code = new_code
    db.session.commit()
    generate_qr(new_code)
    log_action('code reassigned', location=location,
               description=f'{old_code} -> {new_code}')
    return jsonify({'ok': True})


@app.route('/scan/<code>')
def scan(code):
    obj = (Item.query.filter_by(code=code).first() or
           Container.query.filter_by(code=code).first() or
           Location.query.filter_by(code=code).first())
    if not obj:
        if request.args.get('ajax'):
            return jsonify({'error': 'Unknown code'}), 404
        flash('Unknown code')
        return redirect(url_for('index'))

    now = dt.datetime.utcnow()
    window = float(request.args.get('window', 5))
    force_process = window == 0

    scans = session.get('scan_codes', [])
    last_time = session.get('scan_time')
    if last_time and not force_process:
        last_dt = dt.datetime.fromisoformat(last_time)
        if (now - last_dt).total_seconds() > window:
            scans = []

    if code not in scans:
        scans.append(code)
    session['scan_time'] = now.isoformat()

    remaining, message = process_multiple(scans)

    if force_process:
        session.pop('scan_codes', None)
        session.pop('scan_time', None)
    else:
        session['scan_codes'] = remaining

    if request.args.get('ajax'):
        name = getattr(obj, 'name', None)
        if message:
            return jsonify({'message': message, 'name': name})
        else:
            type_name = obj.__class__.__name__.lower()
            return jsonify({'pending': True, 'type': type_name, 'code': obj.code, 'name': name})

    return render_template('scan.html', obj=obj, message=message)


def process_pair(first_code: str, second_code: str) -> str:
    first = (Item.query.filter_by(code=first_code).first() or
             Container.query.filter_by(code=first_code).first() or
             Location.query.filter_by(code=first_code).first())
    second = (Item.query.filter_by(code=second_code).first() or
              Container.query.filter_by(code=second_code).first() or
              Location.query.filter_by(code=second_code).first())

    # item-item -> no action
    if isinstance(first, Item) and isinstance(second, Item):
        return 'No action for scanned pair.'

    # item-container or container-item -> item goes into container
    if isinstance(first, Item) and isinstance(second, Container):
        child, parent = first, second
    elif isinstance(first, Container) and isinstance(second, Item):
        child, parent = second, first
    else:
        child = parent = None
    if child and parent:
        child.container = parent
        child.location = None
        child.updated_by = current_user()
        db.session.commit()
        msg = f'Item <b>{child.name}</b> was moved to <b>{parent.name}</b>'
        log_action('item to container', item=child, container=parent)
        return msg

    # item-location or location-item -> item to location
    if isinstance(first, Item) and isinstance(second, Location):
        itm, loc = first, second
    elif isinstance(first, Location) and isinstance(second, Item):
        itm, loc = second, first
    else:
        itm = loc = None
    if itm and loc:
        itm.location = loc
        itm.container = None
        itm.updated_by = current_user()
        db.session.commit()
        msg = f'Item <b>{itm.name}</b> was moved to <b>{loc.name}</b>'
        log_action('item to location', item=itm, location=loc)
        return msg

    # container-location or location-container -> container to location
    if isinstance(first, Container) and isinstance(second, Location):
        cont, loc = first, second
    elif isinstance(first, Location) and isinstance(second, Container):
        cont, loc = second, first
    else:
        cont = loc = None
    if cont and loc:
        cont.location = loc
        cont.parent = None
        cont.updated_by = current_user()
        db.session.commit()
        msg = f'Container <b>{cont.name}</b> was moved to <b>{loc.name}</b>'
        log_action('container to location', container=cont, location=loc)
        for it in cont.items:
            it.location = loc
            it.updated_by = current_user()
            db.session.add(History(item=it, location=loc,
                                   user=current_user(), action='item to location',
                                   description=f'Item <b>{it.name}</b> was moved to <b>{loc.name}</b>'))
        db.session.commit()
        return msg

    # container-container -> first container into second
    if isinstance(first, Container) and isinstance(second, Container):
        first.parent = second
        first.location = second.location
        first.updated_by = current_user()
        db.session.commit()
        msg = f'Container <b>{first.name}</b> was moved into <b>{second.name}</b>'
        log_action('container to container', container=first, location=second.location,
                   description=(
                       f"Container <a href='{url_for('container_detail', code=first.code)}'><b>{first.name}</b></a> "
                       f"was stored in <a href='{url_for('container_detail', code=second.code)}'><b>{second.name}</b></a>"
                   ))
        return msg

    # location-location -> first location becomes child of second
    if isinstance(first, Location) and isinstance(second, Location):
        first.parent = second
        first.updated_by = current_user()
        db.session.commit()
        msg = f'Location <b>{first.name}</b> was moved under <b>{second.name}</b>'
        log_action('edited location', location=first)
        return msg

    return 'No action for scanned pair.'


def process_multiple(codes: list[str]) -> tuple[list[str], str | None]:
    """Process a list of scanned codes according to the pairing rules.

    Returns a tuple of (remaining_codes, message). remaining_codes contains
    codes that should be kept for subsequent scans (e.g. a container or
    location acting as the parent for further items). message is the last
    action performed, if any.
    """

    objs = []
    for c in codes:
        obj = (Item.query.filter_by(code=c).first() or
               Container.query.filter_by(code=c).first() or
               Location.query.filter_by(code=c).first())
        if obj:
            objs.append(obj)

    if len(objs) < 2:
        return codes, None

    items = [o for o in objs if isinstance(o, Item)]
    containers = [o for o in objs if isinstance(o, Container)]
    locations = [o for o in objs if isinstance(o, Location)]
    messages: list[str] = []

    # Exactly two codes - just process the pair and determine base
    if len(objs) == 2:
        msg = process_pair(codes[0], codes[1])
        messages.append(msg)
        base: list[str] = []
        if ((isinstance(objs[0], Item) and isinstance(objs[1], Container)) or
                (isinstance(objs[0], Container) and isinstance(objs[1], Item)) or
                (isinstance(objs[0], Container) and isinstance(objs[1], Container))):
            base_code = objs[0].code if isinstance(objs[0], Container) and isinstance(objs[1], Item) else objs[1].code
            base = [base_code]
        elif ((isinstance(objs[0], Item) and isinstance(objs[1], Location)) or
              (isinstance(objs[0], Location) and isinstance(objs[1], Item)) or
              (isinstance(objs[0], Container) and isinstance(objs[1], Location)) or
              (isinstance(objs[0], Location) and isinstance(objs[1], Container)) or
              (isinstance(objs[0], Location) and isinstance(objs[1], Location))):
            base_code = objs[0].code if isinstance(objs[0], Location) and not isinstance(objs[1], Location) else objs[1].code
            base = [base_code]
        return base, messages[-1]

    # More than two codes
    if len(locations) == 1 and len(containers) + len(items) >= 1:
        loc = locations[0]
        for obj in [o for o in objs if o is not loc]:
            messages.append(process_pair(obj.code, loc.code))
        return [loc.code], messages[-1]

    if len(containers) == 1 and len(locations) == 0:
        cont = containers[0]
        for obj in [o for o in objs if o is not cont]:
            messages.append(process_pair(obj.code, cont.code))
        return [cont.code], messages[-1]

    if len(locations) >= 2 and len(containers) == 0 and len(items) == 0:
        base_loc = locations[0]
        for loc in locations[1:]:
            messages.append(process_pair(loc.code, base_loc.code))
        return [base_loc.code], messages[-1]

    base_obj = objs[0]
    for obj in objs[1:]:
        messages.append(process_pair(base_obj.code, obj.code))
    keep = [base_obj.code] if isinstance(base_obj, (Container, Location)) else []
    return keep, messages[-1] if messages else None


@app.route('/registrations', methods=['GET', 'POST'])
def registrations():
    items = Item.query.all()
    containers = Container.query.all()
    locations = Location.query.all()
    message = None
    if request.method == 'POST':
        first = request.form['first']
        second = request.form['second']
        message = process_pair(first, second)
    return render_template('registrations.html', items=items, containers=containers, locations=locations, message=message)


@app.route('/relation/add/<etype>/<code>', methods=['GET', 'POST'])
def add_relation(etype, code):
    obj = (Item.query.filter_by(code=code).first() or
           Container.query.filter_by(code=code).first() or
           Location.query.filter_by(code=code).first_or_404())
    items = Item.query.all()
    containers = Container.query.all()
    locations = Location.query.all()
    if request.method == 'POST':
        tcode = request.form['code']
        # perform the same pairing logic as manual registration
        message = process_pair(code, tcode)
        target = (Item.query.filter_by(code=tcode).first() or
                  Container.query.filter_by(code=tcode).first() or
                  Location.query.filter_by(code=tcode).first())
        if target:
            if isinstance(target, Item):
                ttype = 'item'
            elif isinstance(target, Container):
                ttype = 'container'
            else:
                ttype = 'location'
            rel = Relation(first_type=etype, first_id=obj.id,
                           second_type=ttype, second_id=target.id)
            db.session.add(rel)
            db.session.commit()
        if message:
            flash(Markup(message), 'info')
        return redirect(url_for(f'{etype}_detail', code=code))
    return render_template('add_relation.html', etype=etype, obj=obj,
                           items=items, containers=containers, locations=locations)


@app.route('/item/<code>/split', methods=['GET', 'POST'])
def split_item(code):
    item = Item.query.filter_by(code=code).first_or_404()
    if request.method == 'POST':
        qty = int(request.form['quantity'])
        if 0 < qty < item.quantity:
            item.quantity -= qty
            item.updated_by = current_user()
            new_code = generate_code('IT')
            img = save_image(request.files.get('image'), new_code)
            new_item = Item(name=item.name, type=item.type, quantity=qty,
                            code=new_code, image=img,
                            created_by=current_user(), updated_by=current_user())
            db.session.add(new_item)
            db.session.commit()
            generate_qr(new_code)
            log_action('split', item=item,
                       description=(f"<a href='{url_for('item_detail', code=item.code)}'><b>{item.name}</b></a> was split; "
                                    f"<a href='{url_for('item_detail', code=new_item.code)}'><b>{new_item.name}</b></a> created with {qty}"))
            log_action('split from', item=new_item,
                       description=(f"<a href='{url_for('item_detail', code=new_item.code)}'><b>{new_item.name}</b></a> came from "
                                    f"<a href='{url_for('item_detail', code=item.code)}'><b>{item.name}</b></a>"))
            return redirect(url_for('item_detail', code=code))
    return render_template('split_item.html', item=item)


@app.route('/item/<code>/join', methods=['GET', 'POST'])
def join_item(code):
    item = Item.query.filter_by(code=code).first_or_404()
    candidates = Item.query.filter_by(name=item.name).filter(Item.id != item.id).all()
    if request.method == 'POST':
        selected = request.form.getlist('items')
        for sid in selected:
            other = Item.query.get(int(sid))
            if other:
                item.quantity += other.quantity
                log_action('joined item', item=item,
                           description=(f"<a href='{url_for('item_detail', code=other.code)}'><b>{other.name}</b></a> joined into "
                                        f"<a href='{url_for('item_detail', code=item.code)}'><b>{item.name}</b></a>"))
                db.session.delete(other)
        item.updated_by = current_user()
        db.session.commit()
        return redirect(url_for('item_detail', code=code))
    return render_template('join_item.html', item=item, candidates=candidates)


@app.route('/item/<code>/remove')
def remove_item_location(code):
    item = Item.query.filter_by(code=code).first_or_404()
    item.location = None
    item.container = None
    item.missing = False
    item.updated_by = current_user()
    db.session.add(History(item=item, action='removed from location',
                           user=current_user()))
    db.session.commit()
    log_action('removed from location', item=item)
    return redirect(url_for('item_detail', code=code))


@app.route('/item/<code>/missing', methods=['POST'])
def report_missing(code):
    item = Item.query.filter_by(code=code).first_or_404()
    item.missing = True
    item.updated_by = current_user()
    db.session.commit()
    log_action('reported missing item', item=item)
    return redirect(url_for('item_detail', code=code))


@app.route('/item/<code>/found', methods=['POST'])
def report_found(code):
    item = Item.query.filter_by(code=code).first_or_404()
    item.missing = False
    item.updated_by = current_user()
    db.session.commit()
    log_action('reported found item', item=item)
    return redirect(url_for('item_detail', code=code))


@app.route('/item/<code>/regen', methods=['POST'])
def regenerate_code(code):
    item = Item.query.filter_by(code=code).first_or_404()
    new_code = generate_code('IT')
    if item.image:
        ext = os.path.splitext(item.image)[1]
        old_path = os.path.join('static', item.image)
        new_rel = os.path.join('uploads', f'{new_code}{ext}')
        new_path = os.path.join('static', new_rel)
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
        item.image = new_rel
    old_qr = qr_path(item.code)
    if os.path.exists(old_qr):
        os.remove(old_qr)
    item.code = new_code
    db.session.commit()
    generate_qr(new_code)
    log_action('regenerated code', item=item)
    return redirect(url_for('item_detail', code=new_code))


@app.route('/item/<code>/assign', methods=['POST'])
def assign_item_code(code):
    item = Item.query.filter_by(code=code).first_or_404()
    data = request.get_json() or {}
    new_code = data.get('code')
    if not new_code:
        abort(400)
    existing = (Item.query.filter_by(code=new_code).first() or
                Container.query.filter_by(code=new_code).first() or
                Location.query.filter_by(code=new_code).first())
    if existing and existing != item:
        if not data.get('confirm'):
            return jsonify({'conflict': True}), 409
        reassign_code(new_code)
    old_code = item.code
    if item.image:
        ext = os.path.splitext(item.image)[1]
        old_path = os.path.join('static', item.image)
        new_rel = os.path.join('uploads', f'{new_code}{ext}')
        new_path = os.path.join('static', new_rel)
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
        item.image = new_rel
    old_qr = qr_path(item.code)
    if os.path.exists(old_qr):
        os.remove(old_qr)
    item.code = new_code
    db.session.commit()
    generate_qr(new_code)
    log_action('code reassigned', item=item,
               description=f'{old_code} -> {new_code}')
    return jsonify({'ok': True})


@app.route('/scanner')
def scanner():
    return render_template('scanner.html')


def _fuzzy_match(haystack, needle):
    hay = haystack.lower()
    return needle in hay or SequenceMatcher(None, hay, needle).ratio() > 0.6


@app.route('/autocomplete')
def autocomplete():
    q = request.args.get('q', '').lower()
    suggestions = set()
    for item in Item.query.all():
        suggestions.update([item.name or '', item.code])
        if item.custom_data:
            try:
                data = json.loads(item.custom_data)
                for k, v in data.items():
                    suggestions.add(str(k))
                    suggestions.add(str(v))
            except Exception:
                suggestions.add(item.custom_data)
    for c in Container.query.all():
        suggestions.update([c.name or '', c.code])
        if c.custom_data:
            try:
                data = json.loads(c.custom_data)
                for k, v in data.items():
                    suggestions.add(str(k))
                    suggestions.add(str(v))
            except Exception:
                suggestions.add(c.custom_data)
    for l in Location.query.all():
        suggestions.update([l.name or '', l.code])
        if l.custom_data:
            try:
                data = json.loads(l.custom_data)
                for k, v in data.items():
                    suggestions.add(str(k))
                    suggestions.add(str(v))
            except Exception:
                suggestions.add(l.custom_data)
    if q:
        filtered = [s for s in suggestions if _fuzzy_match(s, q)]
    else:
        filtered = list(suggestions)
    return jsonify(sorted([s for s in filtered if s])[:10])


@app.route('/qr/batch', methods=['GET', 'POST'])
def qr_batch():
    codes = []
    zip_name = None
    pdf_name = None
    img_zip_name = None
    cols = 4
    rows = 8
    if request.method == 'POST':
        count = int(request.form.get('count', '1'))
        qr_type = request.form.get('qr_type', 'undefined')
        cols = int(request.form.get('cols', cols))
        rows = int(request.form.get('rows', rows))
        prefix_map = {'item': 'IT', 'container': 'CT', 'location': 'LC', 'undefined': 'QR'}
        prefix = prefix_map.get(qr_type, 'QR')
        for _ in range(count):
            code = generate_code(prefix)
            codes.append(code)
            generate_qr(code)
        zip_name = f"batch_{uuid.uuid4().hex}.zip"
        zip_path = os.path.join('static', 'qr', zip_name)
        with zipfile.ZipFile(zip_path, 'w') as zf:
            for c in codes:
                zf.write(qr_path(c), arcname=f'{c}.png')
        pdf_name = f"batch_{uuid.uuid4().hex}.pdf"
        pdf_path = os.path.join('static', 'qr', pdf_name)
        generate_pdf(codes, pdf_path, cols=cols, rows=rows)
        img_zip_name = f"batch_{uuid.uuid4().hex}_images.zip"
        img_base = os.path.join('static', 'qr', f"batch_{uuid.uuid4().hex}")
        img_files = generate_images(codes, img_base, cols=cols, rows=rows)
        img_zip_path = os.path.join('static', 'qr', img_zip_name)
        with zipfile.ZipFile(img_zip_path, 'w') as zf:
            for f in img_files:
                zf.write(f, arcname=os.path.basename(f))
    return render_template('batch_qr.html', codes=codes,
                           zip_name=zip_name, pdf_name=pdf_name,
                           img_zip_name=img_zip_name,
                           cols=cols if request.method == 'POST' else 4,
                           rows=rows if request.method == 'POST' else 8)


if __name__ == '__main__':
    with app.app_context():
        setup_database()
    ssl = None
    if os.environ.get('FLASK_NO_SSL') != '1':
        cert_files = glob.glob(os.path.join('ssl', 'cert.*'))
        key_files = glob.glob(os.path.join('ssl', 'key.*'))
        if cert_files and key_files:
            ssl = (cert_files[0], key_files[0])
        else:
            ssl = 'adhoc'
    app.run(host='0.0.0.0', port=5000, ssl_context=ssl)

