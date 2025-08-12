import os
import uuid
import datetime as dt

from flask import (Flask, render_template, request, redirect, url_for, session,
                   flash, jsonify, abort)
from markupsafe import Markup
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_, and_
import qrcode
import glob
import json
import zipfile
from PIL import Image


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join('static', 'qr'), exist_ok=True)
app.secret_key = 'inventory-secret'

db = SQLAlchemy(app)


class TimestampMixin:
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow,
                           onupdate=dt.datetime.utcnow)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    must_change = db.Column(db.Boolean, default=False)
    image = db.Column(db.String)
    theme_light = db.Column(db.String, default='#800080')
    theme_dark = db.Column(db.String, default='#ffeb3b')
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Location(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String, unique=True, nullable=False)
    name = db.Column(db.String, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    parent = db.relationship('Location', remote_side=[id], backref='children')
    image = db.Column(db.String)
    custom_data = db.Column(db.Text)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    updated_by = db.relationship('User', foreign_keys=[updated_by_id])

    items = db.relationship('Item', backref='location', lazy=True)
    containers = db.relationship('Container', backref='location', lazy=True)
    histories = db.relationship('History', backref='location', lazy=True)

    def full_path(self):
        if self.parent:
            return f"{self.parent.full_path()} / {self.name}"
        return self.name

    def all_items(self):
        seen = {}
        for i in self.items:
            seen[i.id] = i
        for c in self.containers:
            for i in c.items:
                seen[i.id] = i
        for child in self.children:
            for i in child.all_items():
                seen[i.id] = i
        return list(seen.values())

    def all_containers(self):
        conts = list(self.containers)
        for child in self.children:
            conts.extend(child.all_containers())
        return conts


class Container(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String, unique=True, nullable=False)
    name = db.Column(db.String)
    size = db.Column(db.String)
    color = db.Column(db.String)
    image = db.Column(db.String)
    missing = db.Column(db.Boolean, default=False)
    custom_data = db.Column(db.Text)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    updated_by = db.relationship('User', foreign_keys=[updated_by_id])
    items = db.relationship('Item', backref='container', lazy=True)
    histories = db.relationship('History', backref='container', lazy=True)

    def path_from(self, loc):
        parts = []
        cur = self.location
        while cur and cur != loc:
            parts.append(cur.name)
            cur = cur.parent
        return ' / '.join(parts)


class Item(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String, unique=True, nullable=False)
    name = db.Column(db.String, nullable=False)
    type = db.Column(db.String, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String)
    missing = db.Column(db.Boolean, default=False)
    custom_data = db.Column(db.Text)
    container_id = db.Column(db.Integer, db.ForeignKey('container.id'))
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    updated_by = db.relationship('User', foreign_keys=[updated_by_id])
    histories = db.relationship('History', backref='item', lazy=True)

    def hierarchy(self):
        parts = []
        if self.container:
            parts.append(self.container.name or self.container.code)
        if self.location:
            parts.append(self.location.full_path())
        return ' / '.join(parts)

    def path_from(self, loc):
        parts = []
        container = self.container
        if container:
            parts.append(container.name or container.code)
            cur = container.location
        else:
            cur = self.location
        while cur and cur != loc:
            parts.append(cur.name)
            cur = cur.parent
        return ' / '.join(parts)


class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=dt.datetime.utcnow)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'))
    container_id = db.Column(db.Integer, db.ForeignKey('container.id'))
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String)
    description = db.Column(db.Text)
    user = db.relationship('User', backref='histories')


class Relation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_type = db.Column(db.String, nullable=False)
    first_id = db.Column(db.Integer, nullable=False)
    second_type = db.Column(db.String, nullable=False)
    second_id = db.Column(db.Integer, nullable=False)


def current_user():
    uid = session.get('user_id')
    if uid:
        return User.query.get(uid)
    return None


@app.context_processor
def inject_user():
    return {'current_user': current_user()}


@app.before_request
def enforce_https():
    if (not request.is_secure and
            request.host.split(':')[0] not in ('localhost', '127.0.0.1')):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url)


@app.before_request
def require_login():
    allowed = {'login', 'register', 'static', 'change_password'}
    if request.endpoint not in allowed and not current_user():
        return redirect(url_for('login'))

def ensure_admin():
    if not User.query.filter_by(is_admin=True).first():
        admin = User(username='admin', must_change=True,
                     theme_light='#800080', theme_dark='#ffeb3b',
                     is_admin=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

def setup_database():
    try:
        db.create_all()
        # issue simple selects to ensure all tables match the models;
        # missing columns will raise an OperationalError which triggers
        # a full rebuild of the schema
        for model in (User, Location, Container, Item, History, Relation):
            db.session.query(model).first()
        ensure_admin()
    except Exception:
        db.drop_all()
        db.create_all()
        ensure_admin()


with app.app_context():
    setup_database()


def generate_code(prefix: str) -> str:
    """Generate a unique code with the given prefix.

    The function ensures the generated code is not already associated with
    any existing item, container or location and that no QR image exists for
    it yet. This prevents accidental reuse of codes when generating batches of
    QR codes."""
    while True:
        code = f"{prefix}-{uuid.uuid4().hex[:8]}"
        exists = (Item.query.filter_by(code=code).first() or
                  Container.query.filter_by(code=code).first() or
                  Location.query.filter_by(code=code).first())
        if exists or os.path.exists(qr_path(code)):
            continue
        return code


def qr_path(code: str) -> str:
    return os.path.join('static', 'qr', f'{code}.png')


def generate_qr(code: str):
    img = qrcode.make(code)
    path = qr_path(code)
    img.save(path)
    return path


def generate_pdf(codes, path, cols=4, rows=8):
    """Create a simple A4 PDF grid of QR codes."""
    width, height = 2480, 3508  # A4 at 300 DPI
    page = Image.new('RGB', (width, height), 'white')
    side = min(width // cols, height // rows)
    margin_x = (width - side * cols) // 2
    margin_y = (height - side * rows) // 2
    for idx, code in enumerate(codes):
        img = Image.open(qr_path(code)).resize((side, side))
        x = margin_x + (idx % cols) * side
        y = margin_y + (idx // cols) * side
        page.paste(img, (x, y))
    page.save(path, 'PDF', resolution=300.0)


def parse_custom_data(data_str):
    if not data_str:
        return None
    try:
        obj = json.loads(data_str)
    except Exception:
        obj = {}
        for line in data_str.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
            elif '=' in line:
                k, v = line.split('=', 1)
            else:
                continue
            obj[k.strip()] = v.strip()
    return json.dumps(obj)


def reassign_code(code):
    existing = (Item.query.filter_by(code=code).first() or
                Container.query.filter_by(code=code).first() or
                Location.query.filter_by(code=code).first())
    if existing:
        prefix = existing.code.split('-')[0]
        new_code = generate_code(prefix)
        old_qr = qr_path(existing.code)
        existing.code = new_code
        db.session.commit()
        if os.path.exists(old_qr):
            os.remove(old_qr)
        generate_qr(new_code)
        log_action('regenerated code', item=existing if isinstance(existing, Item) else None,
                   container=existing if isinstance(existing, Container) else None,
                   location=existing if isinstance(existing, Location) else None)


def save_image(file, code: str):
    if file and file.filename:
        ext = os.path.splitext(file.filename)[1]
        filename = secure_filename(f"{code}{ext}")
        rel_path = os.path.join('uploads', filename).replace('\\', '/')
        file.save(os.path.join('static', rel_path))
        return rel_path
    return None


def log_action(action, item=None, container=None, location=None, description=None):
    if description is None:
        if action == 'item to container' and item and container:
            description = (
                f"Item <a href='{url_for('item_detail', code=item.code)}'><b>{item.name}</b></a> "
                f"was moved to <a href='{url_for('container_detail', code=container.code)}'><b>{container.name}</b></a>"
            )
        elif action == 'item to location' and item and location:
            description = (
                f"Item <a href='{url_for('item_detail', code=item.code)}'><b>{item.name}</b></a> "
                f"was moved to <a href='{url_for('location_detail', code=location.code)}'><b>{location.name}</b></a>"
            )
        elif action == 'container to location' and container and location:
            description = (
                f"Container <a href='{url_for('container_detail', code=container.code)}'><b>{container.name}</b></a> "
                f"was moved to <a href='{url_for('location_detail', code=location.code)}'><b>{location.name}</b></a>"
            )
        elif action == 'created item' and item:
            description = f"<b><a href='{url_for('item_detail', code=item.code)}'>{item.name}</a></b> was created"
        elif action == 'created container' and container:
            description = f"<b><a href='{url_for('container_detail', code=container.code)}'>{container.name}</a></b> was created"
        elif action == 'created location' and location:
            description = f"<b><a href='{url_for('location_detail', code=location.code)}'>{location.name}</a></b> was created"
        elif action == 'edited item' and item:
            description = f"<b><a href='{url_for('item_detail', code=item.code)}'>{item.name}</a></b> was edited"
        elif action == 'edited container' and container:
            description = f"<b><a href='{url_for('container_detail', code=container.code)}'>{container.name}</a></b> was edited"
        elif action == 'edited location' and location:
            description = f"<b><a href='{url_for('location_detail', code=location.code)}'>{location.name}</a></b> was edited"
        elif action == 'deleted item' and item:
            description = f"<b>{item.name}</b> was deleted"
        elif action == 'deleted container' and container:
            description = f"<b>{container.name}</b> was deleted"
        elif action == 'deleted location' and location:
            description = f"<b>{location.name}</b> was deleted"
        elif action == 'reported missing item' and item:
            description = (
                f"Item <a href='{url_for('item_detail', code=item.code)}'><b>{item.name}</b></a> was reported missing"
            )
        elif action == 'reported missing container' and container:
            description = (
                f"Container <a href='{url_for('container_detail', code=container.code)}'><b>{container.name}</b></a> was reported missing"
            )
        elif action == 'reported found item' and item:
            description = (
                f"Item <a href='{url_for('item_detail', code=item.code)}'><b>{item.name}</b></a> was reported found"
            )
        elif action == 'reported found container' and container:
            description = (
                f"Container <a href='{url_for('container_detail', code=container.code)}'><b>{container.name}</b></a> was reported found"
            )
        elif action == 'removed from location' and item:
            description = (
                f"Item <a href='{url_for('item_detail', code=item.code)}'><b>{item.name}</b></a> was removed from its location"
            )
        elif action == 'removed container from location' and container:
            description = (
                f"Container <a href='{url_for('container_detail', code=container.code)}'><b>{container.name}</b></a> was removed from its location"
            )
        elif action == 'regenerated code' and item:
            description = f"<b><a href='{url_for('item_detail', code=item.code)}'>{item.name}</a></b> QR code regenerated"
        elif action == 'regenerated container code' and container:
            description = f"<b><a href='{url_for('container_detail', code=container.code)}'>{container.name}</a></b> QR code regenerated"
        elif action == 'regenerated location code' and location:
            description = f"<b><a href='{url_for('location_detail', code=location.code)}'>{location.name}</a></b> QR code regenerated"
        elif action == 'split' and item:
            description = f"<b><a href='{url_for('item_detail', code=item.code)}'>{item.name}</a></b> was split"
        elif action == 'split from' and item:
            description = f"<b><a href='{url_for('item_detail', code=item.code)}'>{item.name}</a></b> was created from a split"
        elif action == 'joined item' and item:
            description = f"Items were joined into <b><a href='{url_for('item_detail', code=item.code)}'>{item.name}</a></b>"
        else:
            description = action
    h = History(action=action, description=description, item=item,
                container=container, location=location, user=current_user())
    db.session.add(h)
    db.session.commit()


@app.route('/')
def index():
    q = request.args.get('q', '')
    item_query = Item.query
    if request.args.get('name'):
        item_query = item_query.filter(Item.name.contains(request.args['name']))
    if request.args.get('type'):
        item_query = item_query.filter(Item.type.contains(request.args['type']))
    if request.args.get('location'):
        item_query = item_query.filter_by(location_id=request.args['location'])
    if request.args.get('container'):
        item_query = item_query.filter_by(container_id=request.args['container'])
    if request.args.get('quantity'):
        item_query = item_query.filter_by(quantity=request.args['quantity'])
    items = item_query.all()

    all_containers = Container.query.all()
    all_locations = Location.query.all()
    containers = all_containers
    locations = all_locations
    if q:
        ql = q.lower()
        items = [i for i in items if ql in i.name.lower() or ql in i.type.lower() or ql in str(i.quantity) or (i.location and ql in i.location.full_path().lower()) or (i.container and i.container.name and ql in i.container.name.lower())]
        containers = [c for c in containers if (c.name and ql in c.name.lower()) or (c.size and ql in c.size.lower()) or (c.color and ql in c.color.lower())]
        locations = [l for l in locations if ql in l.full_path().lower()]

    unaccounted = Item.query.filter_by(container_id=None, location_id=None, missing=False).all()
    missing_items = Item.query.filter_by(missing=True).all()
    missing_containers = Container.query.filter_by(missing=True).all()
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
    items_by_location = (db.session.query(Location, db.func.count(Item.id))
                         .outerjoin(Item)
                         .group_by(Location.id).all())
    items_by_type = db.session.query(Item.type, db.func.count(Item.id)).group_by(Item.type).all()
    moves = (History.query.filter(History.action.in_([
                'item to container', 'item to location', 'container to location']))
             .order_by(History.timestamp.desc()).limit(20).all())
    activities = History.query.order_by(History.timestamp.desc()).limit(20).all()
    logins = (History.query.filter_by(action='user logged in')
              .order_by(History.timestamp.desc()).limit(20).all())
    return render_template('admin_summary.html', items_count=items_count,
                           containers_count=containers_count,
                           locations_count=locations_count,
                           items_by_location=items_by_location,
                           items_by_type=items_by_type,
                           moves=moves, activities=activities, logins=logins)


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
        name = request.form['name'].title()
        type_ = request.form['type'].title()
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
        name = request.form['name'].title()
        size = request.form['size'].title()
        color = request.form['color'].title()
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
        name = request.form['name'].title()
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
        item.name = request.form['name'].title()
        item.type = request.form['type'].title()
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
        container.name = request.form['name'].title()
        container.size = request.form['size'].title()
        container.color = request.form['color'].title()
        img = save_image(request.files.get('image'), container.code)
        if img:
            container.image = img
        container.custom_data = parse_custom_data(request.form.get('custom_data'))
        container.updated_by = current_user()
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
        location.name = request.form['name'].title()
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
    window = float(request.args.get('window', 10))
    last = session.get('last_scan')
    message = None
    if last:
        last_time = dt.datetime.fromisoformat(last['time'])
        if (now - last_time).total_seconds() <= last.get('window', window) and last['code'] != code:
            message = process_pair(last['code'], code)
            session.pop('last_scan')
        else:
            session['last_scan'] = {'code': code, 'time': now.isoformat(), 'window': window}
    else:
        session['last_scan'] = {'code': code, 'time': now.isoformat(), 'window': window}

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
    if isinstance(first, Item) and isinstance(second, Container):
        first.container = second
        first.location = None
        first.updated_by = current_user()
        db.session.commit()
        msg = f'Item <b>{first.name}</b> was moved to <b>{second.name}</b>'
        log_action('item to container', item=first, container=second)
        return msg
    if isinstance(first, Item) and isinstance(second, Location):
        first.location = second
        first.container = None
        first.updated_by = current_user()
        db.session.commit()
        msg = f'Item <b>{first.name}</b> was moved to <b>{second.name}</b>'
        log_action('item to location', item=first, location=second)
        return msg
    if isinstance(first, Container) and isinstance(second, Location):
        first.location = second
        first.updated_by = current_user()
        db.session.commit()
        msg = f'Container <b>{first.name}</b> was moved to <b>{second.name}</b>'
        log_action('container to location', container=first, location=second)
        for it in first.items:
            it.location = second
            it.updated_by = current_user()
            db.session.add(History(item=it, location=second,
                                   user=current_user(), action='item to location',
                                   description=f'Item <b>{it.name}</b> was moved to <b>{second.name}</b>'))
        db.session.commit()
        return msg
    return 'No action for scanned pair.'


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


@app.route('/qr/batch', methods=['GET', 'POST'])
def qr_batch():
    codes = []
    zip_name = None
    pdf_name = None
    if request.method == 'POST':
        count = int(request.form.get('count', '1'))
        qr_type = request.form.get('qr_type', 'undefined')
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
        generate_pdf(codes, pdf_path)
    return render_template('batch_qr.html', codes=codes,
                           zip_name=zip_name, pdf_name=pdf_name)


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

