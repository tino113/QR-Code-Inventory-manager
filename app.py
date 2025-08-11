import os
import uuid
import datetime as dt

from flask import (Flask, render_template, request, redirect, url_for, session,
                   flash, jsonify, abort)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import qrcode


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


class Container(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String, unique=True, nullable=False)
    contents = db.Column(db.String)
    size = db.Column(db.String)
    color = db.Column(db.String)
    image = db.Column(db.String)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    updated_by = db.relationship('User', foreign_keys=[updated_by_id])
    items = db.relationship('Item', backref='container', lazy=True)
    histories = db.relationship('History', backref='container', lazy=True)


class Item(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String, unique=True, nullable=False)
    name = db.Column(db.String, nullable=False)
    type = db.Column(db.String, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String)
    missing = db.Column(db.Boolean, default=False)
    container_id = db.Column(db.Integer, db.ForeignKey('container.id'))
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    updated_by = db.relationship('User', foreign_keys=[updated_by_id])
    histories = db.relationship('History', backref='item', lazy=True)


class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=dt.datetime.utcnow)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'))
    container_id = db.Column(db.Integer, db.ForeignKey('container.id'))
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String)
    user = db.relationship('User', backref='histories')


def current_user():
    uid = session.get('user_id')
    if uid:
        return User.query.get(uid)
    return None


@app.context_processor
def inject_user():
    return {'current_user': current_user()}


@app.before_request
def require_login():
    allowed = {'login', 'register', 'static', 'change_password'}
    if request.endpoint not in allowed and not current_user():
        return redirect(url_for('login'))

def ensure_admin():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', must_change=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

def setup_database():
    try:
        db.create_all()
        ensure_admin()
    except Exception:
        db.drop_all()
        db.create_all()
        ensure_admin()


with app.app_context():
    setup_database()


def generate_code(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def qr_path(code: str) -> str:
    return os.path.join('static', 'qr', f'{code}.png')


def generate_qr(code: str):
    img = qrcode.make(code)
    path = qr_path(code)
    img.save(path)
    return path


def save_image(file, code: str):
    if file and file.filename:
        ext = os.path.splitext(file.filename)[1]
        filename = secure_filename(f"{code}{ext}")
        rel_path = os.path.join('uploads', filename).replace('\\', '/')
        file.save(os.path.join('static', rel_path))
        return rel_path
    return None


def log_action(action, item=None, container=None, location=None):
    h = History(action=action, item=item, container=container,
                location=location, user=current_user())
    db.session.add(h)
    db.session.commit()


@app.route('/')
def index():
    q = request.args.get('q', '')
    item_query = Item.query
    if request.args.get('name'):
        item_query = item_query.filter(Item.name.contains(request.args['name']))
    if request.args.get('location'):
        item_query = item_query.filter_by(location_id=request.args['location'])
    if request.args.get('container'):
        item_query = item_query.filter_by(container_id=request.args['container'])
    if request.args.get('quantity'):
        item_query = item_query.filter_by(quantity=request.args['quantity'])
    items = item_query.all()

    all_containers = Container.query.all()
    all_locations = Location.query.all()
    containers = Container.query
    locations = Location.query
    if q:
        items = [i for i in items if q.lower() in i.name.lower()]
        containers = containers.filter(Container.contents.contains(q)).all()
        locations = locations.filter(Location.name.contains(q)).all()
    else:
        containers = containers.all()
        locations = locations.all()

    unaccounted = Item.query.filter_by(container_id=None, location_id=None, missing=False).all()
    missing_items = Item.query.filter_by(missing=True).all()
    return render_template('index.html', items=items, containers=containers,
                           locations=locations, unaccounted=unaccounted,
                           missing_items=missing_items,
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
    q = History.query.order_by(History.timestamp.desc())
    if user.username != 'admin':
        q = q.filter_by(user_id=user.id)
    logs = q.all()
    return render_template('admin_log.html', logs=logs)


@app.route('/item/<code>')
def item_detail(code):
    item = Item.query.filter_by(code=code).first_or_404()
    return render_template('item_detail.html', item=item)


@app.route('/container/<code>')
def container_detail(code):
    container = Container.query.filter_by(code=code).first_or_404()
    return render_template('container_detail.html', container=container)


@app.route('/location/<code>')
def location_detail(code):
    location = Location.query.filter_by(code=code).first_or_404()
    return render_template('location_detail.html', location=location)


@app.route('/add/item', methods=['GET', 'POST'])
def add_item():
    if request.method == 'POST':
        name = request.form['name']
        type_ = request.form['type']
        quantity = int(request.form['quantity'])
        code = generate_code('IT')
        img = save_image(request.files.get('image'), code)
        item = Item(name=name, type=type_, quantity=quantity, code=code, image=img,
                    created_by=current_user(), updated_by=current_user())
        db.session.add(item)
        db.session.commit()
        generate_qr(code)
        log_action('created item', item=item)
        return redirect(url_for('item_detail', code=code))
    return render_template('add_item.html')


@app.route('/add/container', methods=['GET', 'POST'])
def add_container():
    if request.method == 'POST':
        contents = request.form['contents']
        size = request.form['size']
        color = request.form['color']
        code = generate_code('CT')
        img = save_image(request.files.get('image'), code)
        container = Container(contents=contents, size=size, color=color,
                              code=code, image=img,
                              created_by=current_user(), updated_by=current_user())
        db.session.add(container)
        db.session.commit()
        generate_qr(code)
        log_action('created container', container=container)
        return redirect(url_for('container_detail', code=code))
    return render_template('add_container.html')


@app.route('/add/location', methods=['GET', 'POST'])
def add_location():
    parents = Location.query.all()
    if request.method == 'POST':
        name = request.form['name']
        parent_id = request.form.get('parent_id') or None
        code = generate_code('LC')
        img = save_image(request.files.get('image'), code)
        location = Location(name=name, parent_id=parent_id, code=code, image=img,
                             created_by=current_user(), updated_by=current_user())
        db.session.add(location)
        db.session.commit()
        generate_qr(code)
        log_action('created location', location=location)
        return redirect(url_for('location_detail', code=code))
    return render_template('add_location.html', locations=parents)


@app.route('/item/<code>/edit', methods=['GET', 'POST'])
def edit_item(code):
    item = Item.query.filter_by(code=code).first_or_404()
    if request.method == 'POST':
        item.name = request.form['name']
        item.type = request.form['type']
        item.quantity = int(request.form['quantity'])
        img = save_image(request.files.get('image'), item.code)
        if img:
            item.image = img
        item.updated_by = current_user()
        db.session.commit()
        log_action('edited item', item=item)
        return redirect(url_for('item_detail', code=code))
    return render_template('add_item.html', item=item, edit=True)


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
        container.contents = request.form['contents']
        container.size = request.form['size']
        container.color = request.form['color']
        img = save_image(request.files.get('image'), container.code)
        if img:
            container.image = img
        container.updated_by = current_user()
        db.session.commit()
        log_action('edited container', container=container)
        return redirect(url_for('container_detail', code=code))
    return render_template('add_container.html', container=container, edit=True)


@app.route('/container/<code>/delete')
def delete_container(code):
    container = Container.query.filter_by(code=code).first_or_404()
    log_action('deleted container', container=container)
    db.session.delete(container)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/location/<code>/edit', methods=['GET', 'POST'])
def edit_location(code):
    location = Location.query.filter_by(code=code).first_or_404()
    parents = Location.query.filter(Location.id != location.id).all()
    if request.method == 'POST':
        location.name = request.form['name']
        parent_id = request.form.get('parent_id') or None
        location.parent_id = parent_id
        img = save_image(request.files.get('image'), location.code)
        if img:
            location.image = img
        location.updated_by = current_user()
        db.session.commit()
        log_action('edited location', location=location)
        return redirect(url_for('location_detail', code=code))
    return render_template('add_location.html', location=location,
                           locations=parents, edit=True)


@app.route('/location/<code>/delete')
def delete_location(code):
    location = Location.query.filter_by(code=code).first_or_404()
    if location.children:
        abort(400)
    log_action('deleted location', location=location)
    db.session.delete(location)
    db.session.commit()
    return redirect(url_for('index'))


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
        if message:
            return jsonify({'message': message})
        else:
            type_name = obj.__class__.__name__.lower()
            return jsonify({'pending': True, 'type': type_name, 'code': obj.code})

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
        log_action('item to container', item=first, container=second)
        return f'Item {first.name} added to container.'
    if isinstance(first, Item) and isinstance(second, Location):
        first.location = second
        first.container = None
        first.updated_by = current_user()
        db.session.commit()
        log_action('item to location', item=first, location=second)
        return f'Item {first.name} moved to location.'
    if isinstance(first, Container) and isinstance(second, Location):
        first.location = second
        first.updated_by = current_user()
        db.session.commit()
        log_action('container to location', container=first, location=second)
        for it in first.items:
            it.location = second
            it.updated_by = current_user()
            db.session.add(History(item=it, location=second,
                                   user=current_user(), action='item to location'))
        db.session.commit()
        return 'Container moved to location.'
    return 'No action for scanned pair.'


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
            db.session.add(History(item=item, action='split', user=current_user()))
            db.session.add(History(item=new_item, action='split from',
                                   user=current_user()))
            db.session.commit()
            generate_qr(new_code)
            return redirect(url_for('item_detail', code=code))
    return render_template('split_item.html', item=item)


@app.route('/item/<code>/remove')
def remove_item_location(code):
    item = Item.query.filter_by(code=code).first_or_404()
    item.location = None
    item.container = None
    item.updated_by = current_user()
    db.session.add(History(item=item, action='removed from location',
                           user=current_user()))
    db.session.commit()
    return redirect(url_for('item_detail', code=code))


@app.route('/item/<code>/missing', methods=['POST'])
def report_missing(code):
    item = Item.query.filter_by(code=code).first_or_404()
    item.missing = True
    item.updated_by = current_user()
    db.session.commit()
    log_action('reported missing', item=item)
    return redirect(url_for('item_detail', code=code))


@app.route('/scanner')
def scanner():
    return render_template('scanner.html')


if __name__ == '__main__':
    with app.app_context():
        setup_database()
    app.run(host='0.0.0.0', port=5000)

