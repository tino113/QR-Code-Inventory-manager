import os
import uuid
import datetime as dt

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import qrcode

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'inventory-secret'

db = SQLAlchemy(app)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String, unique=True, nullable=False)
    name = db.Column(db.String, nullable=False)
    type = db.Column(db.String, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    container_id = db.Column(db.Integer, db.ForeignKey('container.id'))
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    histories = db.relationship('History', backref='item', lazy=True)


class Container(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String, unique=True, nullable=False)
    contents = db.Column(db.String)
    size = db.Column(db.String)
    color = db.Column(db.String)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    items = db.relationship('Item', backref='container', lazy=True)
    histories = db.relationship('History', backref='container', lazy=True)


class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String, unique=True, nullable=False)
    room = db.Column(db.String)
    area = db.Column(db.String)
    spot = db.Column(db.String)
    items = db.relationship('Item', backref='location', lazy=True)
    containers = db.relationship('Container', backref='location', lazy=True)
    histories = db.relationship('History', backref='location', lazy=True)


class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=dt.datetime.utcnow)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'))
    container_id = db.Column(db.Integer, db.ForeignKey('container.id'))
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    action = db.Column(db.String)


def generate_code(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def qr_path(code: str) -> str:
    return os.path.join('static', 'qr', f'{code}.png')


def generate_qr(code: str):
    img = qrcode.make(code)
    path = qr_path(code)
    img.save(path)
    return path


@app.route('/')
def index():
    items = Item.query.all()
    containers = Container.query.all()
    locations = Location.query.all()
    unaccounted = Item.query.filter_by(container_id=None, location_id=None).all()
    return render_template('index.html', items=items, containers=containers,
                           locations=locations, unaccounted=unaccounted)


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
        item = Item(name=name, type=type_, quantity=quantity, code=code)
        db.session.add(item)
        db.session.commit()
        generate_qr(code)
        return redirect(url_for('item_detail', code=code))
    return render_template('add_item.html')


@app.route('/add/container', methods=['GET', 'POST'])
def add_container():
    if request.method == 'POST':
        contents = request.form['contents']
        size = request.form['size']
        color = request.form['color']
        code = generate_code('CT')
        container = Container(contents=contents, size=size, color=color, code=code)
        db.session.add(container)
        db.session.commit()
        generate_qr(code)
        return redirect(url_for('container_detail', code=code))
    return render_template('add_container.html')


@app.route('/add/location', methods=['GET', 'POST'])
def add_location():
    if request.method == 'POST':
        room = request.form['room']
        area = request.form['area']
        spot = request.form['spot']
        code = generate_code('LC')
        location = Location(room=room, area=area, spot=spot, code=code)
        db.session.add(location)
        db.session.commit()
        generate_qr(code)
        return redirect(url_for('location_detail', code=code))
    return render_template('add_location.html')


@app.route('/scan/<code>')
def scan(code):
    obj = (Item.query.filter_by(code=code).first() or
           Container.query.filter_by(code=code).first() or
           Location.query.filter_by(code=code).first())
    if not obj:
        flash('Unknown code')
        return redirect(url_for('index'))

    now = dt.datetime.utcnow()
    last = session.get('last_scan')
    message = None
    if last:
        last_time = dt.datetime.fromisoformat(last['time'])
        if (now - last_time).total_seconds() <= 10 and last['code'] != code:
            message = process_pair(last['code'], code)
            session.pop('last_scan')
        else:
            session['last_scan'] = {'code': code, 'time': now.isoformat()}
    else:
        session['last_scan'] = {'code': code, 'time': now.isoformat()}
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
        history = History(item=first, container=second, action='item to container')
        db.session.add(history)
        db.session.commit()
        return f'Item {first.name} added to container.'
    if isinstance(first, Item) and isinstance(second, Location):
        first.location = second
        history = History(item=first, location=second, action='item to location')
        db.session.add(history)
        db.session.commit()
        return f'Item {first.name} moved to location.'
    if isinstance(first, Container) and isinstance(second, Location):
        first.location = second
        history = History(container=first, location=second, action='container to location')
        for it in first.items:
            it.location = second
            db.session.add(History(item=it, location=second, action='item to location'))
        db.session.add(history)
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
            new_code = generate_code('IT')
            new_item = Item(name=item.name, type=item.type, quantity=qty, code=new_code)
            db.session.add(new_item)
            db.session.add(History(item=item, action='split'))
            db.session.add(History(item=new_item, action='split from'))
            db.session.commit()
            generate_qr(new_code)
            return redirect(url_for('item_detail', code=code))
    return render_template('split_item.html', item=item)


@app.route('/item/<code>/remove')
def remove_item_location(code):
    item = Item.query.filter_by(code=code).first_or_404()
    item.location = None
    item.container = None
    db.session.add(History(item=item, action='removed from location'))
    db.session.commit()
    return redirect(url_for('item_detail', code=code))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
