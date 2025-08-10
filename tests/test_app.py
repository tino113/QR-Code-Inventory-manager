from pathlib import Path
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from app import app, db, Item, Location, qr_path, generate_qr, User


def setup_module(module):
    with app.app_context():
        db.drop_all()
        db.create_all()
        u = User(username='tester')
        u.set_password('test')
        db.session.add(u)
        db.session.commit()


def login(client):
    client.post('/login', data={'username': 'tester', 'password': 'test'})


def test_add_item():
    client = app.test_client()
    login(client)
    response = client.post('/add/item', data={'name': 'Hammer', 'type': 'Tool', 'quantity': '3'}, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        item = Item.query.filter_by(name='Hammer').one()
        assert item.quantity == 3
        assert Path(qr_path(item.code)).exists()


def test_split_item():
    with app.app_context():
        item = Item.query.filter_by(name='Hammer').first()
        code = item.code
    client = app.test_client()
    login(client)
    client.post(f'/item/{code}/split', data={'quantity': '1'}, follow_redirects=True)
    with app.app_context():
        item = Item.query.filter_by(code=code).first()
        new_items = Item.query.filter(Item.code != code).all()
        assert item.quantity == 2
        assert len(new_items) == 1
        assert new_items[0].quantity == 1


def test_scan_pair_item_location():
    import time
    client = app.test_client()
    login(client)
    with app.app_context():
        item = Item.query.filter_by(name='Hammer').first()
        item_code = item.code
        loc = Location(name='Room1', code='LC-testloc')
        db.session.add(loc)
        db.session.commit()
        if not Path(qr_path(loc.code)).exists():
            generate_qr(loc.code)
        loc_code = loc.code
    client.get(f'/scan/{item_code}')
    time.sleep(1)
    client.get(f'/scan/{loc_code}')
    with app.app_context():
        item = Item.query.filter_by(code=item_code).first()
        loc = Location.query.filter_by(code='LC-testloc').first()
        assert item.location_id == loc.id


def test_report_missing():
    client = app.test_client()
    login(client)
    with app.app_context():
        item = Item.query.filter_by(name='Hammer').first()
        code = item.code
    client.post(f'/item/{code}/missing', follow_redirects=True)
    with app.app_context():
        item = Item.query.filter_by(code=code).first()
        assert item.missing is True

