from pathlib import Path
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from app import app, db, Item, Location, Container, qr_path, generate_qr, User


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


def test_report_found():
    client = app.test_client()
    login(client)
    with app.app_context():
        item = Item.query.filter_by(name='Hammer').first()
        code = item.code
    client.post(f'/item/{code}/missing', follow_redirects=True)
    client.post(f'/item/{code}/found', follow_redirects=True)
    with app.app_context():
        item = Item.query.filter_by(code=code).first()
        assert item.missing is False


def test_remove_adds_unaccounted():
    client = app.test_client()
    login(client)
    with app.app_context():
        item = Item.query.filter_by(name='Hammer').first()
        code = item.code
    client.get(f'/item/{code}/remove', follow_redirects=True)
    with app.app_context():
        item = Item.query.filter_by(code=code).first()
        assert item.location_id is None and item.container_id is None and item.missing is False


def test_missing_container_list():
    client = app.test_client()
    login(client)
    with app.app_context():
        u = User.query.first()
        c = Container(name='Box', code='CT-test', created_by=u, updated_by=u)
        db.session.add(c)
        db.session.commit()
    client.post('/container/CT-test/missing', follow_redirects=True)
    response = client.get('/')
    assert b'Box' in response.data


def test_join_items():
    client = app.test_client()
    login(client)
    with app.app_context():
        base = Item.query.filter_by(name='Hammer').first()
        base_code = base.code
        u = User.query.first()
        extra = Item(name='Hammer', type='Tool', quantity=2, code='IT-extra',
                     created_by=u, updated_by=u)
        db.session.add(extra)
        db.session.commit()
        generate_qr('IT-extra')
        extra_id = extra.id
    client.post(f'/item/{base_code}/join', data={'items': str(extra_id)}, follow_redirects=True)
    with app.app_context():
        base = Item.query.filter_by(code=base_code).first()
        extra = Item.query.filter_by(id=extra_id).first()
        assert base.quantity == 4
        assert extra is None


def test_add_relation():
    client = app.test_client()
    login(client)
    with app.app_context():
        item = Item.query.filter_by(name='Hammer').first()
        loc = Location.query.filter_by(code='LC-testloc').first()
        item_code = item.code
        loc_code = loc.code
    client.post(f'/relation/add/item/{item_code}', data={'code': loc_code}, follow_redirects=True)
    with app.app_context():
        from app import Relation
        item = Item.query.filter_by(code=item_code).first()
        loc = Location.query.filter_by(code=loc_code).first()
        rel = Relation.query.filter_by(first_type='item', first_id=item.id, second_type='location').first()
        assert rel is not None
        assert item.location_id == loc.id


def test_location_unique_items():
    client = app.test_client()
    login(client)
    with app.app_context():
        loc = Location.query.filter_by(code='LC-testloc').first()
        u = User.query.first()
        cont = Container(name='Box2', code='CT-box2', created_by=u, updated_by=u, location=loc)
        db.session.add(cont)
        item = Item.query.filter_by(name='Hammer').first()
        item.container = cont
        item.location = None
        db.session.commit()
        loc_code = loc.code
    with app.app_context():
        loc = Location.query.filter_by(code=loc_code).first()
        names = [i.name for i in loc.all_items() if i.name == 'Hammer']
        assert len(names) == 1

