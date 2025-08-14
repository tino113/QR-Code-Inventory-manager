from pathlib import Path
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from app import app, db, Item, Location, Container, qr_path, generate_qr, User, History, setup_database


def setup_module(module):
    with app.app_context():
        db.session.remove()
        for bind in (None, 'users', 'locations', 'containers', 'items'):
            engine = db.get_engine(app, bind=bind) if bind else db.engine
            engine.dispose()
        for f in ('inventory.db', 'users.db', 'locations.db', 'containers.db', 'items.db'):
            for p in [Path(f), Path('instance') / f]:
                if p.exists():
                    p.unlink()
        setup_database()
        if not User.query.filter_by(username='tester').first():
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


def test_add_container_with_items():
    client = app.test_client()
    login(client)
    response = client.post('/add/container', data={'name': 'Crate', 'size': '', 'color': '', 'items': 'rope 20 climbing, nails 200 hardware'}, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        cont = Container.query.filter_by(name='Crate').one()
        items = {i.name: (i.quantity, i.type) for i in cont.items}
        assert items['Rope'] == (20, 'Climbing')
        assert items['Nails'] == (200, 'Hardware')


def test_split_item():
    with app.app_context():
        item = Item.query.filter_by(name='Hammer').first()
        code = item.code
    client = app.test_client()
    login(client)
    client.post(f'/item/{code}/split', data={'quantity': '1'}, follow_redirects=True)
    with app.app_context():
        item = Item.query.filter_by(code=code).first()
        new_items = Item.query.filter(Item.name == 'Hammer', Item.code != code).all()
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


def test_inventory_accordion_order():
    client = app.test_client()
    login(client)
    response = client.get('/')
    html = response.get_data(as_text=True)
    idx_cont = html.find('data-bs-target="#collapseContainers"')
    idx_loc = html.find('data-bs-target="#collapseLocations"')
    idx_items = html.find('data-bs-target="#collapseItems"')
    assert idx_cont < idx_loc < idx_items


def test_user_pref_endpoint():
    client = app.test_client()
    login(client)
    client.post('/prefs/test', json={'value': 'hello'})
    resp = client.get('/prefs/test')
    assert resp.json['value'] == 'hello'


def test_scan_container_pair_timeout():
    client = app.test_client()
    login(client)
    with app.app_context():
        u = User.query.first()
        loc = Location.query.filter_by(code='LC-testloc').first()
        c1 = Container(name='Inner', code='CT-inner', created_by=u, updated_by=u, location=loc)
        c2 = Container(name='Outer', code='CT-outer', created_by=u, updated_by=u, location=loc)
        dummy = Item(name='Temp', type='Tool', quantity=1, code='IT-temp', created_by=u, updated_by=u)
        db.session.add_all([c1, c2, dummy])
        db.session.commit()
        for code in (c1.code, c2.code, dummy.code):
            if not Path(qr_path(code)).exists():
                generate_qr(code)
    client.get(f'/scan/{c1.code}')
    client.get(f'/scan/{c2.code}?window=0')
    client.get(f'/scan/{dummy.code}')
    with app.app_context():
        inner = Container.query.filter_by(code='CT-inner').first()
        outer = Container.query.filter_by(code='CT-outer').first()
        assert inner.parent_id == outer.id
        assert inner.location_id == outer.location_id


def test_scan_multiple_items_to_container_includes_last():
    client = app.test_client()
    login(client)
    with app.app_context():
        u = User.query.first()
        loc = Location(name='MultiRoom', code='LC-multi', created_by=u, updated_by=u)
        cont = Container(name='Bin', code='CT-bin', created_by=u, updated_by=u, location=loc)
        db.session.add_all([loc, cont])
        items = []
        for i in range(3):
            it = Item(name=f'Widget{i}', type='Tool', quantity=1, code=f'IT-w{i}', created_by=u, updated_by=u)
            db.session.add(it)
            items.append(it)
        db.session.commit()
        for obj in [loc, cont] + items:
            if not Path(qr_path(obj.code)).exists():
                generate_qr(obj.code)
        cont_code = cont.code
        item_codes = [it.code for it in items]
    client.get(f'/scan/{cont_code}')
    for code in item_codes:
        client.get(f'/scan/{code}')
    with app.app_context():
        cont = Container.query.filter_by(code=cont_code).first()
        for code in item_codes:
            it = Item.query.filter_by(code=code).first()
            assert it.container_id == cont.id


def test_scan_multiple_items_to_container():
    client = app.test_client()
    login(client)
    with app.app_context():
        u = User.query.first()
        loc = Location.query.filter_by(code='LC-testloc').first()
        cont = Container(name='Box3', code='CT-box3', created_by=u, updated_by=u, location=loc)
        i1 = Item(name='Screwdriver', type='Tool', quantity=1, code='IT-screw2', created_by=u, updated_by=u)
        i2 = Item(name='Wrench', type='Tool', quantity=1, code='IT-wrench2', created_by=u, updated_by=u)
        db.session.add_all([cont, i1, i2])
        db.session.commit()
        for code in (cont.code, i1.code, i2.code):
            if not Path(qr_path(code)).exists():
                generate_qr(code)
    client.get(f'/scan/{cont.code}')
    client.get(f'/scan/{i1.code}')
    client.get(f'/scan/{i2.code}')
    with app.app_context():
        cont = Container.query.filter_by(code='CT-box3').first()
        i1 = Item.query.filter_by(code='IT-screw2').first()
        i2 = Item.query.filter_by(code='IT-wrench2').first()
        assert i1.container_id == cont.id
        assert i2.container_id == cont.id


def test_scan_container_container_with_followups():
    client = app.test_client()
    login(client)
    with app.app_context():
        u = User.query.first()
        loc = Location.query.filter_by(code='LC-testloc').first()
        c1 = Container(name='Parent', code='CT-parent', created_by=u, updated_by=u, location=loc)
        c2 = Container(name='Child', code='CT-child', created_by=u, updated_by=u, location=loc)
        i1 = Item(name='Pliers', type='Tool', quantity=1, code='IT-pliers2', created_by=u, updated_by=u)
        i2 = Item(name='Tape', type='Tool', quantity=1, code='IT-tape2', created_by=u, updated_by=u)
        db.session.add_all([c1, c2, i1, i2])
        db.session.commit()
        for code in (c1.code, c2.code, i1.code, i2.code):
            if not Path(qr_path(code)).exists():
                generate_qr(code)
    client.get(f'/scan/{c1.code}')
    client.get(f'/scan/{c2.code}')
    client.get(f'/scan/{i1.code}')
    client.get(f'/scan/{i2.code}')
    with app.app_context():
        c1 = Container.query.filter_by(code='CT-parent').first()
        c2 = Container.query.filter_by(code='CT-child').first()
        i1 = Item.query.filter_by(code='IT-pliers2').first()
        i2 = Item.query.filter_by(code='IT-tape2').first()
        assert c2.parent_id == c1.id
        assert i1.container_id == c1.id
        assert i2.container_id == c1.id


def test_location_path_order_and_title_case_numbers():
    client = app.test_client()
    login(client)
    client.post('/add/location', data={'name': 'Room A', 'code': 'LC-rooma'}, follow_redirects=True)
    with app.app_context():
        parent = Location.query.filter_by(code='LC-rooma').one()
    client.post('/add/location', data={'name': '2nd floor', 'code': 'LC-2nd', 'parent_id': parent.id}, follow_redirects=True)
    with app.app_context():
        child = Location.query.filter_by(code='LC-2nd').one()
        assert child.name == '2nd floor'
        assert child.full_path() == '2nd floor / Room A'


def test_container_full_path_and_item_hierarchy():
    client = app.test_client()
    login(client)
    with app.app_context():
        u = User.query.first()
        loc = Location(name='LocX', code='LC-locx', created_by=u, updated_by=u)
        outer = Container(name='Big Box', code='CT-bigbox', created_by=u, updated_by=u, location=loc)
        inner = Container(name='Little Box', code='CT-littlebox', created_by=u, updated_by=u, location=loc, parent=outer)
        item = Item(name='Widget', type='Tool', quantity=1, code='IT-widget', created_by=u, updated_by=u, container=inner)
        db.session.add_all([loc, outer, inner, item])
        db.session.commit()
        assert inner.full_path() == 'Little Box / Big Box'
        assert item.hierarchy() == f'Little Box / Big Box / {loc.full_path()}'


def test_container_to_container_log_links():
    client = app.test_client()
    login(client)
    with app.app_context():
        u = User.query.first()
        loc = Location.query.filter_by(code='LC-locx').first()
        c1 = Container(name='ChildLog', code='CT-childlog', created_by=u, updated_by=u, location=loc)
        c2 = Container(name='ParentLog', code='CT-parentlog', created_by=u, updated_by=u, location=loc)
        dummy = Item(name='Dummy', type='Tool', quantity=1, code='IT-dummylog', created_by=u, updated_by=u)
        db.session.add_all([c1, c2, dummy])
        db.session.commit()
        for code in (c1.code, c2.code, dummy.code):
            if not Path(qr_path(code)).exists():
                generate_qr(code)
    client.get(f'/scan/{c1.code}')
    client.get(f'/scan/{c2.code}?window=0')
    client.get(f'/scan/{dummy.code}')
    with app.app_context():
        h = History.query.filter_by(action='container to container').order_by(History.timestamp.desc()).first()
        assert f"/container/{c1.code}" in h.description
        assert f"/container/{c2.code}" in h.description
        assert 'ChildLog' in h.description and 'ParentLog' in h.description


def test_scan_location_in_location():
    import time
    client = app.test_client()
    login(client)
    with app.app_context():
        parent = Location(name='Parent', code='LC-parent')
        child = Location(name='Child', code='LC-child')
        db.session.add_all([parent, child])
        db.session.commit()
        for code in (parent.code, child.code):
            if not Path(qr_path(code)).exists():
                generate_qr(code)
    client.get(f'/scan/{child.code}')
    time.sleep(1)
    client.get(f'/scan/{parent.code}')
    with app.app_context():
        child = Location.query.filter_by(code='LC-child').first()
        parent = Location.query.filter_by(code='LC-parent').first()
        assert child.parent_id == parent.id


def test_scan_multiple_items_to_location():
    import time
    client = app.test_client()
    login(client)
    with app.app_context():
        u = User.query.first()
        loc1 = Location(name='Room2', code='LC-room2')
        loc2 = Location(name='Room3', code='LC-room3')
        i1 = Item(name='Screwdriver', type='Tool', quantity=1, code='IT-screw', created_by=u, updated_by=u)
        i2 = Item(name='Wrench', type='Tool', quantity=1, code='IT-wrench', created_by=u, updated_by=u)
        i3 = Item(name='Pliers', type='Tool', quantity=1, code='IT-pliers', created_by=u, updated_by=u)
        db.session.add_all([loc1, loc2, i1, i2, i3])
        db.session.commit()
        for code in (loc1.code, loc2.code, i1.code, i2.code, i3.code):
            if not Path(qr_path(code)).exists():
                generate_qr(code)
    client.get(f'/scan/{loc1.code}')
    time.sleep(1)
    client.get(f'/scan/{i1.code}')
    time.sleep(1)
    client.get(f'/scan/{i2.code}')
    time.sleep(1)
    client.get(f'/scan/{loc2.code}')
    time.sleep(1)
    client.get(f'/scan/{i3.code}')
    with app.app_context():
        loc1 = Location.query.filter_by(code='LC-room2').first()
        loc2 = Location.query.filter_by(code='LC-room3').first()
        i1 = Item.query.filter_by(code='IT-screw').first()
        i2 = Item.query.filter_by(code='IT-wrench').first()
        i3 = Item.query.filter_by(code='IT-pliers').first()
        assert i1.location_id == loc1.id
        assert i2.location_id == loc1.id
        assert i3.location_id == loc2.id


def test_migrate_old_database(tmp_path):
    import sqlite3, shutil
    old_db = tmp_path / 'old_inventory.db'
    conn = sqlite3.connect(old_db)
    cur = conn.cursor()
    cur.execute('CREATE TABLE item (id INTEGER PRIMARY KEY, code TEXT, name TEXT, type TEXT, quantity INTEGER)')
    cur.execute("INSERT INTO item (id, code, name, type, quantity) VALUES (1, 'IT-old', 'OldItem', 'Tool', 5)")
    conn.commit()
    conn.close()
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
    shutil.copy(old_db, 'inventory.db')
    with app.app_context():
        from app import migrate_sqlite, Location, Container, History, Relation
        migrate_sqlite('inventory.db', (Location, Container, Item, History, Relation))
    import sqlite3
    conn = sqlite3.connect('inventory.db')
    row = conn.execute("select name, quantity from item where code='IT-old'").fetchone()
    conn.close()
    assert row == ('OldItem', 5)


def test_admin_download_db():
    import zipfile, io
    client = app.test_client()
    client.post('/login', data={'username': 'admin', 'password': 'admin'})
    resp = client.get('/admin/download/db')
    assert resp.status_code == 200
    with zipfile.ZipFile(io.BytesIO(resp.data)) as z:
        names = set(z.namelist())
        for fname in ['inventory.db', 'users.db', 'locations.db', 'containers.db', 'items.db']:
            assert fname in names


def test_admin_template_headers():
    client = app.test_client()
    client.post('/login', data={'username': 'admin', 'password': 'admin'})
    resp = client.get('/admin/template/items')
    assert resp.data.decode() == 'name,quantity,type,location_code,container_code,custom_data\n'
    resp = client.get('/admin/template/containers')
    assert resp.data.decode() == 'name,location_code,parent_code,children_codes,custom_data\n'
    resp = client.get('/admin/template/locations')
    assert resp.data.decode() == 'name,parent_code,children_codes,custom_data\n'
