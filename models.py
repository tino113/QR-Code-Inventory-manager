import datetime as dt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import foreign
from werkzeug.security import generate_password_hash, check_password_hash

# Create SQLAlchemy database instance to be initialized in app.py
db = SQLAlchemy()

class TimestampMixin:
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=dt.datetime.utcnow,
                           onupdate=dt.datetime.utcnow)


class User(db.Model):
    __bind_key__ = 'users'
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


class Preference(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key = db.Column(db.String, nullable=False)
    value = db.Column(db.String, nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'key'),)


class Location(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String, unique=True, nullable=False)
    name = db.Column(db.String, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    parent = db.relationship('Location', remote_side=[id], backref='children')
    image = db.Column(db.String)
    custom_data = db.Column(db.Text)
    created_by_id = db.Column(db.Integer)
    updated_by_id = db.Column(db.Integer)
    created_by = db.relationship('User',
                                 primaryjoin='User.id==foreign(Location.created_by_id)',
                                 foreign_keys=[created_by_id])
    updated_by = db.relationship('User',
                                 primaryjoin='User.id==foreign(Location.updated_by_id)',
                                 foreign_keys=[updated_by_id])

    items = db.relationship('Item', backref='location', lazy=True)
    containers = db.relationship('Container', backref='location', lazy=True)
    histories = db.relationship('History', backref='location', lazy=True)

    def full_path(self):
        parts = [self.name]
        cur = self.parent
        while cur:
            parts.append(cur.name)
            cur = cur.parent
        return ' / '.join(parts)

    def all_items(self):
        seen = {}
        for i in self.items:
            seen[i.id] = i
        for c in self.containers:
            for i in c.all_items():
                seen[i.id] = i
        for child in self.children:
            for i in child.all_items():
                seen[i.id] = i
        return list(seen.values())

    def all_containers(self):
        conts = []
        for c in self.containers:
            conts.extend(c.all_containers())
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
    parent_id = db.Column(db.Integer, db.ForeignKey('container.id'))
    created_by_id = db.Column(db.Integer)
    updated_by_id = db.Column(db.Integer)
    created_by = db.relationship('User',
                                 primaryjoin='User.id==foreign(Container.created_by_id)',
                                 foreign_keys=[created_by_id])
    updated_by = db.relationship('User',
                                 primaryjoin='User.id==foreign(Container.updated_by_id)',
                                 foreign_keys=[updated_by_id])
    parent = db.relationship('Container', remote_side=[id], backref='children')
    items = db.relationship('Item', backref='container', lazy=True)
    histories = db.relationship('History', backref='container', lazy=True)

    def full_path(self):
        parts = [self.name or self.code]
        cur = self.parent
        while cur:
            parts.append(cur.name or cur.code)
            cur = cur.parent
        return ' / '.join(parts)

    def all_items(self):
        items = list(self.items)
        for child in self.children:
            items.extend(child.all_items())
        return items

    def all_containers(self):
        conts = [self]
        for child in self.children:
            conts.extend(child.all_containers())
        return conts

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
    created_by_id = db.Column(db.Integer)
    updated_by_id = db.Column(db.Integer)
    created_by = db.relationship('User',
                                 primaryjoin='User.id==foreign(Item.created_by_id)',
                                 foreign_keys=[created_by_id])
    updated_by = db.relationship('User',
                                 primaryjoin='User.id==foreign(Item.updated_by_id)',
                                 foreign_keys=[updated_by_id])
    histories = db.relationship('History', backref='item', lazy=True)

    def hierarchy(self):
        parts = []
        if self.container:
            parts.append(self.container.full_path())
            if self.container.location:
                parts.append(self.container.location.full_path())
        elif self.location:
            parts.append(self.location.full_path())
        return ' / '.join(parts)

    def path_from(self, loc):
        parts = []
        container = self.container
        if container:
            parts.append(container.full_path())
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
    user_id = db.Column(db.Integer)
    action = db.Column(db.String)
    description = db.Column(db.Text)
    user = db.relationship('User',
                           primaryjoin='User.id==foreign(History.user_id)',
                           foreign_keys=[user_id],
                           backref='histories')


class Relation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_type = db.Column(db.String, nullable=False)
    first_id = db.Column(db.Integer, nullable=False)
    second_type = db.Column(db.String, nullable=False)
    second_id = db.Column(db.Integer, nullable=False)

