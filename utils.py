import os
import uuid
import json
import zipfile
import math
import shutil
import io
import csv

import qrcode
from PIL import Image
from flask import url_for, session
from werkzeug.utils import secure_filename

from models import db, Item, Container, Location, History, User

def current_user():
    uid = session.get('user_id')
    if uid:
        return User.query.get(uid)
    return None
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


def _qr_pages(codes, cols, rows):
    """Return PIL Images containing grids of codes."""
    width, height = 2480, 3508  # A4 at 300 DPI
    margin = 100  # small margin for printers
    side = min((width - margin * 2) // cols,
               (height - margin * 2) // rows)
    margin_x = (width - side * cols) // 2
    margin_y = (height - side * rows) // 2
    per_page = cols * rows
    pages = []
    for page_idx in range(math.ceil(len(codes) / per_page)):
        page = Image.new('RGB', (width, height), 'white')
        for cell in range(per_page):
            idx = page_idx * per_page + cell
            if idx >= len(codes):
                break
            img = Image.open(qr_path(codes[idx])).resize((side, side))
            x = margin_x + (cell % cols) * side
            y = margin_y + (cell // cols) * side
            page.paste(img, (x, y))
        pages.append(page)
    return pages


def generate_pdf(codes, path, cols=4, rows=8):
    pages = _qr_pages(codes, cols, rows)
    if not pages:
        return
    pages[0].save(path, 'PDF', resolution=300.0,
                  save_all=True, append_images=pages[1:])


def generate_images(codes, base_path, cols=4, rows=8):
    """Generate A4-sized PNG pages and return their paths."""
    pages = _qr_pages(codes, cols, rows)
    files = []
    for i, page in enumerate(pages, 1):
        fname = f"{base_path}_{i}.png"
        page.save(fname, 'PNG')
        files.append(fname)
    return files


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


def maybe_title(value: str) -> str:
    value = value.strip()
    if value and value[0].isalpha():
        return value.title()
    return value


def create_items_from_spec(container, spec: str):
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        name = maybe_title(tokens[0])
        quantity = 1
        type_ = 'Misc'
        if len(tokens) > 1:
            if tokens[1].isdigit():
                quantity = int(tokens[1])
                if len(tokens) > 2:
                    type_ = maybe_title(' '.join(tokens[2:]))
            else:
                type_ = maybe_title(' '.join(tokens[1:]))
        code = generate_code('IT')
        item = Item(name=name, type=type_, quantity=quantity, code=code,
                    container=container, location=container.location,
                    created_by=current_user(), updated_by=current_user())
        db.session.add(item)
        db.session.flush()
        generate_qr(code)
        log_action('created item', item=item)


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


