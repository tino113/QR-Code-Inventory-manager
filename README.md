# QR Code Inventory Manager

A Flask-based web application for tracking items, containers and locations using QR codes.  The project aims to make small inventory systems easy to manage from a phone or desktop browser.

## Features
- **QR tagging** – Every item, container and location gets its own code for quick identification.
- **Scanner interface** – `/scanner` uses the browser camera to read two codes and act on them (e.g., move an item into a location).
- **Audit log** – Each action is recorded and can be filtered by date, type or fuzzy search.
- **Theme and account settings** – Supports light/dark mode and profile customization.
- **Missing item tracking** – Flag items as missing and review unaccounted inventory on the dashboard.

## Getting Started

### 1. Setup a virtual environment
```bash
python -m venv .venv
source .venv/bin/activate
```

### 1.1 Linux / Raspbian OS deps
install the following for Linux / Raspbian OS / Debian installations
#### Deps for pillow
``` bash
sudo apt update
sudo apt install libjpeg-dev zlib1g-dev libtiff-dev libfreetype6-dev
```

#### Dependancies for cryptography
``` bash
sudo apt-get install libffi-dev
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the tests
```bash
pytest -q
```

### 4. Start the development server
```bash
python app.py
```
HTTPS is enabled by default for camera access; use `FLASK_NO_SSL=1` to serve over HTTP. The server listens on `https://localhost:5000` and recreates `inventory.db` when the schema is out of date.

## Usage
1. Log in with the default administrator account `admin`/`admin` (you will be asked to change the password on first login).
2. Register items, containers and locations from the web UI. Each record includes a QR code you can download or print.
3. Visit `/scanner`, click **Start Camera** and scan two codes in succession to pair them. For example, scan an item then a location to move the item there.
4. Access **Logs** to review activity or filter by user, action type or date.
5. Switch between light and dark themes from the navigation bar and adjust other preferences in the account settings.

### Example: moving an item
1. Print the QR codes for an item and a location.
2. From your phone, open `https://<host>:5000/scanner` and start the camera.
3. Scan the item's code followed by the location's code within the selected time window.
4. The application logs the move and shows a message like `Item "Chocolate" was moved to "Kitchen"`.

## Suggestions
- Use a label printer for high-quality QR code stickers.
- Keep a regular backup of `inventory.db`, especially before schema migrations.
- Enable HTTPS in production and restrict administrator accounts.

## Contributing
Pull requests and feature ideas are welcome! Please run `pytest` before submitting any changes.

## License
This project is provided for educational purposes; adapt it to suit your needs.
