# QR Code Inventory Manager

This project provides a simple inventory management system that tags items, containers and locations with QR codes.

## Setup

1. Create and activate a virtual environment
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
3. Run the automated tests
   ```bash
   pytest -q
   ```
4. Start the development server (HTTPS is enabled by default for camera access)
   ```bash
   python app.py
   ```
   Use `FLASK_NO_SSL=1` if you need to serve over plain HTTP. The server listens
   on `https://localhost:5000` by default. The application checks the existing
   `inventory.db` on startup and recreates it if the schema is out-of-date.
   The scanner uses a bundled QR decoder and does not rely on external CDNs.

## Usage

- Log in with the default administrator account `admin` / `admin`.
- You will be prompted to change the password on first login.
- Use the interface to create items, containers and locations. A QR code is generated for each.
- Visit `/scanner` to use the browser camera for scanning. Scanning two codes within the configured window will pair them accordingly.
- The **Logs** page supports filtering by start/end date, period (day, week, month), action type and a fuzzy search that checks item names, types and messages. Results appear in a scrollable table.
- Items may be split into sub-quantities or marked as missing. Unaccounted items are listed on the home page.
- Toggle light and dark themes using the moon/sun icon in the navigation bar.
- Use the account settings (gear icon) to update your username, password, profile image or preferred theme colour (links default to yellow).
- Register items, containers and locations manually from the *Register Pair* page or by scanning QR codes.
- A log of your actions is available via the *Logs* link (admins see all activity).

## Testing

Running `pytest -q` executes unit tests that cover item creation, splitting, scanning and reporting missing items.

### Manual QR scanner testing

1. Start the development server with `python app.py` and navigate to `https://<host>:5000/scanner` on a desktop or mobile browser. Browsers only allow camera access over HTTPS or from `localhost`.
2. Click **Start Camera**, then allow the browser to access the camera. If multiple cameras are available,
   choose one from the dropdown. A live viewfinder should appear. Mobile browsers default to the rear camera.
3. Scan a QR code. A short beep plays and the code along with the item's name is added to the on-page log with a timestamp.
4. Scanning the same QR code again within one second is ignored (no additional log entry), but different codes can be scanned immediately.
5. When two different codes are scanned within the selected window, the application processes them as a pair, displays a verbose message (e.g., `Item <b>Chocolate</b> was moved to <b>Kitchen</b>`) and logs it.
6. Visit `/logs` and apply various filters to verify that verbose entries (e.g., move actions) appear with both the action and details and that the table scrolls when many rows are present.
