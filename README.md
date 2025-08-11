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
4. Start the development server
   ```bash
   python app.py
   ```
   The server starts on `http://localhost:5000`.

## Usage

- Log in with the default administrator account `admin` / `admin`.
- You will be prompted to change the password on first login.
- Use the interface to create items, containers and locations. A QR code is generated for each.
- Visit `/scanner` to use the browser camera for scanning. Scanning two codes within the configured window will pair them accordingly.
- Items may be split into sub-quantities or marked as missing. Unaccounted items are listed on the home page.

## Testing

Running `pytest -q` executes unit tests that cover item creation, splitting, scanning and reporting missing items.
