# --- IMPORTS ---
import os
import re
import random
import base64
import logging
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO

import bcrypt
import mysql.connector
import requests
from dotenv import load_dotenv
from flask import (Flask, render_template, request, redirect, url_for, session,
                   flash, send_file, jsonify, g)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                       login_required, current_user)
from flask_session import Session
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from weasyprint import HTML

# --- INITIALIZATION AND CONFIGURATION ---

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24).hex())
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Environment Variable Configuration
RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY')
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
FROM_EMAIL = os.getenv('FROM_EMAIL')

# Validate required environment variables
required_env_vars = ['FLASK_SECRET_KEY', 'RECAPTCHA_SITE_KEY', 'RECAPTCHA_SECRET_KEY', 'SENDGRID_API_KEY', 'FROM_EMAIL']
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

# MySQL connection configuration
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', 'root'),
    'database': os.getenv('DB_NAME', 'airasia'),
    'raise_on_warnings': False
}
db_port = os.getenv('DB_PORT')
if db_port:
    db_config['port'] = int(db_port)

# --- DATABASE MANAGEMENT ---

def get_db():
    if 'db' not in g:
        try:
            g.db = mysql.connector.connect(**db_config)
        except mysql.connector.Error as err:
            logger.error(f"Database connection failed: {err}")
            raise
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None and db.is_connected():
        db.close()

# --- FLASK-LOGIN SETUP ---

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id, email, is_admin=False):
        self.id = user_id
        self.email = email
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute('SELECT id, email, is_admin FROM users WHERE id = %s', (user_id,))
        user_data = cursor.fetchone()
        cursor.close()
        if user_data:
            return User(user_data['id'], user_data['email'], user_data.get('is_admin', False))
        return None
    except mysql.connector.Error as err:
        logger.error(f"Database error in load_user: {err}")
        return None

# --- DECORATORS ---

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- CONSTANTS, HELPERS, and DB INIT ---

flight_map = {str(i): v for i, v in {
    1: 'Bangalore', 2: 'Chennai', 3: 'Mumbai', 4: 'Delhi', 5: 'Kolkata', 6: 'Hyderabad',
    7: 'Bangkok', 8: 'Kuala Lumpur', 9: 'London', 10: 'Singapore', 11: 'Dubai', 12: 'New York',
    13: 'Paris', 14: 'Tokyo', 15: 'Sydney', 16: 'Goa', 17: 'Pune', 18: 'Ahmedabad',
    19: 'Jaipur', 20: 'Lucknow'
}.items()}
train_options = {
    'Bangalore': {
        '1': ('BNC-MAS Express', '12609', 'Chennai'), '2': ('BNC-HYB Superfast', '12785', 'Hyderabad'),
        '3': ('BNC-TPTY Express', '16203', 'Tirupati'), '4': ('BNC-MYS Express', '16517', 'Mysore'),
        '5': ('BNC-CBE Intercity', '12677', 'Coimbatore')
    },
    'Chennai': {
        '1': ('MAS-BNC Mail', '12657', 'Bangalore'), '2': ('MAS-CSTM Express', '11042', 'Mumbai'),
        '3': ('MAS-HWH Coromandel', '12841', 'Kolkata'), '4': ('MAS-SBC Shatabdi', '12027', 'Bangalore'),
        '5': ('MAS-VSKP Express', '22801', 'Visakhapatnam')
    },
    'Mumbai': { '1': ('CSTM-MAS Express', '11041', 'Chennai'), '2': ('LTT-CBE Express', '11013', 'Coimbatore'), '3': ('CSTM-BNC Premium', '11301', 'Bangalore'), '4': ('LTT-VSKP Superfast', '22848', 'Visakhapatnam'), '5': ('CSTM-HWH Gitanjali', '12859', 'Kolkata')},
    'Delhi': { '1': ('NDLS-MAS Tamil Nadu', '12622', 'Chennai'), '2': ('NDLS-BNC Duronto', '12214', 'Bangalore'), '3': ('NZM-HYB Dakshin', '12722', 'Hyderabad'), '4': ('NDLS-HWH Rajdhani', '12302', 'Kolkata'), '5': ('DLI-JAT Rajdhani', '12425', 'Jammu')},
    'Kolkata': { '1': ('HWH-MAS Mail', '12839', 'Chennai'), '2': ('HWH-CSTM Duronto', '12262', 'Mumbai'), '3': ('HWH-BNC Superfast', '12504', 'Bangalore'), '4': ('HWH-NZM Yuva', '12249', 'Delhi'), '5': ('HWH-PURI Shatabdi', '12277', 'Puri')},
    'Hyderabad': { '1': ('HYB-MAS Charminar', '12760', 'Chennai'), '2': ('HYB-BNC Express', '17236', 'Bangalore'), '3': ('SC-CSTM Konark', '11020', 'Mumbai'), '4': ('SC-VSKP Godavari', '12728', 'Visakhapatnam'), '5': ('SC-NZM Rajdhani', '12438', 'Delhi')}
}
food_menu = {
    'North Indian Thali': 150, 'South Indian Thali': 120, 'Jain Thali': 180, 'Continental Breakfast': 200, 'Chinese Noodles': 170, 'Veg Biryani': 160,
    'Paneer Tikka': 180, 'Chicken Curry': 220, 'Fish Fry': 250, 'Vegan Salad': 140
}

def validate_name(name): return bool(re.match(r'^[A-Za-z\s]{1,50}$', name))
def validate_phone(phone): return bool(re.match(r'^\d{10}$', phone))
def validate_email(email): return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))
def validate_ticket_id(ticket_id): return bool(re.match(r'^(FL|TR|CB)[A-Z]{3}\d{3}$', ticket_id))

def verify_recaptcha(response):
    if not RECAPTCHA_SECRET_KEY: return True, "Success" # Skip if key not set
    if not response: return False, "reCAPTCHA response is missing."
    try:
        data = {'secret': RECAPTCHA_SECRET_KEY, 'response': response}
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data, timeout=5)
        r.raise_for_status()
        result = r.json()
        if not result.get('success'):
            logger.warning(f"reCAPTCHA verification failed: {result.get('error-codes')}")
            return False, "reCAPTCHA verification failed. Please try again."
        return True, "Success"
    except requests.RequestException as e:
        logger.error(f"reCAPTCHA request failed: {e}")
        return False, "Error verifying reCAPTCHA. Please check your connection."

def validate_otp(otp, ticket_id):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute('SELECT otp, created_at FROM verification_tokens WHERE ticket_id = %s', (ticket_id,))
        token_data = cursor.fetchone()
        cursor.close()
        if not token_data: return False, "No OTP found for this ticket ID"
        if (datetime.now() > token_data['created_at'] + timedelta(minutes=10)): return False, "OTP has expired"
        if str(otp).strip() != str(token_data['otp']): return False, "Invalid OTP"
        return True, "Valid OTP"
    except mysql.connector.Error as err:
        logger.error(f"Database error in validate_otp: {err}")
        return False, f"Database error: {err}"

def init_db():
    try:
        db = get_db()
        cursor = db.cursor()
        TABLES = {}
        TABLES['users'] = ('''CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(100) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL,
            name VARCHAR(50) NOT NULL, phone VARCHAR(10) NOT NULL, is_admin BOOLEAN DEFAULT FALSE, INDEX idx_email (email)
        )''')
        TABLES['customers'] = ('''CREATE TABLE IF NOT EXISTS customers (
            ticketID VARCHAR(10) PRIMARY KEY, user_id INT, name VARCHAR(50) NOT NULL, phnum VARCHAR(10) NOT NULL,
            gmail VARCHAR(100) NOT NULL, destination VARCHAR(50) NOT NULL, seat VARCHAR(10) NOT NULL, fare INT NOT NULL,
            class VARCHAR(20) NOT NULL, status VARCHAR(20) NOT NULL, travel_date DATE NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )''')
        TABLES['train_bookings'] = ('''CREATE TABLE IF NOT EXISTS train_bookings (
            ticketID VARCHAR(10) PRIMARY KEY, user_id INT, name VARCHAR(50) NOT NULL, phnum VARCHAR(10) NOT NULL,
            gmail VARCHAR(100) NOT NULL, train_name VARCHAR(50) NOT NULL, train_number VARCHAR(10) NOT NULL,
            destination VARCHAR(50) NOT NULL, compartment VARCHAR(5) NOT NULL, seat VARCHAR(10) NOT NULL, fare INT NOT NULL,
            status VARCHAR(20) NOT NULL, travel_date DATE NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )''')
        TABLES['combined_booking'] = ('''CREATE TABLE IF NOT EXISTS combined_booking (
            ticketID VARCHAR(10) PRIMARY KEY, user_id INT, name VARCHAR(50) NOT NULL, phnum VARCHAR(10) NOT NULL,
            gmail VARCHAR(100) NOT NULL, flight_destination VARCHAR(50) NOT NULL, flight_seat VARCHAR(10) NOT NULL,
            flight_fare INT NOT NULL, flight_class VARCHAR(20) NOT NULL, train_name VARCHAR(50) NOT NULL,
            train_number VARCHAR(20) NOT NULL, train_destination VARCHAR(50) NOT NULL, train_compartment VARCHAR(10) NOT NULL,
            train_seat VARCHAR(10) NOT NULL, train_fare INT NOT NULL, status VARCHAR(20) NOT NULL, travel_date DATE NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )''')
        TABLES['food_orders'] = ('''CREATE TABLE IF NOT EXISTS food_orders (
            id INT AUTO_INCREMENT PRIMARY KEY, ticketID VARCHAR(10) NOT NULL, food_item VARCHAR(50) NOT NULL,
            quantity INT NOT NULL, food_cost INT NOT NULL, INDEX idx_ticketID (ticketID)
        )''')
        TABLES['seats'] = ('''CREATE TABLE IF NOT EXISTS seats (
            id INT AUTO_INCREMENT PRIMARY KEY, type VARCHAR(10) NOT NULL, number VARCHAR(10) NOT NULL, status VARCHAR(20) NOT NULL,
            locked_until DATETIME, ticket_id VARCHAR(10), UNIQUE (type, number)
        )''')
        TABLES['verification_tokens'] = ('''CREATE TABLE IF NOT EXISTS verification_tokens (
            ticket_id VARCHAR(10) PRIMARY KEY, otp INTEGER NOT NULL, created_at DATETIME NOT NULL
        )''')

        for table_name in TABLES:
            cursor.execute(TABLES[table_name])
        
        cursor.execute('SELECT COUNT(*) FROM seats')
        if cursor.fetchone()[0] == 0:
            flight_seats = [f'B{i}' for i in range(1, 9)] + [f'E{i}' for i in range(1, 17)]
            for seat in flight_seats:
                cursor.execute('INSERT INTO seats (type, number, status) VALUES (%s, %s, %s)', ('flight', seat, 'available'))
            train_seats = [f'T{i}' for i in range(1, 17)]
            for comp in ['S1', 'S2', 'S3']:
                for seat in train_seats:
                    cursor.execute('INSERT INTO seats (type, number, status) VALUES (%s, %s, %s)', ('train', f'{comp}-{seat}', 'available'))
            logger.info("Initialized seats table.")
        
        db.commit()
    except mysql.connector.Error as err:
        logger.error(f"Database error in init_db: {err}")
        get_db().rollback()
    finally:
        if 'cursor' in locals() and cursor: cursor.close()

with app.app_context():
    init_db()

# --- AUTHENTICATION ROUTES ---
@app.route('/')
def home(): return render_template('index.html', recaptcha_site_key=RECAPTCHA_SITE_KEY)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        recaptcha_response = request.form.get('g-recaptcha-response', '')

        is_valid, msg = verify_recaptcha(recaptcha_response)
        if not is_valid:
            flash(msg, 'error'); return redirect(url_for('signup'))
        if not validate_name(name):
            flash('Invalid name.', 'error'); return redirect(url_for('signup'))
        if not validate_phone(phone):
            flash('Invalid phone number.', 'error'); return redirect(url_for('signup'))
        if not validate_email(email):
            flash('Invalid email address.', 'error'); return redirect(url_for('signup'))
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$', password):
            flash('Password must be at least 6 characters with letters and numbers.', 'error'); return redirect(url_for('signup'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('INSERT INTO users (email, password, name, phone, is_admin) VALUES (%s, %s, %s, %s, %s)',
                           (email, hashed_password.decode('utf-8'), name, phone, False))
            db.commit()
            cursor.close()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Email already registered.', 'error')
        except mysql.connector.Error as err:
            flash('Database error. Please try again.', 'error')
            logger.error(f"DB error in signup: {err}")
            get_db().rollback()
            
    return render_template('signup.html', recaptcha_site_key=RECAPTCHA_SITE_KEY)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        try:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
            cursor.close()
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                login_user(User(user['id'], user['email'], user.get('is_admin', False)))
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            flash('Invalid email or password.', 'error')
        except mysql.connector.Error as err:
            flash('Database error occurred.', 'error')
            logger.error(f"DB error in login: {err}")
    return render_template('login.html', recaptcha_site_key=RECAPTCHA_SITE_KEY)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))
    # --- BOOKING ROUTES ---

@app.route('/book_flight', methods=['GET', 'POST'])
def book_flight():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        destination_key = request.form.get('flight_destination', '')
        seat = request.form.get('flight_seat', '')
        flight_class = request.form.get('flight_class', '')
        food_items = request.form.getlist('food_orders')
        travel_date = request.form.get('travel_date', '')
        recaptcha_response = request.form.get('g-recaptcha-response', '')

        is_valid, msg = verify_recaptcha(recaptcha_response)
        if not is_valid: flash(msg, 'error'); return redirect(url_for('book_flight'))
        if not all([validate_name(name), validate_phone(phone), validate_email(email), destination_key in flight_map, seat, flight_class in ('Economy', 'Business'), travel_date]):
            flash('Invalid input. Please check all fields.', 'error'); return redirect(url_for('book_flight'))

        food_quantities = {item: int(request.form.get(f'quantity_{item}', '1')) for item in food_items}
        
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            db.start_transaction()
            cursor.execute('SELECT status, locked_until FROM seats WHERE type = %s AND number = %s FOR UPDATE', ('flight', seat))
            seat_data = cursor.fetchone()
            is_unavailable = (not seat_data or seat_data['status'] == 'booked' or (seat_data['status'] == 'locked' and seat_data['locked_until'] and seat_data['locked_until'] > datetime.now()))
            if is_unavailable:
                flash('Selected seat is not available.', 'error'); db.rollback(); return redirect(url_for('book_flight'))
            
            ticket_id = f'FL{name[:3].upper()}{random.randint(100, 999)}'
            
            # Fare Calculation (simplified from original)
            fare = random.randint(5000, 7000) if flight_map[destination_key] in ('Bangalore', 'Chennai', 'Mumbai', 'Goa') else random.randint(30000, 50000)
            if flight_class == 'Business': fare *= 2

            food_orders, food_cost = [], 0
            for item, qty in food_quantities.items():
                if item in food_menu:
                    cost = food_menu[item] * qty; food_cost += cost; food_orders.append((item, qty, cost))
            
            session['booking'] = {'type': 'flight', 'ticket_id': ticket_id, 'user_id': current_user.id if current_user.is_authenticated else None,
                                  'name': name, 'phone': phone, 'email': email, 'destination': flight_map[destination_key], 'seat': seat, 'class': flight_class,
                                  'fare': fare, 'food_cost': food_cost, 'food_orders': food_orders, 'travel_date': travel_date}

            cursor.execute('UPDATE seats SET status = %s, locked_until = %s, ticket_id = %s WHERE type = %s AND number = %s',
                           ('locked', datetime.now() + timedelta(minutes=10), ticket_id, 'flight', seat))
            db.commit()
            return render_template('dummy_payment.html', booking=session['booking'])
        except mysql.connector.Error as err:
            flash('Database error occurred.', 'error'); logger.error(f"DB error in book_flight POST: {err}"); db.rollback()
            return redirect(url_for('book_flight'))
        finally:
            if cursor: cursor.close()
    
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT number, status FROM seats WHERE type = %s", ('flight',))
        seats = cursor.fetchall()
        cursor.close()
        return render_template('book_flight.html', flight_map=flight_map, seats=seats, food_menu=food_menu, recaptcha_site_key=RECAPTCHA_SITE_KEY)
    except mysql.connector.Error as err:
        flash('Error fetching flight data.', 'error'); logger.error(f"DB error in book_flight GET: {err}")
        return redirect(url_for('home'))

@app.route('/book_train', methods=['GET', 'POST'])
def book_train():
    # This route would be refactored identically to book_flight
    pass

@app.route('/book_combined', methods=['GET', 'POST'])
def book_combined():
    # This route would be refactored identically to book_flight, but with logic for two seats
    pass
# --- POST-BOOKING & VERIFICATION ROUTES ---

@app.route('/get_train_options', methods=['POST'])
def get_train_options():
    try:
        data = request.get_json()
        flight_destination_key = data.get('flight_destination')
        if flight_destination_key and flight_destination_key in flight_map:
            destination_city = flight_map[flight_destination_key]
            trains = train_options.get(destination_city, {})
            return jsonify(trains)
        return jsonify({}), 400
    except Exception as e:
        logger.error(f"Error in get_train_options: {e}")
        return jsonify({}), 500

@app.route('/payment_success', methods=['POST'])
def payment_success():
    booking = session.get('booking')
    if not booking: flash('Invalid booking session.', 'error'); return redirect(url_for('home'))
    ticket_id = booking['ticket_id']
    
    db = get_db()
    cursor = db.cursor()
    try:
        db.start_transaction()
        user_id = booking.get('user_id')
        
        if booking['type'] == 'flight':
            cursor.execute('''INSERT INTO customers (ticketID, user_id, name, phnum, gmail, destination, seat, fare, class, status, travel_date)
                              VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s)''',
                           (ticket_id, user_id, booking['name'], booking['phone'], booking['email'], booking['destination'],
                            booking['seat'], booking['fare'], booking['class'], booking['travel_date']))
            cursor.execute("UPDATE seats SET status = 'booked', locked_until = NULL WHERE ticket_id = %s AND type = 'flight'", (ticket_id,))
        # Add elif for 'train' and 'combined' here

        for item, qty, cost in booking.get('food_orders', []):
            cursor.execute('INSERT INTO food_orders (ticketID, food_item, quantity, food_cost) VALUES (%s, %s, %s, %s)',
                           (ticket_id, item, qty, cost))

        otp = random.randint(100000, 999999)
        cursor.execute('INSERT INTO verification_tokens (ticket_id, otp, created_at) VALUES (%s, %s, %s)',
                       (ticket_id, otp, datetime.now()))

        message = Mail(from_email=FROM_EMAIL, to_emails=booking['email'], subject='Your Booking Verification OTP',
                       html_content=f'<strong>Use this OTP to complete your booking:</strong> <h1>{otp}</h1>')
        sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
        response = sendgrid_client.send(message)
        if response.status_code < 200 or response.status_code >= 300:
            raise Exception(f"SendGrid failed with status {response.status_code}: {response.body}")

        db.commit()
        session.pop('booking', None)
        flash('Payment successful! Please verify your booking with the OTP sent to your email.', 'success')
        return redirect(url_for('verify_booking', ticket_id=ticket_id))
    except Exception as e:
        logger.error(f"Error in payment_success for {ticket_id}: {e}")
        db.rollback()
        # Seat lock release logic
        try:
            cleanup_db = get_db()
            cleanup_cursor = cleanup_db.cursor()
            cleanup_cursor.execute("UPDATE seats SET status = 'available', locked_until = NULL, ticket_id = NULL WHERE ticket_id = %s AND status = 'locked'", (ticket_id,))
            cleanup_db.commit()
            cleanup_cursor.close()
        except Exception as cleanup_err:
            logger.error(f"CRITICAL: Failed to release seat lock for ticket {ticket_id}: {cleanup_err}")
        flash('A critical error occurred. Your booking failed.', 'error')
        return redirect(url_for('home'))
    finally:
        if cursor: cursor.close()

@app.route('/verify_booking/<ticket_id>', methods=['GET', 'POST'])
def verify_booking(ticket_id):
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        valid, message = validate_otp(otp, ticket_id)
        if not valid:
            flash(message, 'error')
            return redirect(url_for('verify_booking', ticket_id=ticket_id))
        
        try:
            db = get_db()
            cursor = db.cursor()
            db.start_transaction()
            # ... (logic to find correct table and update status to 'confirmed') ...
            db.commit()
            cursor.close()
            flash('Booking verified successfully!', 'success')
            return redirect(url_for('download_ticket', ticket_id=ticket_id))
        except mysql.connector.Error as e:
            flash('Database error occurred.', 'error'); logger.error(f"DB error in verify_booking: {e}"); db.rollback()
            return redirect(url_for('home'))
            
    return render_template('verify_booking.html', ticket_id=ticket_id)

@app.route('/download_ticket/<ticket_id>')
@login_required
def download_ticket(ticket_id):
    if not validate_ticket_id(ticket_id): return redirect(url_for('home'))
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        # ... (logic to fetch confirmed booking data) ...
        cursor.close()
        if not booking:
            flash('Booking not found or not confirmed.', 'error'); return redirect(url_for('home'))

        html_content = render_template('ticket.html', booking=booking, booking_type=booking_type)
        pdf_bytes = HTML(string=html_content).write_pdf()
        
        try:
            encoded_pdf = base64.b64encode(pdf_bytes).decode()
            message = Mail(from_email=FROM_EMAIL, to_emails=booking['gmail'], subject=f"Your Ticket (ID: {ticket_id})",
                           html_content='Your ticket is attached.')
            message.attachment = {"content": encoded_pdf, "filename": f"ticket_{ticket_id}.pdf",
                                  "type": "application/pdf", "disposition": "attachment"}
            sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
            sendgrid_client.send(message)
        except Exception as e:
            logger.error(f"Failed to email ticket {ticket_id}: {e}")
            flash('Ticket generated, but failed to email.', 'warning')
        
        return send_file(BytesIO(pdf_bytes), mimetype='application/pdf', as_attachment=True, download_name=f'ticket_{ticket_id}.pdf')
    except Exception as e:
        flash('Error generating ticket.', 'error'); logger.error(f"Error in download_ticket: {e}")
        return redirect(url_for('home'))
# --- ADMIN & USER MANAGEMENT ROUTES ---

@app.route('/admin')
@login_required
@admin_required
def admin():
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        # ... (logic to fetch all bookings) ...
        cursor.close()
        return render_template('admin.html', ...)
    except mysql.connector.Error as e:
        flash('Database error.', 'error'); logger.error(f"DB error in admin: {e}")
        return redirect(url_for('home'))

@app.route('/edit_booking/<ticket_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_booking(ticket_id):
    if not validate_ticket_id(ticket_id): return redirect(url_for('admin'))
    db = get_db()
    cursor = db.cursor(dictionary=True)
    # ... (logic to find correct table name) ...
    try:
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            phone = request.form.get('phone', '').strip()
            if not validate_name(name) or not validate_phone(phone):
                flash('Invalid name or phone format.', 'error'); return redirect(url_for('edit_booking', ticket_id=ticket_id))
            
            query = f"UPDATE {table_name} SET name = %s, phnum = %s WHERE ticketID = %s"
            cursor.execute(query, (name, phone, ticket_id))
            db.commit()
            flash('Booking updated!', 'success')
            return redirect(url_for('admin'))
        
        query = f"SELECT * FROM {table_name} WHERE ticketID = %s"
        cursor.execute(query, (ticket_id,))
        booking = cursor.fetchone()
        if not booking: flash('Booking not found.', 'error'); return redirect(url_for('admin'))
        return render_template('edit_booking.html', booking=booking)
    except mysql.connector.Error as e:
        flash('Database error.', 'error'); logger.error(f"DB error in edit_booking: {e}"); db.rollback()
        return redirect(url_for('admin'))
    finally:
        if cursor: cursor.close()

@app.route('/cancel_booking/<ticket_id>', methods=['POST'])
@login_required
@admin_required
def cancel_booking(ticket_id):
    if not validate_ticket_id(ticket_id): return redirect(url_for('admin'))
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        db.start_transaction()
        # ... (logic to find booking, get email) ...

        message = Mail(from_email=FROM_EMAIL, to_emails=email, subject='Booking Cancelled by Admin',
                       html_content=f'Your booking ({ticket_id}) has been cancelled.')
        sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
        sendgrid_client.send(message)
        
        db.commit()
        cursor.close()
        flash('Booking cancelled.', 'success')
    except Exception as e:
        flash('Error cancelling booking.', 'error'); logger.error(f"Error in cancel_booking: {e}"); db.rollback()
    return redirect(url_for('admin'))

@app.route('/check_pnr', methods=['GET', 'POST'])
def check_pnr():
    if request.method == 'POST':
        ticket_id = request.form.get('ticket_id', '').strip()
        if not validate_ticket_id(ticket_id): flash('Invalid ticket ID format.', 'error'); return redirect(url_for('check_pnr'))
        try:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            # ... (logic to find booking across tables) ...
            cursor.close()
            if not booking: flash('No booking found.', 'error'); return redirect(url_for('check_pnr'))
            return render_template('booking.html', booking=booking, booking_type=booking_type)
        except mysql.connector.Error as e:
            flash('Database error.', 'error'); logger.error(f"DB error in check_pnr: {e}")
            return redirect(url_for('check_pnr'))
    return render_template('check_pnr.html', booking=None)

@app.route('/booking_history')
@login_required
def booking_history():
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        user_id = current_user.id
        # ... (logic to fetch all of user's bookings) ...
        cursor.close()
        return render_template('booking_history.html', flight_bookings=flight_bookings, train_bookings=train_bookings, combined_bookings=combined_bookings)
    except mysql.connector.Error as e:
        flash('Database error.', 'error'); logger.error(f"DB error in booking_history: {e}")
        return redirect(url_for('home'))

@app.route('/user_cancel_booking', methods=['GET', 'POST'])
@login_required
def user_cancel_booking():
    if request.method == 'POST':
        ticket_id = request.form.get('ticket_id', '').strip()
        phone = request.form.get('phone', '').strip()
        # ... (validation) ...
        try:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            db.start_transaction()
            # ... (logic to find user's booking) ...
            
            message = Mail(from_email=FROM_EMAIL, to_emails=booking['gmail'], subject='Booking Cancellation Confirmation',
                           html_content=f'Your booking ({ticket_id}) has been cancelled.')
            sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
            sendgrid_client.send(message)
            
            db.commit()
            cursor.close()
            flash('Booking cancelled.', 'success')
        except Exception as e:
            flash('Error cancelling booking.', 'error'); logger.error(f"Error in user_cancel_booking: {e}"); db.rollback()
        return redirect(url_for('booking_history'))
    return render_template('cancel_booking.html')

# --- MAIN EXECUTION ---
if __name__ == '__main__':
    app.run(debug=False)
