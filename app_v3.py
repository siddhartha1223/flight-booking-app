from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_session import Session
from functools import wraps
import mysql.connector
import random
import smtplib
from email.message import EmailMessage
import re
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from datetime import datetime, timedelta
import bcrypt
from dotenv import load_dotenv
from io import BytesIO
import requests
import logging
from weasyprint import HTML

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24).hex())
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Load environment variables
load_dotenv()
SMTP_EMAIL = os.getenv('SMTP_EMAIL')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY')
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')

# Validate environment variables
required_env_vars = ['FLASK_SECRET_KEY', 'SMTP_EMAIL', 'SMTP_PASSWORD', 'RECAPTCHA_SITE_KEY', 'RECAPTCHA_SECRET_KEY']
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

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email, is_admin=False):
        self.id = id
        self.email = email
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT id, email, is_admin FROM users WHERE id = %s', (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(user_data['id'], user_data['email'], user_data.get('is_admin', False))
        return None
    except mysql.connector.Error as err:
        logger.error(f"Database error in load_user: {err}")
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Flight and train options
flight_map = {str(i): v for i, v in {
    1: 'Bangalore', 2: 'Chennai', 3: 'Mumbai', 4: 'Delhi', 5: 'Kolkata', 6: 'Hyderabad',
    7: 'Bangkok', 8: 'Kuala Lumpur', 9: 'London', 10: 'Singapore', 11: 'Dubai', 12: 'New York',
    13: 'Paris', 14: 'Tokyo', 15: 'Sydney', 16: 'Goa', 17: 'Pune', 18: 'Ahmedabad',
    19: 'Jaipur', 20: 'Lucknow'
}.items()}
train_options = {
    'Bangalore': {
        '1': ('BNC-MAS Express', '12609', 'Chennai'),
        '2': ('BNC-HYB Superfast', '12785', 'Hyderabad'),
        '3': ('BNC-TPTY Express', '16203', 'Tirupati'),
        '4': ('BNC-MYS Express', '16517', 'Mysore'),
        '5': ('BNC-CBE Intercity', '12677', 'Coimbatore')
    },
    'Chennai': {
        '1': ('MAS-BNC Mail', '12657', 'Bangalore'),
        '2': ('MAS-CSTM Express', '11042', 'Mumbai'),
        '3': ('MAS-HWH Coromandel', '12841', 'Kolkata'),
        '4': ('MAS-SBC Shatabdi', '12027', 'Bangalore'),
        '5': ('MAS-VSKP Express', '22801', 'Visakhapatnam')
    },
    'Mumbai': {
        '1': ('CSTM-MAS Express', '11041', 'Chennai'),
        '2': ('LTT-CBE Express', '11013', 'Coimbatore'),
        '3': ('CSTM-BNC Premium', '11301', 'Bangalore'),
        '4': ('LTT-VSKP Superfast', '22848', 'Visakhapatnam'),
        '5': ('CSTM-HWH Gitanjali', '12859', 'Kolkata')
    },
    'Delhi': {
        '1': ('NDLS-MAS Tamil Nadu', '12622', 'Chennai'),
        '2': ('NDLS-BNC Duronto', '12214', 'Bangalore'),
        '3': ('NZM-HYB Dakshin', '12722', 'Hyderabad'),
        '4': ('NDLS-HWH Rajdhani', '12302', 'Kolkata'),
        '5': ('DLI-JAT Rajdhani', '12425', 'Jammu')
    },
    'Kolkata': {
        '1': ('HWH-MAS Mail', '12839', 'Chennai'),
        '2': ('HWH-CSTM Duronto', '12262', 'Mumbai'),
        '3': ('HWH-BNC Superfast', '12504', 'Bangalore'),
        '4': ('HWH-NZM Yuva', '12249', 'Delhi'),
        '5': ('HWH-PURI Shatabdi', '12277', 'Puri')
    },
    'Hyderabad': {
        '1': ('HYB-MAS Charminar', '12760', 'Chennai'),
        '2': ('HYB-BNC Express', '17236', 'Bangalore'),
        '3': ('SC-CSTM Konark', '11020', 'Mumbai'),
        '4': ('SC-VSKP Godavari', '12728', 'Visakhapatnam'),
        '5': ('SC-NZM Rajdhani', '12438', 'Delhi')
    }
}

# Food menu
food_menu = {
    'North Indian Thali': 150, 'South Indian Thali': 120, 'Jain Thali': 180,
    'Continental Breakfast': 200, 'Chinese Noodles': 170, 'Veg Biryani': 160,
    'Paneer Tikka': 180, 'Chicken Curry': 220, 'Fish Fry': 250, 'Vegan Salad': 140
}

# --- Validation and Helper Functions ---
def validate_name(name):
    return bool(re.match(r'^[A-Za-z\s]{1,50}$', name))

def validate_phone(phone):
    return bool(re.match(r'^\d{10}$', phone))

def validate_email(email):
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))

def validate_ticket_id(ticket_id):
    return bool(re.match(r'^(FL|TR|CB)[A-Z]{3}\d{3}$', ticket_id))

def verify_recaptcha(response):
    """Helper function to verify reCAPTCHA response."""
    if not response:
        return False, "reCAPTCHA response is missing."
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
        return False, "Error verifying reCAPTCHA. Please check your connection and try again."

def validate_otp(otp, ticket_id):
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT otp, created_at FROM verification_tokens WHERE ticket_id = %s', (ticket_id,))
        token_data = cursor.fetchone()
        if not token_data:
            return False, "No OTP found for this ticket ID"
        stored_otp = token_data['otp']
        created_at = token_data['created_at']
        expiry_time = created_at + timedelta(minutes=10)
        if datetime.now() > expiry_time:
            return False, "OTP has expired"
        if str(otp).strip() != str(stored_otp):
            return False, "Invalid OTP"
        return True, "Valid OTP"
    except mysql.connector.Error as err:
        logger.error(f"Database error in validate_otp: {err}")
        return False, f"Database error: {err}"
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

def init_db():
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        conn.start_transaction()

        # Create users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            name VARCHAR(50) NOT NULL,
            phone VARCHAR(10) NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            INDEX idx_email (email)
        )''')

        # Create customers table (flight bookings) - ADDED travel_date
        cursor.execute('''CREATE TABLE IF NOT EXISTS customers (
            ticketID VARCHAR(10) PRIMARY KEY,
            user_id INT,
            name VARCHAR(50) NOT NULL,
            phnum VARCHAR(10) NOT NULL,
            gmail VARCHAR(100) NOT NULL,
            destination VARCHAR(50) NOT NULL,
            seat VARCHAR(10) NOT NULL,
            fare INT NOT NULL,
            class VARCHAR(20) NOT NULL,
            status VARCHAR(20) NOT NULL,
            travel_date DATE NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_user_id (user_id),
            INDEX idx_status (status)
        )''')

        # Create train_bookings table - ADDED travel_date
        cursor.execute('''CREATE TABLE IF NOT EXISTS train_bookings (
            ticketID VARCHAR(10) PRIMARY KEY,
            user_id INT,
            name VARCHAR(50) NOT NULL,
            phnum VARCHAR(10) NOT NULL,
            gmail VARCHAR(100) NOT NULL,
            train_name VARCHAR(50) NOT NULL,
            train_number VARCHAR(10) NOT NULL,
            destination VARCHAR(50) NOT NULL,
            compartment VARCHAR(5) NOT NULL,
            seat VARCHAR(10) NOT NULL,
            fare INT NOT NULL,
            status VARCHAR(20) NOT NULL,
            travel_date DATE NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_user_id (user_id),
            INDEX idx_status (status)
        )''')

        # Create combined_booking table
        cursor.execute('''CREATE TABLE IF NOT EXISTS combined_booking (
            ticketID VARCHAR(10) PRIMARY KEY,
            user_id INT,
            name VARCHAR(50) NOT NULL,
            phnum VARCHAR(10) NOT NULL,
            gmail VARCHAR(100) NOT NULL,
            flight_destination VARCHAR(50) NOT NULL,
            flight_seat VARCHAR(10) NOT NULL,
            flight_fare INT NOT NULL,
            flight_class VARCHAR(20) NOT NULL,
            train_name VARCHAR(50) NOT NULL,
            train_number VARCHAR(20) NOT NULL,
            train_destination VARCHAR(50) NOT NULL,
            train_compartment VARCHAR(10) NOT NULL,
            train_seat VARCHAR(10) NOT NULL,
            train_fare INT NOT NULL,
            status VARCHAR(20) NOT NULL,
            travel_date DATE NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_user_id (user_id),
            INDEX idx_status (status)
        )''')

        # Create food_orders table
        cursor.execute('''CREATE TABLE IF NOT EXISTS food_orders (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ticketID VARCHAR(10) NOT NULL,
            food_item VARCHAR(50) NOT NULL,
            quantity INT NOT NULL,
            food_cost INT NOT NULL,
            INDEX idx_ticketID (ticketID)
        )''')

        # Create seats table
        cursor.execute('''CREATE TABLE IF NOT EXISTS seats (
            id INT AUTO_INCREMENT PRIMARY KEY,
            type VARCHAR(10) NOT NULL,
            number VARCHAR(10) NOT NULL,
            status VARCHAR(20) NOT NULL,
            locked_until DATETIME,
            ticket_id VARCHAR(10),
            UNIQUE (type, number),
            INDEX idx_type_status (type, status),
            INDEX idx_ticket_id (ticket_id)
        )''')

        # Create verification_tokens table
        cursor.execute('''CREATE TABLE IF NOT EXISTS verification_tokens (
            ticket_id VARCHAR(10) PRIMARY KEY,
            otp INTEGER NOT NULL,
            created_at DATETIME NOT NULL,
            INDEX idx_created_at (created_at)
        )''')

        # Initialize seats only if empty
        cursor.execute('SELECT COUNT(*) as count FROM seats')
        if cursor.fetchone()[0] == 0:
            flight_seats = [f'B{i}' for i in range(1, 9)] + [f'E{i}' for i in range(1, 17)]
            for seat in flight_seats:
                cursor.execute('INSERT INTO seats (type, number, status) VALUES (%s, %s, %s)',
                              ('flight', seat, 'available'))
            train_seats = [f'T{i}' for i in range(1, 17)]
            for comp in ['S1', 'S2', 'S3']:
                for seat in train_seats:
                    cursor.execute('INSERT INTO seats (type, number, status) VALUES (%s, %s, %s)',
                                  ('train', f'{comp}-{seat}', 'available'))
            logger.info(f"Inserted {len(flight_seats)} flight seats and {len(train_seats) * 3} train seats")

        conn.commit()
        logger.info("Database initialized successfully")
    except mysql.connector.Error as err:
        logger.error(f"Database error in init_db: {err}")
        if conn: conn.rollback()
        raise
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

init_db()

# --- Routes ---

@app.route('/')
def home():
    return render_template('index.html', recaptcha_site_key=RECAPTCHA_SITE_KEY)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        recaptcha_response = request.form.get('g-recaptcha-response', '')

        # --- Validation Block ---
        is_valid, msg = verify_recaptcha(recaptcha_response)
        if not is_valid:
            flash(msg, 'error')
            return redirect(url_for('signup'))

        if not validate_name(name):
            flash('Invalid name. Use letters and spaces only (max 50 characters).', 'error')
            return redirect(url_for('signup'))
        if not validate_phone(phone):
            flash('Invalid phone number. Must be 10 digits.', 'error')
            return redirect(url_for('signup'))
        if not validate_email(email):
            flash('Invalid email address.', 'error')
            return redirect(url_for('signup'))
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$', password):
            flash('Password must be at least 6 characters with letters and numbers.', 'error')
            return redirect(url_for('signup'))
        # --- End Validation ---

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = None
        cursor = None
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            conn.start_transaction()
            cursor.execute('INSERT INTO users (email, password, name, phone, is_admin) VALUES (%s, %s, %s, %s, %s)',
                          (email, hashed_password.decode('utf-8'), name, phone, False))
            conn.commit()
            flash('Signup successful! Please log in.', 'success')
            logger.info(f"Signup successful for {email}")
        except mysql.connector.IntegrityError:
            flash('Email already registered.', 'error')
            logger.warning(f"Email already registered: {email}")
            if conn: conn.rollback()
        except mysql.connector.Error as err:
            flash('Database error occurred. Please try again.', 'error')
            logger.error(f"Database error in signup: {err}")
            if conn: conn.rollback()
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
        return redirect(url_for('login'))
    return render_template('signup.html', recaptcha_site_key=RECAPTCHA_SITE_KEY)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        logger.info(f"Login attempt: email={email}")
        conn = None
        cursor = None
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, email, password, is_admin FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                login_user(User(user['id'], user['email'], user.get('is_admin', False)))
                flash('Login successful!', 'success')
                logger.info(f"Login successful for {email}")
                return redirect(url_for('home'))
            flash('Invalid email or password.', 'error')
            logger.warning(f"Invalid email or password for {email}")
        except mysql.connector.Error as err:
            flash('Database error occurred. Please try again.', 'error')
            logger.error(f"Database error in login: {err}")
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
        return redirect(url_for('login'))
    return render_template('login.html', recaptcha_site_key=RECAPTCHA_SITE_KEY)

@app.route('/logout')
@login_required
def logout():
    logger.info(f"User {current_user.email} logged out")
    logout_user()
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/book_flight', methods=['GET', 'POST'])
def book_flight():
    if request.method == 'POST':
        # --- Data Retrieval ---
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        destination = request.form.get('flight_destination', '')
        seat = request.form.get('flight_seat', '')
        flight_class = request.form.get('flight_class', '')
        food_items = request.form.getlist('food_orders')
        travel_date = request.form.get('travel_date', '')
        recaptcha_response = request.form.get('g-recaptcha-response', '')

        # --- Validation Block ---
        is_valid, msg = verify_recaptcha(recaptcha_response)
        if not is_valid:
            flash(msg, 'error')
            return redirect(url_for('book_flight'))

        if not all([validate_name(name), validate_phone(phone), validate_email(email),
                    destination in flight_map, seat, re.match(r'^(B|E)\d+$', seat),
                    flight_class in ('Economy', 'Business'), travel_date]):
            flash('Invalid input provided. Please check all fields carefully.', 'error')
            return redirect(url_for('book_flight'))
        # --- End Validation ---
        
        food_quantities = {}
        for item in food_items:
            qty = request.form.get(f'quantity_{item}', '1').strip()
            if not qty.isdigit() or int(qty) <= 0:
                flash(f'Invalid quantity for {item}. Must be a positive number.', 'error')
                return redirect(url_for('book_flight'))
            food_quantities[item] = int(qty)

        conn = None
        cursor = None
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            conn.start_transaction()

            # Lock seat to prevent race conditions
            cursor.execute('SELECT status, locked_until FROM seats WHERE type = %s AND number = %s FOR UPDATE', ('flight', seat))
            seat_data = cursor.fetchone()

            is_unavailable = (not seat_data or
                              seat_data['status'] == 'booked' or
                              (seat_data['status'] == 'locked' and seat_data['locked_until'] and seat_data['locked_until'] > datetime.now()))

            if is_unavailable:
                flash('Selected seat is not available. Please choose another one.', 'error')
                conn.rollback()
                return redirect(url_for('book_flight'))

            # Generate a unique ticket ID
            ticket_id = f'FL{name[:3].upper()}{random.randint(100, 999)}'
            cursor.execute('SELECT 1 FROM customers WHERE ticketID = %s', (ticket_id,))
            while cursor.fetchone():
                ticket_id = f'FL{name[:3].upper()}{random.randint(100, 999)}'
                cursor.execute('SELECT 1 FROM customers WHERE ticketID = %s', (ticket_id,))

            cursor.execute('UPDATE seats SET status = %s, locked_until = %s, ticket_id = %s WHERE type = %s AND number = %s',
                          ('locked', datetime.now() + timedelta(minutes=10), ticket_id, 'flight', seat))
            
            # Fare Calculation
            now = datetime.now()
            travel_date_obj = datetime.strptime(travel_date, '%Y-%m-%d')
            is_peak = now.hour in range(8, 12) or now.hour in range(17, 21)
            days_to_travel = (travel_date_obj - now).days
            domestic = tuple(flight_map.values())[:6] + ('Goa', 'Pune', 'Ahmedabad', 'Jaipur', 'Lucknow')
            base_fare = (5000, 7000) if flight_map[destination] in domestic else (60000, 80000)
            economy_fare = (3500, 5500) if flight_map[destination] in domestic else (30000, 50000)
            fare = random.randint(base_fare[0], base_fare[1]) if flight_class == 'Business' else random.randint(economy_fare[0], economy_fare[1])
            if is_peak: fare = int(fare * 1.2)
            if days_to_travel < 7: fare = int(fare * 1.3)
            elif days_to_travel > 30: fare = int(fare * 0.8)

            # Food Calculation
            food_orders = []
            food_cost = 0
            for item in sorted(food_items):
                if item in food_menu:
                    qty = food_quantities.get(item, 1)
                    cost = food_menu[item] * qty
                    food_cost += cost
                    food_orders.append((item, qty, cost))

            # Store in session for payment page
            session['booking'] = {
                'type': 'flight', 'ticket_id': ticket_id,
                'user_id': current_user.id if current_user.is_authenticated else None,
                'name': name, 'phone': phone, 'email': email,
                'destination': flight_map[destination], 'seat': seat, 'class': flight_class,
                'fare': fare, 'food_cost': food_cost, 'food_orders': food_orders,
                'travel_date': travel_date
            }
            conn.commit()
            logger.info(f"Booking session created for payment: ticket_id={ticket_id}")
            return render_template('dummy_payment.html', booking=session['booking'])

        except mysql.connector.Error as err:
            flash('Database error occurred. Please try again.', 'error')
            logger.error(f"Database error in book_flight: {err}")
            if conn: conn.rollback()
            return redirect(url_for('book_flight'))
        finally:
            if cursor: cursor.close()
            if conn and conn.is_connected(): conn.close()
    
    # --- GET Request Logic ---
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT number, status, CASE WHEN status = 'locked' AND locked_until < NOW() THEN 'available' ELSE status END as display_status FROM seats WHERE type = %s", ('flight',))
        seats = cursor.fetchall()
        return render_template('book_flight.html', flight_map=flight_map, seats=seats, food_menu=food_menu, recaptcha_site_key=RECAPTCHA_SITE_KEY)
    except mysql.connector.Error as err:
        flash('Database error occurred fetching flight data.', 'error')
        logger.error(f"Database error in book_flight GET: {err}")
        return redirect(url_for('home'))
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

@app.route('/book_train', methods=['GET', 'POST'])
def book_train():
    if request.method == 'POST':
        # --- Data Retrieval ---
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        train_choice = request.form.get('train', '')
        compartment = request.form.get('train_compartment', '')
        seat = request.form.get('train_seat', '')
        food_items = request.form.getlist('food_orders')
        travel_date = request.form.get('travel_date', '')
        recaptcha_response = request.form.get('g-recaptcha-response', '')

        # --- Validation Block ---
        is_valid, msg = verify_recaptcha(recaptcha_response)
        if not is_valid:
            flash(msg, 'error')
            return redirect(url_for('book_train'))

        if not all([validate_name(name), validate_phone(phone), validate_email(email),
                    train_choice, compartment in ['S1', 'S2', 'S3'],
                    seat, re.match(r'^T\d+$', seat), travel_date]):
            flash('Invalid input provided. Please check all fields carefully.', 'error')
            return redirect(url_for('book_train'))
        # --- End Validation ---

        food_quantities = {}
        for item in food_items:
            qty = request.form.get(f'quantity_{item}', '1').strip()
            if not qty.isdigit() or int(qty) <= 0:
                flash(f'Invalid quantity for {item}. Must be a positive number.', 'error')
                return redirect(url_for('book_train'))
            food_quantities[item] = int(qty)

        conn = None
        cursor = None
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            conn.start_transaction()

            seat_number = f'{compartment}-{seat}'
            cursor.execute('SELECT status, locked_until FROM seats WHERE type = %s AND number = %s FOR UPDATE', ('train', seat_number))
            seat_data = cursor.fetchone()

            is_unavailable = (not seat_data or
                              seat_data['status'] == 'booked' or
                              (seat_data['status'] == 'locked' and seat_data['locked_until'] and seat_data['locked_until'] > datetime.now()))

            if is_unavailable:
                flash('Selected seat is not available. Please choose another one.', 'error')
                conn.rollback()
                return redirect(url_for('book_train'))
            
            train_name, train_number, destination = None, None, None
            for dest, trains in train_options.items():
                if train_choice in trains:
                    train_name, train_number, destination = trains[train_choice]
                    break
            
            if not train_name:
                flash('Invalid train selected.', 'error')
                conn.rollback()
                return redirect(url_for('book_train'))

            ticket_id = f'TR{name[:3].upper()}{random.randint(100, 999)}'
            cursor.execute('SELECT 1 FROM train_bookings WHERE ticketID = %s', (ticket_id,))
            while cursor.fetchone():
                ticket_id = f'TR{name[:3].upper()}{random.randint(100, 999)}'
                cursor.execute('SELECT 1 FROM train_bookings WHERE ticketID = %s', (ticket_id,))
            
            cursor.execute('UPDATE seats SET status = %s, locked_until = %s, ticket_id = %s WHERE type = %s AND number = %s',
                          ('locked', datetime.now() + timedelta(minutes=10), ticket_id, 'train', seat_number))

            # Fare Calculation
            now = datetime.now()
            travel_date_obj = datetime.strptime(travel_date, '%Y-%m-%d')
            is_peak = now.hour in range(7, 12) or now.hour in range(16, 17)
            days_to_travel = (travel_date_obj - now).days
            fare = random.randint(500, 1000)
            if is_peak: fare = int(fare * 1.2)
            if days_to_travel < 7: fare = int(fare * 1.3)
            elif days_to_travel > 30: fare = int(fare * 0.8)

            # Food Calculation
            food_orders = []
            food_cost = 0
            for item in sorted(food_items):
                if item in food_menu:
                    qty = food_quantities.get(item, 1)
                    cost = food_menu[item] * qty
                    food_cost += cost
                    food_orders.append((item, qty, cost))

            # Store in session for payment page
            session['booking'] = {
                'type': 'train',
                'ticket_id': ticket_id,
                'user_id': current_user.id if current_user.is_authenticated else None,
                'name': name, 'phone': phone, 'email': email,
                'train_name': train_name, 'train_number': train_number,
                'destination': destination, 'compartment': compartment,
                'seat': seat, 'fare': fare, 'food_cost': food_cost,
                'food_orders': food_orders, 'travel_date': travel_date
            }
            
            conn.commit()
            logger.info(f"Booking session created for payment: ticket_id={ticket_id}")
            return render_template('dummy_payment.html', booking=session['booking'])

        except mysql.connector.Error as err:
            flash('Database error occurred. Please try again.', 'error')
            logger.error(f"Database error in book_train: {err}")
            if conn: conn.rollback()
            return redirect(url_for('book_train'))
        finally:
            if cursor: cursor.close()
            if conn and conn.is_connected(): conn.close()

    # --- GET Request Logic ---
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT number, status, CASE WHEN status = 'locked' AND locked_until < NOW() THEN 'available' ELSE status END as display_status FROM seats WHERE type = %s", ('train',))
        train_seats = cursor.fetchall()
        return render_template('book_train.html', train_options=train_options, seats=train_seats, food_menu=food_menu, recaptcha_site_key=RECAPTCHA_SITE_KEY)
    except mysql.connector.Error as err:
        flash('Database error occurred fetching train data.', 'error')
        logger.error(f"Database error in book_train GET: {err}")
        return redirect(url_for('home'))
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()


@app.route('/book_combined', methods=['GET', 'POST'])
def book_combined():
    if request.method == 'POST':
        # --- Data Retrieval ---
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        flight_destination = request.form.get('flight_destination', '')
        flight_seat = request.form.get('flight_seat', '')
        flight_class = request.form.get('flight_class', '')
        train_choice = request.form.get('train', '')
        train_compartment = request.form.get('train_compartment', '')
        train_seat = request.form.get('train_seat', '')
        food_items = request.form.getlist('food_orders')
        travel_date = request.form.get('travel_date', '')
        recaptcha_response = request.form.get('g-recaptcha-response', '')
        
        # --- Validation Block ---
        is_valid, msg = verify_recaptcha(recaptcha_response)
        if not is_valid:
            flash(msg, 'error')
            return redirect(url_for('book_combined'))
            
        if not all([validate_name(name), validate_phone(phone), validate_email(email),
                    flight_destination in flight_map, flight_seat, re.match(r'^(B|E)\d+$', flight_seat),
                    flight_class in ('Economy', 'Business'), train_choice,
                    train_compartment in ['S1', 'S2', 'S3'], train_seat, re.match(r'^T\d+$', train_seat),
                    travel_date]):
            flash('Invalid input provided. Please check all fields carefully.', 'error')
            return redirect(url_for('book_combined'))
        # --- End Validation ---

        food_quantities = {}
        for item in food_items:
            qty = request.form.get(f'quantity_{item}', '1').strip()
            if not qty.isdigit() or int(qty) <= 0:
                flash(f'Invalid quantity for {item}. Must be a positive number.', 'error')
                return redirect(url_for('book_combined'))
            food_quantities[item] = int(qty)

        conn = None
        cursor = None
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            conn.start_transaction()

            # Lock and check flight seat
            cursor.execute('SELECT status, locked_until FROM seats WHERE type = %s AND number = %s FOR UPDATE', ('flight', flight_seat))
            flight_seat_data = cursor.fetchone()
            flight_seat_unavailable = (not flight_seat_data or
                                       flight_seat_data['status'] == 'booked' or
                                       (flight_seat_data['status'] == 'locked' and flight_seat_data['locked_until'] and flight_seat_data['locked_until'] > datetime.now()))

            # Lock and check train seat
            train_seat_number = f'{train_compartment}-{train_seat}'
            cursor.execute('SELECT status, locked_until FROM seats WHERE type = %s AND number = %s FOR UPDATE', ('train', train_seat_number))
            train_seat_data = cursor.fetchone()
            train_seat_unavailable = (not train_seat_data or
                                      train_seat_data['status'] == 'booked' or
                                      (train_seat_data['status'] == 'locked' and train_seat_data['locked_until'] and train_seat_data['locked_until'] > datetime.now()))

            if flight_seat_unavailable or train_seat_unavailable:
                flash('One or more of the selected seats are not available. Please choose again.', 'error')
                conn.rollback()
                return redirect(url_for('book_combined'))

            ticket_id = f'CB{name[:3].upper()}{random.randint(100, 999)}'
            cursor.execute('SELECT 1 FROM combined_booking WHERE ticketID = %s', (ticket_id,))
            while cursor.fetchone():
                ticket_id = f'CB{name[:3].upper()}{random.randint(100, 999)}'
                cursor.execute('SELECT 1 FROM combined_booking WHERE ticketID = %s', (ticket_id,))

            # Lock both seats for this transaction
            cursor.execute('UPDATE seats SET status = %s, locked_until = %s, ticket_id = %s WHERE type = %s AND number = %s',
                          ('locked', datetime.now() + timedelta(minutes=10), ticket_id, 'flight', flight_seat))
            cursor.execute('UPDATE seats SET status = %s, locked_until = %s, ticket_id = %s WHERE type = %s AND number = %s',
                          ('locked', datetime.now() + timedelta(minutes=10), ticket_id, 'train', train_seat_number))
            
            # Fare and other logic
            flight_fare = 5000 
            train_fare = 800

            train_name, train_number, train_destination = None, None, None
            for dest, trains in train_options.items():
                if train_choice in trains:
                    train_name, train_number, train_destination = trains[train_choice]
                    break
            
            if not train_name:
                flash('Invalid train selected.', 'error')
                conn.rollback()
                return redirect(url_for('book_combined'))

            # Food Calculation
            food_orders = []
            food_cost = 0
            for item in sorted(food_items):
                if item in food_menu:
                    qty = food_quantities.get(item, 1)
                    cost = food_menu[item] * qty
                    food_cost += cost
                    food_orders.append((item, qty, cost))
            
            session['booking'] = {
                'type': 'combined', 'ticket_id': ticket_id,
                'user_id': current_user.id if current_user.is_authenticated else None,
                'name': name, 'phone': phone, 'email': email,
                'flight_destination': flight_map[flight_destination], 'flight_seat': flight_seat,
                'flight_fare': flight_fare, 'flight_class': flight_class,
                'train_name': train_name, 'train_number': train_number,
                'train_destination': train_destination, 'train_compartment': train_compartment,
                'train_seat': train_seat, 'train_fare': train_fare,
                'food_cost': food_cost, 'food_orders': food_orders, 'travel_date': travel_date
            }
            
            conn.commit()
            logger.info(f"Booking session created for payment: ticket_id={ticket_id}")
            return render_template('dummy_payment.html', booking=session['booking'])
        
        except mysql.connector.Error as err:
            flash('Database error occurred. Please try again.', 'error')
            logger.error(f"Database error in book_combined: {err}")
            if conn: conn.rollback()
            return redirect(url_for('book_combined'))
        finally:
            if cursor: cursor.close()
            if conn and conn.is_connected(): conn.close()

    # --- GET Request Logic ---
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT number, status, CASE WHEN status = 'locked' AND locked_until < NOW() THEN 'available' ELSE status END as display_status FROM seats WHERE type = 'flight'")
        flight_seats = cursor.fetchall()
        cursor.execute("SELECT number, status, CASE WHEN status = 'locked' AND locked_until < NOW() THEN 'available' ELSE status END as display_status FROM seats WHERE type = 'train'")
        train_seats = cursor.fetchall()
        return render_template('book_combined.html', flight_map=flight_map, train_options=train_options,
                              flight_seats=flight_seats, train_seats=train_seats, food_menu=food_menu,
                              recaptcha_site_key=RECAPTCHA_SITE_KEY)
    except mysql.connector.Error as err:
        flash('Database error occurred fetching data.', 'error')
        logger.error(f"Database error in book_combined GET: {err}")
        return redirect(url_for('home'))
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()


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

@app.route('/payment_success', methods=['GET', 'POST'])
def payment_success():
    booking = session.get('booking')
    if not booking or not validate_ticket_id(booking['ticket_id']):
        flash('Invalid or expired booking session.', 'error')
        return redirect(url_for('home'))

    conn = None
    cursor = None
    ticket_id = booking['ticket_id']

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        conn.start_transaction()
        user_id = booking['user_id']
        
        # 1. Insert booking record and update seat status
        if booking['type'] == 'flight':
            cursor.execute('''INSERT INTO customers (ticketID, user_id, name, phnum, gmail, destination, seat, fare, class, status, travel_date)
                              VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s)''',
                           (ticket_id, user_id, booking['name'], booking['phone'], booking['email'], booking['destination'],
                            booking['seat'], booking['fare'], booking['class'], booking['travel_date']))
            cursor.execute("UPDATE seats SET status = 'booked', locked_until = NULL WHERE ticket_id = %s AND type = 'flight'", (ticket_id,))
        
        elif booking['type'] == 'train':
            cursor.execute('''INSERT INTO train_bookings (ticketID, user_id, name, phnum, gmail, train_name, train_number, destination, compartment, seat, fare, status, travel_date)
                              VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s)''',
                           (ticket_id, user_id, booking['name'], booking['phone'], booking['email'], booking['train_name'], booking['train_number'],
                            booking['destination'], booking['compartment'], booking['seat'], booking['fare'], booking['travel_date']))
            cursor.execute("UPDATE seats SET status = 'booked', locked_until = NULL WHERE ticket_id = %s AND type = 'train'", (ticket_id,))
            
        elif booking['type'] == 'combined':
            cursor.execute('''INSERT INTO combined_booking (ticketID, user_id, name, phnum, gmail, flight_destination, flight_seat, flight_fare, flight_class, train_name, train_number, train_destination, train_compartment, train_seat, train_fare, status, travel_date)
                              VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s)''',
                           (ticket_id, user_id, booking['name'], booking['phone'], booking['email'], booking['flight_destination'],
                            booking['flight_seat'], booking['flight_fare'], booking['flight_class'], booking['train_name'],
                            booking['train_number'], booking['train_destination'], booking['train_compartment'],
                            booking['train_seat'], booking['train_fare'], booking['travel_date']))
            cursor.execute("UPDATE seats SET status = 'booked', locked_until = NULL WHERE ticket_id = %s", (ticket_id,))

        # 2. Insert food orders
        for item, qty, cost in booking.get('food_orders', []):
            cursor.execute('INSERT INTO food_orders (ticketID, food_item, quantity, food_cost) VALUES (%s, %s, %s, %s)',
                           (ticket_id, item, qty, cost))

        # 3. Create OTP
        otp = random.randint(100000, 999999)
        cursor.execute('INSERT INTO verification_tokens (ticket_id, otp, created_at) VALUES (%s, %s, %s)',
                       (ticket_id, otp, datetime.now()))

        # 4. Send verification email via SendGrid API
        message = Mail(
            from_email='travelbooking234@gmail.com',  # IMPORTANT: Use the email you verified with SendGrid
            to_emails=booking['email'],
            subject='Your Booking Verification OTP',
            html_content=f'<strong>Your booking is pending verification.</strong><br>Please use this OTP to complete your booking: <h1>{otp}</h1>'
        )
        sendgrid_client = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sendgrid_client.send(message)

        if response.status_code < 200 or response.status_code >= 300:
            raise Exception(f"SendGrid email failed with status {response.status_code}: {response.body}")
            
        # 5. If all succeeds, commit the transaction
        conn.commit()
        session.pop('booking', None)
        flash('Payment successful! Please verify your booking with the OTP sent to your email.', 'success')
        logger.info(f"Payment successful, verification pending: ticket_id={ticket_id}")
        return redirect(url_for('verify_booking', ticket_id=ticket_id))

    except Exception as e:
        logger.error(f"Error in payment_success for ticket {ticket_id}: {e}")
        if conn:
            conn.rollback()
        
        # Release the seat lock in a new transaction
        try:
            conn_cleanup = mysql.connector.connect(**db_config)
            cursor_cleanup = conn_cleanup.cursor()
            cursor_cleanup.execute("UPDATE seats SET status = 'available', locked_until = NULL, ticket_id = NULL WHERE ticket_id = %s AND status = 'locked'", (ticket_id,))
            conn_cleanup.commit()
        except mysql.connector.Error as cleanup_err:
            logger.error(f"CRITICAL: Failed to release seat lock for ticket {ticket_id} after payment failure: {cleanup_err}")
        finally:
            if 'conn_cleanup' in locals() and conn_cleanup.is_connected():
                cursor_cleanup.close()
                conn_cleanup.close()
                
        flash('A critical error occurred. Your booking was not completed. Please try again.', 'error')
        return redirect(url_for('home'))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route('/verify_booking/<ticket_id>', methods=['GET', 'POST'])
def verify_booking(ticket_id):
    if not validate_ticket_id(ticket_id):
        flash('Invalid ticket ID format.', 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        valid, message = validate_otp(otp, ticket_id)
        if not valid:
            flash(message, 'error')
            return redirect(url_for('verify_booking', ticket_id=ticket_id))

        conn = None
        cursor = None
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            conn.start_transaction()
            
            # Determine booking type and update status
            table_to_update = None
            cursor.execute('SELECT 1 FROM customers WHERE ticketID = %s', (ticket_id,))
            if cursor.fetchone():
                table_to_update = 'customers'
            else:
                cursor.execute('SELECT 1 FROM train_bookings WHERE ticketID = %s', (ticket_id,))
                if cursor.fetchone():
                    table_to_update = 'train_bookings'
                else:
                    cursor.execute('SELECT 1 FROM combined_booking WHERE ticketID = %s', (ticket_id,))
                    if cursor.fetchone():
                        table_to_update = 'combined_booking'

            if table_to_update:
                query = f'UPDATE {table_to_update} SET status = %s WHERE ticketID = %s'
                cursor.execute(query, ('confirmed', ticket_id))
                cursor.execute('DELETE FROM verification_tokens WHERE ticket_id = %s', (ticket_id,))
                conn.commit()
                flash('Booking verified successfully!', 'success')
                logger.info(f"Booking verified: ticket_id={ticket_id}")
                return redirect(url_for('download_ticket', ticket_id=ticket_id))
            else:
                flash('Booking not found.', 'error')
                conn.rollback()
                return redirect(url_for('home'))

        except mysql.connector.Error as e:
            flash('Database error occurred.', 'error')
            logger.error(f"Database error in verify_booking: {e}")
            if conn: conn.rollback()
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
        return redirect(url_for('verify_booking', ticket_id=ticket_id))

    return render_template('verify_booking.html', ticket_id=ticket_id, recaptcha_site_key=RECAPTCHA_SITE_KEY)

@app.route('/download_ticket/<ticket_id>')
def download_ticket(ticket_id):
    if not validate_ticket_id(ticket_id):
        flash('Invalid ticket ID format.', 'error')
        return redirect(url_for('home'))

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        booking = None
        booking_type = None
        
        # Determine booking type and fetch details
        if ticket_id.startswith('FL'):
            cursor.execute('SELECT * FROM customers WHERE ticketID = %s AND status = %s', (ticket_id, 'confirmed'))
            booking = cursor.fetchone()
            if booking: booking_type = 'flight'
        elif ticket_id.startswith('TR'):
            cursor.execute('SELECT * FROM train_bookings WHERE ticketID = %s AND status = %s', (ticket_id, 'confirmed'))
            booking = cursor.fetchone()
            if booking: booking_type = 'train'
        elif ticket_id.startswith('CB'):
            cursor.execute('SELECT * FROM combined_booking WHERE ticketID = %s AND status = %s', (ticket_id, 'confirmed'))
            booking = cursor.fetchone()
            if booking: booking_type = 'combined'

        if not booking:
            flash('Booking not found or not confirmed.', 'error')
            return redirect(url_for('home'))

        cursor.execute('SELECT food_item, quantity, food_cost FROM food_orders WHERE ticketID = %s', (ticket_id,))
        booking['food_orders'] = cursor.fetchall()

        # --- Generate PDF in memory ---
        html_content = render_template('ticket.html', booking=booking, booking_type=booking_type)
        pdf_file = BytesIO()
        HTML(string=html_content).write_pdf(pdf_file)
        pdf_file.seek(0) # Reset buffer to the beginning

        # --- NEW: Email the generated PDF as an attachment ---
        try:
            msg = EmailMessage()
            msg['Subject'] = f"Your Booking Confirmation and Ticket (ID: {ticket_id})"
            msg['From'] = SMTP_EMAIL
            msg['To'] = booking['gmail']
            msg.set_content('Thank you for your booking! Your ticket is attached to this email.')

            # Attach the PDF
            msg.add_attachment(pdf_file.read(),
                               maintype='application',
                               subtype='pdf',
                               filename=f'ticket_{ticket_id}.pdf')

            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.starttls()
                smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
                smtp.send_message(msg)
            
            logger.info(f"Ticket {ticket_id} successfully mailed to {booking['gmail']}")
            pdf_file.seek(0) # Reset buffer again for the download response

        except smtplib.SMTPException as e:
            logger.error(f"Failed to email ticket {ticket_id}: {e}")
            # Optionally flash a message that email failed but download can proceed
            flash('Your ticket was generated, but there was an error sending it to your email.', 'warning')
        # --- End of new email logic ---

        logger.info(f"Ticket downloaded: ticket_id={ticket_id}, type={booking_type}")
        return send_file(pdf_file, mimetype='application/pdf', as_attachment=True, download_name=f'ticket_{ticket_id}.pdf')

    except Exception as e:
        flash('Error generating ticket.', 'error')
        logger.error(f"Error in download_ticket: {e}")
        return redirect(url_for('home'))
        
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/admin', methods=['GET'])
@login_required
@admin_required
def admin():
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT ticketID, name, gmail, destination, seat, fare, class, status, travel_date FROM customers')
        flight_bookings = cursor.fetchall()
        cursor.execute('SELECT ticketID, name, gmail, train_name, train_number, destination, compartment, seat, fare, status, travel_date FROM train_bookings')
        train_bookings = cursor.fetchall()
        cursor.execute('SELECT ticketID, name, gmail, flight_destination, flight_seat, flight_fare, flight_class, train_name, train_number, train_destination, train_compartment, train_seat, train_fare, status, travel_date FROM combined_booking')
        combined_bookings = cursor.fetchall()

        all_bookings = flight_bookings + train_bookings + combined_bookings
        for booking in all_bookings:
            cursor.execute('SELECT food_item, quantity, food_cost FROM food_orders WHERE ticketID = %s', (booking['ticketID'],))
            booking['food_orders'] = cursor.fetchall()

        return render_template('admin.html', flight_bookings=flight_bookings, train_bookings=train_bookings, combined_bookings=combined_bookings)
    except mysql.connector.Error as e:
        flash('Database error occurred.', 'error')
        logger.error(f"Database error in admin: {e}")
        return redirect(url_for('home'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/edit_booking/<ticket_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_booking(ticket_id):
    if not validate_ticket_id(ticket_id):
        flash('Invalid ticket ID format.', 'error')
        return redirect(url_for('admin'))

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        
        # Determine the table and fetch booking details
        table_name = None
        if ticket_id.startswith('FL'):
            table_name = 'customers'
        elif ticket_id.startswith('TR'):
            table_name = 'train_bookings'
        elif ticket_id.startswith('CB'):
            table_name = 'combined_booking'

        if not table_name:
            flash('Invalid ticket prefix.', 'error')
            return redirect(url_for('admin'))

        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            phone = request.form.get('phone', '').strip()

            if not validate_name(name) or not validate_phone(phone):
                flash('Invalid name or phone format.', 'error')
                return redirect(url_for('edit_booking', ticket_id=ticket_id))

            # Use the correct column name for phone number
            phone_column = 'phnum'
            
            query = f"UPDATE {table_name} SET name = %s, {phone_column} = %s WHERE ticketID = %s"
            cursor.execute(query, (name, phone, ticket_id))
            conn.commit()
            flash('Booking updated successfully!', 'success')
            logger.info(f"Admin {current_user.email} updated ticket {ticket_id}")
            return redirect(url_for('admin'))

        # For GET request, show the edit form
        query = f"SELECT * FROM {table_name} WHERE ticketID = %s"
        cursor.execute(query, (ticket_id,))
        booking = cursor.fetchone()

        if not booking:
            flash('Booking not found.', 'error')
            return redirect(url_for('admin'))
        
        return render_template('edit_booking.html', booking=booking)

    except mysql.connector.Error as e:
        flash('Database error occurred.', 'error')
        logger.error(f"Database error in edit_booking: {e}")
        return redirect(url_for('admin'))
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/cancel_booking/<ticket_id>', methods=['POST'])
@login_required
@admin_required
def cancel_booking(ticket_id):
    if not validate_ticket_id(ticket_id):
        flash('Invalid ticket ID format.', 'error')
        return redirect(url_for('admin'))

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        conn.start_transaction()
        
        # Determine booking type and get details
        email = None
        table_to_update = None
        cursor.execute('SELECT gmail, status FROM customers WHERE ticketID = %s', (ticket_id,))
        booking = cursor.fetchone()
        if booking:
            table_to_update = 'customers'
        else:
            cursor.execute('SELECT gmail, status FROM train_bookings WHERE ticketID = %s', (ticket_id,))
            booking = cursor.fetchone()
            if booking:
                table_to_update = 'train_bookings'
            else:
                cursor.execute('SELECT gmail, status FROM combined_booking WHERE ticketID = %s', (ticket_id,))
                booking = cursor.fetchone()
                if booking:
                    table_to_update = 'combined_booking'

        if not booking:
            flash('Booking not found.', 'error')
            conn.rollback()
            return redirect(url_for('admin'))

        if booking['status'] == 'cancelled':
            flash('Booking already cancelled.', 'error')
            conn.rollback()
            return redirect(url_for('admin'))

        email = booking['gmail']
        query = f'UPDATE {table_to_update} SET status = %s WHERE ticketID = %s'
        cursor.execute(query, ('cancelled', ticket_id))

        cursor.execute('UPDATE seats SET status = %s, locked_until = NULL, ticket_id = NULL WHERE ticket_id = %s',
                      ('available', ticket_id))

        msg = EmailMessage()
        msg.set_content(f'Your booking (Ticket ID: {ticket_id}) has been cancelled by the admin.')
        msg['Subject'] = 'Booking Cancellation'
        msg['From'] = SMTP_EMAIL
        msg['To'] = email
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()
            smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
            smtp.send_message(msg)
        
        conn.commit()
        flash('Booking cancelled successfully.', 'success')
        logger.info(f"Booking cancelled by admin: ticket_id={ticket_id}")
    except (mysql.connector.Error, smtplib.SMTPException) as e:
        flash('Error cancelling booking.', 'error')
        logger.error(f"Error in cancel_booking: {e}")
        if conn: conn.rollback()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    return redirect(url_for('admin'))

@app.route('/check_pnr', methods=['GET', 'POST'])
def check_pnr():
    if request.method == 'POST':
        ticket_id = request.form.get('ticket_id', '').strip()
        if not validate_ticket_id(ticket_id):
            flash('Invalid ticket ID format.', 'error')
            return redirect(url_for('check_pnr'))

        conn = None
        cursor = None
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            booking = None
            booking_type = None

            cursor.execute('SELECT * FROM customers WHERE ticketID = %s', (ticket_id,))
            booking = cursor.fetchone()
            if booking:
                booking_type = 'flight'
            else:
                cursor.execute('SELECT * FROM train_bookings WHERE ticketID = %s', (ticket_id,))
                booking = cursor.fetchone()
                if booking:
                    booking_type = 'train'
                else:
                    cursor.execute('SELECT * FROM combined_booking WHERE ticketID = %s', (ticket_id,))
                    booking = cursor.fetchone()
                    if booking:
                        booking_type = 'combined'

            if not booking:
                flash('No booking found with this ticket ID.', 'error')
                return redirect(url_for('check_pnr'))

            cursor.execute('SELECT food_item, quantity, food_cost FROM food_orders WHERE ticketID = %s', (ticket_id,))
            booking['food_orders'] = cursor.fetchall()

            logger.info(f"PNR checked: ticket_id={ticket_id}, type={booking_type}")
            return render_template('booking.html', booking=booking, booking_type=booking_type)
        except mysql.connector.Error as e:
            flash('Database error.', 'error')
            logger.error(f"Database error in check_pnr: {e}")
            return redirect(url_for('check_pnr'))
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('check_pnr.html', booking=None, recaptcha_site_key=RECAPTCHA_SITE_KEY)

@app.route('/booking_history', methods=['GET'])
@login_required
def booking_history():
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        user_id = current_user.id
        cursor.execute('SELECT * FROM customers WHERE user_id = %s', (user_id,))
        flight_bookings = cursor.fetchall()
        cursor.execute('SELECT * FROM train_bookings WHERE user_id = %s', (user_id,))
        train_bookings = cursor.fetchall()
        cursor.execute('SELECT * FROM combined_booking WHERE user_id = %s', (user_id,))
        combined_bookings = cursor.fetchall()
        
        all_bookings = flight_bookings + train_bookings + combined_bookings
        for booking in all_bookings:
            cursor.execute('SELECT food_item, quantity, food_cost FROM food_orders WHERE ticketID = %s', (booking['ticketID'],))
            booking['food_orders'] = cursor.fetchall()

        return render_template('booking_history.html', flight_bookings=flight_bookings, train_bookings=train_bookings, combined_bookings=combined_bookings)
    except mysql.connector.Error as e:
        flash('Database error occurred.', 'error')
        logger.error(f"Database error in booking_history: {e}")
        return redirect(url_for('home'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/user_cancel_booking', methods=['GET', 'POST'])
@login_required
def user_cancel_booking():
    if request.method == 'POST':
        ticket_id = request.form.get('ticket_id', '').strip()
        phone = request.form.get('phone', '').strip()
        if not validate_ticket_id(ticket_id) or not validate_phone(phone):
            flash('Invalid input format.', 'error')
            return redirect(url_for('user_cancel_booking'))

        conn = None
        cursor = None
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            conn.start_transaction()
            
            # Find the booking across all tables for the current user
            table_to_update = None
            booking = None
            
            cursor.execute('SELECT * FROM customers WHERE ticketID = %s AND user_id = %s', (ticket_id, current_user.id))
            booking_flight = cursor.fetchone()
            if booking_flight:
                table_to_update, booking = 'customers', booking_flight
            else:
                cursor.execute('SELECT * FROM train_bookings WHERE ticketID = %s AND user_id = %s', (ticket_id, current_user.id))
                booking_train = cursor.fetchone()
                if booking_train:
                    table_to_update, booking = 'train_bookings', booking_train
                else:
                    cursor.execute('SELECT * FROM combined_booking WHERE ticketID = %s AND user_id = %s', (ticket_id, current_user.id))
                    booking_combined = cursor.fetchone()
                    if booking_combined:
                        table_to_update, booking = 'combined_booking', booking_combined

            if not booking:
                flash('Booking not found or you are not authorized to cancel it.', 'error')
                conn.rollback()
                return redirect(url_for('user_cancel_booking'))
            
            if booking['status'] == 'cancelled':
                flash('Booking already cancelled.', 'error')
                conn.rollback()
                return redirect(url_for('booking_history'))
            if booking['phnum'] != phone:
                flash('Phone number does not match the booking record.', 'error')
                conn.rollback()
                return redirect(url_for('user_cancel_booking'))

            query = f'UPDATE {table_to_update} SET status = %s WHERE ticketID = %s'
            cursor.execute(query, ('cancelled', ticket_id))

            cursor.execute('UPDATE seats SET status = %s, locked_until = NULL, ticket_id = NULL WHERE ticket_id = %s', ('available', ticket_id))

            msg = EmailMessage()
            msg.set_content(f'Your booking (Ticket ID: {ticket_id}) has been successfully cancelled.')
            msg['Subject'] = 'Booking Cancellation Confirmation'
            msg['From'] = SMTP_EMAIL
            msg['To'] = booking['gmail']
            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.starttls()
                smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
                smtp.send_message(msg)
            
            conn.commit()
            flash('Booking cancelled successfully.', 'success')
            logger.info(f"User {current_user.email} cancelled booking: ticket_id={ticket_id}")
        except (mysql.connector.Error, smtplib.SMTPException) as e:
            flash('Error cancelling booking.', 'error')
            logger.error(f"Error in user_cancel_booking: {e}")
            if conn: conn.rollback()
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
        return redirect(url_for('booking_history'))

    return render_template('cancel_booking.html', recaptcha_site_key=RECAPTCHA_SITE_KEY)

if __name__ == '__main__':
    # Use debug=False in a production environment
    app.run(debug=True)
