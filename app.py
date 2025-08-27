from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, stream_template
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import sqlite3
import re
from datetime import datetime, timedelta
import secrets
import json
import base64
import cv2
import numpy as np
try:
    import mediapipe as mp
    MEDIAPIPE_AVAILABLE = True
except ImportError:
    mp = None
    MEDIAPIPE_AVAILABLE = False
    print("MediaPipe not available - some AI features will be disabled")
import threading
import asyncio
from queue import Queue
import time
try:
    import whisper
    WHISPER_AVAILABLE = True
except ImportError:
    whisper = None
    WHISPER_AVAILABLE = False
    print("Whisper not available - audio detection disabled")

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter as letter_size
    REPORTLAB_AVAILABLE = True
except ImportError:
    canvas = None
    letter_size = (612, 792)  # Standard letter size as tuple
    REPORTLAB_AVAILABLE = False
    print("ReportLab not available - PDF generation disabled")

try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-GUI backend
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    plt = None
    MATPLOTLIB_AVAILABLE = False
    print("Matplotlib not available - chart generation disabled")

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Database configuration
DATABASE = os.path.join('instance', 'cygentic_test_center.db')

# AI Proctoring Configuration
class ProctoringConfig:
    def __init__(self):
        # Initialize MediaPipe if available
        if MEDIAPIPE_AVAILABLE:
            self.mp_face_detection = mp.solutions.face_detection
            self.mp_face_mesh = mp.solutions.face_mesh
            self.mp_pose = mp.solutions.pose
            
            # Initialize face detection models
            self.face_detection = self.mp_face_detection.FaceDetection(model_selection=0, min_detection_confidence=0.5)
            self.face_mesh = self.mp_face_mesh.FaceMesh(min_detection_confidence=0.5, min_tracking_confidence=0.5)
            self.pose = self.mp_pose.Pose(min_detection_confidence=0.5, min_tracking_confidence=0.5)
        else:
            self.mp_face_detection = None
            self.mp_face_mesh = None
            self.mp_pose = None
            self.face_detection = None
            self.face_mesh = None
            self.pose = None
        
        # Initialize Whisper for audio processing
        self.whisper_model = None
        if WHISPER_AVAILABLE and whisper:
            try:
                self.whisper_model = whisper.load_model("base")
            except Exception as e:
                print(f"Warning: Whisper model failed to load: {e}")
        
        # Violation tracking
        self.violation_thresholds = {
            'multiple_faces': 2,  # seconds
            'face_not_detected': 5,  # seconds
            'looking_away': 3,  # seconds
            'audio_violation': 1,  # instances
            'window_switch': 1  # instances
        }

# Initialize AI Proctoring
proctoring_config = ProctoringConfig()
active_sessions = {}  # Store active proctoring sessions

def get_db_connection():
    """Get database connection with proper error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def update_test_categories():
    """Update test categories in the database"""
    conn = get_db_connection()
    if conn:
        try:
            # First, deactivate all existing categories
            conn.execute('UPDATE test_categories SET is_active = 0')
            
            # Updated categories list
            categories = [
                ('AI Test', 'Artificial Intelligence and Machine Learning concepts'),
                ('Cybersecurity Test', 'Information security and cyber defense'),
                ('Web Development Test', 'Frontend and backend web development'),
                ('Software Engineering Test', 'Software development principles and practices'),
                ('Machine Learning Test', 'ML algorithms and data modeling'),
                ('Data Science Test', 'Data analysis and statistical methods'),
                ('Graphic Designing Test', 'Visual design and creative skills'),
                ('IQ/Aptitude Test', 'Intelligence and aptitude assessment')
            ]
            
            # Insert or update new categories
            for category, description in categories:
                conn.execute('''
                    INSERT OR REPLACE INTO test_categories (name, description, is_active)
                    VALUES (?, ?, 1)
                ''', (category, description))
            
            conn.commit()
            print("Test categories updated successfully")
        except Exception as e:
            print(f"Error updating test categories: {e}")
        finally:
            conn.close()
    else:
        print("Failed to connect to database for updating categories")

def init_database():
    """Initialize database with required tables"""
    conn = get_db_connection()
    if conn:
        try:
            # Create students table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    unique_id TEXT UNIQUE NOT NULL,
                    test_category TEXT NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    student_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Create examiners table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS examiners (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Create admins table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Create test categories table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS test_categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Create test schedules table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS test_schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_name TEXT NOT NULL,
                    test_category TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP NOT NULL,
                    duration_minutes INTEGER DEFAULT 40,
                    created_by TEXT NOT NULL,
                    camera_required BOOLEAN DEFAULT 1,
                    microphone_required BOOLEAN DEFAULT 1,
                    ai_proctoring_enabled BOOLEAN DEFAULT 1,
                    proctoring_strictness TEXT DEFAULT 'medium',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Create proctoring sessions table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS proctoring_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL,
                    test_schedule_id INTEGER NOT NULL,
                    session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    session_end TIMESTAMP,
                    camera_verified BOOLEAN DEFAULT 0,
                    microphone_verified BOOLEAN DEFAULT 0,
                    total_violations INTEGER DEFAULT 0,
                    session_status TEXT DEFAULT 'active',
                    FOREIGN KEY (student_id) REFERENCES students (id),
                    FOREIGN KEY (test_schedule_id) REFERENCES test_schedules (id)
                )
            ''')
            
            # Create violation logs table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS violation_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    violation_type TEXT NOT NULL,
                    violation_details TEXT,
                    severity TEXT DEFAULT 'medium',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    action_taken TEXT,
                    FOREIGN KEY (session_id) REFERENCES proctoring_sessions (id)
                )
            ''')
            
            # Create test results table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS test_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL,
                    test_schedule_id INTEGER NOT NULL,
                    session_id INTEGER,
                    score REAL,
                    total_questions INTEGER,
                    correct_answers INTEGER,
                    time_taken_minutes INTEGER,
                    submission_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    violation_count INTEGER DEFAULT 0,
                    result_status TEXT DEFAULT 'completed',
                    FOREIGN KEY (student_id) REFERENCES students (id),
                    FOREIGN KEY (test_schedule_id) REFERENCES test_schedules (id),
                    FOREIGN KEY (session_id) REFERENCES proctoring_sessions (id)
                )
            ''')
            
            # Create validation logs table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS validation_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL,
                    schedule_id INTEGER NOT NULL,
                    camera_available BOOLEAN DEFAULT 0,
                    microphone_available BOOLEAN DEFAULT 0,
                    camera_error TEXT,
                    microphone_error TEXT,
                    validation_result TEXT DEFAULT 'pending',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (student_id) REFERENCES students (id),
                    FOREIGN KEY (schedule_id) REFERENCES test_schedules (id)
                )
            ''')
            
            # Insert default test categories
            categories = [
                ('AI Test', 'Artificial Intelligence and Machine Learning concepts'),
                ('Cybersecurity Test', 'Information security and cyber defense'),
                ('Web Development Test', 'Frontend and backend web development'),
                ('Software Engineering Test', 'Software development principles and practices'),
                ('Machine Learning Test', 'ML algorithms and data modeling'),
                ('Data Science Test', 'Data analysis and statistical methods'),
                ('Graphic Designing Test', 'Visual design and creative skills'),
                ('IQ/Aptitude Test', 'Intelligence and aptitude assessment')
            ]
            
            for category, description in categories:
                conn.execute('''
                    INSERT OR IGNORE INTO test_categories (name, description)
                    VALUES (?, ?)
                ''', (category, description))
            
            # Insert default admin user
            admin_password_hash = generate_password_hash('admin123')
            conn.execute('''
                INSERT OR IGNORE INTO admins (username, password_hash, full_name, email)
                VALUES (?, ?, ?, ?)
            ''', ('admin', admin_password_hash, 'System Administrator', 'admin@cygentic.ai'))
            
            conn.commit()
            print("Database initialized successfully")
        except Exception as e:
            print(f"Database initialization error: {e}")
        finally:
            conn.close()
    else:
        print("Failed to connect to database for initialization")

# Security headers middleware
@app.after_request
def after_request(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"
    return response

# Context processor for global variables
@app.context_processor
def inject_globals():
    """Inject global variables into all templates"""
    return {
        'current_year': datetime.now().year,
        'app_name': 'CYGENTIC AI Test Center',
        'version': '1.0.0'
    }

# Main Routes
@app.route('/')
def home():
    """Homepage with hero section and features overview"""
    return render_template('home.html')

@app.route('/about')
def about():
    """About page with company information"""
    return render_template('about.html')

@app.route('/test-categories')
def test_categories():
    """Test categories and available examinations"""
    # Get all active test categories from the database
    categories = []
    conn = get_db_connection()
    if conn:
        try:
            rows = conn.execute(
                'SELECT name, description FROM test_categories WHERE is_active = 1 ORDER BY name'
            ).fetchall()
            categories = [{'name': row['name'], 'description': row['description']} for row in rows]
        except Exception as e:
            print(f"Error fetching test categories: {e}")
        finally:
            conn.close()
    
    return render_template('test_categories.html', categories=categories)

@app.route('/contact')
def contact():
    """Contact information and support"""
    return render_template('contact.html')

# Authentication Routes
@app.route('/login')
def login():
    """Universal login page with role selection"""
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Student registration page and handling"""
    if request.method == 'POST':
        # Get form data
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip()
        test_category = request.form.get('test_category', '').strip()
        password = request.form.get('password', '')
        terms = request.form.get('terms')
        
        # Validation
        errors = []
        
        if not all([full_name, email, username, test_category, password]):
            errors.append('All required fields must be filled out')
        
        if len(password) < 8:
            errors.append('Password must be at least 8 characters long')
        
        if not terms:
            errors.append('You must agree to the Terms of Service and Privacy Policy')
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            errors.append('Please enter a valid email address')
        
        # Validate username format
        if username and not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            errors.append('Username must be 3-20 characters long and contain only letters, numbers, and underscores')
        
        # Check database for existing records
        if not errors:
            conn = get_db_connection()
            if conn:
                try:
                    # Check for existing email
                    existing_email = conn.execute(
                        'SELECT id FROM students WHERE email = ?', (email,)
                    ).fetchone()
                    if existing_email:
                        errors.append('Email address is already registered')
                    
                    # Check for existing username
                    existing_username = conn.execute(
                        'SELECT id FROM students WHERE username = ?', (username,)
                    ).fetchone()
                    if existing_username:
                        errors.append('Username is already taken. Please choose a different one.')
                    
                    # Validate test category exists
                    valid_category = conn.execute(
                        'SELECT id FROM test_categories WHERE name = ? AND is_active = 1', (test_category,)
                    ).fetchone()
                    if not valid_category:
                        errors.append('Please select a valid test category')
                    
                except Exception as e:
                    errors.append('Database error occurred. Please try again.')
                    print(f"Database query error: {e}")
                finally:
                    conn.close()
            else:
                errors.append('Database connection failed. Please try again.')
        
        # If no errors, create the student account
        if not errors:
            conn = get_db_connection()
            if conn:
                try:
                    # Generate unique student ID
                    current_year = datetime.now().year
                    
                    # Get the next sequential number
                    last_student = conn.execute(
                        'SELECT unique_id FROM students WHERE unique_id LIKE ? ORDER BY unique_id DESC LIMIT 1',
                        (f'EXAM-{current_year}-%',)
                    ).fetchone()
                    
                    if last_student:
                        # Extract number from last ID and increment
                        try:
                            last_num = int(last_student['unique_id'].split('-')[-1])
                            next_num = last_num + 1
                        except (ValueError, IndexError):
                            next_num = 1
                    else:
                        next_num = 1
                    
                    # Format the unique ID
                    unique_id = f"EXAM-{current_year}-{next_num:04d}"
                    
                    # Ensure the generated ID is truly unique (safety check)
                    while conn.execute('SELECT id FROM students WHERE unique_id = ?', (unique_id,)).fetchone():
                        next_num += 1
                        unique_id = f"EXAM-{current_year}-{next_num:04d}"
                    
                    password_hash = generate_password_hash(password)
                    
                    conn.execute('''
                        INSERT INTO students (full_name, email, unique_id, test_category, username, password_hash)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (full_name, email, unique_id, test_category, username, password_hash))
                    conn.commit()
                    
                    # Get available test categories for the success page
                    test_categories = []
                    try:
                        categories = conn.execute(
                            'SELECT name FROM test_categories WHERE is_active = 1 ORDER BY name'
                        ).fetchall()
                        test_categories = [row['name'] for row in categories]
                    except Exception as e:
                        print(f"Error fetching test categories: {e}")
                    
                    # Return success page with modal data
                    return render_template('auth/register.html', 
                                         test_categories=test_categories,
                                         registration_success=True,
                                         student_id=unique_id,
                                         username=username,
                                         email=email,
                                         full_name=full_name)
                except Exception as e:
                    errors.append('Failed to create account. Please try again.')
                    print(f"Registration error: {e}")
                finally:
                    conn.close()
            else:
                errors.append('Database connection failed. Please try again.')
        
        # If there are errors, display them
        for error in errors:
            flash(error, 'error')
    
    # Get available test categories for the form
    test_categories = []
    conn = get_db_connection()
    if conn:
        try:
            categories = conn.execute(
                'SELECT name FROM test_categories WHERE is_active = 1 ORDER BY name'
            ).fetchall()
            test_categories = [row['name'] for row in categories]
        except Exception as e:
            print(f"Error fetching test categories: {e}")
        finally:
            conn.close()
    
    return render_template('auth/register.html', test_categories=test_categories)

@app.route('/auth/student-login', methods=['GET', 'POST'])
def student_login():
    """Student authentication"""
    if request.method == 'POST':
        login_identifier = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        
        if login_identifier and password:
            conn = get_db_connection()
            if conn:
                try:
                    # Check for student by username, email, or unique_id
                    student = conn.execute('''
                        SELECT id, username, password_hash, full_name, email, unique_id, test_category, is_active
                        FROM students 
                        WHERE (LOWER(username) = ? OR LOWER(email) = ? OR UPPER(unique_id) = ?) AND is_active = 1
                    ''', (login_identifier, login_identifier, login_identifier.upper())).fetchone()
                    
                    if student and check_password_hash(student['password_hash'], password):
                        session['user_type'] = 'student'
                        session['user_id'] = student['id']
                        session['username'] = student['username']
                        session['full_name'] = student['full_name']
                        session['email'] = student['email']
                        session['unique_id'] = student['unique_id']
                        session['test_category'] = student['test_category']
                        flash(f'Welcome back, {student["full_name"]}!', 'success')
                        return redirect(url_for('student_dashboard'))
                    else:
                        flash('Invalid login credentials. Please check your username/email/student ID and password.', 'error')
                except Exception as e:
                    flash('Login error occurred. Please try again.', 'error')
                    print(f"Student login error: {e}")
                finally:
                    conn.close()
            else:
                flash('Database connection failed. Please try again.', 'error')
        else:
            flash('Please enter both login credentials and password', 'error')
    
    return render_template('auth/student_login.html')

@app.route('/auth/examiner-login', methods=['GET', 'POST'])
def examiner_login():
    """Examiner authentication"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Demo credentials: EXM001 / examiner123
        if username == 'EXM001' and password == 'examiner123':
            session['user_type'] = 'examiner'
            session['username'] = username
            flash('Welcome, Examiner!', 'success')
            return redirect(url_for('examiner_dashboard'))
        else:
            flash('Invalid examiner credentials', 'error')
    
    return render_template('auth/examiner_login.html')

@app.route('/auth/admin-login', methods=['GET', 'POST'])
def admin_login():
    """Admin authentication"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Demo credentials: admin / admin123 or admin / 123456
        if username == 'admin' and password in ['admin123', '123456']:
            session['user_type'] = 'admin'
            session['username'] = username
            flash('Welcome, Administrator!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'error')
    
    return render_template('auth/admin_login.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('home'))

# Dashboard Routes
@app.route('/student/dashboard')
def student_dashboard():
    """Student main dashboard"""
    if session.get('user_type') != 'student':
        flash('Please log in as a student to access this page', 'error')
        return redirect(url_for('student_login'))
    
    # Get test categories for the dashboard
    test_categories = []
    conn = get_db_connection()
    if conn:
        try:
            categories = conn.execute(
                'SELECT name, description FROM test_categories WHERE is_active = 1 ORDER BY name'
            ).fetchall()
            test_categories = [{'name': row['name'], 'description': row['description']} for row in categories]
        except Exception as e:
            print(f"Error fetching test categories: {e}")
        finally:
            conn.close()
    
    return render_template('dashboards/student_dashboard.html', test_categories=test_categories)

@app.route('/student/tests')
def student_tests():
    """Student available tests"""
    if session.get('user_type') != 'student':
        return redirect(url_for('student_login'))
    
    # Get test categories for the tests page
    test_categories = []
    conn = get_db_connection()
    if conn:
        try:
            categories = conn.execute(
                'SELECT name, description FROM test_categories WHERE is_active = 1 ORDER BY name'
            ).fetchall()
            test_categories = [{'name': row['name'], 'description': row['description']} for row in categories]
        except Exception as e:
            print(f"Error fetching test categories: {e}")
        finally:
            conn.close()
    
    return render_template('dashboards/student_tests.html', test_categories=test_categories)

@app.route('/student/results')
def student_results():
    """Student test results"""
    if session.get('user_type') != 'student':
        return redirect(url_for('student_login'))
    
    return render_template('dashboards/student_results.html')

@app.route('/student/profile')
def student_profile():
    """Student profile management"""
    if session.get('user_type') != 'student':
        return redirect(url_for('student_login'))
    
    return render_template('dashboards/student_profile.html')

@app.route('/examiner/dashboard')
def examiner_dashboard():
    """Examiner main dashboard"""
    if session.get('user_type') != 'examiner':
        flash('Please log in as an examiner to access this page', 'error')
        return redirect(url_for('examiner_login'))
    
    return render_template('dashboards/examiner_dashboard.html')

@app.route('/examiner/live-monitoring')
def examiner_monitoring():
    """Live proctoring and monitoring"""
    if session.get('user_type') != 'examiner':
        return redirect(url_for('examiner_login'))
    
    return render_template('dashboards/examiner_monitoring.html')

@app.route('/examiner/question-bank')
def examiner_questions():
    """Question bank management"""
    if session.get('user_type') != 'examiner':
        return redirect(url_for('examiner_login'))
    
    return render_template('dashboards/examiner_questions.html')

@app.route('/examiner/test-schedule')
def examiner_schedule():
    """Test scheduling and management"""
    if session.get('user_type') != 'examiner':
        return redirect(url_for('examiner_login'))
    
    return render_template('dashboards/examiner_schedule.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin main dashboard"""
    if session.get('user_type') != 'admin':
        flash('Please log in as an administrator to access this page', 'error')
        return redirect(url_for('admin_login'))
    
    return render_template('dashboards/admin_dashboard.html')

@app.route('/admin/users')
def admin_users():
    """User management"""
    if session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))
    
    return render_template('dashboards/admin_users.html')

@app.route('/admin/system')
def admin_system():
    """System configuration and settings"""
    if session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))
    
    return render_template('dashboards/admin_system.html')

@app.route('/admin/analytics')
def admin_analytics():
    """Analytics and reporting"""
    if session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))
    
    return render_template('dashboards/admin_analytics.html')

@app.route('/admin/delete-students', methods=['POST'])
def delete_all_students():
    """Delete all registered students"""
    if session.get('user_type') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
    
    conn = get_db_connection()
    if conn:
        try:
            # Get count of students before deletion
            student_count = conn.execute('SELECT COUNT(*) as count FROM students').fetchone()
            count = student_count['count'] if student_count else 0
            
            # Delete all students
            conn.execute('DELETE FROM students')
            conn.commit()
            
            flash(f'Successfully deleted {count} registered student(s)', 'success')
            return jsonify({
                'success': True, 
                'message': f'Successfully deleted {count} registered student(s)',
                'count': count
            })
        except Exception as e:
            conn.rollback()
            flash(f'Error deleting students: {str(e)}', 'error')
            return jsonify({'success': False, 'message': f'Error deleting students: {str(e)}'}), 500
        finally:
            conn.close()
    else:
        flash('Database connection failed', 'error')
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500

@app.route('/admin/get-students')
def get_all_students():
    """Get all registered students for admin view"""
    if session.get('user_type') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
    
    conn = get_db_connection()
    if conn:
        try:
            students = conn.execute('''
                SELECT id, full_name, email, unique_id, test_category, username, created_at, is_active
                FROM students 
                ORDER BY created_at DESC
            ''').fetchall()
            
            students_list = []
            for student in students:
                students_list.append({
                    'id': student['id'],
                    'full_name': student['full_name'],
                    'email': student['email'],
                    'unique_id': student['unique_id'],
                    'test_category': student['test_category'],
                    'username': student['username'],
                    'created_at': student['created_at'],
                    'is_active': student['is_active']
                })
            
            return jsonify({
                'success': True,
                'students': students_list,
                'count': len(students_list)
            })
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error fetching students: {str(e)}'}), 500
        finally:
            conn.close()
    else:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500

# API Routes for future AI integration
@app.route('/api/proctoring/status')
def api_proctoring_status():
    """API endpoint for proctoring status"""
    return jsonify({
        'status': 'active',
        'ai_monitoring': True,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/test/progress')
def api_test_progress():
    """API endpoint for test progress tracking"""
    return jsonify({
        'progress': 65,
        'time_remaining': 1800,
        'questions_answered': 13,
        'total_questions': 20
    })

# ========================================
# AI PROCTORING SYSTEM ROUTES
# ========================================

@app.route('/api/proctoring/init', methods=['POST'])
def init_proctoring_session():
    """Initialize AI proctoring session for a student"""
    if session.get('user_type') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    test_schedule_id = data.get('test_schedule_id')
    student_id = session.get('user_id')
    
    conn = get_db_connection()
    if conn:
        try:
            # Create proctoring session
            cursor = conn.execute('''
                INSERT INTO proctoring_sessions (student_id, test_schedule_id, camera_verified, microphone_verified)
                VALUES (?, ?, 0, 0)
            ''', (student_id, test_schedule_id))
            session_id = cursor.lastrowid
            
            # Initialize session tracking
            active_sessions[session_id] = {
                'student_id': student_id,
                'start_time': datetime.now(),
                'violations': [],
                'last_frame_time': None,
                'face_count': 0,
                'looking_away_time': 0,
                'audio_violations': 0
            }
            
            conn.commit()
            return jsonify({
                'success': True,
                'session_id': session_id,
                'message': 'Proctoring session initialized'
            })
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            conn.close()
    
    return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/api/proctoring/verify-devices', methods=['POST'])
def verify_devices():
    """Verify camera and microphone access"""
    data = request.get_json()
    session_id = data.get('session_id')
    camera_status = data.get('camera_verified', False)
    microphone_status = data.get('microphone_verified', False)
    
    conn = get_db_connection()
    if conn:
        try:
            conn.execute('''
                UPDATE proctoring_sessions 
                SET camera_verified = ?, microphone_verified = ?
                WHERE id = ?
            ''', (camera_status, microphone_status, session_id))
            conn.commit()
            
            return jsonify({
                'success': True,
                'camera_verified': camera_status,
                'microphone_verified': microphone_status,
                'can_proceed': camera_status and microphone_status
            })
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            conn.close()
    
    return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/api/proctoring/analyze-frame', methods=['POST'])
def analyze_frame():
    """Analyze video frame for AI proctoring violations"""
    data = request.get_json()
    session_id = data.get('session_id')
    frame_data = data.get('frame')  # Base64 encoded image
    
    if not session_id or session_id not in active_sessions:
        return jsonify({'success': False, 'message': 'Invalid session'}), 400
    
    try:
        # Decode base64 image
        image_data = base64.b64decode(frame_data.split(',')[1])
        nparr = np.frombuffer(image_data, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        violations = []
        
        # Convert BGR to RGB for MediaPipe
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        
        # Face Detection
        face_results = proctoring_config.face_detection.process(rgb_frame)
        face_count = 0
        
        if face_results.detections:
            face_count = len(face_results.detections)
            
            # Check for multiple faces
            if face_count > 1:
                violations.append({
                    'type': 'multiple_faces',
                    'severity': 'high',
                    'message': f'Multiple faces detected: {face_count}',
                    'timestamp': datetime.now().isoformat()
                })
            
            # Eye gaze tracking using Face Mesh
            mesh_results = proctoring_config.face_mesh.process(rgb_frame)
            if mesh_results.multi_face_landmarks:
                for landmarks in mesh_results.multi_face_landmarks:
                    # Get key eye landmarks for gaze estimation
                    left_eye = landmarks.landmark[33]  # Left eye corner
                    right_eye = landmarks.landmark[263]  # Right eye corner
                    nose = landmarks.landmark[1]  # Nose tip
                    
                    # Simple gaze estimation (looking away detection)
                    eye_center_x = (left_eye.x + right_eye.x) / 2
                    nose_x = nose.x
                    
                    # If eyes are significantly off-center from nose, student is looking away
                    if abs(eye_center_x - nose_x) > 0.05:  # Threshold for "looking away"
                        violations.append({
                            'type': 'looking_away',
                            'severity': 'medium',
                            'message': 'Student looking away from screen',
                            'timestamp': datetime.now().isoformat()
                        })
        else:
            # No face detected
            violations.append({
                'type': 'face_not_detected',
                'severity': 'high',
                'message': 'No face detected in frame',
                'timestamp': datetime.now().isoformat()
            })
        
        # Body pose analysis
        pose_results = proctoring_config.pose.process(rgb_frame)
        if pose_results.pose_landmarks:
            # Check for excessive body movement
            nose_landmark = pose_results.pose_landmarks.landmark[0]
            # Store previous position and compare for movement detection
            # (This would require storing previous frame data)
            pass
        
        # Update session tracking
        active_sessions[session_id]['face_count'] = face_count
        active_sessions[session_id]['last_frame_time'] = datetime.now()
        active_sessions[session_id]['violations'].extend(violations)
        
        # Log violations to database
        if violations:
            conn = get_db_connection()
            if conn:
                try:
                    for violation in violations:
                        conn.execute('''
                            INSERT INTO violation_logs (session_id, violation_type, violation_details, severity)
                            VALUES (?, ?, ?, ?)
                        ''', (session_id, violation['type'], violation['message'], violation['severity']))
                    
                    # Update total violations count
                    conn.execute('''
                        UPDATE proctoring_sessions 
                        SET total_violations = total_violations + ?
                        WHERE id = ?
                    ''', (len(violations), session_id))
                    
                    conn.commit()
                except Exception as e:
                    print(f"Database error logging violations: {e}")
                finally:
                    conn.close()
        
        return jsonify({
            'success': True,
            'violations': violations,
            'face_count': face_count,
            'analysis_timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Analysis error: {str(e)}'}), 500

@app.route('/api/proctoring/analyze-audio', methods=['POST'])
def analyze_audio():
    """Analyze audio for whisper detection and suspicious sounds"""
    if not proctoring_config.whisper_model:
        return jsonify({'success': False, 'message': 'Whisper model not available'}), 500
    
    data = request.get_json()
    session_id = data.get('session_id')
    audio_data = data.get('audio')  # Base64 encoded audio
    
    if not session_id or session_id not in active_sessions:
        return jsonify({'success': False, 'message': 'Invalid session'}), 400
    
    try:
        # Decode audio data
        audio_bytes = base64.b64decode(audio_data)
        
        # Save temporary audio file for Whisper processing
        temp_audio_path = f'/tmp/audio_{session_id}_{int(time.time())}.wav'
        with open(temp_audio_path, 'wb') as f:
            f.write(audio_bytes)
        
        # Transcribe audio using Whisper
        result = proctoring_config.whisper_model.transcribe(temp_audio_path)
        transcription = result.get('text', '').strip().lower() if isinstance(result, dict) else str(result).strip().lower()
        
        # Clean up temporary file
        os.remove(temp_audio_path)
        
        violations = []
        
        # Check for suspicious speech patterns
        suspicious_keywords = ['help', 'answer', 'tell me', 'what is', 'google', 'search', 'copy', 'paste']
        if any(keyword in transcription for keyword in suspicious_keywords):
            violations.append({
                'type': 'suspicious_speech',
                'severity': 'high',
                'message': f'Suspicious speech detected: "{transcription}"',
                'timestamp': datetime.now().isoformat()
            })
        
        # Check for multiple voices (basic detection)
        if len(transcription.split()) > 10:  # If too much speech detected
            violations.append({
                'type': 'excessive_speech',
                'severity': 'medium',
                'message': 'Excessive speech or multiple voices detected',
                'timestamp': datetime.now().isoformat()
            })
        
        # Update session tracking
        active_sessions[session_id]['audio_violations'] += len(violations)
        
        # Log violations
        if violations:
            conn = get_db_connection()
            if conn:
                try:
                    for violation in violations:
                        conn.execute('''
                            INSERT INTO violation_logs (session_id, violation_type, violation_details, severity)
                            VALUES (?, ?, ?, ?)
                        ''', (session_id, violation['type'], violation['message'], violation['severity']))
                    conn.commit()
                except Exception as e:
                    print(f"Database error logging audio violations: {e}")
                finally:
                    conn.close()
        
        return jsonify({
            'success': True,
            'transcription': transcription,
            'violations': violations,
            'analysis_timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Audio analysis error: {str(e)}'}), 500

@app.route('/api/proctoring/window-focus', methods=['POST'])
def track_window_focus():
    """Track window focus changes (tab switching detection)"""
    data = request.get_json()
    session_id = data.get('session_id')
    focus_lost = data.get('focus_lost', False)
    
    if not session_id or session_id not in active_sessions:
        return jsonify({'success': False, 'message': 'Invalid session'}), 400
    
    if focus_lost:
        violation = {
            'type': 'window_switch',
            'severity': 'high',
            'message': 'Student switched tabs or applications',
            'timestamp': datetime.now().isoformat()
        }
        
        # Log violation
        conn = get_db_connection()
        if conn:
            try:
                conn.execute('''
                    INSERT INTO violation_logs (session_id, violation_type, violation_details, severity)
                    VALUES (?, ?, ?, ?)
                ''', (session_id, violation['type'], violation['message'], violation['severity']))
                
                conn.execute('''
                    UPDATE proctoring_sessions 
                    SET total_violations = total_violations + 1
                    WHERE id = ?
                ''', (session_id,))
                
                conn.commit()
                
                return jsonify({
                    'success': True,
                    'violation': violation,
                    'action': 'warning_issued'
                })
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
            finally:
                conn.close()
    
    return jsonify({'success': True, 'message': 'Focus tracked'})

@app.route('/api/proctoring/end-session', methods=['POST'])
def end_proctoring_session():
    """End proctoring session and generate final report"""
    data = request.get_json()
    session_id = data.get('session_id')
    
    if not session_id or session_id not in active_sessions:
        return jsonify({'success': False, 'message': 'Invalid session'}), 400
    
    session_data = active_sessions.pop(session_id)
    
    conn = get_db_connection()
    if conn:
        try:
            # Update session end time
            conn.execute('''
                UPDATE proctoring_sessions 
                SET session_end = CURRENT_TIMESTAMP, session_status = 'completed'
                WHERE id = ?
            ''', (session_id,))
            
            # Get violation summary
            violations = conn.execute('''
                SELECT violation_type, COUNT(*) as count, severity
                FROM violation_logs 
                WHERE session_id = ? 
                GROUP BY violation_type, severity
            ''', (session_id,)).fetchall()
            
            violation_summary = [{
                'type': row['violation_type'],
                'count': row['count'],
                'severity': row['severity']
            } for row in violations]
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'session_summary': {
                    'session_id': session_id,
                    'duration_minutes': (datetime.now() - session_data['start_time']).total_seconds() / 60,
                    'total_violations': len(session_data['violations']),
                    'violation_summary': violation_summary
                }
            })
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            conn.close()
    
    return jsonify({'success': False, 'message': 'Database error'}), 500

# ========================================
# TEST SCHEDULING ROUTES
# ========================================

@app.route('/api/test-schedules')
def get_test_schedules():
    """Get available test schedules for current user"""
    if session.get('user_type') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    conn = get_db_connection()
    if conn:
        try:
            # Get current time for schedule validation
            now = datetime.now()
            
            schedules = conn.execute('''
                SELECT * FROM test_schedules 
                WHERE is_active = 1 AND end_time > ?
                ORDER BY start_time ASC
            ''', (now.isoformat(),)).fetchall()
            
            schedule_list = []
            for schedule in schedules:
                start_time = datetime.fromisoformat(schedule['start_time'])
                end_time = datetime.fromisoformat(schedule['end_time'])
                
                # Check if test is currently available
                is_available = start_time <= now <= end_time
                time_until_start = (start_time - now).total_seconds() if start_time > now else 0
                time_until_end = (end_time - now).total_seconds() if end_time > now else 0
                
                schedule_list.append({
                    'id': schedule['id'],
                    'test_name': schedule['test_name'],
                    'test_category': schedule['test_category'],
                    'start_time': schedule['start_time'],
                    'end_time': schedule['end_time'],
                    'duration_minutes': schedule['duration_minutes'],
                    'camera_required': schedule['camera_required'],
                    'microphone_required': schedule['microphone_required'],
                    'ai_proctoring_enabled': schedule['ai_proctoring_enabled'],
                    'is_available': is_available,
                    'time_until_start_minutes': int(time_until_start / 60),
                    'time_until_end_minutes': int(time_until_end / 60)
                })
            
            return jsonify({
                'success': True,
                'schedules': schedule_list
            })
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            conn.close()
    
    return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/api/validate-test-timing', methods=['POST'])
def validate_test_timing():
    """Validate if student can start test within time window"""
    data = request.get_json()
    test_schedule_id = data.get('test_schedule_id')
    
    conn = get_db_connection()
    if conn:
        try:
            schedule = conn.execute('''
                SELECT * FROM test_schedules WHERE id = ? AND is_active = 1
            ''', (test_schedule_id,)).fetchone()
            
            if not schedule:
                return jsonify({'success': False, 'message': 'Test schedule not found'}), 404
            
            now = datetime.now()
            start_time = datetime.fromisoformat(schedule['start_time'])
            end_time = datetime.fromisoformat(schedule['end_time'])
            duration_minutes = schedule['duration_minutes']
            
            # Check if current time is within the schedule window
            if now < start_time:
                return jsonify({
                    'success': False,
                    'message': 'Test has not started yet',
                    'minutes_until_start': int((start_time - now).total_seconds() / 60)
                })
            
            if now > end_time:
                return jsonify({
                    'success': False,
                    'message': 'Test window has expired'
                })
            
            # Calculate maximum allowed test duration
            time_remaining_in_window = (end_time - now).total_seconds() / 60
            actual_test_duration = min(duration_minutes, time_remaining_in_window)
            
            # Ensure student has enough time (at least 10 minutes)
            if actual_test_duration < 10:
                return jsonify({
                    'success': False,
                    'message': 'Insufficient time remaining in test window',
                    'time_remaining_minutes': int(time_remaining_in_window)
                })
            
            return jsonify({
                'success': True,
                'can_start': True,
                'test_duration_minutes': int(actual_test_duration),
                'window_end_time': schedule['end_time'],
                'requirements': {
                    'camera_required': schedule['camera_required'],
                    'microphone_required': schedule['microphone_required'],
                    'ai_proctoring_enabled': schedule['ai_proctoring_enabled']
                }
            })
            
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            conn.close()
    
    return jsonify({'success': False, 'message': 'Database error'}), 500

# ========================================
# CAMERA & MICROPHONE VALIDATION SYSTEM
# ========================================

@app.route('/api/media/validate-access', methods=['POST'])
def validate_media_access():
    """Validate camera and microphone access before test starts"""
    if session.get('user_type') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        schedule_id = data.get('schedule_id')
        camera_available = data.get('camera_available', False)
        microphone_available = data.get('microphone_available', False)
        camera_error = data.get('camera_error', '')
        microphone_error = data.get('microphone_error', '')
        
        if not schedule_id:
            return jsonify({'success': False, 'message': 'Schedule ID required'}), 400
        
        conn = get_db_connection()
        if conn:
            try:
                # Get schedule requirements
                schedule = conn.execute('''
                    SELECT camera_required, microphone_required, test_name
                    FROM test_schedules 
                    WHERE id = ? AND is_active = 1
                ''', (schedule_id,)).fetchone()
                
                if not schedule:
                    return jsonify({'success': False, 'message': 'Test schedule not found'}), 404
                
                validation_results = {
                    'camera_valid': True,
                    'microphone_valid': True,
                    'can_proceed': True,
                    'errors': [],
                    'warnings': []
                }
                
                # Validate camera access
                if schedule['camera_required']:
                    if not camera_available:
                        validation_results['camera_valid'] = False
                        validation_results['can_proceed'] = False
                        validation_results['errors'].append({
                            'type': 'camera_required',
                            'message': 'Camera access is mandatory for this test',
                            'details': camera_error or 'Camera not accessible'
                        })
                else:
                    if not camera_available:
                        validation_results['warnings'].append({
                            'type': 'camera_optional',
                            'message': 'Camera not available, but not required for this test'
                        })
                
                # Validate microphone access
                if schedule['microphone_required']:
                    if not microphone_available:
                        validation_results['microphone_valid'] = False
                        validation_results['can_proceed'] = False
                        validation_results['errors'].append({
                            'type': 'microphone_required',
                            'message': 'Microphone access is mandatory for this test',
                            'details': microphone_error or 'Microphone not accessible'
                        })
                else:
                    if not microphone_available:
                        validation_results['warnings'].append({
                            'type': 'microphone_optional',
                            'message': 'Microphone not available, but not required for this test'
                        })
                
                return jsonify({
                    'success': True,
                    'validation': validation_results,
                    'requirements': {
                        'camera_required': bool(schedule['camera_required']),
                        'microphone_required': bool(schedule['microphone_required'])
                    },
                    'test_name': schedule['test_name']
                })
                
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
            finally:
                conn.close()
        
        return jsonify({'success': False, 'message': 'Database error'}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/media/test-camera', methods=['POST'])
def test_camera_functionality():
    """Test camera functionality and quality"""
    if session.get('user_type') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        # Get test frame from frontend
        if 'test_frame' not in request.files:
            return jsonify({'success': False, 'message': 'No test frame provided'}), 400
        
        frame_file = request.files['test_frame']
        frame_data = frame_file.read()
        
        # Convert to OpenCV format
        nparr = np.frombuffer(frame_data, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if frame is None:
            return jsonify({
                'success': False, 
                'message': 'Invalid camera frame',
                'camera_status': 'error'
            }), 400
        
        # Analyze frame quality
        height, width = frame.shape[:2]
        frame_area = height * width
        
        # Check resolution
        min_resolution = 480 * 640  # Minimum 480p
        recommended_resolution = 720 * 1280  # Recommended 720p
        
        quality_analysis = {
            'resolution': {'width': width, 'height': height},
            'resolution_adequate': frame_area >= min_resolution,
            'resolution_recommended': frame_area >= recommended_resolution,
            'brightness_adequate': True,
            'face_detectable': False,
            'overall_quality': 'good'
        }
        
        # Check brightness (simple average)
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        brightness = np.mean(gray)
        quality_analysis['brightness_level'] = float(brightness)
        quality_analysis['brightness_adequate'] = 50 <= brightness <= 200
        
        # Test face detection
        try:
            analysis_result = analyze_video_frame(frame, 0)  # Test session ID
            quality_analysis['face_detectable'] = analysis_result['faces_detected'] > 0
            quality_analysis['face_confidence'] = analysis_result.get('face_confidence', 0)
            quality_analysis['detection_mode'] = analysis_result.get('detection_mode', 'unknown')
        except Exception as e:
            print(f"Face detection test error: {e}")
        
        # Determine overall quality
        issues = []
        if not quality_analysis['resolution_adequate']:
            issues.append('Resolution too low (minimum 640x480 required)')
        if not quality_analysis['brightness_adequate']:
            if brightness < 50:
                issues.append('Image too dark - please improve lighting')
            else:
                issues.append('Image too bright - please reduce lighting')
        if not quality_analysis['face_detectable']:
            issues.append('Face not clearly detectable - please position yourself properly')
        
        if len(issues) > 2:
            quality_analysis['overall_quality'] = 'poor'
        elif len(issues) > 0:
            quality_analysis['overall_quality'] = 'fair'
        else:
            quality_analysis['overall_quality'] = 'excellent'
        
        return jsonify({
            'success': True,
            'camera_status': 'working',
            'quality': quality_analysis,
            'issues': issues,
            'recommendations': [
                'Ensure good lighting on your face',
                'Position camera at eye level',
                'Keep face centered in frame',
                'Avoid backlighting from windows'
            ] if issues else []
        })
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'message': str(e),
            'camera_status': 'error'
        }), 500

# ========================================
# VIOLATION TRACKING & WARNING SYSTEM
# ========================================

@app.route('/api/violations/track', methods=['POST'])
def track_violation():
    """Track and log violations with immediate warning system"""
    if session.get('user_type') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        violation_type = data.get('violation_type')
        violation_details = data.get('violation_details', '')
        severity = data.get('severity', 'medium')
        
        if not all([session_id, violation_type]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Validate session belongs to current student
        student_id = session.get('user_id')
        if not student_id or int(session_id) not in active_sessions:
            return jsonify({'success': False, 'message': 'Invalid session'}), 400
        
        session_data = active_sessions[int(session_id)]
        if session_data.get('student_id') != student_id:
            return jsonify({'success': False, 'message': 'Session mismatch'}), 403
        
        conn = get_db_connection()
        if conn:
            try:
                # Log violation to database
                cursor = conn.execute('''
                    INSERT INTO violation_logs 
                    (session_id, violation_type, violation_details, severity, action_taken)
                    VALUES (?, ?, ?, ?, ?)
                ''', (session_id, violation_type, violation_details, severity, 'logged'))
                
                violation_id = cursor.lastrowid
                
                # Update session violation count
                conn.execute('''
                    UPDATE proctoring_sessions 
                    SET total_violations = total_violations + 1
                    WHERE id = ?
                ''', (session_id,))
                
                # Get current violation count for this session
                violation_count = conn.execute('''
                    SELECT COUNT(*) as count FROM violation_logs 
                    WHERE session_id = ?
                ''', (session_id,)).fetchone()['count']
                
                conn.commit()
                
                # Determine action based on violation count and severity
                warning_level = 'info'
                action_required = None
                warning_message = f"Violation detected: {violation_type}"
                
                # Progressive warning system
                if violation_count == 1:
                    warning_level = 'warning'
                    warning_message = "First violation detected. Please follow test guidelines."
                elif violation_count == 2:
                    warning_level = 'warning'
                    warning_message = "Second violation detected. Further violations may result in test termination."
                elif violation_count >= 3:
                    warning_level = 'critical'
                    warning_message = "Multiple violations detected. Test may be terminated."
                    action_required = 'notify_examiner'
                
                # High severity violations get immediate escalation
                if severity == 'high':
                    if violation_count >= 2:
                        warning_level = 'critical'
                        action_required = 'terminate_test'
                        warning_message = "Critical violation detected. Test will be terminated."
                    else:
                        warning_level = 'warning'
                        action_required = 'notify_examiner'
                
                # Update in-memory session data
                session_data['violations'].append({
                    'id': violation_id,
                    'type': violation_type,
                    'details': violation_details,
                    'severity': severity,
                    'timestamp': time.time()
                })
                session_data['violation_count'] = violation_count
                
                return jsonify({
                    'success': True,
                    'violation_id': violation_id,
                    'warning': {
                        'level': warning_level,
                        'message': warning_message,
                        'violation_count': violation_count,
                        'action_required': action_required
                    },
                    'session_status': {
                        'can_continue': action_required != 'terminate_test',
                        'total_violations': violation_count
                    }
                })
                
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
            finally:
                conn.close()
        
        return jsonify({'success': False, 'message': 'Database error'}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# Removed duplicate get_session_violations function - using the one with proper parameters below

@app.route('/api/violations/warnings/live', methods=['GET'])
def get_live_warnings():
    """Get live warnings for student's active session"""
    if session.get('user_type') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        student_id = session.get('user_id')
        
        # Find student's active session
        active_session_id = None
        for sid, session_data in active_sessions.items():
            if session_data.get('student_id') == student_id:
                active_session_id = sid
                break
        
        if not active_session_id:
            return jsonify({
                'success': True,
                'warnings': [],
                'session_active': False
            })
        
        session_data = active_sessions[active_session_id]
        violations = session_data.get('violations', [])
        
        # Generate current warnings based on violations
        warnings = []
        violation_count = len(violations)
        
        if violation_count > 0:
            latest_violation = violations[-1]
            
            if violation_count == 1:
                warnings.append({
                    'level': 'warning',
                    'message': 'First violation detected. Please follow test guidelines.',
                    'timestamp': latest_violation['timestamp'],
                    'type': 'first_warning'
                })
            elif violation_count == 2:
                warnings.append({
                    'level': 'warning',
                    'message': 'Second violation detected. Further violations may result in test termination.',
                    'timestamp': latest_violation['timestamp'],
                    'type': 'second_warning'
                })
            elif violation_count >= 3:
                warnings.append({
                    'level': 'critical',
                    'message': 'Multiple violations detected. Test may be terminated.',
                    'timestamp': latest_violation['timestamp'],
                    'type': 'critical_warning'
                })
        
        return jsonify({
            'success': True,
            'warnings': warnings,
            'session_active': True,
            'violation_count': violation_count,
            'session_id': active_session_id
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/violations/terminate-session', methods=['POST'])
def terminate_session_for_violations():
    """Terminate session due to excessive violations"""
    if session.get('user_type') not in ['examiner', 'admin']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        reason = data.get('reason', 'Excessive violations')
        
        if not session_id:
            return jsonify({'success': False, 'message': 'Session ID required'}), 400
        
        conn = get_db_connection()
        if conn:
            try:
                # Update session status
                conn.execute('''
                    UPDATE proctoring_sessions 
                    SET session_end = CURRENT_TIMESTAMP,
                        session_status = 'terminated'
                    WHERE id = ?
                ''', (session_id,))
                
                # Log termination violation
                conn.execute('''
                    INSERT INTO violation_logs 
                    (session_id, violation_type, violation_details, severity, action_taken)
                    VALUES (?, ?, ?, ?, ?)
                ''', (session_id, 'session_terminated', reason, 'critical', 'terminated_by_examiner'))
                
                conn.commit()
                
                # Remove from active sessions if present
                if int(session_id) in active_sessions:
                    del active_sessions[int(session_id)]
                
                return jsonify({
                    'success': True,
                    'message': 'Session terminated successfully',
                    'termination_reason': reason
                })
                
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
            finally:
                conn.close()
        
        return jsonify({'success': False, 'message': 'Database error'}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ========================================
# INSTANT RESULTS & PDF REPORT GENERATION
# ========================================

@app.route('/api/results/generate', methods=['POST'])
def generate_test_results():
    """Generate instant test results with comprehensive analysis"""
    if session.get('user_type') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        test_score = data.get('score', 0)
        total_questions = data.get('total_questions', 0)
        correct_answers = data.get('correct_answers', 0)
        time_taken_minutes = data.get('time_taken_minutes', 0)
        
        if not session_id:
            return jsonify({'success': False, 'message': 'Session ID required'}), 400
        
        student_id = session.get('user_id')
        if int(session_id) not in active_sessions:
            return jsonify({'success': False, 'message': 'Invalid session'}), 400
        
        conn = get_db_connection()
        if conn:
            try:
                # Get session details
                session_info = conn.execute('''
                    SELECT ps.*, ts.test_name, ts.test_category, ts.duration_minutes
                    FROM proctoring_sessions ps
                    JOIN test_schedules ts ON ps.test_schedule_id = ts.id
                    WHERE ps.id = ?
                ''', (session_id,)).fetchone()
                
                if not session_info:
                    return jsonify({'success': False, 'message': 'Session not found'}), 404
                
                # Get violation count
                violations_count = conn.execute(
                    'SELECT COUNT(*) as count FROM violation_logs WHERE session_id = ?', 
                    (session_id,)
                ).fetchone()['count']
                
                # Calculate performance metrics
                accuracy = (correct_answers / total_questions * 100) if total_questions > 0 else 0
                
                # Insert test result
                cursor = conn.execute('''
                    INSERT INTO test_results 
                    (student_id, test_schedule_id, session_id, score, total_questions, 
                     correct_answers, time_taken_minutes, violation_count, result_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (student_id, session_info['test_schedule_id'], session_id, 
                      test_score, total_questions, correct_answers, time_taken_minutes,
                      violations_count, 'completed'))
                
                result_id = cursor.lastrowid
                conn.commit()
                
                # Remove from active sessions
                if int(session_id) in active_sessions:
                    del active_sessions[int(session_id)]
                
                return jsonify({
                    'success': True,
                    'message': 'Results generated successfully',
                    'results': {
                        'result_id': result_id,
                        'score': test_score,
                        'accuracy': round(accuracy, 2),
                        'violations': violations_count
                    }
                })
                
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
            finally:
                conn.close()
        
        return jsonify({'success': False, 'message': 'Database error'}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# Removed duplicate generate_pdf_report function - using the one with proper parameters below

# ========================================
# RESULTS AND REPORTING ROUTES
# ========================================

@app.route('/api/submit-test', methods=['POST'])
def submit_test():
    """Submit test and generate instant results"""
    if session.get('user_type') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    test_schedule_id = data.get('test_schedule_id')
    session_id = data.get('session_id')
    answers = data.get('answers', [])
    time_taken_minutes = data.get('time_taken_minutes', 0)
    
    student_id = session.get('user_id')
    
    # Calculate score (mock calculation for demo)
    total_questions = len(answers)
    correct_answers = sum(1 for answer in answers if answer.get('is_correct', False))
    score = (correct_answers / total_questions * 100) if total_questions > 0 else 0
    
    conn = get_db_connection()
    if conn:
        try:
            # Get violation count from session
            violation_count = 0
            if session_id:
                session_data = conn.execute('''
                    SELECT total_violations FROM proctoring_sessions WHERE id = ?
                ''', (session_id,)).fetchone()
                if session_data:
                    violation_count = session_data['total_violations']
            
            # Insert test result
            conn.execute('''
                INSERT INTO test_results 
                (student_id, test_schedule_id, session_id, score, total_questions, correct_answers, time_taken_minutes, violation_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (student_id, test_schedule_id, session_id, score, total_questions, correct_answers, time_taken_minutes, violation_count))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'results': {
                    'score': round(score, 2),
                    'percentage': round(score, 2),
                    'correct_answers': correct_answers,
                    'total_questions': total_questions,
                    'time_taken_minutes': time_taken_minutes,
                    'violation_count': violation_count,
                    'grade': get_letter_grade(score),
                    'passed': score >= 60
                }
            })
            
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            conn.close()
    
    return jsonify({'success': False, 'message': 'Database error'}), 500

def get_letter_grade(score):
    """Convert numeric score to letter grade"""
    if score >= 90:
        return 'A'
    elif score >= 80:
        return 'B'
    elif score >= 70:
        return 'C'
    elif score >= 60:
        return 'D'
    else:
        return 'F'

@app.route('/api/generate-report/<int:result_id>')
def generate_pdf_report(result_id):
    """Generate PDF report card for test result"""
    if not canvas:
        return jsonify({'success': False, 'message': 'PDF generation not available'}), 500
    
    conn = get_db_connection()
    if conn:
        try:
            # Get test result with related data
            result = conn.execute('''
                SELECT tr.*, ts.test_name, ts.test_category, s.full_name, s.unique_id
                FROM test_results tr
                JOIN test_schedules ts ON tr.test_schedule_id = ts.id
                JOIN students s ON tr.student_id = s.id
                WHERE tr.id = ?
            ''', (result_id,)).fetchone()
            
            if not result:
                return jsonify({'success': False, 'message': 'Result not found'}), 404
            
            # Generate PDF
            pdf_filename = f"result_card_{result_id}_{int(time.time())}.pdf"
            pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
            
            c = canvas.Canvas(pdf_path, pagesize=letter_size)
            width, height = letter_size
            
            # Add content to PDF
            c.setFont("Helvetica-Bold", 24)
            c.drawString(50, height - 50, "CYGENTIC AI Test Center")
            c.drawString(50, height - 80, "Test Result Report")
            
            c.setFont("Helvetica", 14)
            y_position = height - 120
            
            report_data = [
                f"Student Name: {result['full_name']}",
                f"Student ID: {result['unique_id']}",
                f"Test Name: {result['test_name']}",
                f"Test Category: {result['test_category']}",
                f"Score: {result['score']:.1f}%",
                f"Grade: {get_letter_grade(result['score'])}",
                f"Correct Answers: {result['correct_answers']}/{result['total_questions']}",
                f"Time Taken: {result['time_taken_minutes']} minutes",
                f"Violations Detected: {result['violation_count']}",
                f"Submission Date: {result['submission_time']}",
                f"Status: {'PASSED' if result['score'] >= 60 else 'FAILED'}"
            ]
            
            for line in report_data:
                c.drawString(50, y_position, line)
                y_position -= 25
            
            c.save()
            
            return jsonify({
                'success': True,
                'pdf_url': f'/uploads/{pdf_filename}',
                'filename': pdf_filename
            })
            
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            conn.close()
    
    return jsonify({'success': False, 'message': 'Database error'}), 500

# ========================================
# AI PROCTORING BACKEND ROUTES
# ========================================

@app.route('/api/proctoring/session/start', methods=['POST'])
def start_proctoring_session():
    """Initialize a new proctoring session"""
    if session.get('user_type') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    test_id = data.get('test_id')
    student_id = session.get('user_id')
    
    conn = get_db_connection()
    if conn:
        try:
            # Create new proctoring session
            cursor = conn.execute('''
                INSERT INTO proctoring_sessions 
                (student_id, test_schedule_id, camera_verified, microphone_verified)
                VALUES (?, ?, 1, 1)
            ''', (student_id, test_id))
            
            session_id = cursor.lastrowid
            
            # Store in active sessions for real-time tracking
            active_sessions[session_id] = {
                'student_id': student_id,
                'test_id': test_id,
                'start_time': time.time(),
                'violations': [],
                'last_frame_analysis': None,
                'face_detection_failures': 0,
                'multiple_faces_detected': 0,
                'suspicious_movements': 0,
                'audio_violations': 0
            }
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'session_id': session_id,
                'message': 'Proctoring session started successfully'
            })
            
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            conn.close()
    
    return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/api/proctoring/session/<int:session_id>/violations')
def get_session_violations(session_id):
    """Get all violations for a proctoring session"""
    if session.get('user_type') not in ['student', 'examiner', 'admin']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    conn = get_db_connection()
    if conn:
        try:
            violations = conn.execute('''
                SELECT * FROM violation_logs 
                WHERE session_id = ? 
                ORDER BY timestamp DESC
            ''', (session_id,)).fetchall()
            
            violation_list = []
            for violation in violations:
                violation_list.append({
                    'id': violation['id'],
                    'type': violation['violation_type'],
                    'details': violation['violation_details'],
                    'severity': violation['severity'],
                    'timestamp': violation['timestamp'],
                    'action_taken': violation['action_taken']
                })
            
            return jsonify({
                'success': True,
                'violations': violation_list,
                'total_count': len(violation_list)
            })
            
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            conn.close()
    
    return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/api/health-check')
def health_check():
    """System health check for proctoring readiness"""
    return jsonify({
        'success': True,
        'status': 'healthy',
        'timestamp': time.time(),
        'ai_status': {
            'mediapipe': MEDIAPIPE_AVAILABLE,
            'whisper': WHISPER_AVAILABLE,
            'reportlab': REPORTLAB_AVAILABLE,
            'matplotlib': MATPLOTLIB_AVAILABLE
        }
    })

# ========================================
# TEST SCHEDULING SYSTEM
# ========================================

@app.route('/api/schedule/create', methods=['POST'])
def create_test_schedule():
    """Create a new test schedule with 40-minute window enforcement"""
    if session.get('user_type') not in ['admin', 'examiner']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        test_name = data.get('test_name', '').strip()
        test_category = data.get('test_category', '').strip()
        start_time = data.get('start_time')  # ISO format: 2024-01-15T16:00:00
        end_time = data.get('end_time')    # ISO format: 2024-01-15T17:00:00
        duration_minutes = data.get('duration_minutes', 40)
        camera_required = data.get('camera_required', True)
        microphone_required = data.get('microphone_required', True)
        ai_proctoring_enabled = data.get('ai_proctoring_enabled', True)
        proctoring_strictness = data.get('proctoring_strictness', 'medium')
        
        # Validation
        if not all([test_name, test_category, start_time, end_time]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Parse and validate time format
        try:
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid time format. Use ISO format.'}), 400
        
        # Validate window duration
        window_minutes = (end_dt - start_dt).total_seconds() / 60
        if window_minutes < duration_minutes:
            return jsonify({
                'success': False, 
                'message': f'Test window ({window_minutes} min) must be at least {duration_minutes} minutes'
            }), 400
        
        # Ensure test doesn't start in the past
        if start_dt <= datetime.now():
            return jsonify({'success': False, 'message': 'Test cannot be scheduled in the past'}), 400
        
        conn = get_db_connection()
        if conn:
            try:
                # Check for schedule conflicts
                existing = conn.execute('''
                    SELECT id FROM test_schedules 
                    WHERE test_category = ? AND 
                          ((start_time <= ? AND end_time > ?) OR 
                           (start_time < ? AND end_time >= ?) OR
                           (start_time >= ? AND end_time <= ?))
                          AND is_active = 1
                ''', (test_category, start_time, start_time, end_time, end_time, start_time, end_time)).fetchone()
                
                if existing:
                    return jsonify({
                        'success': False, 
                        'message': 'Schedule conflict detected for this category and time slot'
                    }), 409
                
                # Create schedule
                cursor = conn.execute('''
                    INSERT INTO test_schedules 
                    (test_name, test_category, start_time, end_time, duration_minutes, 
                     created_by, camera_required, microphone_required, ai_proctoring_enabled, 
                     proctoring_strictness)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (test_name, test_category, start_time, end_time, duration_minutes,
                      session.get('username', 'system'), camera_required, microphone_required,
                      ai_proctoring_enabled, proctoring_strictness))
                
                conn.commit()
                
                return jsonify({
                    'success': True,
                    'schedule_id': cursor.lastrowid,
                    'message': 'Test schedule created successfully',
                    'details': {
                        'test_name': test_name,
                        'start_time': start_time,
                        'end_time': end_time,
                        'duration_minutes': duration_minutes,
                        'window_minutes': int(window_minutes)
                    }
                })
                
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
            finally:
                conn.close()
        
        return jsonify({'success': False, 'message': 'Database error'}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/schedule/list', methods=['GET'])
def list_test_schedules():
    """List all active test schedules"""
    if session.get('user_type') not in ['admin', 'examiner', 'student']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        conn = get_db_connection()
        if conn:
            try:
                # For students, only show schedules for their category
                if session.get('user_type') == 'student':
                    student_id = session.get('user_id')
                    student_data = conn.execute(
                        'SELECT test_category FROM students WHERE id = ?', (student_id,)
                    ).fetchone()
                    
                    if not student_data:
                        return jsonify({'success': False, 'message': 'Student not found'}), 404
                    
                    schedules = conn.execute('''
                        SELECT id, test_name, test_category, start_time, end_time, 
                               duration_minutes, camera_required, microphone_required,
                               ai_proctoring_enabled, proctoring_strictness, created_at
                        FROM test_schedules 
                        WHERE test_category = ? AND is_active = 1
                        ORDER BY start_time ASC
                    ''', (student_data['test_category'],)).fetchall()
                else:
                    # For admin/examiner, show all schedules
                    schedules = conn.execute('''
                        SELECT id, test_name, test_category, start_time, end_time, 
                               duration_minutes, camera_required, microphone_required,
                               ai_proctoring_enabled, proctoring_strictness, created_by, created_at
                        FROM test_schedules 
                        WHERE is_active = 1
                        ORDER BY start_time ASC
                    ''').fetchall()
                
                schedule_list = []
                current_time = datetime.now()
                
                for schedule in schedules:
                    start_dt = datetime.fromisoformat(schedule['start_time'].replace('Z', '+00:00'))
                    end_dt = datetime.fromisoformat(schedule['end_time'].replace('Z', '+00:00'))
                    
                    # Determine schedule status
                    if current_time < start_dt:
                        status = 'upcoming'
                    elif start_dt <= current_time <= end_dt:
                        status = 'active'
                    else:
                        status = 'expired'
                    
                    # Calculate remaining time for active tests
                    remaining_minutes = None
                    if status == 'active':
                        remaining_minutes = int((end_dt - current_time).total_seconds() / 60)
                    
                    schedule_data = {
                        'id': schedule['id'],
                        'test_name': schedule['test_name'],
                        'test_category': schedule['test_category'],
                        'start_time': schedule['start_time'],
                        'end_time': schedule['end_time'],
                        'duration_minutes': schedule['duration_minutes'],
                        'camera_required': bool(schedule['camera_required']),
                        'microphone_required': bool(schedule['microphone_required']),
                        'ai_proctoring_enabled': bool(schedule['ai_proctoring_enabled']),
                        'proctoring_strictness': schedule['proctoring_strictness'],
                        'status': status,
                        'remaining_minutes': remaining_minutes,
                        'created_at': schedule['created_at']
                    }
                    
                    # Add creator info for admin/examiner
                    if session.get('user_type') in ['admin', 'examiner']:
                        schedule_data['created_by'] = schedule['created_by']
                    
                    schedule_list.append(schedule_data)
                
                return jsonify({
                    'success': True,
                    'schedules': schedule_list,
                    'total_count': len(schedule_list)
                })
                
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
            finally:
                conn.close()
        
        return jsonify({'success': False, 'message': 'Database error'}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/schedule/<int:schedule_id>/validate', methods=['POST'])
def validate_test_access():
    """Validate if student can start test based on schedule window"""
    if session.get('user_type') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        student_id = session.get('user_id')
        current_time = datetime.now()
        
        conn = get_db_connection()
        if conn:
            try:
                # Get schedule details
                schedule = conn.execute('''
                    SELECT ts.*, s.test_category as student_category
                    FROM test_schedules ts
                    JOIN students s ON s.id = ?
                    WHERE ts.id = ? AND ts.is_active = 1
                ''', (student_id, schedule_id)).fetchone()
                
                if not schedule:
                    return jsonify({'success': False, 'message': 'Test schedule not found'}), 404
                
                # Check if student's category matches
                if schedule['test_category'] != schedule['student_category']:
                    return jsonify({
                        'success': False, 
                        'message': 'You are not enrolled in this test category'
                    }), 403
                
                start_dt = datetime.fromisoformat(schedule['start_time'].replace('Z', '+00:00'))
                end_dt = datetime.fromisoformat(schedule['end_time'].replace('Z', '+00:00'))
                
                # Check if current time is within the test window
                if current_time < start_dt:
                    minutes_until = int((start_dt - current_time).total_seconds() / 60)
                    return jsonify({
                        'success': False,
                        'message': f'Test has not started yet. Starts in {minutes_until} minutes.',
                        'can_start': False,
                        'starts_in_minutes': minutes_until
                    })
                
                if current_time > end_dt:
                    return jsonify({
                        'success': False,
                        'message': 'Test window has expired.',
                        'can_start': False
                    })
                
                # Check if student has already taken this test
                existing_session = conn.execute('''
                    SELECT id FROM proctoring_sessions 
                    WHERE student_id = ? AND test_schedule_id = ?
                ''', (student_id, schedule_id)).fetchone()
                
                if existing_session:
                    return jsonify({
                        'success': False,
                        'message': 'You have already taken this test.',
                        'can_start': False
                    })
                
                # Calculate available time (40-minute duration vs remaining window)
                remaining_window_minutes = int((end_dt - current_time).total_seconds() / 60)
                test_duration = schedule['duration_minutes']
                
                # Enforce strict 40-minute rule within window
                available_time = min(remaining_window_minutes, test_duration)
                
                if available_time < test_duration:
                    return jsonify({
                        'success': True,
                        'message': f'Warning: Only {available_time} minutes remaining in test window.',
                        'can_start': True,
                        'available_time_minutes': available_time,
                        'full_duration': test_duration,
                        'schedule_ends_early': True
                    })
                
                return jsonify({
                    'success': True,
                    'message': 'Test access validated. You can start the test.',
                    'can_start': True,
                    'available_time_minutes': available_time,
                    'schedule': {
                        'test_name': schedule['test_name'],
                        'duration_minutes': test_duration,
                        'camera_required': bool(schedule['camera_required']),
                        'microphone_required': bool(schedule['microphone_required']),
                        'ai_proctoring_enabled': bool(schedule['ai_proctoring_enabled']),
                        'strictness': schedule['proctoring_strictness']
                    }
                })
                
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
            finally:
                conn.close()
        
        return jsonify({'success': False, 'message': 'Database error'}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ========================================
# AI PROCESSING HELPER FUNCTIONS
# ========================================

def analyze_video_frame(frame, session_id):
    """Analyze video frame using MediaPipe and OpenCV with fallback modes"""
    try:
        # Convert BGR to RGB for MediaPipe
        if frame is None:
            return {
                'faces_detected': 0,
                'face_confidence': 0,
                'eye_gaze_direction': 'unknown',
                'pose_landmarks': [],
                'suspicious_pose': False,
                'looking_away': False,
                'error': 'Invalid frame data'
            }
        
        results = {
            'faces_detected': 0,
            'face_confidence': 0,
            'eye_gaze_direction': 'unknown',
            'pose_landmarks': [],
            'suspicious_pose': False,
            'looking_away': False
        }
        
        # Use MediaPipe if available, otherwise fallback to OpenCV
        if MEDIAPIPE_AVAILABLE and proctoring_config.face_detection:
            # MediaPipe face detection
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
            # Face Detection
            face_results = proctoring_config.face_detection.process(rgb_frame)
            if face_results.detections:
                results['faces_detected'] = len(face_results.detections)
                if face_results.detections:
                    results['face_confidence'] = face_results.detections[0].score[0]
            
            # Face Mesh for detailed analysis
            if proctoring_config.face_mesh:
                mesh_results = proctoring_config.face_mesh.process(rgb_frame)
                if mesh_results.multi_face_landmarks:
                    landmarks = mesh_results.multi_face_landmarks[0]
                    
                    # Analyze eye gaze (simplified)
                    eye_landmarks = [landmarks.landmark[i] for i in [33, 7, 163, 144, 145, 153]]
                    
                    if len(eye_landmarks) >= 6:
                        left_eye_center = eye_landmarks[0]
                        right_eye_center = eye_landmarks[3]
                        
                        # Check if looking away (simplified logic)
                        if abs(left_eye_center.x - right_eye_center.x) > 0.08:
                            results['looking_away'] = True
                            results['eye_gaze_direction'] = 'side'
                        else:
                            results['eye_gaze_direction'] = 'forward'
            
            # Pose Detection
            if proctoring_config.pose:
                pose_results = proctoring_config.pose.process(rgb_frame)
                if pose_results.pose_landmarks:
                    landmarks = pose_results.pose_landmarks.landmark
                    
                    # Extract key pose points
                    nose = landmarks[0]
                    left_shoulder = landmarks[11]
                    right_shoulder = landmarks[12]
                    
                    # Check for suspicious pose (leaning away, turned away)
                    shoulder_diff = abs(left_shoulder.y - right_shoulder.y)
                    if shoulder_diff > 0.1 or nose.x < 0.3 or nose.x > 0.7:
                        results['suspicious_pose'] = True
                    
                    # Store pose landmarks for further analysis
                    results['pose_landmarks'] = [
                        {'x': landmark.x, 'y': landmark.y, 'z': landmark.z} 
                        for landmark in landmarks[:15]  # Store first 15 landmarks
                    ]
        
        else:
            # Fallback to OpenCV face detection when MediaPipe is not available
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            
            # Load OpenCV's pre-trained face detection classifier
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
            
            # Detect faces
            faces = face_cascade.detectMultiScale(gray, 1.1, 4)
            results['faces_detected'] = len(faces)
            
            if len(faces) > 0:
                # Get the largest face (primary subject)
                largest_face = max(faces, key=lambda x: x[2] * x[3])
                x, y, w, h = largest_face
                
                # Basic confidence based on face size relative to frame
                frame_area = frame.shape[0] * frame.shape[1]
                face_area = w * h
                results['face_confidence'] = min(0.9, (face_area / frame_area) * 10)
                
                # Extract face region for eye detection
                face_roi_gray = gray[y:y+h, x:x+w]
                eyes = eye_cascade.detectMultiScale(face_roi_gray)
                
                # Simple gaze estimation based on eye positions
                if len(eyes) >= 2:
                    eye_centers = [(ex + ew//2, ey + eh//2) for ex, ey, ew, eh in eyes[:2]]
                    
                    # Check if eyes are roughly horizontal (normal forward gaze)
                    if len(eye_centers) == 2:
                        eye1, eye2 = eye_centers
                        vertical_diff = abs(eye1[1] - eye2[1])
                        horizontal_diff = abs(eye1[0] - eye2[0])
                        
                        if vertical_diff > horizontal_diff * 0.3:  # Eyes not aligned horizontally
                            results['looking_away'] = True
                            results['eye_gaze_direction'] = 'tilted'
                        else:
                            results['eye_gaze_direction'] = 'forward'
                
                # Basic pose estimation based on face position in frame
                face_center_x = (x + w//2) / frame.shape[1]
                face_center_y = (y + h//2) / frame.shape[0]
                
                # Check if face is significantly off-center
                if face_center_x < 0.3 or face_center_x > 0.7 or face_center_y < 0.2 or face_center_y > 0.8:
                    results['suspicious_pose'] = True
                
                # Store basic face landmarks for compatibility
                results['pose_landmarks'] = [
                    {'x': face_center_x, 'y': face_center_y, 'z': 0},  # Face center
                    {'x': x/frame.shape[1], 'y': y/frame.shape[0], 'z': 0},  # Top-left
                    {'x': (x+w)/frame.shape[1], 'y': (y+h)/frame.shape[0], 'z': 0}  # Bottom-right
                ]
            
            # Add fallback mode indicator
            results['detection_mode'] = 'opencv_fallback'
        
        return results
        
    except Exception as e:
        print(f"Frame analysis error: {e}")
        return {
            'faces_detected': 0,
            'face_confidence': 0,
            'eye_gaze_direction': 'unknown',
            'pose_landmarks': [],
            'suspicious_pose': False,
            'looking_away': False,
            'error': str(e),
            'detection_mode': 'error'
        }

def log_violations(session_id, violations):
    """Log violations to database"""
    conn = get_db_connection()
    if conn:
        try:
            for violation in violations:
                conn.execute('''
                    INSERT INTO violation_logs 
                    (session_id, violation_type, violation_details, severity, action_taken)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    session_id,
                    violation['type'],
                    violation['details'],
                    violation['severity'],
                    'logged'
                ))
            
            # Update session violation count
            conn.execute('''
                UPDATE proctoring_sessions 
                SET total_violations = total_violations + ?
                WHERE id = ?
            ''', (len(violations), session_id))
            
            conn.commit()
            
        except Exception as e:
            print(f"Error logging violations: {e}")
        finally:
            conn.close()

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    """Custom 404 error page"""
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Custom 500 error page"""
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden(error):
    """Custom 403 error page"""
    return render_template('errors/403.html'), 403

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Update test categories to latest
    update_test_categories()
    
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)