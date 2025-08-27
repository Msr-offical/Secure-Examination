#!/usr/bin/env python3
"""
Database Initialization Script for CYGENTIC AI Test Center
This script initializes the database and adds test categories
"""

import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = 'cygentic_test_center.db'

def get_db_connection():
    """Get database connection with proper error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def initialize_database():
    """Initialize database with all required tables and test categories"""
    conn = get_db_connection()
    if conn:
        try:
            print("Initializing database...")
            
            # Create test_categories table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS test_categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
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
            
            # Clear existing test categories
            conn.execute('DELETE FROM test_categories')
            
            # Insert the 8 test categories requested by user
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
            
            print("Inserting test categories...")
            for category, description in categories:
                conn.execute('''
                    INSERT INTO test_categories (name, description, is_active)
                    VALUES (?, ?, 1)
                ''', (category, description))
                print(f"  - {category}")
            
            conn.commit()
            print("Database initialized successfully!")
            
            # Verify categories were inserted
            categories_count = conn.execute('SELECT COUNT(*) FROM test_categories WHERE is_active = 1').fetchone()[0]
            print(f"Total active test categories: {categories_count}")
            
        except Exception as e:
            print(f"Database initialization error: {e}")
        finally:
            conn.close()
    else:
        print("Failed to connect to database")

if __name__ == "__main__":
    initialize_database()