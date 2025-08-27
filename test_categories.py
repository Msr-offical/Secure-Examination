#!/usr/bin/env python3
"""
Test script to verify the student dashboard with test categories
"""

import sqlite3
import os

DATABASE = 'cygentic_test_center.db'

def test_database():
    """Test database connection and check test categories"""
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        
        # Check if test_categories table exists and has data
        result = conn.execute('''
            SELECT name, description FROM test_categories 
            WHERE is_active = 1 ORDER BY name
        ''').fetchall()
        
        print(f"Database file exists: {os.path.exists(DATABASE)}")
        print(f"Found {len(result)} active test categories:")
        
        for row in result:
            print(f"  - {row['name']}: {row['description']}")
            
        conn.close()
        
        if len(result) == 8:
            print("\n✅ All 8 test categories are properly configured!")
            return True
        else:
            print(f"\n❌ Expected 8 categories, found {len(result)}")
            return False
            
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

def test_template_syntax():
    """Basic check if template file exists and has our categories section"""
    template_path = 'templates/dashboards/student_dashboard.html'
    
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        print(f"Template file exists: {os.path.exists(template_path)}")
        
        # Check for our test categories section
        has_categories_section = 'test-categories-section' in content
        has_category_loop = '{% for category in test_categories %}' in content
        has_category_cards = 'category-card' in content
        
        print(f"Has test categories section: {has_categories_section}")
        print(f"Has category loop: {has_category_loop}")
        print(f"Has category cards: {has_category_cards}")
        
        if has_categories_section and has_category_loop and has_category_cards:
            print("✅ Template has all required test category elements!")
            return True
        else:
            print("❌ Template is missing some test category elements")
            return False
            
    except Exception as e:
        print(f"❌ Template error: {e}")
        return False

if __name__ == "__main__":
    print("=== Testing Student Dashboard Test Categories Implementation ===\n")
    
    print("1. Testing Database:")
    db_ok = test_database()
    
    print("\n2. Testing Template:")
    template_ok = test_template_syntax()
    
    print("\n=== Test Results ===")
    if db_ok and template_ok:
        print("✅ All tests passed! The test categories implementation should work correctly.")
    else:
        print("❌ Some tests failed. Please check the issues above.")