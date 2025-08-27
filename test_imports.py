#!/usr/bin/env python3
\"\"\"
Test script to verify all required imports for the CYGENTIC AI Test Center
\"\"\"

import sys
print(\"Testing imports for CYGENTIC AI Test Center...\n\")

# Basic Flask imports
try:
    from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
    print(\"✓ Flask imports successful\")
except ImportError as e:
    print(f\"✗ Flask import error: {e}\")

# Security imports
try:
    from werkzeug.security import generate_password_hash, check_password_hash
    from werkzeug.utils import secure_filename
    print(\"✓ Werkzeug security imports successful\")
except ImportError as e:
    print(f\"✗ Werkzeug import error: {e}\")

# Standard library imports
try:
    import os, sqlite3, re, secrets, json, base64, time, threading, asyncio
    from datetime import datetime, timedelta
    from queue import Queue
    print(\"✓ Standard library imports successful\")
except ImportError as e:
    print(f\"✗ Standard library import error: {e}\")

# OpenCV (for computer vision)
try:
    import cv2
    print(f\"✓ OpenCV version: {cv2.__version__}\")
except ImportError:
    print(\"✗ OpenCV not installed - pip install opencv-python\")

# NumPy (for image processing)
try:
    import numpy as np
    print(f\"✓ NumPy version: {np.__version__}\")
except ImportError:
    print(\"✗ NumPy not installed - pip install numpy\")

# MediaPipe (for AI face detection)
try:
    import mediapipe as mp
    print(f\"✓ MediaPipe version: {mp.__version__}\")
except ImportError:
    print(\"✗ MediaPipe not installed - pip install mediapipe\")

# Whisper (for audio transcription)
try:
    import whisper
    print(f\"✓ Whisper available\")
except ImportError:
    print(\"✗ Whisper not installed - pip install openai-whisper\")

# ReportLab (for PDF generation)
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    print(\"✓ ReportLab available\")
except ImportError:
    print(\"✗ ReportLab not installed - pip install reportlab\")

print(\"\n\" + \"=\"*50)
print(\"Import test completed!\")
print(\"To install missing packages, run:\")
print(\"pip install opencv-python numpy mediapipe openai-whisper reportlab\")
print(\"=\"*50)
