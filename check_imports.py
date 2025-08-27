# Test script to verify imports

print(\"Testing imports for CYGENTIC AI Test Center...\")

# Basic Flask imports
try:
    from flask import Flask
    print(\"✓ Flask available\")
except ImportError:
    print(\"✗ Flask not available\")

# OpenCV (for computer vision)
try:
    import cv2
    print(\"✓ OpenCV available\")
except ImportError:
    print(\"✗ OpenCV not installed - pip install opencv-python\")

# NumPy (for image processing)
try:
    import numpy as np
    print(\"✓ NumPy available\")
except ImportError:
    print(\"✗ NumPy not installed\")

# MediaPipe (for AI face detection)
try:
    import mediapipe as mp
    print(\"✓ MediaPipe available\")
except ImportError:
    print(\"✗ MediaPipe not installed - pip install mediapipe\")

# Whisper (for audio transcription)
try:
    import whisper
    print(\"✓ Whisper available\")
except ImportError:
    print(\"✗ Whisper not installed - pip install openai-whisper\")

# ReportLab (for PDF generation)
try:
    from reportlab.pdfgen import canvas
    print(\"✓ ReportLab available\")
except ImportError:
    print(\"✗ ReportLab not installed - pip install reportlab\")

print(\"\nImport test completed!\")
print(\"To install missing packages:\")
print(\"pip install opencv-python numpy mediapipe openai-whisper reportlab\")
