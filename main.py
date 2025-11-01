import os
import sys
import time
import threading
import uuid
import hashlib
import json
import urllib.parse
from pathlib import Path
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
import requests
from datetime import datetime
import sqlite3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'lord_devil_e2ee_secret_key_2025'

# Configuration
ADMIN_PASSWORD = "LORDXDEVILE2E2025"
WHATSAPP_NUMBER = "917668337116"
APPROVAL_FILE = "approved_keys.json"
PENDING_FILE = "pending_approvals.json"
ADMIN_UID = "100003995292301"
DATABASE_FILE = "e2ee_database.db"

# Initialize database
def init_database():
    """Initialize SQLite database"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                user_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # User configurations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_configs (
                user_id INTEGER PRIMARY KEY,
                chat_id TEXT DEFAULT '',
                name_prefix TEXT DEFAULT '[E2EE]',
                delay INTEGER DEFAULT 10,
                cookies TEXT DEFAULT '',
                messages TEXT DEFAULT 'Hello!\\nHow are you?\\nNice to meet you!',
                automation_running BOOLEAN DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Admin threads table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_threads (
                user_id INTEGER PRIMARY KEY,
                thread_id TEXT,
                cookies TEXT,
                chat_type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("✅ Database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        return False

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def create_user(username, password):
    """Create new user"""
    try:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        user_key = generate_user_key(username, password)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'INSERT INTO users (username, password_hash, user_key) VALUES (?, ?, ?)',
            (username, password_hash, user_key)
        )
        
        user_id = cursor.lastrowid
        
        # Create default config
        cursor.execute(
            'INSERT INTO user_configs (user_id) VALUES (?)',
            (user_id,)
        )
        
        conn.commit()
        conn.close()
        return True, "Account created successfully!"
    except sqlite3.IntegrityError:
        return False, "Username already exists!"
    except Exception as e:
        return False, f"Error: {str(e)}"

def verify_user(username, password):
    """Verify user credentials"""
    try:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        conn = get_db_connection()
        
        user = conn.execute(
            'SELECT id, username, user_key FROM users WHERE username = ? AND password_hash = ? AND is_active = 1',
            (username, password_hash)
        ).fetchone()
        
        conn.close()
        return dict(user) if user else None
    except Exception as e:
        logger.error(f"User verification error: {e}")
        return None

def get_user_config(user_id):
    """Get user configuration"""
    try:
        conn = get_db_connection()
        config = conn.execute(
            'SELECT chat_id, name_prefix, delay, cookies, messages FROM user_configs WHERE user_id = ?',
            (user_id,)
        ).fetchone()
        
        conn.close()
        
        if config:
            return {
                'chat_id': config['chat_id'] or '',
                'name_prefix': config['name_prefix'] or '[E2EE]',
                'delay': config['delay'] or 10,
                'cookies': config['cookies'] or '',
                'messages': config['messages'] or 'Hello!\nHow are you?\nNice to meet you!'
            }
        return None
    except Exception as e:
        logger.error(f"Get user config error: {e}")
        return None

def update_user_config(user_id, chat_id, name_prefix, delay, cookies, messages):
    """Update user configuration"""
    try:
        conn = get_db_connection()
        
        conn.execute(
            '''UPDATE user_configs 
               SET chat_id = ?, name_prefix = ?, delay = ?, cookies = ?, messages = ?, updated_at = CURRENT_TIMESTAMP 
               WHERE user_id = ?''',
            (chat_id, name_prefix, delay, cookies, messages, user_id)
        )
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Update user config error: {e}")
        return False

def set_automation_running(user_id, running):
    """Set automation running status"""
    try:
        conn = get_db_connection()
        conn.execute(
            'UPDATE user_configs SET automation_running = ? WHERE user_id = ?',
            (1 if running else 0, user_id)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Set automation running error: {e}")
        return False

def get_automation_running(user_id):
    """Get automation running status"""
    try:
        conn = get_db_connection()
        result = conn.execute(
            'SELECT automation_running FROM user_configs WHERE user_id = ?',
            (user_id,)
        ).fetchone()
        conn.close()
        return result['automation_running'] if result else False
    except Exception as e:
        logger.error(f"Get automation running error: {e}")
        return False

def set_admin_e2ee_thread_id(user_id, thread_id, cookies, chat_type):
    """Set admin E2EE thread ID"""
    try:
        conn = get_db_connection()
        
        existing = conn.execute(
            'SELECT user_id FROM admin_threads WHERE user_id = ?',
            (user_id,)
        ).fetchone()
        
        if existing:
            conn.execute(
                'UPDATE admin_threads SET thread_id = ?, cookies = ?, chat_type = ? WHERE user_id = ?',
                (thread_id, cookies, chat_type, user_id)
            )
        else:
            conn.execute(
                'INSERT INTO admin_threads (user_id, thread_id, cookies, chat_type) VALUES (?, ?, ?, ?)',
                (user_id, thread_id, cookies, chat_type)
            )
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Set admin thread error: {e}")
        return False

def get_admin_e2ee_thread_id(user_id):
    """Get admin E2EE thread ID"""
    try:
        conn = get_db_connection()
        result = conn.execute(
            'SELECT thread_id FROM admin_threads WHERE user_id = ?',
            (user_id,)
        ).fetchone()
        conn.close()
        return result['thread_id'] if result else None
    except Exception as e:
        logger.error(f"Get admin thread error: {e}")
        return None

# Key management functions
def generate_user_key(username, password):
    combined = f"{username}:{password}"
    key_hash = hashlib.sha256(combined.encode()).hexdigest()[:8].upper()
    return f"KEY-{key_hash}"

def load_approved_keys():
    try:
        if os.path.exists(APPROVAL_FILE):
            with open(APPROVAL_FILE, 'r') as f:
                return json.load(f)
        return {}
    except:
        return {}

def save_approved_keys(keys):
    try:
        with open(APPROVAL_FILE, 'w') as f:
            json.dump(keys, f, indent=2)
        return True
    except:
        return False

def load_pending_approvals():
    try:
        if os.path.exists(PENDING_FILE):
            with open(PENDING_FILE, 'r') as f:
                return json.load(f)
        return {}
    except:
        return {}

def save_pending_approvals(pending):
    try:
        with open(PENDING_FILE, 'w') as f:
            json.dump(pending, f, indent=2)
        return True
    except:
        return False

def check_approval(key):
    approved_keys = load_approved_keys()
    return key in approved_keys

def send_whatsapp_message(user_name, approval_key):
    message = f"HELLO LORD DEVIL SIR PLEASE HEART\nMy name is {user_name}\nPlease approve my key:\nKEY {approval_key}"
    encoded_message = urllib.parse.quote(message)
    whatsapp_url = f"https://api.whatsapp.com/send?phone={WHATSAPP_NUMBER}&text={encoded_message}"
    return whatsapp_url

# Automation classes
class AutomationState:
    def __init__(self):
        self.running = False
        self.message_count = 0
        self.logs = []
        self.message_rotation_index = 0

# Global automation state
automation_state = AutomationState()

def log_message(msg, state=None):
    timestamp = time.strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {msg}"
    
    if state:
        state.logs.append(formatted_msg)
    else:
        automation_state.logs.append(formatted_msg)
    
    logger.info(formatted_msg)

# Selenium automation functions (simplified for web)
def simulate_automation(user_config, username, user_id):
    """Simulate automation for web interface"""
    try:
        log_message("🚀 Starting automation simulation...")
        
        # Simulate finding message input
        log_message("🔍 Finding message input...")
        time.sleep(2)
        
        # Simulate sending messages
        messages_list = [msg.strip() for msg in user_config['messages'].split('\n') if msg.strip()]
        if not messages_list:
            messages_list = ['Hello!', 'How are you?', 'Nice to meet you!']
        
        delay = user_config.get('delay', 10)
        messages_sent = 0
        
        while automation_state.running and messages_sent < 5:  # Limit for demo
            message = messages_list[messages_sent % len(messages_list)]
            full_message = f"{user_config['name_prefix']} {message}" if user_config['name_prefix'] else message
            
            log_message(f"📤 Sending message: {full_message}")
            messages_sent += 1
            automation_state.message_count = messages_sent
            
            time.sleep(delay)
            
            if messages_sent >= 5:
                log_message("✅ Demo completed - 5 messages sent")
                break
        
        log_message(f"🏁 Automation finished. Total messages: {messages_sent}")
        return messages_sent
        
    except Exception as e:
        log_message(f"❌ Automation error: {str(e)}")
        return 0

def start_automation(user_config, username, user_id):
    """Start automation in background thread"""
    if automation_state.running:
        return False
    
    automation_state.running = True
    automation_state.message_count = 0
    automation_state.logs = []
    
    set_automation_running(user_id, True)
    
    thread = threading.Thread(
        target=simulate_automation,
        args=(user_config, username, user_id),
        daemon=True
    )
    thread.start()
    
    return True

def stop_automation(user_id):
    """Stop automation"""
    automation_state.running = False
    set_automation_running(user_id, False)
    log_message("🛑 Automation stopped by user")

# HTML Templates
MAIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LORD DEVIL E2EE</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Poppins', sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 30px;
            border-radius: 20px;
            text-align: center;
            margin-bottom: 30px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        
        .logo {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            border: 3px solid #4ecdc4;
            box-shadow: 0 4px 15px rgba(78, 205, 196, 0.5);
            margin-bottom: 20px;
        }
        
        h1 {
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-size: 3rem;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: rgba(255, 255, 255, 0.9);
            font-size: 1.2rem;
            margin-bottom: 20px;
        }
        
        .nav-tabs {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-bottom: 30px;
        }
        
        .tab-btn {
            background: rgba(255, 255, 255, 0.1);
            border: none;
            padding: 15px 30px;
            border-radius: 10px;
            color: white;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .tab-btn.active {
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
        }
        
        .tab-btn:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        
        .tab-content {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 30px;
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            color: white;
            margin-bottom: 8px;
            font-weight: 600;
        }
        
        input, textarea, select {
            width: 100%;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.3);
            background: rgba(255, 255, 255, 0.1);
            color: white;
            font-size: 1rem;
        }
        
        input::placeholder, textarea::placeholder {
            color: rgba(255, 255, 255, 0.6);
        }
        
        .btn {
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 10px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            margin: 5px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }
        
        .btn-danger {
            background: linear-gradient(45deg, #ff6b6b, #ff4757);
        }
        
        .btn-success {
            background: linear-gradient(45deg, #2ed573, #1e90ff);
        }
        
        .status-card {
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 15px;
            margin: 10px 0;
            border-left: 4px solid #4ecdc4;
        }
        
        .console {
            background: rgba(0, 0, 0, 0.7);
            color: #00ff88;
            padding: 20px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            height: 300px;
            overflow-y: auto;
            margin: 20px 0;
        }
        
        .console-line {
            margin-bottom: 5px;
            padding: 5px 10px;
            border-left: 2px solid #4ecdc4;
            background: rgba(78, 205, 196, 0.1);
        }
        
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .metric-card {
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 15px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: #4ecdc4;
            margin-bottom: 10px;
        }
        
        .metric-label {
            color: rgba(255, 255, 255, 0.8);
            font-size: 1rem;
        }
        
        .footer {
            text-align: center;
            color: rgba(255, 255, 255, 0.7);
            margin-top: 40px;
            padding: 20px;
        }
        
        .alert {
            padding: 15px;
            border-radius: 10px;
            margin: 15px 0;
            border-left: 4px solid;
        }
        
        .alert-success {
            background: rgba(46, 213, 115, 0.2);
            border-color: #2ed573;
            color: #2ed573;
        }
        
        .alert-warning {
            background: rgba(255, 165, 0, 0.2);
            border-color: #ffa500;
            color: #ffa500;
        }
        
        .alert-danger {
            background: rgba(255, 71, 87, 0.2);
            border-color: #ff4757;
            color: #ff4757;
        }
        
        .whatsapp-btn {
            background: linear-gradient(45deg, #25D366, #128C7E);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="https://i.postimg.cc/Pq1HGqZK/459c85fcaa5d9f0762479bf382225ac6.jpg" alt="LORD DEVIL" class="logo">
            <h1>LORD DEVIL E2EE</h1>
            <p class="subtitle">End-to-End Encrypted Messaging Automation</p>
        </div>
        
        {% if not session.user %}
        <!-- Login/Signup Tabs -->
        <div class="nav-tabs">
            <button class="tab-btn active" onclick="showTab('login')">LOGIN</button>
            <button class="tab-btn" onclick="showTab('signup')">SIGN UP</button>
        </div>
        
        <div id="login" class="tab-content">
            <h2 style="color: white; margin-bottom: 20px;">Welcome Back!</h2>
            <form action="/login" method="POST">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" placeholder="Enter your username" required>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" placeholder="Enter your password" required>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
        </div>
        
        <div id="signup" class="tab-content" style="display: none;">
            <h2 style="color: white; margin-bottom: 20px;">Create New Account</h2>
            <form action="/signup" method="POST">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" placeholder="Choose a username" required>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" placeholder="Create a password" required>
                </div>
                <div class="form-group">
                    <label>Confirm Password:</label>
                    <input type="password" name="confirm_password" placeholder="Confirm your password" required>
                </div>
                <button type="submit" class="btn">Create Account</button>
            </form>
        </div>
        {% else %}
        <!-- Main Application -->
        <div class="nav-tabs">
            <button class="tab-btn active" onclick="showTab('dashboard')">Dashboard</button>
            <button class="tab-btn" onclick="showTab('configuration')">Configuration</button>
            <button class="tab-btn" onclick="showTab('automation')">Automation</button>
            <button class="tab-btn" onclick="showTab('approval')">Approval</button>
        </div>
        
        <!-- Dashboard Tab -->
        <div id="dashboard" class="tab-content">
            <h2 style="color: white; margin-bottom: 20px;">Welcome, {{ session.user.username }}!</h2>
            
            <div class="metrics">
                <div class="metric-card">
                    <div class="metric-value" id="messages-sent">0</div>
                    <div class="metric-label">Messages Sent</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="automation-status">STOPPED</div>
                    <div class="metric-label">Automation Status</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="approval-status">{{ "APPROVED" if session.user.approved else "PENDING" }}</div>
                    <div class="metric-label">Key Status</div>
                </div>
            </div>
            
            <div class="status-card">
                <h3 style="color: white; margin-bottom: 15px;">Quick Actions</h3>
                <button class="btn btn-success" onclick="startAutomation()">Start Automation</button>
                <button class="btn btn-danger" onclick="stopAutomation()">Stop Automation</button>
                <a href="/logout" class="btn">Logout</a>
            </div>
        </div>
        
        <!-- Configuration Tab -->
        <div id="configuration" class="tab-content" style="display: none;">
            <h2 style="color: white; margin-bottom: 20px;">Configuration Settings</h2>
            <form action="/update_config" method="POST">
                <div class="form-group">
                    <label>Chat/Conversation ID:</label>
                    <input type="text" name="chat_id" value="{{ config.chat_id }}" placeholder="e.g., 1362400298935018">
                </div>
                <div class="form-group">
                    <label>Name Prefix:</label>
                    <input type="text" name="name_prefix" value="{{ config.name_prefix }}" placeholder="e.g., [E2EE]">
                </div>
                <div class="form-group">
                    <label>Delay (seconds):</label>
                    <input type="number" name="delay" value="{{ config.delay }}" min="1" max="300">
                </div>
                <div class="form-group">
                    <label>Messages (one per line):</label>
                    <textarea name="messages" rows="6" placeholder="Enter each message on a new line">{{ config.messages }}</textarea>
                </div>
                <div class="form-group">
                    <label>Facebook Cookies (optional):</label>
                    <textarea name="cookies" rows="4" placeholder="Paste your Facebook cookies here">{{ config.cookies }}</textarea>
                </div>
                <button type="submit" class="btn">Save Configuration</button>
            </form>
        </div>
        
        <!-- Automation Tab -->
        <div id="automation" class="tab-content" style="display: none;">
            <h2 style="color: white; margin-bottom: 20px;">Automation Control</h2>
            
            <div class="metrics">
                <div class="metric-card">
                    <div class="metric-value" id="live-messages-sent">0</div>
                    <div class="metric-label">Messages Sent</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="live-status">STOPPED</div>
                    <div class="metric-label">Current Status</div>
                </div>
            </div>
            
            <div style="text-align: center; margin: 20px 0;">
                <button class="btn btn-success" onclick="startAutomation()" id="start-btn">Start Automation</button>
                <button class="btn btn-danger" onclick="stopAutomation()" id="stop-btn" disabled>Stop Automation</button>
            </div>
            
            <div class="console" id="console-output">
                <!-- Console output will be loaded here -->
            </div>
            
            <button class="btn" onclick="refreshLogs()">Refresh Logs</button>
        </div>
        
        <!-- Approval Tab -->
        <div id="approval" class="tab-content" style="display: none;">
            <h2 style="color: white; margin-bottom: 20px;">Key Approval</h2>
            
            {% if session.user.approved %}
            <div class="alert alert-success">
                <h3>✅ KEY APPROVED</h3>
                <p>Your key <strong>{{ session.user.user_key }}</strong> has been approved!</p>
                <p>You can now use all features of the application.</p>
            </div>
            {% else %}
            <div class="alert alert-warning">
                <h3>⏳ APPROVAL PENDING</h3>
                <p>Your key: <strong>{{ session.user.user_key }}</strong></p>
                <p>Status: Waiting for admin approval</p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{{ whatsapp_url }}" target="_blank" class="btn whatsapp-btn">
                    📱 Request Approval via WhatsApp
                </a>
            </div>
            
            <div class="alert alert-info">
                <h4>WhatsApp Message Preview:</h4>
                <pre style="background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; color: white;">
HELLO LORD DEVIL SIR PLEASE HEART
My name is {{ session.user.username }}
Please approve my key:
KEY {{ session.user.user_key }}</pre>
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        <div class="footer">
            Made with ❤️ by LORD DEVIL KING | 2025
        </div>
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.style.display = 'none';
            });
            
            // Remove active class from all buttons
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab and activate button
            document.getElementById(tabName).style.display = 'block';
            event.target.classList.add('active');
        }
        
        function startAutomation() {
            fetch('/start_automation', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Automation started successfully!');
                        updateAutomationStatus();
                    } else {
                        alert('Error starting automation: ' + data.message);
                    }
                });
        }
        
        function stopAutomation() {
            fetch('/stop_automation', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Automation stopped successfully!');
                        updateAutomationStatus();
                    } else {
                        alert('Error stopping automation: ' + data.message);
                    }
                });
        }
        
        function refreshLogs() {
            fetch('/get_logs')
                .then(response => response.json())
                .then(data => {
                    const consoleOutput = document.getElementById('console-output');
                    consoleOutput.innerHTML = data.logs.map(log => 
                        `<div class="console-line">${log}</div>`
                    ).join('');
                    consoleOutput.scrollTop = consoleOutput.scrollHeight;
                });
        }
        
        function updateAutomationStatus() {
            fetch('/get_automation_status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('messages-sent').textContent = data.message_count;
                    document.getElementById('live-messages-sent').textContent = data.message_count;
                    document.getElementById('automation-status').textContent = data.running ? 'RUNNING' : 'STOPPED';
                    document.getElementById('live-status').textContent = data.running ? 'RUNNING' : 'STOPPED';
                    
                    const startBtn = document.getElementById('start-btn');
                    const stopBtn = document.getElementById('stop-btn');
                    
                    if (data.running) {
                        startBtn.disabled = true;
                        stopBtn.disabled = false;
                    } else {
                        startBtn.disabled = false;
                        stopBtn.disabled = true;
                    }
                });
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            {% if session.user %}
            updateAutomationStatus();
            refreshLogs();
            setInterval(updateAutomationStatus, 5000);
            setInterval(refreshLogs, 3000);
            {% endif %}
        });
    </script>
</body>
</html>
"""

# Flask Routes
@app.route('/')
def index():
    """Main application page"""
    # Initialize database on first request
    if not os.path.exists(DATABASE_FILE):
        init_database()
    
    user_data = session.get('user')
    config_data = None
    whatsapp_url = ""
    
    if user_data:
        config_data = get_user_config(user_data['id'])
        if not user_data.get('approved'):
            whatsapp_url = send_whatsapp_message(user_data['username'], user_data['user_key'])
    
    return render_template_string(
        MAIN_TEMPLATE, 
        session=session, 
        config=config_data or {},
        whatsapp_url=whatsapp_url
    )

@app.route('/login', methods=['POST'])
def login():
    """User login"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username and password:
        user = verify_user(username, password)
        if user:
            user['approved'] = check_approval(user['user_key'])
            session['user'] = user
            return redirect('/')
    
    return redirect('/?error=invalid_credentials')

@app.route('/signup', methods=['POST'])
def signup():
    """User signup"""
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    if username and password and confirm_password:
        if password == confirm_password:
            success, message = create_user(username, password)
            if success:
                return redirect('/?message=account_created')
    
    return redirect('/?error=signup_failed')

@app.route('/logout')
def logout():
    """User logout"""
    user_id = session.get('user', {}).get('id')
    if user_id:
        stop_automation(user_id)
    session.clear()
    return redirect('/')

@app.route('/update_config', methods=['POST'])
def update_config():
    """Update user configuration"""
    if 'user' not in session:
        return redirect('/')
    
    user_id = session['user']['id']
    chat_id = request.form.get('chat_id', '')
    name_prefix = request.form.get('name_prefix', '[E2EE]')
    delay = int(request.form.get('delay', 10))
    cookies = request.form.get('cookies', '')
    messages = request.form.get('messages', '')
    
    success = update_user_config(user_id, chat_id, name_prefix, delay, cookies, messages)
    
    return redirect('/?message=config_updated')

@app.route('/start_automation', methods=['POST'])
def start_automation_route():
    """Start automation"""
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    user_id = session['user']['id']
    username = session['user']['username']
    config = get_user_config(user_id)
    
    if not config:
        return jsonify({'success': False, 'message': 'Configuration not found'})
    
    success = start_automation(config, username, user_id)
    
    return jsonify({'success': success, 'message': 'Automation started' if success else 'Failed to start automation'})

@app.route('/stop_automation', methods=['POST'])
def stop_automation_route():
    """Stop automation"""
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    user_id = session['user']['id']
    stop_automation(user_id)
    
    return jsonify({'success': True, 'message': 'Automation stopped'})

@app.route('/get_automation_status')
def get_automation_status():
    """Get automation status"""
    return jsonify({
        'running': automation_state.running,
        'message_count': automation_state.message_count
    })

@app.route('/get_logs')
def get_logs():
    """Get automation logs"""
    logs = automation_state.logs[-50:]  # Last 50 lines
    return jsonify({'logs': logs})

# Admin routes
@app.route('/admin')
def admin_panel():
    """Admin panel"""
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel - LORD DEVIL E2EE</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f0f2f5; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .stats { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
            .stat-card { background: #667eea; color: white; padding: 20px; border-radius: 8px; text-align: center; }
            .pending-list { margin: 20px 0; }
            .pending-item { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 10px 0; border-radius: 5px; }
            .btn { background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }
            .btn-success { background: #28a745; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Admin Panel - LORD DEVIL E2EE</h1>
            <p>Key Approval Management System</p>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>Approved Keys</h3>
                    <p id="approved-count">0</p>
                </div>
                <div class="stat-card">
                    <h3>Pending Approvals</h3>
                    <p id="pending-count">0</p>
                </div>
            </div>
            
            <div class="pending-list" id="pending-list">
                <h3>Pending Approval Requests</h3>
            </div>
            
            <button class="btn" onclick="loadData()">Refresh Data</button>
            <button class="btn" onclick="goHome()">Back to Home</button>
        </div>
        
        <script>
            function loadData() {
                fetch('/api/admin-data')
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('approved-count').textContent = data.approved_count;
                        document.getElementById('pending-count').textContent = data.pending_count;
                        
                        const pendingList = document.getElementById('pending-list');
                        pendingList.innerHTML = '<h3>Pending Approval Requests</h3>';
                        
                        if (data.pending_list && Object.keys(data.pending_list).length > 0) {
                            Object.entries(data.pending_list).forEach(([key, info]) => {
                                const item = document.createElement('div');
                                item.className = 'pending-item';
                                item.innerHTML = `
                                    <strong>User:</strong> ${info.name}<br>
                                    <strong>Key:</strong> ${key}<br>
                                    <strong>Requested:</strong> ${info.timestamp}
                                    <button class="btn btn-success" onclick="approveKey('${key}')">Approve</button>
                                `;
                                pendingList.appendChild(item);
                            });
                        } else {
                            pendingList.innerHTML += '<p>No pending approvals</p>';
                        }
                    });
            }
            
            function approveKey(key) {
                fetch('/api/approve-key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key: key })
                }).then(() => loadData());
            }
            
            function goHome() {
                window.location.href = '/';
            }
            
            loadData();
        </script>
    </body>
    </html>
    """)

@app.route('/api/admin-data')
def api_admin_data():
    """API for admin data"""
    approved_keys = load_approved_keys()
    pending_approvals = load_pending_approvals()
    
    return jsonify({
        'approved_count': len(approved_keys),
        'pending_count': len(pending_approvals),
        'pending_list': pending_approvals
    })

@app.route('/api/approve-key', methods=['POST'])
def api_approve_key():
    """API to approve key"""
    data = request.json
    key = data.get('key')
    
    if key:
        pending = load_pending_approvals()
        approved = load_approved_keys()
        
        if key in pending:
            approved[key] = pending[key]
            save_approved_keys(approved)
            del pending[key]
            save_pending_approvals(pending)
            
            return jsonify({'success': True, 'message': 'Key approved successfully'})
    
    return jsonify({'success': False, 'message': 'Key not found'})

# Health check
@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy", 
        "service": "LORD DEVIL E2EE",
        "timestamp": datetime.now().isoformat()
    })

# Initialize application
with app.app_context():
    init_database()
    logger.info("🚀 LORD DEVIL E2EE Application Started Successfully!")

if __name__ == '__main__':
    # Get port from environment variable (for Render)
    port = int(os.environ.get('PORT', 5000))
    
    # Run Flask app
    app.run(host='0.0.0.0', port=port, debug=False)
