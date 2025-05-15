"""
VulneraBlog - A Deliberately Vulnerable Flask Application
This application contains multiple vulnerabilities from the OWASP Top 10 for educational purposes.
DO NOT USE IN PRODUCTION! 
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response, send_file
import sqlite3
import os
import pickle
import base64
import json
import re
import xml.etree.ElementTree as ET
import subprocess
from functools import wraps
import random
import hashlib
import logging
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey123'  # Hardcoded secret key (CWE-798)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'database.db'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Set up basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database initialization
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Create users table
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        is_admin INTEGER DEFAULT 0,
        api_key TEXT
    )
    ''')
    
    # Create blog posts table
    c.execute('''
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        author_id INTEGER,
        is_public INTEGER DEFAULT 1,
        FOREIGN KEY (author_id) REFERENCES users(id)
    )
    ''')
    
    # Create comments table
    c.execute('''
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY,
        post_id INTEGER,
        content TEXT NOT NULL,
        author_id INTEGER,
        FOREIGN KEY (post_id) REFERENCES posts(id),
        FOREIGN KEY (author_id) REFERENCES users(id)
    )
    ''')
    
    # Create user_profile table with additional info
    c.execute('''
    CREATE TABLE IF NOT EXISTS user_profiles (
        user_id INTEGER PRIMARY KEY,
        full_name TEXT,
        bio TEXT,
        phone TEXT,
        address TEXT,
        credit_card TEXT,
        ssn TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Insert default admin and test users if they don't exist
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        # Vulnerability: Weak credentials (CWE-521)
        c.execute("INSERT INTO users (username, password, email, is_admin, api_key) VALUES (?, ?, ?, ?, ?)",
                 ('admin', 'admin123', 'admin@example.com', 1, 'ADMIN_SECRET_API_KEY_123'))
        c.execute("INSERT INTO users (username, password, email, is_admin, api_key) VALUES (?, ?, ?, ?, ?)",
                 ('user', 'password', 'user@example.com', 0, 'USER_API_KEY_456'))
        c.execute("INSERT INTO users (username, password, email, is_admin, api_key) VALUES (?, ?, ?, ?, ?)",
                 ('alice', 'alice123', 'alice@example.com', 0, 'ALICE_API_KEY_789'))
        
        # Add some sample profile data
        c.execute("INSERT INTO user_profiles (user_id, full_name, bio, phone, address, credit_card, ssn) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (1, 'Admin User', 'System administrator', '555-123-4567', '123 Admin St', '4111-1111-1111-1111', '123-45-6789'))
        c.execute("INSERT INTO user_profiles (user_id, full_name, bio, phone, address, credit_card, ssn) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (2, 'Test User', 'Regular user account', '555-987-6543', '456 User Ave', '4222-2222-2222-2222', '987-65-4321'))
    
    # Insert sample blog posts
    c.execute("SELECT * FROM posts LIMIT 1")
    if not c.fetchone():
        c.execute("INSERT INTO posts (title, content, author_id, is_public) VALUES (?, ?, ?, ?)",
                 ('Welcome to VulneraBlog', 'This is our first post on this vulnerable blog platform!', 1, 1))
        c.execute("INSERT INTO posts (title, content, author_id, is_public) VALUES (?, ?, ?, ?)",
                 ('Security Tips', 'Never share your password with anyone!', 1, 1))
        c.execute("INSERT INTO posts (title, content, author_id, is_public) VALUES (?, ?, ?, ?)",
                 ('Private Post', 'This post should only be visible to admins', 1, 0))
        
        # Add some comments
        c.execute("INSERT INTO comments (post_id, content, author_id) VALUES (?, ?, ?)",
                 (1, 'Great first post!', 2))
        c.execute("INSERT INTO comments (post_id, content, author_id) VALUES (?, ?, ?)",
                 (1, 'Looking forward to more content.', 3))
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# Helper function to get database connection
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row  # This enables column access by name
    return conn

# Decorator for checking if user is logged in (vulnerable implementation)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Vulnerability: No CSRF protection used in the application

# Routes
@app.route('/')
def index():
    conn = get_db()
    # Vulnerability: SQL Injection in the query parameter (CWE-89)
    sort_by = request.args.get('sort', 'id')
    # No validation on sort_by parameter
    posts = conn.execute(f"SELECT * FROM posts WHERE is_public=1 ORDER BY {sort_by}").fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        # Vulnerability: SQL Injection in login (CWE-89)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        user = conn.execute(query).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            # Vulnerability: Session information displayed in URL
            return redirect(url_for('dashboard', user_id=user['id']))
        else:
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

@app.route('/dashboard')
@login_required
def dashboard():
    # Vulnerability: Insecure Direct Object Reference (IDOR) (CWE-639)
    # User ID from query parameter without proper authorization
    user_id = request.args.get('user_id', session['user_id'])
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    profile = conn.execute("SELECT * FROM user_profiles WHERE user_id=?", (user_id,)).fetchone()
    posts = conn.execute("SELECT * FROM posts WHERE author_id=?", (user_id,)).fetchall()
    conn.close()
    
    if not user:
        return "User not found", 404
    
    return render_template('dashboard.html', user=user, profile=profile, posts=posts)

@app.route('/admin')
def admin_panel():
    # Vulnerability: Missing Function Level Access Control (CWE-285)
    # No check if the user is an admin
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    posts = conn.execute("SELECT * FROM posts").fetchall()
    conn.close()
    
    return render_template('admin.html', users=users, posts=posts)

@app.route('/admin/secure')
def admin_secure():
    # Partially fixed version with weak authorization check
    # Vulnerability: Weak authorization check that can be bypassed
    if session.get('is_admin') != 1:
        return "Unauthorized", 403
    
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    posts = conn.execute("SELECT * FROM posts").fetchall()
    conn.close()
    
    return render_template('admin.html', users=users, posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Vulnerability: No password complexity requirements (CWE-521)
        # Vulnerability: No input validation (CWE-20)
        
        conn = get_db()
        try:
            # Generate a simple API key
            api_key = hashlib.md5((username + str(random.randint(1, 1000))).encode()).hexdigest()
            
            conn.execute("INSERT INTO users (username, password, email, api_key) VALUES (?, ?, ?, ?)",
                       (username, password, email, api_key))
            conn.commit()
            # Get the new user's ID
            user = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            # Create an empty profile
            conn.execute("INSERT INTO user_profiles (user_id) VALUES (?)", (user['id'],))
            conn.commit()
            
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = 'Username already exists'
        finally:
            conn.close()
    
    return render_template('register.html', error=error)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    conn = get_db()
    # Vulnerability: SQL Injection via string formatting in integer context (CWE-89)
    post = conn.execute(f"SELECT * FROM posts WHERE id={post_id}").fetchone()
    
    if not post:
        conn.close()
        return "Post not found", 404
    
    # Check if the post is private and user is not logged in or not admin
    if post['is_public'] == 0 and (not session.get('user_id') or session.get('is_admin') != 1):
        conn.close()
        return "Unauthorized", 403
    
    comments = conn.execute("SELECT comments.*, users.username FROM comments JOIN users ON comments.author_id = users.id WHERE post_id=?", (post_id,)).fetchall()
    conn.close()
    
    return render_template('post.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form['content']
    user_id = session['user_id']
    
    conn = get_db()
    # No validation on content - XSS vulnerability (CWE-79)
    conn.execute("INSERT INTO comments (post_id, content, author_id) VALUES (?, ?, ?)",
               (post_id, content, user_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        is_public = 1 if request.form.get('is_public') else 0
        user_id = session['user_id']
        
        conn = get_db()
        conn.execute("INSERT INTO posts (title, content, author_id, is_public) VALUES (?, ?, ?, ?)",
                   (title, content, user_id, is_public))
        conn.commit()
        conn.close()
        
        return redirect(url_for('dashboard', user_id=user_id))
    
    return render_template('create_post.html')

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_id = session['user_id']
    
    if request.method == 'POST':
        full_name = request.form['full_name']
        bio = request.form['bio']
        phone = request.form['phone']
        address = request.form['address']
        
        # Vulnerability: Sensitive data exposure (CWE-359)
        credit_card = request.form.get('credit_card', '')
        ssn = request.form.get('ssn', '')
        
        conn = get_db()
        conn.execute("""
            UPDATE user_profiles SET 
            full_name=?, bio=?, phone=?, address=?, credit_card=?, ssn=?
            WHERE user_id=?
        """, (full_name, bio, phone, address, credit_card, ssn, user_id))
        conn.commit()
        conn.close()
        
        return redirect(url_for('dashboard', user_id=user_id))
    
    conn = get_db()
    profile = conn.execute("SELECT * FROM user_profiles WHERE user_id=?", (user_id,)).fetchone()
    conn.close()
    
    return render_template('edit_profile.html', profile=profile)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    conn = get_db()
    # Vulnerability: SQL Injection (CWE-89)
    posts = conn.execute(f"SELECT * FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'").fetchall()
    conn.close()
    
    return render_template('search_results.html', posts=posts, query=query)

@app.route('/api/user/<int:user_id>')
def api_user(user_id):
    # Vulnerability: Insecure Direct Object Reference (IDOR) (CWE-639)
    api_key = request.headers.get('X-API-Key')
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    # Vulnerability: Information disclosure through error messages
    if api_key != user['api_key']:
        conn.close()
        return jsonify({"error": f"Invalid API key. Expected: {user['api_key']}"}), 403
    
    # Convert user to dictionary
    user_dict = dict(user)
    
    # Include sensitive data in API response
    profile = conn.execute("SELECT * FROM user_profiles WHERE user_id=?", (user_id,)).fetchone()
    if profile:
        user_dict['profile'] = dict(profile)
    
    conn.close()
    return jsonify(user_dict)

@app.route('/api/posts')
def api_posts():
    # Vulnerability: API with no rate limiting (CWE-770)
    conn = get_db()
    posts = conn.execute("SELECT * FROM posts WHERE is_public=1").fetchall()
    conn.close()
    
    result = []
    for post in posts:
        result.append(dict(post))
    
    return jsonify(result)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        # Vulnerability: Unrestricted File Upload (CWE-434)
        if 'file' not in request.files:
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        
        # Save the file with original filename - path traversal vulnerability
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        return redirect(url_for('uploaded_file', filename=filename))
    
    return render_template('upload.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # Vulnerability: Path Traversal (CWE-22)
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

@app.route('/process_data', methods=['POST'])
@login_required
def process_data():
    # Vulnerability: Insecure Deserialization (CWE-502)
    if 'data' in request.form:
        serialized_data = request.form['data']
        try:
            # Extremely dangerous: deserializing user-provided data
            data = pickle.loads(base64.b64decode(serialized_data))
            return jsonify({"result": f"Processed: {data}"})
        except Exception as e:
            return jsonify({"error": str(e)})
    
    return jsonify({"error": "No data provided"})

@app.route('/serialize_example')
def serialize_example():
    # Example for testing insecure deserialization
    class ExampleObject:
        def __init__(self, name):
            self.name = name
    
    example = ExampleObject("test")
    serialized = base64.b64encode(pickle.dumps(example)).decode('utf-8')
    
    return jsonify({"serialized": serialized})

@app.route('/check_server', methods=['GET', 'POST'])
@login_required
def check_server():
    # Vulnerability: Server-Side Request Forgery (SSRF) (CWE-918)
    if request.method == 'POST':
        server_url = request.form['url']
        try:
            import urllib.request
            response = urllib.request.urlopen(server_url)
            content = response.read().decode('utf-8')[:500]  # Limit response size
            return render_template('check_server.html', result=content)
        except Exception as e:
            return render_template('check_server.html', error=str(e))
    
    return render_template('check_server.html')

@app.route('/exec_command', methods=['GET', 'POST'])
def exec_command():
    # Vulnerability: Command Injection (CWE-78)
    if request.method == 'POST' and session.get('is_admin') == 1:
        command = request.form['command']
        try:
            # Extremely dangerous: directly executing user input as a command
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            return render_template('exec_command.html', output=output.decode('utf-8'))
        except subprocess.CalledProcessError as e:
            return render_template('exec_command.html', error=str(e), output=e.output.decode('utf-8'))
    
    if session.get('is_admin') != 1:
        return "Unauthorized", 403
    
    return render_template('exec_command.html')

@app.route('/process_xml', methods=['POST'])
@login_required
def process_xml():
    # Vulnerability: XML External Entity (XXE) Processing (CWE-611)
    xml_data = request.data.decode('utf-8')
    try:
        # Insecure parsing of XML
        root = ET.fromstring(xml_data)
        data = {}
        for child in root:
            data[child.tag] = child.text
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/xml_example')
def xml_example():
    example_xml = """<?xml version="1.0" encoding="UTF-8"?>
<root>
    <name>Test User</name>
    <email>test@example.com</email>
</root>"""
    return render_template('xml_example.html', example_xml=example_xml)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    # Vulnerability: Security Misconfiguration (No rate limiting, weak security questions)
    if request.method == 'POST':
        username = request.form['username']
        favorite_color = request.form['favorite_color']  # Weak security question
        new_password = request.form['new_password']
        
        conn = get_db()
        # This is just a simulation - in a real vulnerable app, this would actually change the password
        # But we'll just pretend it worked if the username exists
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        
        if user:
            # In a real app, this would actually check the answer and reset the password
            # We're just simulating the vulnerability without actually changing anything
            return render_template('reset_success.html', username=username)
        else:
            return render_template('reset_password.html', error="User not found")
    
    return render_template('reset_password.html')

@app.route('/api/parse_json', methods=['POST'])
def parse_json():
    # Vulnerability: Improper Input Validation (CWE-20)
    try:
        # No validation on the incoming data
        data = json.loads(request.data)
        return jsonify({"success": True, "data": data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

"""
New Routes and Analytics Dashboard for VulneraBlog
This code adds a post analytics dashboard and 5 new vulnerable endpoints to the application.
"""

# -----------------------------------------------------
# 1. Post Analytics Dashboard
# -----------------------------------------------------
@app.route('/analytics/dashboard')
@login_required
def analytics_dashboard():
    """
    Post analytics dashboard for users
    Vulnerability: Broken Access Control - Any user can view any other user's analytics 
    by manipulating the user_id parameter
    """
    # Vulnerability: IDOR (Insecure Direct Object Reference)
    user_id = request.args.get('user_id', session.get('user_id'))
    
    conn = get_db()
    # Get user details
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    
    if not user:
        conn.close()
        return "User not found", 404
    
    # Get posts statistics
    # Vulnerability: SQL Injection
    posts = conn.execute(f"SELECT * FROM posts WHERE author_id={user_id}").fetchall()
    
    # Check if views column exists before adding it
    try:
        # Try to query using the views column to check if it exists
        conn.execute("SELECT views FROM posts LIMIT 1")
    except sqlite3.OperationalError:
        # Column doesn't exist, so add it
        conn.execute("ALTER TABLE posts ADD COLUMN views INTEGER DEFAULT 0")
        conn.commit()
    
    # Get comments per post
    post_stats = []
    for post in posts:
        comments = conn.execute("SELECT COUNT(*) as comment_count FROM comments WHERE post_id=?", 
                             (post['id'],)).fetchone()
        
        # Update random view count for demonstration purposes
        # Fix: Access sqlite3.Row object correctly
        try:
            views = post['views']
            # If views is None, set a random value
            if views is None:
                views = random.randint(10, 1000)
                conn.execute("UPDATE posts SET views=? WHERE id=?", (views, post['id']))
                conn.commit()
        except (IndexError, KeyError):
            # If 'views' column doesn't exist in this row or is not accessible
            views = random.randint(10, 1000)
            conn.execute("UPDATE posts SET views=? WHERE id=?", (views, post['id']))
            conn.commit()
            
        post_stats.append({
            'id': post['id'],
            'title': post['title'],
            'views': views,
            'comments': comments['comment_count'],
            'is_public': post['is_public']
        })
    
    # Calculate total statistics
    total_posts = len(posts)
    total_views = sum(post['views'] for post in post_stats)
    total_comments = sum(post['comments'] for post in post_stats)
    
    conn.close()
    
    return render_template('analytics_dashboard.html', 
                          user=user,
                          post_stats=post_stats,
                          total_posts=total_posts,
                          total_views=total_views,
                          total_comments=total_comments)

# -----------------------------------------------------
# 2. Export User Data
# -----------------------------------------------------
@app.route('/export/user_data')
@login_required
def export_user_data():
    """
    Export user data
    Vulnerability: Server-Side Template Injection (SSTI)
    """
    user_id = session.get('user_id')
    format_type = request.args.get('format', 'json')
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    profile = conn.execute("SELECT * FROM user_profiles WHERE user_id=?", (user_id,)).fetchone()
    posts = conn.execute("SELECT * FROM posts WHERE author_id=?", (user_id,)).fetchall()
    conn.close()
    
    if not user:
        return "User not found", 404
    
    # Convert to dictionaries
    user_dict = dict(user)
    profile_dict = dict(profile) if profile else {}
    posts_list = [dict(post) for post in posts]
    
    # Prepare the data
    data = {
        'user': user_dict,
        'profile': profile_dict,
        'posts': posts_list
    }
    
    if format_type == 'json':
        return jsonify(data)
    elif format_type == 'html':
        # Vulnerability: Server-Side Template Injection (SSTI)
        # Using string formatting with user-provided template is dangerous
        template = request.args.get('template', '{{ user.username }}')
        from flask import render_template_string
        try:
            # Dangerous: renders a template string that can be manipulated by user
            return render_template_string(template, user=user_dict, profile=profile_dict, posts=posts_list)
        except Exception as e:
            return f"Template rendering error: {str(e)}"
    else:
        return "Unsupported format", 400

# -----------------------------------------------------
# 3. Bulk Update Posts
# -----------------------------------------------------
@app.route('/posts/bulk_update', methods=['POST'])
@login_required
def bulk_update_posts():
    """
    Bulk update post settings
    Vulnerability: Mass Assignment
    """
    user_id = session.get('user_id')
    
    # Vulnerability: No input validation or sanitization
    # This accepts and processes any JSON data sent in, allowing mass assignment
    data = request.get_json()
    
    if not data or 'posts' not in data:
        return jsonify({"error": "Invalid data format"}), 400
    
    conn = get_db()
    updated_count = 0
    
    for post_update in data['posts']:
        post_id = post_update.get('id')
        if not post_id:
            continue
            
        # Vulnerability: No ownership check, any user can update any post
        # Vulnerability: Mass Assignment - allowing any field to be updated
        
        # Build dynamic SQL update statement based on provided fields
        # This is vulnerable as it allows updating any field
        fields = []
        values = []
        
        for key, value in post_update.items():
            if key != 'id':
                fields.append(f"{key}=?")
                values.append(value)
        
        if fields:
            query = f"UPDATE posts SET {', '.join(fields)} WHERE id=?"
            values.append(post_id)
            
            conn.execute(query, values)
            updated_count += 1
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "updated": updated_count})

# -----------------------------------------------------
# 4. User Password Change
# -----------------------------------------------------
@app.route('/user/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    Change user password
    Vulnerability: Broken Authentication (weak password policies)
    """
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            return render_template('change_password.html', error="All fields are required")
        
        if new_password != confirm_password:
            return render_template('change_password.html', error="New passwords do not match")
            
        # Vulnerability: No password complexity requirements
        # Accepts any password, even "1" or "a"
        
        user_id = session.get('user_id')
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        
        if not user or user['password'] != current_password:
            conn.close()
            return render_template('change_password.html', error="Current password is incorrect")
        
        # Update password without any security checks
        conn.execute("UPDATE users SET password=? WHERE id=?", (new_password, user_id))
        conn.commit()
        conn.close()
        
        return redirect(url_for('dashboard', user_id=user_id))
    
    return render_template('change_password.html')

# -----------------------------------------------------
# 5. Post Import API
# -----------------------------------------------------
@app.route('/api/import/posts', methods=['POST'])
@login_required
def import_posts():
    """
    Import posts API
    Vulnerability: XML External Entity (XXE) Injection via XML import
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
        
    if not file.filename.endswith('.xml'):
        return jsonify({"error": "Only XML files are allowed"}), 400
    
    try:
        # Vulnerability: XXE Injection - XML parsing without disabling external entities
        import xml.etree.ElementTree as ET
        tree = ET.parse(file)
        root = tree.getroot()
        
        conn = get_db()
        user_id = session.get('user_id')
        imported_count = 0
        
        for post_elem in root.findall('post'):
            title = post_elem.findtext('title', '')
            content = post_elem.findtext('content', '')
            is_public = int(post_elem.findtext('is_public', '1'))
            
            conn.execute("INSERT INTO posts (title, content, author_id, is_public) VALUES (?, ?, ?, ?)",
                      (title, content, user_id, is_public))
            imported_count += 1
            
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "imported": imported_count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------------------------------
# 6. Direct File Include
# -----------------------------------------------------
@app.route('/template/view')
@login_required
def view_template():
    """
    View template files
    Vulnerability: Local File Inclusion (LFI)
    """
    # Vulnerability: Local File Inclusion
    template_name = request.args.get('name', 'default')
    
    try:
        # Extremely dangerous - direct file inclusion from user input
        with open(f"templates/{template_name}.html", 'r') as file:
            content = file.read()
        return render_template('view_template.html', template_name=template_name, content=content)
    except Exception as e:
        return f"Error loading template: {str(e)}", 404


@app.route('/reflected', methods=['GET'])
def reflected_xss():
    # Vulnerability: Reflected XSS (CWE-79)
    name = request.args.get('name', '')
    return render_template('reflected.html', name=name)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    # Vulnerability: Information Leakage (CWE-200)
    return render_template('404.html', path=request.path), 404

@app.errorhandler(500)
def server_error(e):
    # Vulnerability: Information Leakage through detailed error messages (CWE-200)
    return render_template('500.html', error=str(e)), 500

if __name__ == '__main__':
    # Vulnerability: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0', port=3000)
