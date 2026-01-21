from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- Configuración MUST be antes de instanciar SQLAlchemy/Bcrypt ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' # Usa SQLite para simplicidad
app.config['SECRET_KEY'] = 'your_secret_key'  # cambia por una clave real en producción

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

@app.route('/')
def home():
    return render_template("main.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template("login.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template("dashboard.html")


#
# codigo para leer el archivo
#
import os
import json
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import pymupdf

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20MB as per your HTML
ALLOWED_EXTENSIONS = {'pdf', 'epub'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ===== MAIN ROUTES =====

@app.route('/')
def index():
    """Home page - shows upload form"""
    return render_template('upload.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file upload (GET shows form, POST processes upload)"""
    if request.method == 'GET':
        # If someone visits /upload directly, redirect to home
        return redirect(url_for('index'))
    
    # Handle POST request
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    title = request.form.get('title', '')
    author = request.form.get('author', '')
    genre = request.form.get('genre', '')
    public = request.form.get('public', 'off')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        # Secure filename
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)
        
        # Create book metadata
        book_metadata = {
            'title': title or filename.rsplit('.', 1)[0],
            'author': author or 'Unknown',
            'genre': genre,
            'public': public,
            'filename': filename,
            'filepath': save_path,
            'uploaded_at': datetime.now().isoformat()
        }
        
        # Save metadata to JSON file
        metadata_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.meta.json")
        with open(metadata_path, 'w') as f:
            json.dump(book_metadata, f, indent=4)
        
        return jsonify({
            'success': True,
            'message': 'Book uploaded successfully',
            'filename': filename,
            'redirect': url_for('read_file', filename=filename)
        })
    
    return jsonify({'error': 'File type not allowed. Use PDF or EPUB.'}), 400

@app.route('/read/<filename>', methods=['GET'])
def read_file(filename):
    """Render the reading interface for the uploaded file"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    metadata_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.meta.json")
    
    # Load metadata if exists
    metadata = {}
    if os.path.exists(metadata_path):
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
    
    # Verify file exists
    if not os.path.exists(filepath):
        flash('File not found')
        return redirect(url_for('index'))
    
    # Determine file type and extract first page
    file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    first_page_text = ""
    total_pages = 0
    
    try:
        if file_ext in ['pdf', 'epub']:
            doc = pymupdf.open(filepath)
            total_pages = len(doc)
            
            # Get first page for preview
            if total_pages > 0:
                first_page = doc[0]
                first_page_text = first_page.get_text()
            
            doc.close()
    except Exception as e:
        flash(f'Error reading file: {str(e)}')
        return redirect(url_for('index'))
    
    return render_template('reader.html',
                           filename=filename,
                           metadata=metadata,
                           first_page=first_page_text[:500] + "..." if len(first_page_text) > 500 else first_page_text,
                           total_pages=total_pages,
                           file_type=file_ext.upper())

@app.route('/api/get_page/<filename>/<int:page>', methods=['GET'])
def get_page(filename, page):
    """API endpoint to get specific page content"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    page_index = max(0, page - 1)  # Convert to 0-index
    
    try:
        doc = pymupdf.open(filepath)
        total_pages = len(doc)
        
        if page_index >= total_pages:
            return jsonify({'error': 'Page out of range'}), 400
        
        page_content = doc[page_index].get_text()
        doc.close()
        
        return jsonify({
            'success': True,
            'page': page,
            'content': page_content,
            'total_pages': total_pages
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files (optional - for direct file access)"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/cancel', methods=['GET'])
def cancel():
    """Handle cancel action"""
    return redirect(url_for('index'))

# ===== ERROR HANDLERS =====

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Page not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed for this endpoint'}), 405

@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# ===== APPLICATION START =====

if __name__ == '__main__':
    app.run(debug=True, port=5000)