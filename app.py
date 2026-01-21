from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, send_from_directory
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
        else:
            flash('Usuario o contraseña incorrectos', 'error')
    else:
        if request.method == 'POST':
            flash('Por favor completa el formulario correctamente.', 'error')

    return render_template("login.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # El archivo de plantilla en templates/ está nombrado `dahsboard.html` (typo).
    # Usamos el nombre existente para evitar TemplateNotFound.
    return render_template("dahsboard.html")


#
# codigo para leer el archivo
#
import os
import json
from datetime import datetime
import pymupdf

app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20MB
ALLOWED_EXTENSIONS = {'pdf', 'epub'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ===== ROUTES =====

@app.route('/upload', methods=['GET'])
def index():
    """Home page - shows upload form"""
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload"""
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
        
        # Extract basic metadata from file
        try:
            doc = pymupdf.open(save_path)
            total_pages = len(doc)
            doc.close()
        except:
            total_pages = 0
        
        # Create book metadata
        book_metadata = {
            'title': title or filename.rsplit('.', 1)[0],
            'author': author or 'Unknown',
            'genre': genre,
            'public': public,
            'filename': filename,
            'total_pages': total_pages,
            'uploaded_at': datetime.now().isoformat(),
            'current_page': 1,
            'progress': 0
        }
        
        # Save metadata to JSON file
        metadata_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.meta.json")
        with open(metadata_path, 'w') as f:
            json.dump(book_metadata, f, indent=4, default=str)
        
        return jsonify({
            'success': True,
            'message': 'Book uploaded successfully',
            'filename': filename,
            'redirect': url_for('reader', filename=filename)
        })
    
    return jsonify({'error': 'File type not allowed. Use PDF or EPUB.'}), 400

@app.route('/reader/<filename>')
def reader(filename):
    """Render the beautiful reader interface"""
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
    
    # Get current page from metadata or default to 1
    current_page = metadata.get('current_page', 1)
    
    # Get page content
    content = ""
    total_pages = 0
    
    try:
        if filename.lower().endswith(('.pdf', '.epub')):
            doc = pymupdf.open(filepath)
            total_pages = len(doc)
            
            # Get the current page content
            if 1 <= current_page <= total_pages:
                page = doc[current_page - 1]  # 0-indexed
                content = page.get_text()
            else:
                # If invalid page, get first page
                page = doc[0]
                content = page.get_text()
                current_page = 1
            
            # Update metadata with total pages
            metadata['total_pages'] = total_pages
            doc.close()
    except Exception as e:
        flash(f'Error reading file: {str(e)}')
        return redirect(url_for('index'))
    
    # Update progress
    progress = int((current_page / total_pages) * 100) if total_pages > 0 else 0
    metadata['progress'] = progress
    metadata['current_page'] = current_page
    
    # Save updated metadata
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=4, default=str)
    
    return render_template('reader.html',
                           filename=filename,
                           metadata=metadata,
                           content=content,
                           current_page=current_page,
                           total_pages=total_pages,
                           progress=progress)

@app.route('/api/page/<filename>/<int:page_number>')
def get_page(filename, page_number):
    """API endpoint to get specific page content"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    metadata_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.meta.json")
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        doc = pymupdf.open(filepath)
        total_pages = len(doc)
        
        # Validate page number
        if page_number < 1:
            page_number = 1
        elif page_number > total_pages:
            page_number = total_pages
        
        # Get page content
        page = doc[page_number - 1]  # 0-indexed
        content = page.get_text()
        doc.close()
        
        # Load and update metadata
        metadata = {}
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
        
        # Update current page and progress
        metadata['current_page'] = page_number
        metadata['progress'] = int((page_number / total_pages) * 100) if total_pages > 0 else 0
        
        # Save updated metadata
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=4, default=str)
        
        return jsonify({
            'success': True,
            'content': content,
            'page_number': page_number,
            'total_pages': total_pages,
            'progress': metadata['progress'],
            'metadata': metadata
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/toc/<filename>')
def get_toc(filename):
    """Get table of contents for EPUB files"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        if filename.lower().endswith('.epub'):
            # For EPUB files, try to get TOC
            doc = pymupdf.open(filepath)
            toc = doc.get_toc()
            doc.close()
            
            # Format TOC entries
            formatted_toc = []
            for entry in toc:
                level, title, page = entry
                formatted_toc.append({
                    'level': level,
                    'title': title,
                    'page': page
                })
            
            return jsonify({
                'success': True,
                'toc': formatted_toc
            })
        else:
            # For PDF files, generate a simple TOC based on page numbers
            doc = pymupdf.open(filepath)
            total_pages = len(doc)
            doc.close()
            
            # Generate simple TOC (every 10 pages)
            toc = []
            for page_num in range(1, total_pages + 1, 10):
                toc.append({
                    'level': 1,
                    'title': f'Page {page_num}',
                    'page': page_num
                })
            
            return jsonify({
                'success': True,
                'toc': toc
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/save_progress/<filename>', methods=['POST'])
def save_progress(filename):
    """Save reading progress (bookmark)"""
    metadata_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.meta.json")
    
    if not os.path.exists(metadata_path):
        return jsonify({'error': 'Book not found'}), 404
    
    try:
        data = request.get_json()
        current_page = data.get('current_page', 1)
        
        # Load existing metadata
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Update progress
        metadata['current_page'] = current_page
        metadata['last_read'] = datetime.now().isoformat()
        
        # Save updated metadata
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=4, default=str)
        
        return jsonify({'success': True, 'message': 'Progress saved'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/library')
def library():
    """Show user's library of uploaded books"""
    library_books = []
    
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            if filename.endswith('.meta.json'):
                metadata_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                    
                    # Check if the actual file exists
                    book_filename = metadata.get('filename')
                    book_path = os.path.join(app.config['UPLOAD_FOLDER'], book_filename)
                    
                    if os.path.exists(book_path):
                        library_books.append(metadata)
                        
                except Exception as e:
                    print(f"Error loading metadata for {filename}: {e}")
    
    return render_template('library.html', books=library_books)

# ===== STATIC FILES =====

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.errorhandler(404)
def not_found(error):
    return redirect(url_for('home'))

@app.errorhandler(500)
def server_error(error):
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)