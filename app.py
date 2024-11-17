from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sumanth'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://keratoconus_owner:qvmlDYL5uPp1@ep-lucky-cherry-a8rvw356.eastus2.azure.neon.tech/keratoconus?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'users'  # Change table name to 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)  # Store date of birth
    phone = db.Column(db.String(20), nullable=False)  # Add phone number
    password = db.Column(db.String(60), nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        date_of_birth = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d')  # Parse date of birth
        phone = request.form['phone']  # Get phone number
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        
        user = User(name=name, email=email, date_of_birth=date_of_birth, phone=phone, password=password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Your account has been created!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    today = datetime.today()
    age = today.year - current_user.date_of_birth.year - ((today.month, today.day) < (current_user.date_of_birth.month, current_user.date_of_birth.day))
    return render_template('dashboard.html', age=age)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        # db.drop_all()  
        db.create_all()  # Create database tables for all models
    app.run(debug=True)