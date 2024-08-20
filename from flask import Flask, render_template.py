from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Message
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/profile/<int:user_id>', methods=['GET', 'POST'])
@login_required
def profile(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        content = request.form.get('content')
        new_message = Message(sender_id=current_user.id, recipient_id=user_id, content=content)
        db.session.add(new_message)
        db.session.commit()
    messages = Message.query.filter_by(sender_id=current_user.id, recipient_id=user_id).all() + \
               Message.query.filter_by(sender_id=user_id, recipient_id=current_user.id).all()
    return render_template('profile.html', user=user, messages=messages)

@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        content = request.form.get('content')
        new_message = Message(sender_id=current_user.id, recipient_id=user_id, content=content)
        db.session.add(new_message)
        db.session.commit()
    messages = Message.query.filter_by(sender_id=current_user.id, recipient_id=user_id).all() + \
               Message.query.filter_by(sender_id=user_id, recipient_id=current_user.id).all()
    return render_template('chat.html', user=user, messages=messages)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
