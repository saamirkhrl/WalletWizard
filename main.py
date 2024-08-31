from flask import Flask, redirect, url_for, flash, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, logout_user, login_user, UserMixin, current_user, login_required
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from werkzeug.security import check_password_hash, generate_password_hash
import string
import random
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(150)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    wallet = db.Column(db.String(), unique=True)
    cash = db.Column(db.Integer, default=500)

    def __repr__(self):
        return f'ID: {self.id}, Username: {self.username}, Password: {self.password}, Cash: {self.cash}, Wallet: {self.wallet}'

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField('Username', render_kw={'placeholder': "Choose a username.."})
    password = PasswordField('Password', render_kw={'placeholder': "Choose a strong password.."})
    password2 = PasswordField('Confirm Password', render_kw={'placeholder': "Re-type your chosen password.."})
    submit = SubmitField('Sign up!')

class LoginForm(FlaskForm):
    username = StringField('Username', render_kw={'placeholder': "Enter your username.."})
    password = PasswordField('Password', render_kw={'placeholder': "Enter your password.."})
    submit = SubmitField('Login!')

class SendForm(FlaskForm):
    amount = IntegerField('Amount', render_kw={'placeholder': 'How much would you like to send?'}, default=0)
    wallet = StringField('Wallet', render_kw={'placeholder': "Enter your recipient's walet"})
    password = PasswordField('Password', render_kw={'placeholder': 'Enter your password to send money'})
    submit = SubmitField('Send!')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
     if form.validate_on_submit():
          username = request.form.get('username')
          password = request.form.get('password')
          password2 = request.form.get('password2')

          is_user = User.query.filter_by(username=username).first()

          if is_user:
               flash('User already exists, try again','danger')
          elif password != password2:
               flash('Both passwords must match.','danger')
          else:
               cash=500
               wallet = '$'+''.join(random.choices(string.ascii_uppercase + string.digits, k=35))
               hashed_password = generate_password_hash(password)
               new_user = User(username=username, password=hashed_password, cash=cash, wallet=wallet)
               db.session.add(new_user)
               db.session.commit()
               flash('Created account! Redirecting to login page now.','success')
               return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = request.form.get('username')
            password = request.form.get('password')

            if User.query.filter_by(username=username).first() and check_password_hash(User.query.filter_by(username=username).first().password, password):
                login_user(User.query.filter_by(username=username).first())
                flash('Logged in succesfully','success')
                return redirect(url_for('home'))
            else:
                flash('Wrong password or username. Try again, or create a new account','danger')
                return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/home', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    form = SendForm()
    user = User.query.get(current_user.id)
    if request.method == 'POST':
        if form.validate_on_submit():
            amount = int(request.form.get('amount'))
            recipient_wallet = request.form.get('wallet')
            password = request.form.get('password')
            recipient = User.query.filter_by(wallet=recipient_wallet).first()
            sender_pass = current_user
            current_user_password = check_password_hash(sender_pass.password, password)

            if amount < 1:
                flash('Amount cannot be less than $1','danger')
                return redirect(url_for('home'))
            elif not current_user_password:
                flash('Wrong password, try again','danger')
                return redirect(url_for('home'))
            elif not recipient:
                flash('That wallet does not exist, try again carefully','danger')
                return redirect(url_for('home'))
            elif current_user.cash < amount:
                flash('You cant send more than you have','danger')
            elif current_user.wallet == recipient_wallet:
                flash('You cannot send your self money','danger')
            else:
                recipient.cash += amount
                current_user.cash -= amount
                db.session.commit()
                flash(f'Sent {recipient.username} ${amount}','success')
                return redirect(url_for('home'))

    return render_template('home.html', user=user, form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully','success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
