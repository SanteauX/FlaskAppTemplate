# -*- coding: utf-8 -*-
import os
import bcrypt
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from flask import Flask, session, render_template, request, url_for, redirect, flash, request
from wtforms import Form, fields,TextField, StringField, PasswordField, BooleanField,validators
from wtforms.validators import InputRequired, Email, Length, DataRequired
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

########################### CONFIG
app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config['USE_SESSION_FOR_NEXT'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///db.sqlite3'
db = SQLAlchemy(app)

########################### LOGIN CONFIG
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

########################### CLASSES
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    password = db.Column(db.String(1000))
    question = db.Column(db.String(1000))
    answer = db.Column(db.String(1000))
    date_created = db.Column(db.DateTime, default=datetime.now)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    picture = db.Column(db.String(50))
    description = db.Column(db.String(1000))
    date_created = db.Column(db.DateTime, default=datetime.now)

class LoginForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField("password", validators=[InputRequired(), Length(max=80)])

########################### FUNCTIONS
def listOfUsers():
    user_lines = User.query.all()
    lines = []
    for i in range(0, len(user_lines)):
        line = [user_lines[i].id, user_lines[i].name,user_lines[i].email, user_lines[i].password, user_lines[i].question,user_lines[i].answer,user_lines[i].date_created]
        lines.append(line)
    return lines

########################### LOGIN MANAGER
@login_manager.user_loader
def load_user(email):
    accounts = listOfUsers()
    for i in range(0, len(accounts)):
        if email == accounts[i][2]:
            user = User(accounts[i][1], accounts[i][2], accounts[i][3], accounts[i][4], accounts[i][5])
            return user

def email_exists(email):
    accounts = listOfUsers()
    for i in range(0, len(accounts)):
        if email == accounts[i][2]:
            return True
    return False

def check_password(email, password):
    accounts = listOfUsers()
    for i in range(0, len(accounts)):
        if email == accounts[i][2]:
            if password == accounts[i][3]:
                print("password true")
                return True
            print("password false")
            return False
    print("account not found with email")
    return False

########################### CREATE USER FROM FORM
def create_user(req):
    name = req["name"]
    email = req.get("email")
    password = request.form["password"]
    question = request.form["question"]
    answer = request.form["answer"]
    salt = bcrypt.gensalt()
    password = bcrypt.hashpw(password.encode(), salt)
    user = User(name=name, email=email, password=password, question=question, answer=answer)
    return user

########################### ACCOUNT
@app.route('/signup', methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        user = create_user(request.form)
        db.session.add(user)
        db.session.commit()
        return redirect(request.url)
    return render_template("account/signup.html")

@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        if email_exists(email):
            user = load_user(email)
            session['name'] = user.name
            if bcrypt.checkpw(form.password.data.encode(), user.password.encode()):
                login_user(user)
                return redirect('account', name=user.name)
    return render_template('account/login.html')

########################### ROUTES
@app.route('/')
def default():
    return render_template("others/home.html")

@app.route('/upload', methods=["POST", "GET"])
def upload():
    form = Upload()
    if request.method == "POST":
        req = request.form
        title = req["title"]
        description = req["description"]
        print(req)
        if request.files:
            if allowed_image_filesize(request.cookies.get("filesize")):
                print("ERROR: File exceeded maximum size")
                return redirect(request.url)
            print(request.cookies)
            image = request.files["image"]
            if image.filename=="":
                print("ERROR: Image must have a name")
                return redirect(request.url)
            if not allowed_image(image.filename):
                print("ERROR: That image extension is not allowed")
                return redirect(request.url)
            else:
                filename = secure_filename(image.filename)
            image.save(os.path.join(app.config["IMAGE_UPLOADS"], filename))
            #print(image)
            project = Project(title=title, picture=filename, description=description)
            db.session.add(project)
            db.session.commit()
            return redirect(request.url)
    return render_template('others/upload.html', form = form)

######################### ERROR 404
@app.errorhandler(404)
def not_found(e):
    return render_template("others/404.html", home="/home.html")

######################### APP.RUN
if __name__ == '__main__':
    app.run(host="localhost", port=8000, debug=True)