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

########################### FUNCTIONS
def listOfUsers():
    user_lines = User.query.all()
    lines = []
    for i in range(0, len(user_lines)):
        line = [user_lines[i].id + 1000000000, user_lines[i].name,user_lines[i].email, user_lines[i].password, user_lines[i].question,user_lines[i].answer,user_lines[i].date_created]
        lines.append(line)
    return lines

########################### LOGIN MANAGER
@login_manager.user_loader
def load_user(email):
    accounts = listOfUsers()
    for i in range(0, len(listOfUsers)):
        if email == listOfUsers[i][2]:
            return User(listOfUsers[i][0], listOfUsers[i][1], listOfUsers[i][2], listOfUsers[i][3], listOfUsers[i][4], listOfUsers[i][5], listOfUsers[i][6])

def email_exists(email):
    accounts = listOfUsers()
    for i in range(0, len(accounts)):
        print(accounts[i])
        if email == accounts[i][2]:
            return True
    return False

def check_password(email, password):
    accounts = listOfUsers()
    for i in range(0, len(listOfUsers)):
        if email == listOfUsers[i][2]:
            if password == listOfUsers[i][3]:
                return True
            return False
    return False

########################### ACCOUNT
@app.route('/signup', methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        req = request.form
        name = req["name"]
        email = req.get("email")
        password = request.form["password"]
        question = request.form["question"]
        answer = request.form["answer"]
        salt = bcrypt.gensalt()
        password = bcrypt.hashpw(password.encode(), salt)
        user = User(name=name, email=email, password=password, question=question, answer=answer)
        db.session.add(user)
        db.session.commit()
        return redirect(request.url)
    return render_template("account/signup.html")

@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        req = request.form
        email = req.get("email")
        password = req["password"]
        salt = bcrypt.gensalt()
        password = bcrypt.hashpw(password.encode(), salt)
        accounts = listOfUsers()
        if email_exists(email):
            if check_password(email, password):
                user = load_user(email)
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