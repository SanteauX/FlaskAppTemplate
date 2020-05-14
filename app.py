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
    quesiton = db.Column(db.String(1000))
    answer = db.Column(db.String(1000))
    date_created = db.Column(db.DateTime, default=datetime.now)

########################### LOGIN MANAGER
@login_manager.user_loader
def load_user(email):
    f = open('database/admin.csv')
    lines = f.readlines()
    line = lines[1].split(",")
    if line[0] == email:
        return True
    else:
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
        answer = request.form["ansqer"]
        salt = bcrypt.gensalt()
        password = bcrypt.hashpw(form.password.data.encode(), salt)
        user = User(name=name, email=email, description=description)
        db.session.add(user)
        db.session.commit()
        return redirect(request.url)
    return render_template("account/signup.html")

@app.route('/login', methods=["POST", "GET"])
def login():
    return render_template("account/login.html")

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