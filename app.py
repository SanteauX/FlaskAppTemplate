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


@login_manager.user_loader
def load_user(email):
    f = open('database/admin.csv')
    lines = f.readlines()
    line = lines[1].split(",")
    if line[0] == email:
        return True
    else:
        return False

########################### ROUTES

@app.route('/')
def default():
    return render_template("home.html")


######################### ERROR 404
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", home="/home.html")

######################### APP.RUN
if __name__ == '__main__':
    app.run(host="localhost", port=8000, debug=True)