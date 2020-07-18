from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, IntegerField, TextAreaField
from wtforms.validators import InputRequired, Length, Optional, NumberRange
from flask_sqlalchemy  import SQLAlchemy
from sqlalchemy import exc
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import phonenumbers
import subprocess
import os
import re
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'b_5#y2_^+LF4Q8z#n$xec]/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database table
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(20))
    phone = db.Column(db.String(15), nullable=False)

class Queries(db.Model):
    __tablename__ = 'queries'
    QueryID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20))
    QueryText = db.Column(db.String(5000))
    QueryResult = db.Column(db.String(5000))

class Userlogs(db.Model):
    __tablename__ = 'userlogs'
    LogID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20))
    LogInTime = db.Column(db.DateTime)
    LogOutTime = db.Column(db.DateTime, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    uname = StringField('username', validators=[InputRequired(), Length(min=1)])
    pword = PasswordField('password', validators=[InputRequired(), Length(min=8)])
    phone = IntegerField('phone', validators=[Optional()], id='2fa')

class LoginForm(FlaskForm):
    uname = StringField('username', validators=[InputRequired(),Length(min=1)])
    pword = PasswordField('password', validators=[InputRequired(), Length(min=8)])
    phone = IntegerField('phone', validators=[Optional()], id='2fa')

class SpellcheckForm(FlaskForm):
    inputtext = TextAreaField('Input Text', id='inputtext')
    textout = TextAreaField('Output Text', id='textout')
    misspelled = TextAreaField('Misspelled Text', id='misspelled')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    outcome = ''
    if current_user.is_authenticated:
        return redirect(url_for('spell_check'))

    form = RegisterForm()

    if form.validate_on_submit():
        try:
            hashed_password = generate_password_hash(form.pword.data, method='pbkdf2:sha256', salt_length=8)
            new_user = User(username=form.uname.data, password=hashed_password, phone=form.phone.data)
            db.session.add(new_user)
            db.session.commit()
            # outcome = 'success'
            # return render_template('register.html', form=form, outcome=outcome)
            return redirect(url_for('login'))
        except exc.IntegrityError:
            db.session.rollback()
            outcome = 'failure: user exist'
            return render_template('register.html', form=form, outcome=outcome)
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    outcome = ''
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.uname.data).first()
        if user:
            if check_password_hash(user.password, form.pword.data):
                if (int((user.phone)) == form.phone.data):
                    # outcome = 'success'
                    datetimestamp = datetime.now()
                    login_user(user)
                    loginlogs = Userlogs(username=user.username, LogInTime=datetimestamp)
                    db.session.add(loginlogs)
                    db.session.commit()
                    # return render_template('login.html', form=form, outcome=outcome)
                    return redirect(url_for('spell_check'))
                else:
                    outcome = 'Two-factor failure'
                    return render_template('login.html', form=form, outcome=outcome)
            else:
                outcome = 'Incorrect'
                return render_template('login.html', form=form, outcome=outcome)
        else:
            outcome = 'Incorrect'
            return render_template('login.html', form=form, outcome=outcome)

    return render_template('login.html', form=form, outcome=outcome)

@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    if current_user.is_authenticated:
        form = SpellcheckForm()
        if form.validate_on_submit():
            inputtext = form.inputtext.data

            lines = inputtext.split('\n')
            f = open('check_words.txt', 'w')
            f.writelines(lines)
            f.close()

            p = subprocess.check_output(['./a.out', './check_words.txt', './wordlist.txt'])
            msg = p.decode('utf-8')
            msg = msg.replace('\n', ', ').strip().strip(',')
            
            textout = '\n'.join(lines)
            misspelled = msg
            # print(textout)
            # print(misspelled)
            queryhistory = Queries(username=current_user.username, QueryText=inputtext, QueryResult=misspelled)
            db.session.add(queryhistory)
            db.session.commit()
            return render_template('spellcheck.html', form=form, textout=textout, misspelled=misspelled)

        outcome = 'success'
        return render_template('spellcheck.html', form=form, outcome=outcome)

@app.route('/history', methods=['GET'])
@login_required
def history():
    if current_user.is_authenticated:
        if current_user.username == 'admin':
            allhistory = Queries.query.all()
        else:
            allhistory = Queries.query.filter_by(username=current_user.username)
        
        querycount = Queries.query.filter_by(username=current_user.username).count()
        
        return render_template('history.html', queryid=allhistory, querycount=querycount)

@app.route('/history/query<id>', methods=['GET'])
@login_required
def queryreview(id):
    if current_user.is_authenticated:
        if current_user.username == 'admin':
            queryreview = Queries.query.filter_by(QueryID = id).first()
        else:
            queryreview = Queries.query.filter_by(QueryID = id, username=current_user.username).first()
    
        return render_template('queryreview.html', queryreview=queryreview)

@app.route('/login_history', methods=['GET', 'POST'])
@login_required
def login_history():
    if current_user.is_authenticated:
        form = SpellcheckForm()
        if current_user.username == 'admin':
            return render_template('loginhistory.html', form=form)

        outcome = 'You are not admin'
        return render_template('spellcheck.html', form=form, outcome=outcome)

@app.route('/login_history_page', methods=['GET', 'POST'])
@login_required
def login_history_page():
    if current_user.is_authenticated:
        form = SpellcheckForm()
        if form.validate_on_submit():
            username = form.inputtext.data
            loginhistory = Userlogs.query.filter_by(username=username)

            return render_template('loginhistory.html', form=form, loginhistory=loginhistory)

        return render_template('loginhistory.html', form=form)


@app.route('/logout')
def logout():
    #datetimestamp = datetime.now()
    logout_user()
    return redirect(url_for('index'))

#if __name__ == '__main__':
#    app.run(debug=True)
