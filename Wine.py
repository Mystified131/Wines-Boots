from flask import Flask, request, render_template, session, redirect, flash
from flask_sqlalchemy import SQLAlchemy
import datetime, os, cgi, hashlib, random

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://Wine:Jackson1313@localhost:8889/Wine'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)
app.secret_key = os.urandom(24)

class Wine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(120))
    name = db.Column(db.String(120))
    description = db.Column(db.String(120))

    def __init__(self, timestamp, name, description):
        self.timestamp = timestamp
        self.name = name
        self.description = description

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    password = db.Column(db.String(120))

    def __init__(self, email, password):
        self.email = email
        self.password = password

def make_salt():
    sal = ""
    for elem in range(5):
        num1 = random.randrange(9)
        num2 = str(num1)
        sal += num2
    return sal
    
def make_pw_hash(password):
    hash = hashlib.sha256(str.encode(password)).hexdigest()
    return hash

def check_pw_hash(password, hash):
    hash2 = hash[5:]
    if make_pw_hash(password) == hash2:
        return True
    else:
        return False

@app.before_request
def require_login():
    allowed_routes = ['login', 'signup']
    if request.endpoint not in allowed_routes and 'email' not in session:
        return redirect('/login')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_pw_hash(password, user.password):
            session['email'] = email
            #flash("Logged in")
            return redirect('/wine')
        elif not user:
            flash("User does not exist")
            return redirect('/signup')
        else:
            flash('User password incorrect')
    return render_template('login.html')

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        verify = request.form['verify']
        if not email or not password or not verify:
            flash("Please fill in all form spaces")
            return redirect('/signup')
        if password != verify:
            flash("Password and Password Verify fields do not match")
            return redirect('/signup')
        existing_user = User.query.filter_by(email=email).first()
        if not existing_user:
            salt = make_salt()
            hash = make_pw_hash(password)
            password = salt + hash
            new_user = User(email, password)
            db.session.add(new_user)
            db.session.commit()
            session['email'] = email
            flash("Signed In")
            return redirect('/wine')
        else:
            flash('Duplicate User')
            return redirect('/signup')

    return render_template('signup.html')

@app.route('/logout')
def logout():
    del session['email']
    return redirect('/login')

@app.route("/wine", methods =['GET', 'POST'])
def index():
    right_now = datetime.datetime.now().isoformat()
    list = []

    for i in right_now:
        if i.isnumeric():
           list.append(i)

    tim = "".join(list)
    session['timestamp'] = tim
    wines = Wine.query.all()
    winelist = []
    for wine in wines:
        winestr = wine.name + ": " + wine.description
        winelist.append(winestr)
    winelist.sort()
    return render_template('index.html', wines = winelist)

@app.route("/login", methods =['GET', 'POST'])
def frontpage():
    return render_template('login.html')

@app.route("/add", methods =['GET', 'POST'])
def add():
    error = ""
    winename = request.form["name"]
    winedescript = request.form["descript"]
    timestamp = session['timestamp']
    name = cgi.escape(winename)
    name = name.lower()
    description = cgi.escape(winedescript)
    old_wine = Wine.query.filter_by(name=name).first()
    if old_wine or not name or not description:
        if not description:
            error = "Please describe the wine, in order to add it."
        if not name:
            error = "There is no wine with no name."
        if old_wine:
            error = "That wine is already in the database."
        wines = Wine.query.all()
        winelist = []
        for wine in wines:
            winestr = wine.name + ": " + wine.description
            winelist.append(winestr)
        winelist.sort()
        return render_template('index.html', wines = winelist, error = error)
    new_wine = Wine(timestamp, name, description)
    db.session.add(new_wine)
    db.session.commit()
    wines = Wine.query.all()
    winelist = []
    for wine in wines:
        winestr = wine.name + ": " + wine.description
        winelist.append(winestr)
    winelist.sort()
    return render_template('index.html', wines = winelist)

@app.route("/remove", methods =['GET', 'POST'])
def remove():
    winename = request.form["remname"]
    name = cgi.escape(winename)
    the_wine = Wine.query.filter_by(name=name).first()
    if the_wine:
        db.session.delete(the_wine)
        db.session.commit()
        wines = Wine.query.all()
        winelist = []
        for wine in wines:
            winestr = wine.name + ": " + wine.description
            winelist.append(winestr)
        winelist.sort()
        return render_template('index.html', wines = winelist)
    else:
        error2 = "That wine is not in the database."
        wines = Wine.query.all()
        winelist = []
        for wine in wines:
            winestr = wine.name + ": " + wine.description
            winelist.append(winestr)
        winelist.sort()
        return render_template('index.html', wines = winelist, error2 = error2)

## THE GHOST OF THE SHADOW ##

if __name__ == '__main__':
    app.run()



