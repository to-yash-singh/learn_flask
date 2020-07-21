from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, validators
from passlib.hash import sha256_crypt
from werkzeug import secure_filename
from collections import Counter
from functools import wraps
import os

app = Flask(__name__)
app.secret_key='flaskapp123'

app.config['UPLOAD_FOLDER'] = '/home/ubuntu/flaskapp/wordcount' 

# config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'User1ydsingh'
app.config['MYSQL_DB'] = 'flaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#init MySQL
mysql = MySQL(app)

#Index
@app.route('/')
def index():
	return render_template('home.html')

#About
@app.route('/about')
def about():
	return render_template('about.html')

#Register Form Class
class RegisterForm(Form):
	uname = StringField('Username', [validators.Length(min=4, max=50)])
	email = StringField('Email', [validators.Length(min=6, max=50)])
	fname = StringField('First Name', [validators.Length(min=1, max=25)])
	lname = StringField('Last Name', [validators.Length(min=1, max=25)])
	password = PasswordField('Password', [
		validators.DataRequired(),
		validators.EqualTo('confirm', message='Passwords do not match!')	
	])
	confirm = PasswordField('Confirm Password')

#User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		uname = form.uname.data
		email = form.email.data
		fname = form.fname.data
		lname = form.lname.data
		password = sha256_crypt.encrypt(str(form.password.data))

		#Create cursor
		cur = mysql.connection.cursor()

		#Execute query
		cur.execute("INSERT INTO users(uname, email, fname, lname, password) VALUES(%s, %s, %s, %s, %s)", (uname, email, fname, lname, password))

		#Commit to DB
		mysql.connection.commit()
		
		#Close connection
		cur.close()		

		flash('Sign-Up complete. You can now Log-In.', 'success')

		return redirect(url_for('login'))
	return render_template('register.html', form=form)

#User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		#Get Form Fields
		uname = request.form['Username']
		password_candidate = request.form['password']
		
		#Create cursor
		cur = mysql.connection.cursor()
		#Get user by username
		result = cur.execute("SELECT * FROM users WHERE uname = %s", [uname])

		if result > 0:
			#Get stored hash
			data = cur.fetchone()
			password = data['password']

			#Compare Passwords
			if sha256_crypt.verify(password_candidate, password):
				#Passed
				session['logged_in'] = True
				session['username'] = uname
				flash('You are now logged in.', 'success')
				return dashboard(uname)
			else:
				error = 'Invalid Login!'
				return render_template('login.html', error=error)

			#Close Connection
			cur.close()
		else:
			error = 'Username Not Found!'
			return render_template('login.html', error=error)

	return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash('Unauthorized Access! Please login to continue.', 'danger')
            		return redirect(url_for('login'))
	return wrap

#Logout
@app.route('/logout')
def logout():
	session.clear()
	flash('You are now logged out.', 'success')
	return redirect(url_for('login'))

@app.route('/uploader/<uname>', methods = ['GET','POST'])
def uploader(uname):
	if request.method == 'POST':
		f = request.files['file']
		if f.filename == '':
			return redirect(request.url)
		f.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename)))
		with open(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename)), 'r') as file:
			data = file.read().replace('\n', '')
		input_counter = Counter(data)
		response = []
		for letter, count in input_counter.most_common():
			response.append('"{}": {}'.format(letter, count))
		return '<br>'.join(response)
	else:
		flash('File not selected!', 'danger')
		return dashboard(uname)

#dashboard
@app.route('/dashboard/<uname>')
@is_logged_in
def dashboard(uname):
	cur = mysql.connection.cursor()
	# Get details
	result = cur.execute("SELECT * FROM users WHERE uname=%s",uname)

	articles = cur.fetchone()
	uname = articles['uname']
	fname = articles['fname']
	lname = articles['lname']
	email = articles['email']

        return render_template('dashboard.html',uname=uname,fname=fname,lname=lname,email=email)

if __name__ == '__main__':
	app.run(debug=True)
