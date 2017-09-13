from flask import Flask, render_template, request, redirect, flash, session
import os, binascii, re, md5
from mysqlconnection import MySQLConnector
app = Flask(__name__)
mysql = MySQLConnector(app,'mydb')

app.secret_key = "ThisIsSecret!2"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NO_NUM_REGEX = re.compile(r'.*[0-9]+.*')
PASSWORD_VALID_L_N_REGEX=re.compile(r'.*[A-Z]+.*\d+.*')
PASSWORD_VALID_N_L_REGEX=re.compile(r'.*\d+.*[A-Z].*')
ALL_LETTERS_REGEX = re.compile(r'[A-Za-z]+')

@app.route('/')
def index():
    session['logged_in']=False
    return render_template("index.html")

@app.route('/is_valid', methods=['POST'])
def isValid():

    print "Request form",request.form
    # check if we have content
    
    data = {
        'first_name':  request.form['first_name'],
        'last_name':  request.form['last_name'],
        'email': request.form['email'],
        'password': request.form['password'],
        'confirm_password': request.form['confirm_password']
    }
    # next step, let's go and salt and hash password later for storage
    flash_error = False

    # check for blank
    if len(data['first_name'])<=2:
        flash("First name doesn't have enough letters", "ERROR: invalid first name")
        flash_error = True
    else: # something there to check
        if not (ALL_LETTERS_REGEX.match(data['first_name'])):
            flash("First Name is not all letters", "ERROR: invalid entry")
            flash_error = True
    if len(data['last_name'])==0:
        flash("Last name doesn't have enough letters","ERROR: invalid last name")
        flash_error = True
    else: # something there to check
        if not (ALL_LETTERS_REGEX.match(data['last_name'])):
            flash("Last Name is not all letters", "ERROR: invalid entry")
            flash_error = True
    if len(data['password'])==0:
        flash("Password is blank","ERROR: blank entry")
        flash_error = True
    elif len(data['password'])<=8:
        flash("Password needs to be more than 8 characters", "ERROR: Invalid password")
        flash_error = True
    elif len(data['password']) >8:
        #check if the password and confirm password match
        if (data['password']!=data['confirm_password']):
            flash("Passwords do not match", "ERROR: Passwords do not match")
            flash_error = True
        # check if the password is valid
        if not (PASSWORD_VALID_L_N_REGEX.match(data['password'])) and not (PASSWORD_VALID_N_L_REGEX.match(data['password'])) :
            flash("Password needs at least one uppercase letter and number",'ERROR: Invalid password' )
            flash_error = True
    if len(data['confirm_password'])==0:
        flash("Confirm Password is blank","ERROR: blank entry")
        flash_error = True
    if len(data['email'])==0:
        flash("Email is blank","ERROR: blank entry")
        flash_error = True
    else:  # there is something there to check
        if not ( EMAIL_REGEX.match(data['email']) ):
            flash("invalid email", "ERROR: invalid entry")
            flash_error = True
    
    
    print "Any errors?: ", flash_error
    
    # no errors, so let's redirect to success
    if (flash_error == False):
        print "success!"
        salt = binascii.b2a_hex(os.urandom(15))
        hashed_pw = md5.new(data['password'] + salt).hexdigest()
        data['salt']= salt
         # here's the encrypted password
        data['password']=hashed_pw
        data['salt']=salt

        # My query to insert
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at, salt) VALUES (:first_name,:last_name, :email, :password, NOW(), NOW(), :salt)"
        mysql.query_db(query, data)
        print "Salt, hashed_password", salt, hashed_pw

        return redirect('/success')

    return redirect('/')

@app.route('/success')
def success():
    query = "SELECT * FROM users"                           
    my_users = mysql.query_db(query) 
    return render_template("success.html", all_data=my_users)

@app.route('/login', methods=['POST'])
def login():
    mydata = { 'email': request.form['email'],
               'password': request.form['password']}
    print "form", request.form
    query = "SELECT * FROM users WHERE email=:email"
    result =  mysql.query_db(query, mydata)

    print "result", result
    # no results
    if len(result)==0:
        flash("Login not found in our records", "ERROR: Record doesn't exist")
        return redirect('/') 
    # we assume we get only one result because only entry per email
    print "RESULT SALT", result[0]['salt']

    # test if the emails we have on file are the same
    test_password = md5.new(mydata['password'] + result[0]['salt']).hexdigest()
    if test_password == result[0]['password']:
        print "Passwords match"
        session['logged_in']=True
        return redirect('/success')
    else :
        print "FAIL"
        flash("Passwords do not match our records", "ERROR: incorrect password")
    
    return redirect('/')

app.run(debug=True)