from flask import Flask, render_template, request, redirect, flash, session
import re

app = Flask(__name__)

app.secret_key = "ThisIsSecret!2"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NO_NUM_REGEX = re.compile(r'.*[0-9]+.*')
PASSWORD_VALID_L_N_REGEX=re.compile(r'.*[A-Z]+.*\d+.*')
PASSWORD_VALID_N_L_REGEX=re.compile(r'.*\d+.*[A-Z].*')

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/is_valid', methods=['POST'])
def isValid():

    print "Request form",request.form
    # check if we have content
    
    session.clear()

    session['first_name'] = request.form['first_name']
    session['last_name'] = request.form['last_name']
    session['password'] = request.form['password']
    session['confirm_password']=request.form['confirm_password']
    session['email']=request.form['email']

    # check for blank
    if len(session['first_name'])==0:
        flash("First name is blank", "ERROR: blank entry")
    else: # something there to check
        if (NO_NUM_REGEX.match(session['first_name'])):
            flash("First Name has numbers", "ERROR: invalid entry")
    if len(session['last_name'])==0:
        flash("Last name is blank","ERROR: blank entry")
    else: # something there to check
        if (NO_NUM_REGEX.match(session['last_name'])):
            flash("Last Name has numbers", "ERROR: invalid entry")

    if len(session['password'])==0:
        flash("Password is blank","ERROR: blank entry")
    elif len(session['password'])<=8:
        flash("Password needs to be more than 8 characters", "ERROR: Invalid password")
    elif len(session['password']) >8:
        #check if the password and confirm password match
        if (session['password']!=session['confirm_password']):
            flash("Passwords do not match", "ERROR: Passwords do not match")

        # check if the password is valid
        if not (PASSWORD_VALID_L_N_REGEX.match(session['password'])) and not (PASSWORD_VALID_N_L_REGEX.match(session['password'])) :
            flash("Password needs at least one uppercase letter and number",'ERROR: Invalid password' )
    if len(session['confirm_password'])==0:
        flash("Confirm Password is blank","ERROR: blank entry")
    if len(session['email'])==0:
        flash("Email is blank","ERROR: blank entry")
    else:  # there is something there to check
        if not ( EMAIL_REGEX.match(session['email']) ):
            flash("invalid email", "ERROR: invalid entry")

    
    return redirect('/')



app.run(debug=True)