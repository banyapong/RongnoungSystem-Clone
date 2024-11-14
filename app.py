from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from datetime import datetime
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)
app.secret_key = 'secret'

server = 'cdex-server.database.windows.net'  # Replace with your server name
database = 'cdex-db'                    # Replace with your database name
username = 'cdex-admin'                         # Replace with your database username
password = '$D1nKxRwOGMQf8Mf'                         # Replace with your database password
driver = 'ODBC Driver 18 for SQL Server'

app.config['SQLALCHEMY_DATABASE_URI'] = f'mssql+pyodbc://{username}:{password}@{server}/{database}?driver={driver}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Database model
class User(db.Model):
    _id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)

class Email(db.Model):
    _id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(100), nullable=False)
    recipient = db.Column(db.String(100), nullable=False)  # Link to User model
    subject = db.Column(db.String(200), nullable=False)
    date = db.Column(db.Date, nullable=False)
    body = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='draft')

    def __repr__(self):
        return f'<Email {self.subject}>'

@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return render_template('user.html', user=user)  # Pass the user object to the template
    return render_template('login.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        session.permanent = True
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session.permanent = True
            session['user_id'] = user._id
            flash('Login Successful', 'success')
            return redirect(url_for('user', id=user._id))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
    else:
        if 'user_id' in session:
            return redirect(url_for('user', id=session['user_id']))
        return render_template('login.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        
        # Validate email format
        try:
            # This will raise an exception if the email is not valid
            validate_email(email)
        except EmailNotValidError as e:
            flash(f"Invalid email address: {e}", 'danger')
            return redirect(url_for('register'))  # Redirect to register page if email is invalid
        
        # Check if password matches
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email address already registered', 'danger')
            return redirect(url_for('register'))

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('register'))

        # Hash the password and save the new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            firstname=firstname,
            lastname=lastname
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration Successful.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/user/<int:id>', methods=['GET'])
def user(id):
    print(f"Session user_id: {session.get('user_id')}")
    if 'user_id' not in session:  # Check if the user is logged in
        flash('You must be logged in to view this page', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(id)
    if user:
        # Get the received emails for the user
        received_emails = Email.query.filter_by(recipient=user.email).all()
        return render_template('user.html', user=user, emails=received_emails)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('index'))  # Redirect to the homepage

@app.route('/logout')
def logout():
    flash('You have been logged out.')
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/compose', methods=['GET', 'POST'])
def compose_email():
    if 'user_id' not in session:
        flash('You must be logged in to compose an email', 'danger')
        return redirect(url_for('login'))
    
    # Retrieve the logged-in user's information
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        recipient = request.form['recipient']
        subject = request.form['subject']
        body = request.form['body']
        
        # Check if the recipient email exists in the User table
        recipient_user = User.query.filter_by(email=recipient).first()
        
        if not recipient_user:
            flash('Recipient email not found. Please check the email address and try again.', 'danger')
            return redirect(url_for('compose_email'))  # Redirect back to the compose email page
        
        # If recipient exists, send the email
        new_email = Email(sender=user.email, recipient=recipient, subject=subject, body=body, date=datetime.utcnow())
        db.session.add(new_email)
        db.session.commit()
        flash('Email sent successfully!', 'success')
    
    return render_template('compose_email.html', user=user)



@app.route('/email/<int:email_id>', methods=['GET'])
def view_email(email_id):
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You must be logged in to view the email', 'danger')
        return redirect(url_for('login'))

    # Get the logged-in user's object
    user = User.query.get(session['user_id'])

    # Query the specific email by ID
    email = Email.query.get(email_id)

    # Check if the email exists and if the user is the recipient
    if email and email.recipient == user.email:
        # Render the email details page with the email and user info
        return render_template('view_email.html', email=email, user=user)
    else:
        flash('Email not found or you do not have permission to view it', 'danger')
        return redirect(url_for('user', id=session['user_id']))  # Redirect to inbox
    
@app.route('/email/delete/<int:email_id>', methods=['POST'])
def delete_email(email_id):
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You must be logged in to delete the email', 'danger')
        return redirect(url_for('login'))

    # Get the logged-in user's object
    user = User.query.get(session['user_id'])

    # Query the specific email by ID
    email = Email.query.get(email_id)

    # Check if the email exists and if the user is the recipient
    if email and email.recipient == user.email:
        db.session.delete(email)  # Delete the email
        db.session.commit()  # Commit the transaction
        flash('Email deleted successfully', 'success')
    else:
        flash('Email not found or you do not have permission to delete it', 'danger')

    return redirect(url_for('user', id=session['user_id']))  # Redirect back to the inbox

@app.route('/delete_multiple_emails', methods=['POST'])
def delete_multiple_emails():
    if 'user_id' not in session:
        flash('You must be logged in to delete emails', 'danger')
        return redirect(url_for('login'))

    selected_emails = request.form.getlist('email_ids')
    if selected_emails:
        user = User.query.get(session['user_id'])
        
        # For debugging: print selected email IDs and user email
        print("Selected emails for deletion:", selected_emails)
        print("Current user email:", user.email)

        # Delete only emails that match the selected IDs and belong to the user
        emails_to_delete = Email.query.filter(
            Email._id.in_(selected_emails),
            Email.recipient == user.email
        ).all()

        # For debugging: check the emails retrieved
        print("Emails to delete:", emails_to_delete)

        if emails_to_delete:
            for email in emails_to_delete:
                db.session.delete(email)
            db.session.commit()
            flash(f'{len(emails_to_delete)} email(s) deleted successfully', 'success')
        else:
            flash('No emails found to delete', 'warning')
    else:
        flash('No emails selected for deletion', 'warning')

    return redirect(url_for('user', id=session['user_id']))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=8080)