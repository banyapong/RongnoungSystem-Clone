from flask import Flask, render_template, redirect, url_for, request, session, flash
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

class FlaskAppWrapper(object):
    def __init__(self, app, **configs):
        self.app = app
        self.configs(**configs)
    def configs(self, **configs):
        for config, value in configs.items():
            self.app.config[config.upper()] = value
    def add_endpoint(self, endpoint=None, endpoint_name=None, handler=None, methods=['GET'], *args, **kwargs):
        self.app.add_url_rule(endpoint, endpoint_name, handler, methods=methods, *args, **kwargs)
    def run(self, **kwargs):
        self.app.run(**kwargs)

flask_app = Flask(__name__)

app = FlaskAppWrapper(flask_app, SQLALCHEMY_DATABASE_URI='sqlite:///database.db', SECRET_KEY='GoldenEagle')
bcrypt = Bcrypt(flask_app)
db = SQLAlchemy(flask_app)

# Accounting Start -/
class Users(db.Model):
    _id = db.Column("user_id", db.Integer, primary_key=True)
    user_email = db.Column(db.String(360), unique=True, nullable=False)
    user_password = db.Column(db.String(255), nullable=False)
    user_is_admin = db.Column( db.Boolean, nullable=False, default=False)

    def __init__(self, user_email, user_password, user_is_admin):
        self.user_email = user_email
        self.user_password = user_password
        self.user_is_admin = user_is_admin

class RegisterForm(FlaskForm):
    user_email = EmailField(validators=[InputRequired()], render_kw={"placeholder":"Email"})
    user_password = PasswordField(validators=[InputRequired(), Length(min=8, max=64)], render_kw={"placeholder":"Password"})
    conf_password = PasswordField(validators=[InputRequired(), Length(min=8, max=64)], render_kw={"placeholder":"Confirm Password"})

    submit = SubmitField("Register")

    def validate_email(self, user_email):
        existing_user_email = Users.query.filter_by(user_email=user_email.data).first()
        if existing_user_email:
            raise ValidationError("Email already registered.")

class LoginForm(FlaskForm):
    user_email = StringField(validators=[InputRequired()], render_kw={"placeholder":"Email"})
    user_password = PasswordField(validators=[InputRequired(), Length(min=8, max=64)], render_kw={"placeholder":"Password"})

    submit = SubmitField("Login")
# /- Accounting End

# class movies(db.Model):
#     _id = db.Column("movie_id", db.Integer, primary_key=True)
#     movie_name = db.Column(db.String(255), unique=True)
#     movie_length = db.Column(db.Integer)

#     def __init__(self, movie_name, movie_length):
#         self.movie_name = movie_name
#         self.movie_length = movie_length

# class movie_imgs(db.Model):
#     _id = db.Column("movie_id", db.Integer, primary_key=True)
#     img = db.Column(db.Text, unique=True, nullable=False)
#     mimetype = db.Column(db.Text, nullable=False)
#     movie_id = db.Column(db.Integer, unique=True, nullable=False)

#     def __init__(self, img, mimetype, movie_id):
#         self.img = img
#         self.mimetype = mimetype
#         self.movie_id = movie_id

# class theaters(db.Model):
#     _id = db.Column("theaters_id", db.Integer, primary_key=True)
#     seat_amount = db.Column(db.Integer)

#     def __init__(self, seat_amount):
#         self.seat_amount = seat_amount

def index():
    return redirect('home')
def home():
    return render_template('home.html')

# Accounting
def login():
    form = LoginForm()
    return render_template('login.html', form=form)
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.user_password.data)
        new_user = Users(user_email=form.user_email.data, user_password=hashed_password, user_is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        flash("Register complete")
        return redirect(url_for('login'))
    else:
        flash("Not complete")
    return render_template('register.html', form = form)
def logout():
    return render_template('login.html')

app.add_endpoint('/', 'index', index, methods=['GET'])
app.add_endpoint('/home', 'home', home, methods=['GET'])
app.add_endpoint('/register', 'register', register, methods=['GET','POST'])
app.add_endpoint('/login', 'login', login, methods=['GET','POST'])
app.add_endpoint('/logout', 'logout', logout, methods=['GET'])

if __name__ == "__main__":
    with flask_app.app_context():
        db.create_all()
    app.run(debug=True)