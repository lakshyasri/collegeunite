from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm, Form
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SubmitField, IntegerField, FloatField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Message, Mail

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
mail = Mail()
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = 'lakshyasrivastava007@gmail.com'
app.config["MAIL_PASSWORD"] = ''

mail.init_app(app)

Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Loginpage(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Loginpage()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if user.password == form.password.data:
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
        return '<h1> invalid</h1>'
    return render_template('login.html', form=form)



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        new_user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()

        return '<h1> hi newbie</h1>'

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


class ContactForm(Form):
    name = StringField("Name", validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField("Email", validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    subject = StringField("Subject", validators=[InputRequired(), Length(min=4, max=15)])
    message = TextAreaField("Message", validators=[InputRequired(), Length(min=4, max=15)])
    submit = SubmitField("Send")


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()

    if request.method == 'POST':
        if form.validate() == False:
            flash('All fields are required.')
            return render_template('contact.html', form=form)
        else:
            msg = Message(form.subject.data, sender='lakshyasrivastava007@gmail.com',
                          recipients=['lakshyasri@outlook.com'])
            msg.body = """
      From: %s &lt;%s&gt;
      %s
      """ % (form.name.data, form.email.data, form.message.data)
            mail.send(msg)

            return render_template('contact.html', success=True)

    elif request.method == 'GET':
        return render_template('contact.html', form=form)


class postingForm(Form):
    Job_Title = StringField("Job title", validators=[InputRequired(), Length(min = 5, max = 20)])
    Job_Description = TextAreaField("Job Description", validators=[InputRequired(), Length(min = 15, max = 100)])
    Job_Address = StringField("Job Address", validators=[InputRequired(), Length(min=15, max=50)])
    Job_Duration = FloatField("Job Duration", validators=[InputRequired()])
    Job_Pay = FloatField("Job Pay", validators=[InputRequired()])
    Opening = IntegerField("Openings", validators=[InputRequired()])
    Job_Requirements = TextAreaField("Job_Requirements")
    submit = SubmitField("Send")


@app.route('/posting', methods=['GET','POST'])
def posting():

    form = postingForm()

    if request.method =='POST':
        if form.validate() == False:
            flash('All fields are required')
            return render_template('posting.html')
        else:
            msg = Message(form.Job_Title.data, sender='lakshyasrivastava007@gmail.com', recipients=['lakshyasri@outlook.com'])
            msg.body = f"""
        From: {form.Job_Title.data} &lt;{form.Job_Description.data}&gt;
        {form.Job_Address.data}
        """
            mail.send(msg)

            return render_template('posting.html', success = True)
    elif request.method == 'GET':
        return render_template('posting.html', form = form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


def hello_world():
    return 'Hello World!'


if __name__ == '__main__':
    app.run()
