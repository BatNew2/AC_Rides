

# import flask_session
import sqlalchemy.exc
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, Boolean, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import StringField, SubmitField, SelectField, RadioField, FileField, TextAreaField
from wtforms.validators import DataRequired, Length, ValidationError, Optional
import random
import smtplib
import os
import datetime
import requests
from math import sqrt


class Base(DeclarativeBase):
    pass


def get_random():
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
               'I',
               'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '$', '&', '(', ')', '*', '+']
    password_list = []
    code = ""
    for char in range(10):
        password_list += random.choice(letters)
        password_list += random.choice(symbols)
        password_list += random.choice(numbers)
    for char in password_list:
        code += char
    return code


app = Flask(__name__)
app.config["SECRET_KEY"] = "33dc65055bcf34dea0ebc3ee2fb9f5e2dd5613c8fcb7f5a9c7c4cf9e89eb4c28"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ac_rides.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SESSION_TYPE"] = 'sqlalchemy'
app.config["SESSION_PERMANENT"] = True
app.config['WTF_CSRF_ENABLED'] = True
db = SQLAlchemy(model_class=Base)
app.config["SESSION_SQLALCHEMY"] = db
db.init_app(app)
app.config.from_object(__name__)


def check_logged():  # returns whether the user is logged in or not by tapping into session['username']
    try:
        if session['username'] is None:
            return False
        else:
            return True
    except KeyError:
        session['username'] = None
        return False


def acs_email(form, field):
    field = str(field.data)
    if "@" in field:
        field = field.split("@")
    else:
        raise ValidationError("Please use an ACS Jakarta Email")
    if not field[1] == "acsjakarta.sch.id":
        raise ValidationError("Please use an ACS Jakarta Email")


class Cars(db.Model):
    id: Mapped[int] = mapped_column(Integer, autoincrement=True, primary_key=True)
    days: Mapped[str] = mapped_column(String, nullable=False)
    owner: Mapped[str] = mapped_column(String, nullable=False)
    address: Mapped[str] = mapped_column(String, nullable=False)
    location: Mapped[str] = mapped_column(String, nullable=False)
    code: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    registered: Mapped[str] = mapped_column(String, nullable=False)
    interested: Mapped[str] = mapped_column(String, nullable=True)
    note: Mapped[str] = mapped_column(String, nullable=True)


class Admins(db.Model):
    id = mapped_column(Integer, autoincrement=True, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    phone: Mapped[str] = mapped_column(String, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False)


class Notifications(db.Model):
    id: Mapped[int] = mapped_column(Integer, autoincrement=True, primary_key=True)
    email: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    code: Mapped[str] = mapped_column(String, nullable=False, unique=True)


class Users(db.Model):
    id = mapped_column(Integer, autoincrement=True, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    phone: Mapped[str] = mapped_column(String, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    fullname: Mapped[str] = mapped_column(String, nullable=False)
    nickname: Mapped[str] = mapped_column(String)
    grade: Mapped[str] = mapped_column(String, nullable=False)
    grade_class: Mapped[str] = mapped_column(String, nullable=False)
    join_date: Mapped[str] = mapped_column(String, nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    last_upd: Mapped[str] = mapped_column(String)
    pw_code: Mapped[str] = mapped_column(String, unique=True)
    car: Mapped[str] = mapped_column(String, unique=True, nullable=True)
    profile: Mapped[str] = mapped_column(String, nullable=True)
    bio: Mapped[str] = mapped_column(String, nullable=True)
    request: Mapped[str] = mapped_column(String, nullable=True)


class Verifier(db.Model):
    id: Mapped[int] = mapped_column(Integer, autoincrement=True, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True)
    name: Mapped[str] = mapped_column(String)
    code: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    time: Mapped[str] = mapped_column(String, nullable=False)
    sent: Mapped[bool] = mapped_column(Boolean, nullable=False)
    verifier: Mapped[int] = mapped_column(Integer)


class Requests(db.Model):
    id: Mapped[int] = mapped_column(Integer, autoincrement=True, primary_key=True)
    days: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False)
    address: Mapped[str] = mapped_column(String, nullable=False)
    location: Mapped[str] = mapped_column(String, nullable=False)
    code: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    registered: Mapped[str] = mapped_column(String, nullable=False)
    note: Mapped[str] = mapped_column(String, nullable=True)


class Matches(db.Model):
    id: Mapped[int] = mapped_column(Integer, autoincrement=True, primary_key=True)
    days: Mapped[str] = mapped_column(String, nullable=False)
    car_user: Mapped[str] = mapped_column(String, nullable=False)
    car: Mapped[str] = mapped_column(String, nullable=False)
    admin: Mapped[str] = mapped_column(String, nullable=False)
    request: Mapped[str] = mapped_column(String, nullable=False)
    request_user: Mapped[str] = mapped_column(String, nullable=False)
    code: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    registered: Mapped[str] = mapped_column(String, nullable=False)
    note: Mapped[str] = mapped_column(String, nullable=True)


with app.app_context():
    db.create_all()


class Reset(FlaskForm):
    password = StringField('password', validators=[DataRequired(), Length(min=8, max=50, message="Password must be between 8 to 50 characters long")])


class PwEmail(FlaskForm):
    email = StringField('email', validators=[DataRequired(), acs_email])


class Login(FlaskForm):
    email = StringField('email', validators=[DataRequired(), acs_email])
    password = StringField('password', validators=[DataRequired(message="Please fill this field"), Length(min=8, max=50, message="Password must be between 8 to 50 characters long")])
    submit = SubmitField('login')


class Book(FlaskForm):
    full_address = StringField('email', validators=[DataRequired()])
    password = StringField('password', validators=[DataRequired(message="Please fill this field"), Length(min=8, max=50, message="Password must be between 8 to 50 characters long")])
    submit = SubmitField('login')


class Verify(FlaskForm):
    ver_code = StringField('Verification Code', validators=[DataRequired()])
    submit = SubmitField('login')


class SignUp(FlaskForm):
    email = StringField('email', validators=[DataRequired(), acs_email])
    password = StringField('password', validators=[DataRequired(message="Please fill this field"), Length(min=8, max=50, message="Password must be between 8 to 50 characters long")])
    phone = StringField('phone number', validators=[DataRequired(message="Please fill this field")])
    grade = SelectField('grade', choices=["", "7", "8", "9", "10", "11", "12"], validators=[DataRequired(message="Select your grade")])
    grade_class = SelectField('grade', choices=["", "Teamwork", "Respect", "Integrity", "Humility"], validators=[DataRequired(message="Select your class")])
    fullname = StringField('name', validators=[DataRequired("Please enter your name")])
    nickname = StringField('nick')
    submit = SubmitField('Sign Up')


@app.route("/")
def home():
    return render_template("index.html", logged=check_logged(), user=session["username"])


@app.route('/login', methods=["GET", "POST"])
def login():
    if check_logged():
        return redirect(url_for('home'))
    form = Login()
    form.validate_on_submit()
    errors = ""
    if form.validate_on_submit():
        try:
            user = Users.query.filter_by(email=form.email.data).one()
        except sqlalchemy.exc.NoResultFound:
            errors = "Invalid email"
        else:
            if user.password == form.password.data:
                if not user.verified:
                    user = Verifier.query.filter_by(email=user.email).one()
                    return redirect(url_for('verify', code=user.code))
                else:
                    print("Logged in")
                    session['username'] = form.email.data
                    return redirect(url_for('home'))
            else:
                errors = "Invalid password"
    return render_template('login.html', form=form, additional_errors=errors)


@app.route('/signup', methods=["GET", "POST"])
def signup():
    if check_logged():
        return redirect(url_for('home'))
    form = SignUp()
    form.validate_on_submit()
    error = ""
    if form.validate_on_submit():
        try:
            user = Users(
                email=form.email.data,
                password=form.password.data,
                phone=form.phone.data,
                grade=form.grade.data,
                grade_class=form.grade_class.data,
                fullname=form.fullname.data,
                nickname=form.nickname.data,
                join_date=datetime.datetime.now(),
                verified=False,
                last_upd=datetime.datetime(2023, 11, 3, 22, 6, 56, 0),
                pw_code=get_random(),
            )
            db.session.add(user)
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            error = "Account already made."
        else:
            if not form.nickname.data == "":
                name = form.nickname.data
            else:
                print(form.nickname.data)
                name = form.fullname.data
            code = get_random()
            _verify = Verifier(
                email=form.email.data,
                name=name,
                code=code,
                sent=False,
                time=datetime.datetime(2023, 11, 3, 22, 6, 56, 0),
                verifier="",
            )
            db.session.add(_verify)
            db.session.commit()
            return redirect(url_for('verify', code=code))
    return render_template('signup.html', form=form, error=error)


@app.route('/verify/<code>', methods=["POST", "GET"])
def verify(code):
    if check_logged():
        return redirect(url_for('home'))
    error = ""  # error if user code is not found
    err = ""  # error if verification code is wrong
    try:
        _verify = Verifier.query.filter_by(code=code).one()
    except sqlalchemy.exc.NoResultFound:
        error = "not_found"
    else:
        user = Users.query.filter_by(email=_verify.email).one()
        if user.verified:
            return redirect(url_for('home'))
        year = int(str(_verify.time).split(" ")[0].split("-")[0])
        month = int(str(_verify.time).split(" ")[0].split("-")[1])
        day = int(str(_verify.time).split(" ")[0].split("-")[2])
        hour = int(str(_verify.time).split(" ")[1].split(":")[0])
        minute = int(str(_verify.time).split(" ")[1].split(":")[1])
        second = round(float(str(_verify.time).split(" ")[1].split(":")[2].split(".")[0]))
        time = datetime.datetime(year=year, month=month, day=day, hour=hour, minute=minute, second=second)
        difference = str(datetime.datetime.now() - time)
        if ", " in str(difference):
            sec_difference = (int(str(difference).split(", ")[1].split(":")[0]) * 3600) + (int(str(difference).split(", ")[1].split(":")[1]) * 60) + int(str(difference).split(", ")[1].split(":")[2].split(".")[0])
        else:
            sec_difference = (int(str(difference).split(":")[0]) * 3600) + (int(str(difference).split(":")[1]) * 60) + int(str(difference).split(":")[2].split(".")[0])
        if ", " in str(difference) or sec_difference > 900:
            _verify.verifier = random.randint(10000, 99999)
            _verify.sent = False
            _verify.time = datetime.datetime.now()
            db.session.commit()
        if not _verify.sent:
            with smtplib.SMTP("smtp.gmail.com") as connection:
                connection.starttls()
                connection.login(user="acrides.help@gmail.com", password="vdfjaerevsebqyza")
                connection.sendmail(
                    from_addr="acrides.help@gmail.com",
                    to_addrs=_verify.email,
                    msg=f"Subject:{_verify.verifier}: AC Rides Verification Code\n\nHello AC Rides User!\n\n{_verify.verifier} is your verification code\nVERIFICATION CODE EXPIRES IN 15 MINUTES"
                )
                _verify.sent = True
                db.session.commit()
    form = Verify()

    form.validate_on_submit()
    if form.validate_on_submit():
        _verify = Verifier.query.filter_by(code=code).one()
        print(_verify.verifier)
        if not int(form.ver_code.data) == _verify.verifier:
            err = "Verification Code Incorrect"
            print(form.ver_code.data)
        else:
            user = Users.query.filter_by(email=_verify.email).one()
            user.verified = True
            db.session.commit()
            session["username"] = user.email
            return redirect(url_for('home'))
    return render_template("verify.html", error=error, form=form, code=code, err=err)


@app.route('/reset-password', methods=["GET", "POST"])
def forgot_password():
    if check_logged():
        return redirect(url_for('home'))
    form = PwEmail()
    if form.validate_on_submit():
        error = ""
        try:
            user = Users.query.filter_by(email=form.email.data).one()
        except sqlalchemy.exc.NoResultFound:
            error = "not_found"
        else:
            year = int(str(user.last_upd).split(" ")[0].split("-")[0])
            month = int(str(user.last_upd).split(" ")[0].split("-")[1])
            day = int(str(user.last_upd).split(" ")[0].split("-")[2])
            hour = int(str(user.last_upd).split(" ")[1].split(":")[0])
            minute = int(str(user.last_upd).split(" ")[1].split(":")[1])
            second = round(float(str(user.last_upd).split(" ")[1].split(":")[2].split(".")[0]))
            time = datetime.datetime(year=year, month=month, day=day, hour=hour, minute=minute, second=second)
            difference = str(datetime.datetime.now() - time)
            if ", " in str(difference):
                sec_difference = (int(str(difference).split(", ")[1].split(":")[0]) * 3600) + (int(str(difference).split(", ")[1].split(":")[1]) * 60) + int(str(difference).split(", ")[1].split(":")[2].split(".")[0])
            else:
                sec_difference = (int(str(difference).split(":")[0]) * 3600) + (int(str(difference).split(":")[1]) * 60) + int(str(difference).split(":")[2].split(".")[0])
            if ", " in str(difference) or sec_difference > 900:
                code = get_random()
                user.pw_code = code
                user.last_upd = datetime.datetime.now()
                db.session.commit()
            user = Users.query.filter_by(email=form.email.data).one()
            with smtplib.SMTP("smtp.gmail.com") as connection:
                connection.starttls()
                connection.login(user="acrides.help@gmail.com", password="vdfjaerevsebqyza")
                connection.sendmail(
                    from_addr="acrides.help@gmail.com",
                    to_addrs=form.email.data,
                    msg=f"Subject:Reset your AC Rides password: AC Rides Verification Code\n\nHello AC Rides User!\n\nOpen this link to change your password acrides.com/reset-password/{user.pw_code}\nLINK EXPIRES IN 15 MINUTES"
                )
                print('email_sent')
                print(form.email.data)
        return render_template("verify_password.html", form=form, sent=True, error=error)
    return render_template("verify_password.html", form=form, sent=False, error="")


@app.route("/reset-password/<code>", methods=["GET", "POST"])
def reset_password(code):
    if check_logged():
        return redirect(url_for('home'))
    form = Reset()
    if form.validate_on_submit():
        try:
            user = Users.query.filter_by(pw_code=str(code)).one()
            year = int(str(user.last_upd).split(" ")[0].split("-")[0])
            month = int(str(user.last_upd).split(" ")[0].split("-")[1])
            day = int(str(user.last_upd).split(" ")[0].split("-")[2])
            hour = int(str(user.last_upd).split(" ")[1].split(":")[0])
            minute = int(str(user.last_upd).split(" ")[1].split(":")[1])
            second = round(float(str(user.last_upd).split(" ")[1].split(":")[2].split(".")[0]))
            time = datetime.datetime(year=year, month=month, day=day, hour=hour, minute=minute, second=second)
            difference = str(datetime.datetime.now() - time)
            if ", " in str(difference):
                sec_difference = (int(str(difference).split(", ")[1].split(":")[0]) * 3600) + (int(str(difference).split(", ")[1].split(":")[1]) * 60) + int(str(difference).split(", ")[1].split(":")[2].split(".")[0])
            else:
                sec_difference = (int(str(difference).split(":")[0]) * 3600) + (int(str(difference).split(":")[1]) * 60) + int(str(difference).split(":")[2].split(".")[0])
            if ", " in str(difference) or sec_difference > 900:
                user.pw_code = get_random()
                user.last_upd = datetime.datetime.now()
                db.session.commit()
        except sqlalchemy.exc.NoResultFound:
            print(code)
            return "Account not found 1"
        else:
            try:
                user = Users.query.filter_by(pw_code=code).one()
            except sqlalchemy.exc.NoResultFound:
                return "Account not found"
            else:
                user.password = form.password.data
                db.session.commit()
                return redirect(url_for("login"))
    return render_template("change_password.html", form=form, code=code)


@app.route("/book_bus")
def book_bus():
    return "This is still being built"
    # form = Book()
    # if session["username"] is None:
    #     return render_template("not_allowed.html", logged=False)
    # if form.validate_on_submit():
    #     user = Users.query.filter_by(email=session["username"]).one()
    #     info = {
    #         "name": user.full_name,
    #         "class": f"{user.grade}-{user.grade_class}",
    #         "address": form.full_address.data,
    #         "phone": user.phone,
    #         "email": user.email,
    #     }
    #     response = requests.get("")
    # return render_template("book_bus.html", form=form, logged=check_logged(), user=session["username"])


@app.route("/rideshare")
def ride_share():
    check_logged()
    if session["username"] is None:
        return redirect(url_for('signup'))
    return render_template("rideshare.html", user=session["username"])


class CarForm(FlaskForm):
    address = StringField('address', validators=[DataRequired()])
    monday = RadioField('days', choices=["Monday"], validators=[Optional()])
    tuesday = RadioField('days', choices=["Tuesday"], validators=[Optional()])
    wednesday = RadioField('days', choices=["Wednesday"], validators=[Optional()])
    thursday = RadioField('days', choices=["Thursday"], validators=[Optional()])
    friday = RadioField('days', choices=["Friday"], validators=[Optional()])
    password = StringField('password', validators=[DataRequired(message="Please fill this field"), Length(min=8, max=50, message="Password must be between 8 to 50 characters long")])


@app.route('/rideshare/add_car', methods=["GET", "POST"])
def add_car():
    check_logged()
    if session["username"] is None:
        return render_template("not_allowed.html", logged=False)
    form = CarForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=session["username"]).one()
        if user.password == form.password.data:
            days = [form.monday.data, form.tuesday.data, form.wednesday.data, form.thursday.data, form.friday.data]
            formatted_day = ""
            for day in days:
                if day is not None:
                    formatted_day += f"{day}, "
            code = get_random()
            location = requests.get('https://geocode.maps.co/search', params={"q": form.address.data}).json()
            try:
                formatted_location = f"{location[0]['lat']},{location[0]['lon']}"
            except IndexError:
                return render_template('add_car.html', form=form, message="Please enter only your address with out house number. Contact us if this problem keeps showing up", logged=check_logged(), user=session["username"])
            new_car = Cars(
                address=form.address.data,
                location=formatted_location,
                owner=session['username'],
                code=code,
                registered=datetime.datetime.now(),
                days=formatted_day,
                interested=""
            )
            try:
                old_car = Cars.query.filter_by(owner=user.email).one()
            except sqlalchemy.exc.NoResultFound:
                pass
            else:
                db.session.delete(old_car)
            db.session.add(new_car)
            user.car = code
            db.session.commit()
            return render_template('add_car.html', form=form, done=True, logged=check_logged(), user=session["username"])
        else:
            return render_template('add_car.html', form=form, message="Wrong password", logged=check_logged(), user=session["username"])
    return render_template('add_car.html', form=form, logged=check_logged(), user=session["username"])


class RequestForm(FlaskForm):
    address = StringField('address', validators=[DataRequired()])
    monday = RadioField('days', choices=["Monday"], validators=[Optional()])
    tuesday = RadioField('days', choices=["Tuesday"], validators=[Optional()])
    wednesday = RadioField('days', choices=["Wednesday"], validators=[Optional()])
    thursday = RadioField('days', choices=["Thursday"], validators=[Optional()])
    friday = RadioField('days', choices=["Friday"], validators=[Optional()])
    note = TextAreaField('note', render_kw={"rows": 70, "cols": 11}, validators=[Optional()])
    password = StringField('password', validators=[DataRequired(message="Please fill this field"), Length(min=8, max=50, message="Password must be between 8 to 50 characters long")])


@app.route('/rideshare/find_car', methods=["GET", "POST"])
def find_car():
    check_logged()
    if session["username"] is None:
        return render_template("not_allowed.html", logged=False)
    form = RequestForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=session["username"]).one()
        if user.password == form.password.data:
            days = [form.monday.data, form.tuesday.data, form.wednesday.data, form.thursday.data, form.friday.data]
            formatted_day = ""
            for day in days:
                if day is not None:
                    formatted_day += f"{day}, "
            if formatted_day == "":
                return render_template('req_car.html', form=form, message="Please select days", logged=check_logged(), user=session["username"])
            code = get_random()
            location = requests.get('https://geocode.maps.co/search', params={"q": form.address.data}).json()
            try:
                formatted_location = f"{location[0]['lat']},{location[0]['lon']}"
            except IndexError:
                return render_template('req_car.html', form=form, message="Please enter only your address with out house number. Contact us if this problem keeps showing up", logged=check_logged(), user=session["username"])
            new_req = Requests(
                address=form.address.data,
                email=session['username'],
                location=formatted_location,
                code=code,
                registered=datetime.datetime.now(),
                days=formatted_day,
                note=form.note.data,
            )
            try:
                old_requests = Requests.query.filter_by(email=user.email).one()
            except sqlalchemy.exc.NoResultFound:
                pass
            else:
                db.session.delete(old_requests)
            db.session.add(new_req)
            user.request = code
            db.session.commit()
            return render_template('req_car.html', form=form, done=True, logged=check_logged(), user=session["username"])
        else:
            return render_template('req_car.html', form=form, message="Wrong password", logged=check_logged(), user=session["username"])
    return render_template('req_car.html', form=form, logged=check_logged(), user=session["username"])


@app.route("/dashboard")
def dashboard():
    check_logged()
    if session["username"] is None:
        return render_template("not_allowed.html", logged=False)
    try:
        car = Cars.query.filter_by(owner=session["username"]).one()
    except sqlalchemy.exc.NoResultFound:
        car_code = ""
    else:
        car_code = car.code
    try:
        req = Requests.query.filter_by(email=session['username']).one()
    except sqlalchemy.exc.NoResultFound:
        request_code = ""
    else:
        request_code = req.code
    return render_template("dashboard.html", car_code=car_code, car="Your RideShare", logged=check_logged(), user=session["username"], req_code=request_code)


@app.route('/car/<code>/remove')
def remove_car(code):
    check_logged()
    if session["username"] is None:
        return render_template("not_allowed.html", logged=False)
    try:
        car = Cars.query.filter_by(code=code).one()
    except sqlalchemy.exc.NoResultFound:
        return "404 Not Found"
    if car.owner == session["username"]:
        user = Users.query.filter_by(car=code).one()
        user.request = None
        db.session.delete(car)
        db.session.commit()
        return redirect(url_for('dashboard'))
    else:
        return render_template('not_allowed.html', logged=False)


@app.route('/request/<code>/remove')
def remove_req(code):
    check_logged()
    if session["username"] is None:
        return render_template("not_allowed.html", logged=False)
    try:
        req = Requests.query.filter_by(code=code).one()
    except sqlalchemy.exc.NoResultFound:
        return "404 Not Found"
    if req.email == session["username"]:
        user = Users.query.filter_by(request=code).one()
        user.request = None
        db.session.delete(req)
        db.session.commit()
        return redirect(url_for('dashboard'))
    else:
        return render_template('not_allowed.html', logged=False)


@app.route("/car/<code>")
def car_info(code):
    check_logged()
    if session["username"] is None:
        return render_template("not_allowed.html", logged=False)
    car = Cars.query.filter_by(code=code).one()
    user = Users.query.filter_by(car=code).one()
    return render_template('car_info.html', owner=user, car=car, user=session["username"], logged=check_logged())


@app.route("/request/<code>")
def req_info(code):
    check_logged()
    if session["username"] is None:
        return render_template("not_allowed.html", logged=False)
    req = Requests.query.filter_by(code=code).one()
    user = Users.query.filter_by(request=code).one()
    return render_template('req_info.html', owner=user, req=req, user=session["username"], logged=check_logged())


class Profile(FlaskForm):
    pfp = FileField('profile picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    fullname = StringField('fullname')
    nickname = StringField('nickname')
    # grade = SelectField('grade', choices=["", "7", "8", "9", "10", "11", "12"])
    # gradeclass = SelectField('class', choices=["", "Teamwork", "Respect", "Integrity", "Humility"])
    phone = StringField('class')


@app.route("/profile/<email>/edit", methods=["GET", "POST"])
def profile(email):
    check_logged()
    if session["username"] is None:
        return render_template("not_allowed.html", logged=False)
    try:
        admin = Admins.query.filter_by(email=session['username']).one()
    except sqlalchemy.exc.NoResultFound:
        admin = False
    else:
        admin = True
    if not session["username"] == email and not admin:
        return redirect(url_for('profile_view', email=email))
    pfp_form = Profile()
    try:
        user = Users.query.filter_by(email=email).one()
    except sqlalchemy.exc.NoResultFound:
        return "404 Not Found"
    else:
        if pfp_form.validate_on_submit():
            file = pfp_form.pfp.data
            if file.filename != "":
                file.save(os.path.join('./static/assets/pfp', f"{user.email}.jpg"))
            if user.fullname != pfp_form.fullname.data:
                user.fullname = pfp_form.fullname.data
            if user.nickname != pfp_form.nickname.data:
                user.nickname = pfp_form.nickname.data
            # if user.grade != pfp_form.grade.data:
            #     user.grade = pfp_form.grade.data
            # if user.gradeclass != pfp_form.gradeclass.data:
            #     user.gradeclass = pfp_form.gradeclass.data
            if user.phone != pfp_form.phone.data:
                user.phone = pfp_form.phone.data
            db.session.commit()
            user = Users.query.filter_by(email=email).one()
        file_path = f'../../static/assets/pfp/{user.email}.jpg'
        if not os.path.exists(f"./static/assets/pfp/{user.email}.jpg"):
            file_path = "../../static/person-circle.svg"
        return render_template("profile_edit.html", current_user=session['username'], user=user, form=pfp_form, file_path=file_path, logged=check_logged())


@app.route("/profile/<email>/view")
def profile_view(email):
    check_logged()
    if session["username"] is None:
        return render_template("not_allowed.html", logged=False)
    try:
        user = Users.query.filter_by(email=email).one()
    except sqlalchemy.exc.NoResultFound:
        return "404 Not Found"
    try:
        car = Cars.query.filter_by(owner=user.email).one()
    except sqlalchemy.exc.NoResultFound:
        car = False
    try:
        req = Requests.query.filter_by(email=user.email).one()
    except sqlalchemy.exc.NoResultFound:
        req = False
    file_path = f'../../static/assets/pfp/{user.email}.jpg'
    if not os.path.exists(f"./static/assets/pfp/{user.email}.jpg"):
        file_path = "../../static/person-circle.svg"
    return render_template("profile.html", user=user, file_path=file_path, car=car, current_user=session['username'], request=req)


class SearchBar(FlaskForm):
    filter = StringField('filter', validators=[DataRequired()])
    type = SelectField('type', validators=[DataRequired()], choices=['email', 'fullname', 'nickname', 'class', 'grade'])


@app.route("/asd0i01wA2312386i7dha8sd9ho12dnskabdu9/admin/users")
def admin_users():
    check_logged()
    try:
        user = Admins.query.filter_by(email=session["username"]).one()
    except sqlalchemy.exc.NoResultFound:
        return redirect(url_for('home'))
    form = SearchBar()
    fltr = request.args.get('filter')
    typ = request.args.get('type')
    result = db.session.execute(db.select(Users).order_by(Users.grade))
    all_users = result.scalars().all()
    num_users = len(all_users)
    if fltr is not None:
        results = []
        if typ == 'email':
            for user in all_users:
                if fltr in user.email:
                    results.append(user)
        elif typ == 'fullname':
            for user in all_users:
                if fltr.lower() in user.fullname.lower():
                    results.append(user)
        elif typ == 'nickname':
            for user in all_users:
                if fltr.lower() in user.nickname.lower():
                    results.append(user)
        elif typ == 'class':
            for user in all_users:
                if fltr.lower() in user.grade_class.lower():
                    results.append(user)
        else:
            for user in all_users:
                if fltr.lower() in user.grade.lower():
                    results.append(user)
        all_users = results
    return render_template("users.html", users=all_users, num=num_users, current_user=session['username'], form=form)


@app.route("/asd0i01wA2312386i7dha8sd9ho12dnskabdu9/admin")
def admin_board():
    check_logged()
    try:
        user = Admins.query.filter_by(email=session["username"]).one()
    except sqlalchemy.exc.NoResultFound:
        return redirect(url_for('home'))
    result = db.session.execute(db.select(Users).order_by(Users.grade))
    all_users = result.scalars().all()
    num_users = len(all_users)
    return render_template("admin.html", users=all_users, num=num_users, current_user=session['username'])


class RideshareSearch(FlaskForm):
    filter = StringField('filter', validators=[DataRequired()])
    search_type = SelectField('search_type', validators=[DataRequired()], choices=['email', 'code', 'day'])
    type = StringField('type', validators=[DataRequired()])


@app.route("/asd0i01wA2312386i7dha8sd9ho12dnskabdu9/admin/rideshares", methods=["GET", "POST"])
def admin_rideshares(match=False):
    check_logged()
    try:
        user = Admins.query.filter_by(email=session["username"]).one()
    except sqlalchemy.exc.NoResultFound:
        return redirect(url_for('home'))
    request_type = request.args.get('request_type')
    if request_type == "cars":
        result = db.session.execute(db.select(Cars).order_by(Cars.registered))
    elif request_type == "requests":
        result = db.session.execute(db.select(Requests).order_by(Requests.registered))
    else:
        return redirect(url_for('admin_board'))
    form = RideshareSearch()
    mtching = request.args.get('code')
    print(mtching)
    fltr = request.args.get('filter')
    typ = request.args.get('type')
    unformatted_cars = result.scalars().all()
    all_cars = [["None", car] for car in unformatted_cars]
    if mtching is not None:
        if typ == "requests":
            car2 = Requests.query.filter_by(code=mtching).one()
        else:
            car2 = Cars.query.filter_by(code=mtching).one()
        car2_days = car2.days.replace(" ", "").split(",")
        print(car2_days)
        dayformatted_cars = []
        for car in all_cars:
            car_days = car[1].days.replace(" ", "").split(",")
            for day in car2_days:
                print(day)
                if day in car_days:
                    dayformatted_cars.append(car)
                    break
        all_cars = [[sqrt(((float(car1[1].location.split(',')[0]) - float(car2.location.split(',')[0]))**2) + ((float(car1[1].location.split(',')[1]) - float(car2.location.split(',')[1]))**2)), car1[1]] for car1 in dayformatted_cars]
        all_cars.sort(key=lambda x: x[0])
    num_cars = len(all_cars)
    if fltr is not None:
        results = []
        print(fltr)
        if typ == 'email':
            if request_type == "cars":
                for user in all_cars:
                    if fltr.lower() in user[1].owner.lower():
                        results.append(user)
            else:
                for user in all_cars:
                    if fltr in user[1].email:
                        results.append(user)
        elif typ == 'day':
            for user in all_cars:
                if fltr.lower() in user[1].days.lower():
                    results.append(user)
        else:
            for user in all_cars:
                if fltr.lower() in user[1].code.lower():
                    results.append(user)
        print(results)
        all_cars = results
        num_cars = len(all_cars)
        print(all_cars)
    return render_template("view_rideshares.html", cars=all_cars, num=num_cars, current_user=session['username'], form=form, type=request_type, code=mtching)


@app.route("/asd0i01wA2312386i7dha8sd9ho12dnskabdu9/admin/matching")
def matching():
    check_logged()
    try:
        user = Admins.query.filter_by(email=session["username"]).one()
    except sqlalchemy.exc.NoResultFound:
        return redirect(url_for('home'))
    old_code, typ, current_code, distance = request.args.get('old'), request.args.get('type'), request.args.get('code'), request.args.get('distance')
    if old_code is None or typ is None or current_code is None:
        return "Missing argument make sure you have selected a car and request"
    try:
        if typ == "requests":
            this_request = Requests.query.filter_by(code=old_code).one()
            request_user = Users.query.filter_by(request=old_code).one()
            this_car = Cars.query.filter_by(code=current_code).one()
            car_user = Users.query.filter_by(car=current_code).one()
        else:
            request_user = Users.query.filter_by(request=current_code).one()
            this_request = Requests.query.filter_by(code=current_code).one()
            car_user = Users.query.filter_by(car=old_code).one()
            this_car = Cars.query.filter_by(code=old_code).one()
    except sqlalchemy.exc.NoResultFound:
        return "one of codes wrong please retry"
    if request.args.get('match') == "yes":
        code = get_random()
        new_match = Matches(
            car_user=car_user.email,
            car=this_car.code,
            code=code,
            request_user=request_user.email,
            request=this_request.code,
            registered=str(datetime.datetime.now()),
            admin=session['username'],
        )
        db.session.add(new_match)
        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(user="acrides.help@gmail.com", password="vdfjaerevsebqyza")
            connection.sendmail(
                from_addr="acrides.help@gmail.com",
                to_addrs=car_user.email,
                msg=f"Subject: We have found a match for your RideShare!\n\nHello AC Rides User! \n\nWe have found matched your RideShare with another user.\nFor more information go to acsrides.com/dashboard and check your notification."
            )
            connection.sendmail(
                from_addr="acrides.help@gmail.com",
                to_addrs=request_user.email,
                msg=f"Subject: We have found a RideShare!\n\nHello AC Rides User! \n\nWe have found matched your request with a RideShare.\nFor more information go to acsrides.com/dashboard and check your notifications."
            )
        car_notif = Notifications(
            email=car_user.email,
            name="We have found a request for you!",
            body=f'To check request information please open this link: acsrides.com/matches/{code}',
            code=get_random()
        )
        request_notif = Notifications(
            email=request_user.email,
            name="We have found a RideShare for you!",
            body=f'To check request information please open this link: acsrides.com/matches/{code}',
            code=get_random()
        )
        db.session.commit()
    if not os.path.exists(f"./static/assets/pfp/{car_user.email}.jpg"):
        car_profile = "../../static/person-circle.svg"
    else:
        car_profile = f'../../static/assets/pfp/{car_user.email}.jpg'
    if not os.path.exists(f"./static/assets/pfp/{request_user.email}.jpg"):
        request_profile = "../../static/person-circle.svg"
    else:
        request_profile = f'../../static/assets/pfp/{request_user.email}.jpg'
    return render_template('matching.html', request_user=request_user, request=this_request, car_user=car_user, car=this_car, current_code=user, logged=check_logged(), car_profile=car_profile, request_profile=request_profile, old=old_code, code=current_code, distance=distance, type=typ)


@app.route("/logout")
def logout():
    session["username"] = None
    return redirect(url_for('home'))


# @app.errorhandler(Exception)
# def error_page(error):
#     return render_template('error.html', error=error)


if __name__ == '__main__':
    app.run(debug=True)
