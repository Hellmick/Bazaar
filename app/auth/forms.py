from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, ValidationError, TextAreaField
from wtforms.fields.html5 import DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from ..models import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired(),])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log in')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 
            'Usernames must have only letters, numbers, dots or '
            'underscores.')])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Confirm password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username is taken.')

class ChangePassword(FlaskForm):
    password = PasswordField('Old password', validators=[DataRequired()])
    new_password = PasswordField('New password', validators=[DataRequired()])
    new_password2 = PasswordField('Confirm new password', validators=[
        DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Change password')

class ForgotPassword(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField('Submit')

class ResetPassword(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Confirm password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Submit')

class ChangeEmail(FlaskForm):
    email = StringField('New email address', validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField('Submit')

class DeleteUser(FlaskForm):
    password = PasswordField('Please enter your password to delete your account', validators=[DataRequired()])
    submit = SubmitField('Delete account')

class AdditionalInformation(FlaskForm):
    first_name = StringField('First name', validators=[Length(0, 32)])
    second_name = StringField('Second name', validators=[Length(0, 32)])
    last_name = StringField('Last name', validators=[Length(0, 64)])
    birth_date = DateField('Birth date', format='%Y-%m-%d')
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField()
