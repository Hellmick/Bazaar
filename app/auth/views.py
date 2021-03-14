from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user
from . import auth
from .forms import LoginForm, RegistrationForm, ChangePassword, ForgotPassword, ResetPassword, ChangeEmail, DeleteUser, AdditionalInformation
from ..models import User
from ..email import send_email
from app import db

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            flash('There\'s no account registered with this email address.')
        elif user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        else:
            flash('Invalid password.')
    return render_template('auth/login.html', form=form, page_title="Login")

from flask_login import logout_user, login_required

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
            username=form.username.data,
            password=form.password.data)
        db.session.add(user)
        token = user.generate_token('confirm')
        send_email(user.email, 'Confirm Your Account',
            'auth/email/confirm', user=user, token=token)
        db.session.commit()
        return redirect(url_for('auth.additional_info'))
    return render_template('auth/single-form.html', form=form, page_title="Register")

from flask_login import current_user

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        db.session.commit()
        flash("Your account has been confirmed.")
    else:
        flash("Your confirmation link is invalid or has expired.")
    return redirect(url_for('main.index'))

@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.blueprint != 'auth' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html', page_title="Hello, %s!" % (current_user.username))

@auth.route('/resend_token')
def resend_token():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    token = current_user.generate_token('confirm')
    send_email(current_user.email, 'Confirm Your Account',
            'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you.')
    return redirect(url_for('auth.unconfirmed'))

@auth.route('/account_management')
@login_required
def account_management():
    pass
    return render_template('auth/account-management.html', page_title="Account management")

@auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePassword()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            current_user.password = form.new_password.data
            db.session.commit()
            flash('Your password has been changed.')
        else:
            flash('Old password incorrect.')
    return render_template('auth/single-form.html', form=form, page_title="Change password")

@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_token('password_reset')
            send_email(user.email, 'Password reset',
                'auth/email/password-reset', token=token, username=user.username)
            flash('An email with password reset link has been sent to you.')
    return render_template('auth/forgot-password.html', form=form, page_title="Forgot password")

@auth.route('/reset_password/<username>/<token>', methods=['GET', 'POST'])
def reset_password(username, token):
    form = ResetPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first()
        if user.reset_password(token=token, password=form.password.data):
            db.session.commit()
            flash('Your password has been changed.')
        else:
            flash('Your password reset token is invalid or has expired.')
    return render_template('auth/single-form.html', form=form, page_title="Password reset")

@auth.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    form = ChangeEmail()
    if form.validate_on_submit():
        current_user.new_email = form.email.data
        token = current_user.generate_token(purpose='change_email')
        db.session.commit()
        send_email(current_user.email, 'Email address change',
            'auth/email/change-email', token=token)
        flash('An email with password reset link has been sent to you.')
    return render_template('auth/single-form.html', form=form, page_title="Change email")

@auth.route('/ch_em/<token>', methods=['GET', 'POST'])
@login_required
def ch_em(token):
    if current_user.change_email(token=token):
        db.session.commit()
        flash('Your email address has been changed.')
    else:
        flash('Your email address change token is invalid or has expired.')
    return redirect(url_for('auth.change_email'))

@auth.route('/delete_user', methods=['GET', 'POST'])
@login_required
def delete_user():
    form = DeleteUser()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            db.session.delete(current_user)
            flash("Your account has been deleted.")
            db.session.commit()
            return redirect(url_for('main.index'))
        else:
            flash("Incorrect password.")
    return render_template('auth/single-form.html', form=form, page_title="Delete account", label='Note: This acction is irreversible.', warning=True)

@auth.route('/additional_info', methods=['GET', 'POST'])
@login_required
def additional_info():
    if not current_user.confirmed:
        return redirect(url_for('auth.unconfirmed'))
    form = AdditionalInformation()
    if form.validate_on_submit():
        if form.first_name.data or form.second_name.data or form.last_name.data:
            current_user.name = form.first_name.data + ' ' + form.second_name.data + ' ' + form.last_name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        current_user.birth_date = form.birth_date.data
        db.session.commit()
        flash("Your profile information has been changed.")
        return redirect(url_for('.user', username=current_user.username))
    return render_template('auth/additional-info.html', form=form, page_title="Edit your profile")
