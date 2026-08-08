from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, IntegerField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Optional, NumberRange, EqualTo
from dotenv import load_dotenv
import os
import json
import uuid
import base64
from datetime import datetime, timedelta

load_dotenv()

# ========== راه‌اندازی اپلیکیشن ==========
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///trex.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'لطفاً ابتدا وارد شوید'

# ============================================================
# مدل‌ها
# ============================================================
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    status = db.Column(db.String(20), default='Active')
    traffic = db.Column(db.Integer, default=0)  # برای سازگاری با نسخه قبلی
    traffic_limit = db.Column(db.Integer, default=0)  # 0 = نامحدود
    traffic_used = db.Column(db.Integer, default=0)
    requests = db.Column(db.Integer, default=0)
    time = db.Column(db.String(20), default='∞')
    expiry_date = db.Column(db.DateTime, nullable=True)  # None = ∞
    online = db.Column(db.Integer, default=0)
    ports = db.Column(db.String(100), default='443, 80')
    max_ips = db.Column(db.Integer, default=0)  # 0 = نامحدود
    link = db.Column(db.String(500), default='')
    uuid = db.Column(db.String(36), default='')
    inbound_id = db.Column(db.Integer, db.ForeignKey('inbound.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def get_status(self):
        if self.status == 'Disabled':
            return 'Disabled'
        if self.expiry_date and datetime.utcnow() > self.expiry_date:
            return 'Expired'
        if self.traffic_limit > 0 and self.traffic_used >= self.traffic_limit:
            return 'Expired'
        return 'Active'

    def get_expiry_status(self):
        if not self.expiry_date:
            return '∞'
        days_left = (self.expiry_date - datetime.utcnow()).days
        if days_left < 0:
            return 'منقضی'
        elif days_left == 0:
            return 'امروز'
        elif days_left < 7:
            return f'{days_left} روز'
        else:
            return self.expiry_date.strftime('%Y-%m-%d')

class Inbound(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, default='Main')
    domain = db.Column(db.String(200), nullable=False)
    port = db.Column(db.Integer, nullable=False, default=443)
    path = db.Column(db.String(200), default='/')
    protocol = db.Column(db.String(20), default='vmess')
    security = db.Column(db.String(20), default='tls')
    sni = db.Column(db.String(200), default='')
    allow_insecure = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    config_extra = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.Text, default='')
    
    @staticmethod
    def get(key, default=None):
        setting = Setting.query.filter_by(key=key).first()
        return setting.value if setting else default
    
    @staticmethod
    def set(key, value):
        setting = Setting.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            setting = Setting(key=key, value=value)
            db.session.add(setting)
        db.session.commit()

# ============================================================
# فرم‌ها
# ============================================================
class LoginForm(FlaskForm):
    password = PasswordField('رمز عبور', validators=[DataRequired()])

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('رمز عبور فعلی', validators=[DataRequired()])
    new_password = PasswordField('رمز عبور جدید', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('تکرار رمز عبور جدید', validators=[DataRequired(), EqualTo('new_password')])

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=80)])
    status = SelectField('Status', choices=[('Active','Active'), ('Disabled','Disabled'), ('Expired','Expired')])
    traffic_limit = IntegerField('حجم کل (MB) - 0=نامحدود', default=0, validators=[Optional()])
    traffic_used = IntegerField('حجم مصرف‌شده (MB)', default=0, validators=[Optional()])
    requests = IntegerField('تعداد درخواست‌ها', default=0, validators=[Optional()])
    expiry_date = StringField('تاریخ انقضا (YYYY-MM-DD) - خالی=∞', default='', validators=[Optional()])
    online = IntegerField('آنلاین (شبیه‌سازی)', default=0, validators=[Optional()])
    ports = StringField('پورت‌ها', default='443, 80')
    max_ips = IntegerField('حداکثر آیپی همزمان - 0=نامحدود', default=0, validators=[Optional()])
    link = StringField('لینک اشتراک (تولید خودکار)', validators=[Optional()])
    inbound_id = SelectField('اینباند', coerce=int, choices=[], validators=[Optional()])

class InboundForm(FlaskForm):
    name = StringField('نام اینباند', validators=[DataRequired(), Length(max=80)])
    domain = StringField('دامنه یا IP', validators=[DataRequired(), Length(max=200)])
    port = IntegerField('پورت', validators=[DataRequired(), NumberRange(min=1, max=65535)], default=443)
    path = StringField('مسیر', default='/')
    protocol = SelectField('پروتکل', choices=[('vmess','VMess'), ('trojan','Trojan'), ('vless','VLESS'), ('ss','Shadowsocks')])
    security = SelectField('امنیت', choices=[('tls','TLS'), ('none','هیچ')])
    sni = StringField('SNI', default='')
    allow_insecure = BooleanField('Allow Insecure (تست)')
    is_active = BooleanField('فعال', default=True)
    config_extra = TextAreaField('کانفیگ اضافی (JSON)', default='{}')

# ============================================================
# توابع کمکی
# ============================================================
def generate_user_link(username, user_uuid, inbound_id=None):
    if inbound_id:
        inbound = Inbound.query.get(inbound_id)
    else:
        inbound = Inbound.query.filter_by(is_active=True).first()
    if not inbound:
        return None

    if inbound.protocol == 'vmess':
        config = {
            "v": "2",
            "ps": username,
            "add": inbound.domain,
            "port": inbound.port,
            "id": user_uuid,
            "aid": "0",
            "net": "ws" if inbound.path != '/' and inbound.path else "tcp",
            "type": "none",
            "host": inbound.sni or inbound.domain,
            "path": inbound.path if inbound.path != '/' else "",
            "tls": "tls" if inbound.security == 'tls' else ""
        }
        if inbound.config_extra:
            try:
                extra = json.loads(inbound.config_extra)
                config.update(extra)
            except:
                pass
        link = "vmess://" + base64.b64encode(json.dumps(config).encode()).decode()
    elif inbound.protocol == 'trojan':
        link = f"trojan://{user_uuid}@{inbound.domain}:{inbound.port}?security={inbound.security}&sni={inbound.sni}#{username}"
    elif inbound.protocol == 'vless':
        link = f"vless://{user_uuid}@{inbound.domain}:{inbound.port}?security={inbound.security}&encryption=none&sni={inbound.sni}#{username}"
    else:
        link = f"{inbound.protocol}://{user_uuid}@{inbound.domain}:{inbound.port}?security={inbound.security}#{username}"
    return link

def check_user_status(user):
    if user.status == 'Disabled':
        return 'Disabled'
    if user.expiry_date and datetime.utcnow() > user.expiry_date:
        return 'Expired'
    if user.traffic_limit > 0 and user.traffic_used >= user.traffic_limit:
        return 'Expired'
    return 'Active'

# ترجمه‌ها
translations = {
    'fa': {
        'dashboard': 'داشبورد', 'users': 'کاربران', 'inbounds': 'اینباندها',
        'settings': 'تنظیمات', 'logout': 'خروج', 'login': 'ورود',
        'password': 'رمز عبور', 'change_password': 'تغییر رمز عبور',
        'current_password': 'رمز عبور فعلی', 'new_password': 'رمز عبور جدید',
        'confirm_password': 'تکرار رمز عبور', 'language': 'زبان', 'theme': 'تم',
        'light': 'روشن', 'dark': 'تاریک', 'save': 'ذخیره', 'cancel': 'انصراف',
        'back': 'بازگشت', 'search': 'جستجو', 'add_user': 'افزودن کاربر',
        'edit_user': 'ویرایش کاربر', 'delete_user': 'حذف کاربر', 'status': 'وضعیت',
        'traffic': 'ترافیک', 'traffic_limit': 'حجم کل', 'traffic_used': 'مصرف‌شده',
        'remaining': 'باقی‌مانده', 'requests': 'درخواست‌ها', 'time': 'زمان',
        'expiry_date': 'تاریخ انقضا', 'online': 'آنلاین', 'ports': 'پورت‌ها',
        'max_ips': 'حداکثر آیپی', 'link': 'لینک', 'actions': 'عملیات',
        'active': 'فعال', 'disabled': 'غیرفعال', 'expired': 'منقضی',
        'total_users': 'کل کاربران', 'active_users': 'کاربران فعال',
        'expired_users': 'کاربران منقضی', 'total_traffic': 'ترافیک کل',
        'total_requests': 'درخواست‌ها', 'total_inbounds': 'اینباندهای فعال',
        'inbound_name': 'نام اینباند', 'domain': 'دامنه', 'port': 'پورت',
        'protocol': 'پروتکل', 'security': 'امنیت', 'path': 'مسیر',
        'sni': 'SNI', 'allow_insecure': 'Allow Insecure',
        'config_extra': 'کانفیگ اضافی', 'add_inbound': 'افزودن اینباند',
        'edit_inbound': 'ویرایش اینباند', 'delete_inbound': 'حذف اینباند',
        'settings_saved': 'تنظیمات ذخیره شد', 'password_changed': 'رمز عبور تغییر کرد',
        'wrong_password': 'رمز عبور فعلی اشتباه است', 'search_user': 'جستجوی کاربر...',
        'all_accounts': 'همه حساب‌ها', 'newest': 'جدیدترین',
        'quick_user': 'کاربر سریع', 'new_user': 'کاربر جدید',
        'unlimited': 'نامحدود', 'traffic_remaining': 'حجم باقی‌مانده',
    },
    'en': {
        'dashboard': 'Dashboard', 'users': 'Users', 'inbounds': 'Inbounds',
        'settings': 'Settings', 'logout': 'Logout', 'login': 'Login',
        'password': 'Password', 'change_password': 'Change Password',
        'current_password': 'Current Password', 'new_password': 'New Password',
        'confirm_password': 'Confirm Password', 'language': 'Language',
        'theme': 'Theme', 'light': 'Light', 'dark': 'Dark', 'save': 'Save',
        'cancel': 'Cancel', 'back': 'Back', 'search': 'Search',
        'add_user': 'Add User', 'edit_user': 'Edit User', 'delete_user': 'Delete User',
        'status': 'Status', 'traffic': 'Traffic', 'traffic_limit': 'Total Traffic',
        'traffic_used': 'Used', 'remaining': 'Remaining', 'requests': 'Requests',
        'expiry_date': 'Expiry Date', 'time': 'Time', 'online': 'Online',
        'ports': 'Ports', 'max_ips': 'Max IPs', 'link': 'Link',
        'actions': 'Actions', 'active': 'Active', 'disabled': 'Disabled',
        'expired': 'Expired', 'total_users': 'Total Users', 'active_users': 'Active Users',
        'expired_users': 'Expired Users', 'total_traffic': 'Total Traffic',
        'total_requests': 'Total Requests', 'total_inbounds': 'Active Inbounds',
        'inbound_name': 'Inbound Name', 'domain': 'Domain', 'port': 'Port',
        'protocol': 'Protocol', 'security': 'Security', 'path': 'Path',
        'sni': 'SNI', 'allow_insecure': 'Allow Insecure',
        'config_extra': 'Extra Config', 'add_inbound': 'Add Inbound',
        'edit_inbound': 'Edit Inbound', 'delete_inbound': 'Delete Inbound',
        'settings_saved': 'Settings saved', 'password_changed': 'Password changed',
        'wrong_password': 'Current password is incorrect', 'search_user': 'Search user...',
        'all_accounts': 'All accounts', 'newest': 'Newest',
        'quick_user': 'Quick user', 'new_user': 'New user',
        'unlimited': 'Unlimited', 'traffic_remaining': 'Remaining Traffic',
    }
}

def get_text(key, lang='fa'):
    return translations.get(lang, translations['fa']).get(key, key)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# ============================================================
# Context Processor (برای دسترسی به ترجمه و تنظیمات در قالب‌ها)
# ============================================================
@app.context_processor
def inject_settings():
    return {
        'current_language': Setting.get('language', 'fa'),
        'current_theme': Setting.get('theme', 'light'),
        '_': lambda key: get_text(key, Setting.get('language', 'fa'))
    }

# ============================================================
# روت‌ها
# ============================================================

# ---------- احراز هویت ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(username='admin').first()
        if admin and check_password_hash(admin.password, form.password.data):
            login_user(admin)
            return redirect(url_for('dashboard'))
        flash('رمز عبور اشتباه است', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------- داشبورد ----------
@app.route('/')
@login_required
def dashboard():
    total_users = User.query.count()
    active_users = User.query.filter_by(status='Active').count()
    expired_users = User.query.filter_by(status='Expired').count()
    total_traffic = db.session.query(db.func.sum(User.traffic_used)).scalar() or 0
    total_traffic_limit = db.session.query(db.func.sum(User.traffic_limit)).scalar() or 0
    total_requests = db.session.query(db.func.sum(User.requests)).scalar() or 0
    total_inbounds = Inbound.query.filter_by(is_active=True).count()
    return render_template('dashboard.html',
                           total_users=total_users,
                           active_users=active_users,
                           expired_users=expired_users,
                           total_traffic=total_traffic,
                           total_traffic_limit=total_traffic_limit,
                           total_requests=total_requests,
                           total_inbounds=total_inbounds)

# ---------- مدیریت کاربران ----------
@app.route('/users')
@login_required
def users():
    search = request.args.get('search', '')
    if search:
        all_users = User.query.filter(User.username.contains(search)).all()
    else:
        all_users = User.query.all()
    # به‌روزرسانی وضعیت
    for user in all_users:
        real_status = check_user_status(user)
        if user.status != real_status:
            user.status = real_status
    db.session.commit()
    return render_template('users.html', users=all_users)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    form = UserForm()
    form.inbound_id.choices = [(i.id, i.name) for i in Inbound.query.filter_by(is_active=True).all()]
    if form.validate_on_submit():
        expiry_date = None
        if form.expiry_date.data and form.expiry_date.data.strip():
            try:
                expiry_date = datetime.strptime(form.expiry_date.data, '%Y-%m-%d')
            except ValueError:
                flash('فرمت تاریخ نامعتبر است. از YYYY-MM-DD استفاده کنید.', 'danger')
                return render_template('add_user.html', form=form)
        user = User(
            username=form.username.data,
            status=form.status.data,
            traffic_limit=form.traffic_limit.data,
            traffic_used=form.traffic_used.data,
            requests=form.requests.data,
            expiry_date=expiry_date,
            online=form.online.data,
            ports=form.ports.data,
            max_ips=form.max_ips.data,
            inbound_id=form.inbound_id.data
        )
        user.uuid = uuid.uuid4().hex
        user.link = generate_user_link(user.username, user.uuid, user.inbound_id)
        user.time = user.get_expiry_status()
        db.session.add(user)
        db.session.commit()
        flash('کاربر با موفقیت اضافه شد', 'success')
        return redirect(url_for('users'))
    return render_template('add_user.html', form=form)

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    user = User.query.get_or_404(id)
    form = UserForm(obj=user)
    form.inbound_id.choices = [(i.id, i.name) for i in Inbound.query.filter_by(is_active=True).all()]
    if user.expiry_date:
        form.expiry_date.data = user.expiry_date.strftime('%Y-%m-%d')
    if form.validate_on_submit():
        expiry_date = None
        if form.expiry_date.data and form.expiry_date.data.strip():
            try:
                expiry_date = datetime.strptime(form.expiry_date.data, '%Y-%m-%d')
            except ValueError:
                flash('فرمت تاریخ نامعتبر است. از YYYY-MM-DD استفاده کنید.', 'danger')
                return render_template('edit_user.html', form=form, user=user)
        user.username = form.username.data
        user.status = form.status.data
        user.traffic_limit = form.traffic_limit.data
        user.traffic_used = form.traffic_used.data
        user.requests = form.requests.data
        user.expiry_date = expiry_date
        user.online = form.online.data
        user.ports = form.ports.data
        user.max_ips = form.max_ips.data
        user.inbound_id = form.inbound_id.data
        user.time = user.get_expiry_status()
        user.link = generate_user_link(user.username, user.uuid, user.inbound_id)
        db.session.commit()
        flash('کاربر ویرایش شد', 'success')
        return redirect(url_for('users'))
    return render_template('edit_user.html', form=form, user=user)

@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('کاربر حذف شد', 'success')
    return redirect(url_for('users'))

# ---------- مدیریت اینباندها ----------
@app.route('/inbounds')
@login_required
def inbounds():
    all_inbounds = Inbound.query.all()
    return render_template('inbounds.html', inbounds=all_inbounds)

@app.route('/add_inbound', methods=['GET', 'POST'])
@login_required
def add_inbound():
    form = InboundForm()
    if form.validate_on_submit():
        inbound = Inbound(
            name=form.name.data,
            domain=form.domain.data,
            port=form.port.data,
            path=form.path.data,
            protocol=form.protocol.data,
            security=form.security.data,
            sni=form.sni.data,
            allow_insecure=form.allow_insecure.data,
            is_active=form.is_active.data,
            config_extra=form.config_extra.data
        )
        db.session.add(inbound)
        db.session.commit()
        flash('اینباند با موفقیت اضافه شد', 'success')
        return redirect(url_for('inbounds'))
    return render_template('add_inbound.html', form=form)

@app.route('/edit_inbound/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_inbound(id):
    inbound = Inbound.query.get_or_404(id)
    form = InboundForm(obj=inbound)
    if form.validate_on_submit():
        form.populate_obj(inbound)
        db.session.commit()
        flash('اینباند ویرایش شد', 'success')
        return redirect(url_for('inbounds'))
    return render_template('edit_inbound.html', form=form, inbound=inbound)

@app.route('/delete_inbound/<int:id>')
@login_required
def delete_inbound(id):
    inbound = Inbound.query.get_or_404(id)
    db.session.delete(inbound)
    db.session.commit()
    flash('اینباند حذف شد', 'success')
    return redirect(url_for('inbounds'))

# ---------- تنظیمات ----------
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    password_form = ChangePasswordForm()
    if password_form.validate_on_submit():
        admin = Admin.query.filter_by(username='admin').first()
        if admin and check_password_hash(admin.password, password_form.current_password.data):
            admin.password = generate_password_hash(password_form.new_password.data)
            db.session.commit()
            flash('رمز عبور با موفقیت تغییر کرد', 'success')
            return redirect(url_for('settings'))
        else:
            flash('رمز عبور فعلی اشتباه است', 'danger')
    if request.method == 'POST' and 'language' in request.form:
        Setting.set('language', request.form['language'])
        flash('زبان با موفقیت تغییر کرد', 'success')
        return redirect(url_for('settings'))
    if request.method == 'POST' and 'theme' in request.form:
        Setting.set('theme', request.form['theme'])
        flash('تم با موفقیت تغییر کرد', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html',
                         password_form=password_form,
                         current_language=Setting.get('language', 'fa'),
                         current_theme=Setting.get('theme', 'light'))

# ============================================================
# ایجاد دیتابیس
# ============================================================
with app.app_context():
    db.create_all()

# ============================================================
# اجرا
# ============================================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
