import os
import secrets
import sys
import time
import threading
import smtplib
import random
import io
import base64
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from sklearn.cluster import KMeans
from sklearn.linear_model import LinearRegression
from flask import Flask, request, redirect, url_for, session, render_template, jsonify
from pathlib import Path
from werkzeug.utils import secure_filename
from email.message import EmailMessage

class man_system:
    def __init__(self):
        if getattr(sys, 'frozen', False):
            self.dir_root = Path(sys.executable).parent.resolve()
        else:
            self.dir_root = Path(__file__).parent.resolve()
        self.dir_db = self.dir_root / "database"
        self.system_dir = self.dir_db / "system"
        self.user_db_path = self.system_dir / "user.sysriot"
        self.system_conf_path = self.system_dir / "system.sysriot"
        self.analysis_conf_path = self.system_dir / "analysis.sysriot"
        self.master_check()
        self.master_init()

    def master_check(self):
        self.dir_root.mkdir(parents=True, exist_ok=True)
        self.dir_db.mkdir(parents=True, exist_ok=True)
        self.system_dir.mkdir(parents=True, exist_ok=True)
        (self.dir_root / "static" / "res").mkdir(parents=True, exist_ok=True)
        (self.dir_root / "static" / "themes").mkdir(parents=True, exist_ok=True)

    def parse_sysriot(self, path):
        data = {}
        if not path.exists():
            return data
        current_section = None
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    current_section = line[1:-1]
                    data[current_section] = {}
                elif "=" in line and current_section:
                    k, v = line.split("=", 1)
                    val = v.strip()
                    if val.lstrip('-').isdigit():
                        val = int(val)
                    elif val.lower() == "true":
                        val = True
                    elif val.lower() == "false":
                        val = False
                    data[current_section][k.strip()] = val
        return data

    def save_sysriot(self, path, data):
        with open(path, "w") as f:
            for section, values in data.items():
                f.write(f"[{section}]\n")
                for k, v in values.items():
                    f.write(f"{k}={v}\n")
                f.write("\n")

    def master_init(self):
        if not self.system_conf_path.exists():
            default_config = {
                "security": {
                    "block_common_usernames": "root,system,admin",
                    "allowed_email_domains": "unikom,duck.com",
                    "blocked_emails": ""
                },
                "server": {
                    "port": 5000,
                    "debug_mode": "false",
                    "session_timeout_minutes": 60
                }
            }
            self.save_sysriot(self.system_conf_path, default_config)
        if not list(self.dir_db.glob("*.sysriot")):
            defaults = {
                "admin": {"info": {"password": "Perkumpulan@adminbersama007", "level": 2, "theme": "default", "email": ""}},
            }
            for u, cfg in defaults.items():
                self.save_sysriot(self.dir_db / f"{u}.sysriot", cfg)

    def load_users(self):
        users = {}
        for f in self.dir_db.glob("*.sysriot"):
            if f.parent == self.system_dir:
                continue
            u_data = self.parse_sysriot(f)
            if "info" in u_data:
                users[f.stem] = u_data["info"]
        return users

    def save_users(self, users):
        for u, data in users.items():
            self.save_sysriot(self.dir_db / f"{u}.sysriot", {"info": data})

    def load_config(self):
        return self.parse_sysriot(self.system_conf_path)

    def save_config(self, config_data):
        self.save_sysriot(self.system_conf_path, config_data)

    def write_log(self, user, action, detail):
        log_path = self.system_dir / "logs.sysriot"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] user={user} action={action} detail={detail}\n"
        with open(log_path, "a") as f:
            f.write(log_entry)

    def get_db_usage(self):
        total_size = 0
        for f in self.dir_db.rglob('*'):
            if f.is_file():
                total_size += f.stat().st_size
        return total_size

    def get_total_usage_formatted(self):
        total_size = 0
        for f in self.dir_db.rglob('*'):
            if f.is_file():
                total_size += f.stat().st_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if total_size < 1024:
                return f"{total_size:.2f} {unit}"
            total_size /= 1024
        return f"{total_size:.2f} TB"

    def delete_user_data(self, username):
        u_path = self.dir_db / f"{username}.sysriot"
        if u_path.exists():
            os.remove(u_path)
        user_dir = self.dir_db / username
        if user_dir.exists() and user_dir.is_dir():
            import shutil
            shutil.rmtree(user_dir)


class webserver:
    def __init__(self):
        self.sys_man = man_system()
        self.app = Flask(__name__, template_folder='static', static_folder='static')
        self.app.secret_key = "DEVKEY"
        self.active_sessions = {}
        self.pending_registrations = {}
        self.routes()
        self.start_cleanup_thread()

    def start_cleanup_thread(self):
        def cleanup():
            while True:
                time.sleep(600)
                now = time.time()
                expired = [k for k, v in self.pending_registrations.items() if now - v.get('time', 0) > 300]
                for k in expired:
                    del self.pending_registrations[k]

        t = threading.Thread(target=cleanup, daemon=True)
        t.start()

    def send_otp(self, target_email, code):
        conf = self.sys_man.load_config().get('mail', {})
        if not conf:
            return False
        msg = EmailMessage()
        msg['Subject'] = 'Verification Code'
        msg['From'] = conf.get('user')
        msg['To'] = target_email
        msg.set_content(f"Your verification code is: {code}. Valid for 5 minutes.")

        logo_path = self.sys_man.dir_root / "static" / "res" / "logo_OTP.png"
        img_tag = '<img src="cid:logo" style="width: 140px; margin-bottom: 20px;">' if logo_path.exists() else ''

        html_content = f"""
        <div style="font-family: 'Segoe UI', Helvetica, Arial, sans-serif; background-color: #f0f2f5; padding: 40px 10px; text-align: center;">
            <div style="max-width: 480px; margin: auto; background-color: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); border: 1px solid #e1e4e8;">
                {img_tag}
                <h2 style="color: #1a1a1a; margin-top: 0; font-weight: 600;">Security Verification</h2>
                <p style="color: #4a5568; font-size: 16px; line-height: 1.5;">Please use the following verification code to complete your request.</p>
                <div style="margin: 30px 0; padding: 20px; background-color: #f8fafc; border-radius: 8px; border: 2px dashed #cbd5e0;">
                    <span style="font-size: 38px; font-weight: 800; color: #2563eb; letter-spacing: 6px; font-family: monospace;">{code}</span>
                </div>
                <p style="color: #a0aec0; font-size: 11px; margin: 0;">&copy; {time.strftime("%Y")} RIOT Management System.</p>
            </div>
        </div>
        """
        msg.add_alternative(html_content, subtype='html')
        if logo_path.exists():
            html_part = msg.get_payload()[1]
            with open(logo_path, 'rb') as f:
                img_data = f.read()
            html_part.add_related(img_data, 'image', 'png', cid='logo')

        try:
            with smtplib.SMTP_SSL(conf.get('host'), conf.get('port')) as smtp:
                smtp.login(conf.get('user'), conf.get('pass'))
                smtp.send_message(msg)
            return True
        except:
            return False

    def render_page(self, template_name, use_frame=True, **kwargs):
        users = self.sys_man.load_users()
        current_theme = 'default'
        if 'username' in session and session['username'] in users:
            candidate = users[session['username']].get('theme', 'default')
            theme_path = Path(self.app.static_folder) / 'themes' / f"{candidate}.css"
            if theme_path.exists():
                current_theme = candidate

        kwargs['theme'] = current_theme
        kwargs['username'] = session.get('username')
        kwargs['level'] = session.get('level', 0)
        kwargs['config'] = self.sys_man.load_config()
        kwargs['db_usage'] = self.sys_man.get_db_usage()
        if not use_frame:
            return render_template(template_name, **kwargs)
        if request.args.get('content'):
            return render_template(template_name, **kwargs)

        target_url = f"{template_name}?content=1"
        return render_template('frame.html', target=target_url, **kwargs)

    def create_session(self, username, level):
        session['username'] = username
        session['level'] = int(level)
        session['login_time'] = time.time()
        token = secrets.token_hex(16)
        session['token'] = token
        self.active_sessions[username] = token

    def routes(self):
        @self.app.before_request
        def session_management():
            if request.endpoint == 'static':
                return
            if 'username' in session:
                c_user = session['username']
                c_token = session.get('token')
                if c_user not in self.active_sessions or self.active_sessions[c_user] != c_token:
                    session.clear()
                    return redirect(url_for('index_route'))
                config = self.sys_man.load_config()
                timeout_minutes = int(config.get('server', {}).get('session_timeout_minutes', 60))
                login_time = session.get('login_time', 0)
                if time.time() - login_time > (timeout_minutes * 60):
                    if c_user in self.active_sessions:
                        del self.active_sessions[c_user]
                    session.clear()
                    return redirect(url_for('index_route', content=1, notify_title="Session Expired", notify_msg="Your session has expired"))

        @self.app.route('/', methods=['GET', 'POST'])
        @self.app.route('/index.html', methods=['GET', 'POST'])
        def index_route():
            if 'username' in session and not session.get('pending_2fa') and not session.get('reg_id'):
                return redirect(url_for('home'))
            req_mode = request.args.get('mode')
            if req_mode in ['login', 'signup']:
                session.pop('pending_2fa', None)
                session.pop('reg_id', None)
                session.pop('active_otp_data', None)
                session.pop('temp_user', None)
                mode = req_mode
            else:
                if session.get('pending_2fa') or session.get('reg_id'):
                    mode = 'verify'
                else:
                    mode = 'login'
            error = None
            remaining = 0
            target_email = "your email"
            if mode == 'verify':
                reg_id = session.get('reg_id')
                otp_data = None
                if reg_id:
                    otp_data = self.pending_registrations.get(reg_id)
                else:
                    otp_data = session.get('active_otp_data')
                    if otp_data and not otp_data.get('email'):
                        users = self.sys_man.load_users()
                        temp_user = session.get('temp_user') or session.get('username')
                        if temp_user and temp_user in users:
                            otp_data['email'] = users[temp_user].get('email')
                if not otp_data:
                    session.pop('pending_2fa', None)
                    session.pop('reg_id', None)
                    session.pop('active_otp_data', None)
                    session.pop('temp_user', None)
                    mode = 'login'
                else:
                    target_email = otp_data.get('email', 'your email')
                    elapsed = time.time() - otp_data['time']
                    remaining = max(0, int(300 - elapsed))
            if request.method == 'POST':
                action = request.form.get('action')
                if action == 'login':
                    username = request.form.get('username')
                    password = request.form.get('password')
                    users = self.sys_man.load_users()
                    if username in users:
                        u_level = users[username].get('level', 0)
                        conf_sec = self.sys_man.load_config().get('security', {})
                        blocked_emails = [e.strip().lower() for e in conf_sec.get('blocked_emails', '').split(',') if e.strip()]
                        user_email = users[username].get('email', '').lower()

                        if user_email in blocked_emails and u_level != 0 and u_level != -1:
                            users[username]['level'] = 0
                            self.sys_man.save_sysriot(self.sys_man.dir_db / f"{username}.sysriot", {"info": users[username]})
                            u_level = 0
                            self.sys_man.write_log("SYSTEM", "auto_ban", f"Banned user {username} (Blocked Email)")

                        if u_level == 0 and username != 'admin':
                            error = "Account Banned"
                        elif str(users[username]['password']) == str(password):
                            if users[username].get('2fa', True):
                                otp_code = secrets.token_hex(3).upper()
                                session['pending_2fa'] = True
                                session['temp_user'] = username
                                session['active_otp_data'] = {"otp": otp_code, "time": time.time(), "type": "2fa", "email": users[username].get('email')}
                                threading.Thread(target=self.send_otp, args=(users[username]['email'], otp_code)).start()
                                return redirect(url_for('index_route'))
                            self.create_session(username, u_level)
                            return redirect(url_for('home'))
                        else:
                            error = "Invalid Credentials"
                    else:
                        error = "Invalid Credentials"
                    mode = 'login'
                elif action == 'signup':
                    username = request.form.get('username', '').strip()
                    email = request.form.get('email', '').strip()
                    password = request.form.get('password')
                    confirm = request.form.get('confirm_password')
                    agree = request.form.get('agree')
                    users = self.sys_man.load_users()
                    conf_sec = self.sys_man.load_config().get('security', {})
                    allowed_domains = [d.strip().lower() for d in conf_sec.get('allowed_email_domains', '').split(',') if d.strip()]
                    blocked_emails = [e.strip().lower() for e in conf_sec.get('blocked_emails', '').split(',') if e.strip()]
                    domain = email.split('@')[1].lower() if '@' in email else ''
                    domain_allowed = False
                    if not allowed_domains:
                        domain_allowed = True
                    else:
                        for d in allowed_domains:
                            if d in domain:
                                domain_allowed = True
                                break

                    if not agree:
                        error = "You must agree to the Terms & Conditions"
                    elif password != confirm:
                        error = "Passwords do not match"
                    elif not domain_allowed:
                        error = "Email domain not allowed by system policy"
                    elif email.lower() in blocked_emails:
                        error = "This email address is banned"
                    elif any(u.get('email') == email for u in users.values()):
                        error = "Email already linked"
                    elif (self.sys_man.dir_db / f"{username}.sysriot").exists():
                        error = "Username unavailable"
                    else:
                        otp_code = secrets.token_hex(3).upper()
                        reg_id = secrets.token_hex(8)
                        self.pending_registrations[reg_id] = {"username": username, "email": email, "password": password, "otp": otp_code, "time": time.time()}
                        session['reg_id'] = reg_id
                        threading.Thread(target=self.send_otp, args=(email, otp_code)).start()
                        return redirect(url_for('index_route'))
                    mode = 'signup'
                elif action == 'verify':
                    user_input = request.form.get('otp', '').upper()
                    reg_id = session.get('reg_id')
                    pending = self.pending_registrations.get(reg_id) if reg_id else None
                    active_otp = session.get('active_otp_data')
                    otp_data = pending if pending else active_otp
                    if not otp_data:
                        return redirect(url_for('index_route', mode='login'))
                    if remaining <= 0:
                        error = "Code expired. Please resend."
                    elif user_input == otp_data['otp']:
                        users = self.sys_man.load_users()
                        if pending:
                            target_user = pending['username']
                            u_data = {"password": pending['password'], "email": pending['email'], "level": 1, "theme": "default", "2fa": True}
                            self.sys_man.save_sysriot(self.sys_man.dir_db / f"{target_user}.sysriot", {"info": u_data})
                            del self.pending_registrations[reg_id]
                            session.pop('reg_id')
                            self.create_session(target_user, 1)
                        elif active_otp.get('type') == '2fa':
                            target_user = session.get('temp_user')
                            self.create_session(target_user, users[target_user].get('level', 0))
                            session.pop('pending_2fa', None)
                            session.pop('temp_user', None)
                            session.pop('active_otp_data', None)
                        return redirect(url_for('home'))
                    else:
                        error = "Invalid code"
                    mode = 'verify'
                elif action == 'resend':
                    now = time.time()
                    last_time = session.get('last_otp_time', 0)
                    if now - last_time < 30:
                        error = f"Please wait {int(30 - (now - last_time))} seconds."
                    else:
                        session['last_otp_time'] = now
                        target_mail = None
                        otp_code = secrets.token_hex(3).upper()
                        if 'reg_id' in session and session['reg_id'] in self.pending_registrations:
                            reg_id = session['reg_id']
                            self.pending_registrations[reg_id]['otp'] = otp_code
                            self.pending_registrations[reg_id]['time'] = now
                            target_mail = self.pending_registrations[reg_id]['email']
                        elif 'active_otp_data' in session:
                            session['active_otp_data']['otp'] = otp_code
                            session['active_otp_data']['time'] = now
                            target_mail = session['active_otp_data'].get('email')
                            if not target_mail:
                                users = self.sys_man.load_users()
                                user_key = session.get('temp_user') or session.get('username')
                                if user_key in users:
                                    target_mail = users[user_key]['email']
                        if target_mail:
                            threading.Thread(target=self.send_otp, args=(target_mail, otp_code)).start()
                            remaining = 300
                    mode = 'verify'
            bg_image = None
            frame_dir = self.sys_man.dir_root / "static" / "res" / "login"
            if frame_dir.exists():
                images = list(frame_dir.glob("*.jpg"))
                if images:
                    bg_image = f"res/login/{random.choice(images).name}"
            return self.render_page('index.html', use_frame=False, error=error, remaining=remaining, bg_image=bg_image, mode=mode, target_email=target_email)

        @self.app.route('/home.html')
        def home():
            if 'username' not in session:
                return redirect(url_for('index_route'))
            return self.render_page('home.html', use_frame=True)

        @self.app.route('/API/db/add_data', methods=['POST'])
        def add_data():
            if 'username' not in session:
                return redirect(url_for('index_route'))
            f = request.files.get('file')
            note = request.form.get('note', '')
            if f and f.filename:
                if not f.filename.lower().endswith('.csv'):
                    return redirect(url_for('database', content=1, notify_title="Upload Failed", notify_msg="Invalid file type. Please upload only a .CSV file"))

                user_path = self.sys_man.dir_db / session['username']
                user_path.mkdir(parents=True, exist_ok=True)

                current_usage = 0
                for item in user_path.iterdir():
                    if item.is_file() and item.name != "indexing.sysriot":
                        current_usage += item.stat().st_size

                f.seek(0, os.SEEK_END)
                file_size = f.tell()
                f.seek(0)

                if current_usage + file_size > 10 * 1024 * 1024:
                    return redirect(url_for('database', content=1, notify_title="Upload Failed", notify_msg="Sorry, there is not enough storage to upload this file. Please clean up your storage and try again"))

                filename = secure_filename(f.filename)
                file_stem = Path(filename).stem
                file_suffix = Path(filename).suffix

                if len(file_stem) > 80:
                    file_stem = file_stem[:80]

                filename = f"{file_stem}{file_suffix}"
                file_path = user_path / filename

                counter = 1
                while file_path.exists():
                    filename = f"{file_stem}-{counter}{file_suffix}"
                    file_path = user_path / filename
                    counter += 1

                f.save(file_path)

                index_path = user_path / "indexing.sysriot"
                index_data = self.sys_man.parse_sysriot(index_path)
                file_id = secrets.token_hex(8)

                index_data[file_id] = {
                    "file": filename,
                    "name": filename,
                    "note": note,
                    "size": file_path.stat().st_size,
                    "uploaded_at": time.strftime("%Y-%m-%d %H:%M")
                }
                self.sys_man.save_sysriot(index_path, index_data)
            return redirect(url_for('database', content=1))

        @self.app.route('/API/db/edit_data/<data_id>', methods=['POST'])
        def edit_data(data_id):
            if 'username' not in session:
                return redirect(url_for('index_route'))

            user_path = self.sys_man.dir_db / session['username']
            public_path = self.sys_man.dir_db / "public"
            index_path = user_path / "indexing.sysriot"
            public_index_path = public_path / "indexing.sysriot"

            index_data = self.sys_man.parse_sysriot(index_path)
            target_path = user_path
            target_index_path = index_path

            if data_id not in index_data:
                user_level = session.get('level', 0)
                if user_level == 2 or user_level == -1:
                    index_data = self.sys_man.parse_sysriot(public_index_path)
                    if data_id in index_data:
                        target_path = public_path
                        target_index_path = public_index_path
                    else:
                        return redirect(url_for('database', content=1, notify_title="Upload Failed", notify_msg="Sorry, there is not enough storage to upload this file. Please clean up your storage and try again"))
                else:
                    return redirect(url_for('database', content=1, notify_title="Edit Failed", notify_msg="Sorry, there is a problem while editing your file. Please try again later"))

            current_data = index_data[data_id]
            new_name = request.form.get('name', '').strip()
            new_note = request.form.get('note', '')

            if new_name:
                old_filename = current_data.get('file')
                safe_new_name = secure_filename(new_name)

                if len(safe_new_name) > 80:
                    safe_new_name = safe_new_name[:80]

                final_filename = f"{safe_new_name}.csv"

                old_file_path = target_path / old_filename
                new_file_path = target_path / final_filename

                if old_file_path.exists():
                    try:
                        os.rename(old_file_path, new_file_path)
                        current_data['file'] = final_filename
                        current_data['name'] = final_filename
                    except:
                        return redirect(url_for('database', content=1, notify_title="Edit Failed", notify_msg="Sorry, there is a problem while renaming your file. Please try again later"))

            current_data['note'] = new_note
            index_data[data_id] = current_data
            self.sys_man.save_sysriot(target_index_path, index_data)
            return redirect(url_for('database', content=1))

        @self.app.route('/API/db/delete_data/<data_id>', methods=['POST'])
        def delete_data(data_id):
            if 'username' not in session:
                return redirect(url_for('index_route'))

            user_path = self.sys_man.dir_db / session['username']
            public_path = self.sys_man.dir_db / "public"
            index_path = user_path / "indexing.sysriot"
            public_index_path = public_path / "indexing.sysriot"

            index_data = self.sys_man.parse_sysriot(index_path)
            target_path = user_path
            target_index_path = index_path

            if data_id not in index_data:
                user_level = session.get('level', 0)
                if user_level == 2 or user_level == -1:
                    index_data = self.sys_man.parse_sysriot(public_index_path)
                    if data_id in index_data:
                        target_path = public_path
                        target_index_path = public_index_path
                    else:
                        return redirect(url_for('database', content=1, notify_title="Delete Failed", notify_msg="Sorry, there is a problem while trying to find the file"))
                else:
                    return redirect(url_for('database', content=1, notify_title="Delete Failed", notify_msg="Sorry, there is a problem while deleting your file. Please try again later"))

            file_info = index_data.pop(data_id)
            filename = file_info.get('file')
            if filename:
                file_path = target_path / filename
                if file_path.exists():
                    os.remove(file_path)

            self.sys_man.save_sysriot(target_index_path, index_data)
            return redirect(url_for('database', content=1))

        @self.app.route('/API/db/delete_all_data', methods=['POST'])
        def delete_all_data():
            if 'username' not in session:
                return redirect(url_for('index_route'))

            user_path = self.sys_man.dir_db / session['username']
            if user_path.exists():
                index_path = user_path / "indexing.sysriot"

                for item in user_path.glob("*.csv"):
                    try:
                        os.remove(item)
                    except:
                        pass

                self.sys_man.save_sysriot(index_path, {})

            return redirect(url_for('database', content=1))

        @self.app.route('/database.html')
        def database():
            if 'username' not in session:
                return redirect(url_for('index_route'))

            user_path = self.sys_man.dir_db / session['username']
            public_path = self.sys_man.dir_db / "public"
            user_path.mkdir(parents=True, exist_ok=True)
            public_path.mkdir(parents=True, exist_ok=True)

            user_index = self.sys_man.parse_sysriot(user_path / "indexing.sysriot")
            public_index = self.sys_man.parse_sysriot(public_path / "indexing.sysriot")

            datasets = []
            user_usage = 0
            limit_size = 10 * 1024 * 1024

            def format_size(size):
                if not isinstance(size, (int, float)):
                    return str(size)
                for unit in ['B', 'KB', 'MB', 'GB']:
                    if size < 1024:
                        return f"{size:.1f} {unit}"
                    size /= 1024
                return f"{size:.1f} TB"

            existing_files = {f.name: f for f in user_path.iterdir() if f.is_file() and f.name != "indexing.sysriot"}

            for fid, info in user_index.items():
                fname = info.get('file')
                if fname in existing_files:
                    f_size = existing_files[fname].stat().st_size
                    user_usage += f_size
                    datasets.append({
                        "data_id": fid,
                        "name": info.get('name', fname),
                        "note": info.get('note', ''),
                        "type": Path(fname).suffix,
                        "size": format_size(f_size),
                        "uploaded_at": info.get('uploaded_at', ''),
                        "is_public": False
                    })
                    del existing_files[fname]

            for fname, f_obj in existing_files.items():
                f_size = f_obj.stat().st_size
                user_usage += f_size
                datasets.append({
                    "data_id": "raw_" + fname,
                    "name": fname,
                    "note": "Unindexed File",
                    "type": f_obj.suffix,
                    "size": format_size(f_size),
                    "uploaded_at": time.strftime("%Y-%m-%d %H:%M", time.localtime(f_obj.stat().st_mtime)),
                    "is_public": False
                })

            public_files = {f.name: f for f in public_path.iterdir() if f.is_file() and f.name != "indexing.sysriot"}
            for fid, info in public_index.items():
                fname = info.get('file')
                if fname in public_files:
                    datasets.append({
                        "data_id": fid,
                        "name": info.get('name', fname),
                        "note": info.get('note', 'Public Resource'),
                        "type": Path(fname).suffix,
                        "size": format_size(public_files[fname].stat().st_size),
                        "uploaded_at": info.get('uploaded_at', ''),
                        "is_public": True
                    })

            search_query = request.args.get('cari', '').lower()
            if search_query:
                datasets = [d for d in datasets if search_query in d['name'].lower()]

            return self.render_page(
                'database.html',
                use_frame=True,
                datasets=datasets,
                current_count=format_size(user_usage),
                limit_count=format_size(limit_size),
                storage_percent=min(100, int((user_usage / limit_size) * 100))
            )

        @self.app.route('/analysis.html')
        def analysis():
            if 'username' not in session:
                return redirect(url_for('index_route'))
            return self.render_page('analysis.html', use_frame=True)

        @self.app.route('/user_settings.html', methods=['GET', 'POST'])
        def user_settings():
            if 'username' not in session:
                return redirect(url_for('index_route'))
            users = self.sys_man.load_users()
            target_user = request.args.get('edit_user', session['username'])
            user_level = session.get('level', 0)

            if user_level != -1:
                target_level = users.get(target_user, {}).get('level', 0)
                if user_level != 2:
                    target_user = session['username']
                elif target_level == -1:
                    return redirect(url_for('admin_settings', content=1))

            if request.method == 'POST':
                new_username = request.form.get('new_username', '').strip().lower()
                new_email = request.form.get('email', '').strip().lower()
                is_2fa = request.form.get('2fa') == 'on'
                u_data = users[target_user]
                u_data['password'] = request.form.get('password') or u_data['password']
                u_data['theme'] = request.form.get('theme')
                u_data['email'] = new_email or u_data['email']
                u_data['2fa'] = is_2fa
                if new_username and new_username != target_user:
                    if not (self.sys_man.dir_db / f"{new_username}.sysriot").exists():
                        os.remove(self.sys_man.dir_db / f"{target_user}.sysriot")
                        target_user = new_username
                        if session['username'] != 'admin':
                            session['username'] = new_username
                self.sys_man.save_sysriot(self.sys_man.dir_db / f"{target_user}.sysriot", {"info": u_data})
                return redirect(url_for('user_settings', edit_user=target_user, content=1))
            themes = {f.stem.lower() for f in (Path(self.app.static_folder) / "themes").glob("*.css")}
            if 'default' in themes:
                themes.remove('default')
            themes = sorted(list(themes))
            themes.insert(0, 'Default')

            return self.render_page('user_settings.html', use_frame=True, themes=themes, target_user=target_user, target_data=users.get(target_user, {}))

        @self.app.route('/API/user/init_delete', methods=['POST'])
        def api_init_delete():
            if 'username' not in session:
                return jsonify({"status": "error"}), 403
            user = session['username']
            users = self.sys_man.load_users()
            if user not in users:
                return jsonify({"status": "error"}), 400

            otp_code = secrets.token_hex(3).upper()
            session['delete_otp'] = {"code": otp_code, "time": time.time()}
            threading.Thread(target=self.send_otp, args=(users[user]['email'], otp_code)).start()
            return jsonify({"status": "success"})

        @self.app.route('/API/user/confirm_delete', methods=['POST'])
        def api_confirm_delete():
            if 'username' not in session:
                return jsonify({"status": "error"}), 403
            otp_input = request.json.get('otp', '').upper()
            otp_data = session.get('delete_otp')

            if not otp_data or time.time() - otp_data['time'] > 300:
                return jsonify({"status": "error", "msg": "OTP Expired"}), 400

            if otp_input != otp_data['code']:
                return jsonify({"status": "error", "msg": "Invalid OTP"}), 400

            user = session['username']
            self.sys_man.delete_user_data(user)
            self.sys_man.write_log("SYSTEM", "account_delete", f"User {user} deleted their account")

            session.clear()
            return jsonify({"status": "success"})

        @self.app.route('/API/admin/system_status', methods=['GET'])
        def api_system_status():
            user_level = session.get('level', 0)
            if user_level != -1 and user_level != 2:
                return jsonify({"status": "error"}), 403
            files = []
            for path in self.sys_man.dir_root.rglob('*'):
                if path.is_file():
                    files.append({
                        "name": str(path.relative_to(self.sys_man.dir_root)),
                        "size": f"{path.stat().st_size / 1024:.1f} KB"
                    })
            return jsonify({"status": "success", "files": files, "time": time.strftime("%Y-%m-%d %H:%M:%S")})

        @self.app.route('/API/admin/create_user', methods=['POST'])
        def api_create_user():
            user_level = session.get('level', 0)
            if user_level != -1 and user_level != 2:
                return jsonify({"status": "error"}), 403
            data = request.json
            username = data.get('username', '').lower().strip()
            email = data.get('email', '').lower().strip()
            password = data.get('password')
            level = int(data.get('level', 0))

            if user_level != -1 and level == -1:
                return jsonify({"status": "error"}), 403

            if not username or not password or not email:
                return jsonify({"status": "error"}), 400
            if (self.sys_man.dir_db / f"{username}.sysriot").exists():
                return jsonify({"status": "exists"}), 400
            new_user_data = {"info": {"password": password, "email": email, "level": level, "theme": "default"}}
            self.sys_man.save_sysriot(self.sys_man.dir_db / f"{username}.sysriot", new_user_data)
            self.sys_man.write_log(session['username'], "create_user", f"Created: {username}")
            return jsonify({"status": "success"})

        @self.app.route('/API/admin/save_config', methods=['POST'])
        def api_save_config():
            user_level = session.get('level', 0)
            if user_level != -1 and user_level != 2:
                return jsonify({"status": "error"}), 403
            new_config = request.json
            current_config = self.sys_man.load_config()
            if user_level != -1:
                if 'mail' in new_config:
                    del new_config['mail']
                if 'server' in new_config:
                    new_config['server'] = current_config.get('server', {})
            self.sys_man.save_config(new_config)
            self.sys_man.write_log(session['username'], "config_update", "Config changed")
            return jsonify({"status": "success"})

        @self.app.route('/API/admin/batch_delete', methods=['POST'])
        def api_batch_delete():
            user_level = session.get('level', 0)
            if user_level != -1 and user_level != 2:
                return jsonify({"status": "error"}), 403
            usernames = request.json.get('users', [])
            current_admin = session.get('username')
            deleted = []
            users = self.sys_man.load_users()
            for u in usernames:
                if u == current_admin or u == 'admin':
                    continue
                target_level = users.get(u, {}).get('level', 0)
                if target_level == -1:
                    continue
                u_path = self.sys_man.dir_db / f"{u}.sysriot"
                if u_path.exists():
                    os.remove(u_path)
                    deleted.append(u)
            if deleted:
                self.sys_man.write_log(current_admin, "batch_delete", f"Deleted: {', '.join(deleted)}")
            return jsonify({"status": "success"})

        @self.app.route('/API/admin/batch_level', methods=['POST'])
        def api_batch_level():
            user_level = session.get('level', 0)
            if user_level != -1 and user_level != 2:
                return jsonify({"status": "error"}), 403
            usernames = request.json.get('users', [])
            new_level = int(request.json.get('level'))

            if user_level != -1 and new_level == -1:
                return jsonify({"status": "error"}), 403

            if new_level is None:
                return jsonify({"status": "error"}), 400
            users = self.sys_man.load_users()
            updated = []
            for u in usernames:
                if u == session['username']:
                    continue
                if u in users:
                    target_level = users[u].get('level', 0)
                    if target_level == -1:
                        continue
                    users[u]['level'] = new_level
                    self.sys_man.save_sysriot(self.sys_man.dir_db / f"{u}.sysriot", {"info": users[u]})
                    updated.append(u)
            if updated:
                self.sys_man.write_log(session['username'], "batch_level", f"Set level {new_level} for: {', '.join(updated)}")
            return jsonify({"status": "success"})

        @self.app.route('/API/admin/upload_theme', methods=['POST'])
        def api_upload_theme():
            user_level = session.get('level', 0)
            if user_level != -1 and user_level != 2:
                return jsonify({"status": "error"}), 403
            file = request.files.get('theme_file')
            if file and file.filename.endswith('.css'):
                filename = secure_filename(file.filename)
                file.save(Path(self.app.static_folder) / "themes" / filename)
                return jsonify({"status": "success"})
            return jsonify({"status": "error"}), 400

        @self.app.route('/API/admin/stat_details', methods=['POST'])
        def api_stat_details():
            user_level = session.get('level', 0)
            if user_level != -1 and user_level != 2:
                return jsonify({"status": "error"}), 403
            category = request.json.get('category')
            identifier = request.json.get('identifier')
            files = []
            target_path = None
            if category == 'config':
                target_path = self.sys_man.system_dir
            elif category == 'public':
                target_path = self.sys_man.dir_db / "public"
            elif category == 'user':
                if user_level == 2:
                    users = self.sys_man.load_users()
                    if identifier in users and users[identifier].get('level', 0) == -1:
                        return jsonify({"status": "error"}), 403
                target_path = self.sys_man.dir_db / identifier
            if target_path and target_path.exists() and target_path.is_dir():
                for f in target_path.iterdir():
                    if f.is_file():
                        can_delete = True
                        if category == 'config' or f.name == 'indexing.sysriot':
                            can_delete = False
                        files.append({
                            "name": f.name,
                            "size": f.stat().st_size,
                            "can_delete": can_delete,
                            "path_id": str(f.relative_to(self.sys_man.dir_db)) if category != 'config' else ''
                        })
            return jsonify({"status": "success", "files": files})

        @self.app.route('/API/admin/stat_delete', methods=['POST'])
        def api_stat_delete():
            user_level = session.get('level', 0)
            if user_level != -1 and user_level != 2:
                return jsonify({"status": "error"}), 403
            path_id = request.json.get('path_id')
            if not path_id:
                return jsonify({"status": "error"}), 400

            path_id = path_id.replace('\\', '/')
            file_path = self.sys_man.dir_db / path_id

            try:
                file_path.resolve().relative_to(self.sys_man.dir_db.resolve())
            except (ValueError, RuntimeError):
                return jsonify({"status": "error"}), 403

            if user_level == 2:
                target_user = Path(path_id).parts[0]
                users = self.sys_man.load_users()
                if target_user in users and users[target_user].get('level', 0) == -1:
                    return jsonify({"status": "error"}), 403

            if file_path.exists() and file_path.name != "indexing.sysriot":
                os.remove(file_path)
                parent_dir = file_path.parent
                index_path = parent_dir / "indexing.sysriot"
                if index_path.exists():
                    index_data = self.sys_man.parse_sysriot(index_path)
                    new_index = {k: v for k, v in index_data.items() if v.get('file') != file_path.name}
                    if len(new_index) != len(index_data):
                        self.sys_man.save_sysriot(index_path, new_index)

                self.sys_man.write_log(session['username'], "stat_delete", f"Deleted: {path_id}")
                return jsonify({"status": "success", "new_size": self.sys_man.get_total_usage_formatted()})
            return jsonify({"status": "error"}), 400

        @self.app.route('/API/admin/delete_theme', methods=['POST'])
        def api_delete_theme():
            user_level = session.get('level', 0)
            if user_level != -1 and user_level != 2:
                return jsonify({"status": "error"}), 403
            theme_name = request.json.get('theme')
            if theme_name and theme_name != 'default':
                theme_path = Path(self.app.static_folder) / "themes" / f"{theme_name}.css"
                if theme_path.exists():
                    os.remove(theme_path)
                    return jsonify({"status": "success"})
            return jsonify({"status": "error"}), 400

        @self.app.route('/API/admin/upload_public', methods=['POST'])
        def api_upload_public():
            user_level = session.get('level', 0)
            if user_level != -1 and user_level != 2:
                return jsonify({"status": "error"}), 403
            f = request.files.get('file')
            if f and f.filename and f.filename.endswith('.csv'):
                public_path = self.sys_man.dir_db / "public"
                filename = secure_filename(f.filename)
                file_path = public_path / filename
                if file_path.exists():
                    file_stem = Path(filename).stem
                    file_suffix = Path(filename).suffix
                    counter = 1
                    while file_path.exists():
                        filename = f"{file_stem}-{counter}{file_suffix}"
                        file_path = public_path / filename
                        counter += 1
                f.save(file_path)
                index_path = public_path / "indexing.sysriot"
                index_data = self.sys_man.parse_sysriot(index_path)
                file_id = secrets.token_hex(8)
                index_data[file_id] = {
                    "file": filename,
                    "name": filename,
                    "note": "This File Is provided by Us and wont eat your storage",
                    "size": file_path.stat().st_size,
                    "uploaded_at": time.strftime("%Y-%m-%d %H:%M")
                }
                self.sys_man.save_sysriot(index_path, index_data)
                self.sys_man.write_log(session['username'], "upload_public", f"Uploaded: {filename}")
                return jsonify({"status": "success", "new_size": self.sys_man.get_total_usage_formatted()})
            return jsonify({"status": "error"}), 400

        @self.app.route('/admin_settings.html')
        def admin_settings():
            user_level = session.get('level', 0)
            if user_level != -1 and user_level != 2:
                return redirect(url_for('home'))

            users = self.sys_man.load_users()
            stats = {
                "total_size": self.sys_man.get_total_usage_formatted(),
                "system_config": "0 B",
                "public": {"count": 0, "size": "0 B"},
                "users": {}
            }

            sc_path = self.sys_man.system_conf_path
            if sc_path.exists():
                stats["system_config"] = f"{sc_path.stat().st_size / 1024:.2f} KB"

            pb_path = self.sys_man.dir_db / "public"
            if pb_path.exists():
                p_fs = list(pb_path.glob("*.csv"))
                p_sz = sum(f.stat().st_size for f in p_fs)
                stats["public"] = {"count": len(p_fs), "size": f"{p_sz / 1024:.2f} KB"}

            for u in users:
                u_d = self.sys_man.dir_db / u
                if u_d.exists():
                    u_fs = [f for f in u_d.iterdir() if f.is_file() and f.name != "indexing.sysriot"]
                    u_sz = sum(f.stat().st_size for f in u_fs)
                    stats["users"][u] = {"count": len(u_fs), "size": f"{u_sz / 1024:.2f} KB"}

            themes = [f.stem for f in (Path(self.app.static_folder) / "themes").glob("*.css")]
            logs = []
            l_path = self.sys_man.system_dir / "logs.sysriot"
            if l_path.exists():
                with open(l_path, "r") as f:
                    logs = f.readlines()[-100:]
                logs.reverse()

            return self.render_page('admin_settings.html', use_frame=True, users_list=users, stats=stats, themes=themes, logs=logs)

        @self.app.route('/API/analysis/get_sources', methods=['GET'])
        def api_get_sources():
            if 'username' not in session:
                return jsonify({"status": "error"}), 403

            user_path = self.sys_man.dir_db / session['username']
            public_path = self.sys_man.dir_db / "public"

            sources = []

            if user_path.exists():
                for f in user_path.glob("*.csv"):
                    sources.append({"id": f.name, "name": f.name, "origin": "user"})

            if public_path.exists():
                for f in public_path.glob("*.csv"):
                    sources.append({"id": f.name, "name": f"[Public] {f.name}", "origin": "public"})

            config = {}
            if self.sys_man.analysis_conf_path.exists():
                full_conf = self.sys_man.parse_sysriot(self.sys_man.analysis_conf_path)
                if session['username'] in full_conf:
                    import json
                    try:
                        config = json.loads(full_conf[session['username']].get('data', '{}'))
                    except:
                        pass

            return jsonify({"status": "success", "sources": sources, "config": config})

        @self.app.route('/API/analysis/save_config', methods=['POST'])
        def api_save_analysis_config():
            if 'username' not in session:
                return jsonify({"status": "error"}), 403

            import json
            data_config = request.json
            user = session['username']

            full_conf = self.sys_man.parse_sysriot(self.sys_man.analysis_conf_path)

            if user not in full_conf:
                full_conf[user] = {}

            full_conf[user]['data'] = json.dumps(data_config)
            self.sys_man.save_sysriot(self.sys_man.analysis_conf_path, full_conf)

            return jsonify({"status": "success"})

        @self.app.route('/API/analysis/execute', methods=['POST'])
        def api_execute_analysis():
            if 'username' not in session:
                return jsonify({"status": "error"}), 403

            req = request.json
            slot_id = req.get('slot_id')
            sources = req.get('sources', [])
            atype = req.get('type')
            col_a = req.get('col_a')
            col_b = req.get('col_b')
            param = req.get('param')

            if not sources or not isinstance(sources, list):
                return jsonify({"status": "error", "msg": "No Sources Assigned"})

            dfs = []
            for src in sources:
                user_file = self.sys_man.dir_db / session['username'] / src
                public_file = self.sys_man.dir_db / "public" / src

                target = None
                if user_file.exists():
                    target = user_file
                elif public_file.exists():
                    target = public_file

                if target:
                    try:
                        dfs.append((src, pd.read_csv(target)))
                    except:
                        pass

            if not dfs:
                return jsonify({"status": "error", "msg": "Files not found"})

            try:
                result = ""
                is_image = False

                if slot_id in ['data1', 'data2', 'data3']:
                    primary_name, df = dfs[0]

                    if atype == 'summary':
                        desc = df.describe()
                        html = f"<div class='analysis-text-header'>Source: {primary_name}</div>"
                        html += "<div class='analysis-text-grid'>"
                        for col in desc.columns:
                            stats = desc[col]
                            html += f"<div class='analysis-text-card'><strong>{col}</strong>"
                            for stat_name, val in stats.items():
                                html += f"<div class='analysis-text-row'><span>{stat_name}</span><span>{val:.2f}</span></div>"
                            html += "</div>"
                        html += "</div>"
                        result = html

                    elif atype == 'head':
                        head = df.head(3)
                        html = f"<div class='analysis-text-header'>Source: {primary_name} (First 3)</div>"
                        html += "<div class='analysis-text-list'>"
                        for idx, row in head.iterrows():
                            html += "<div class='analysis-text-item'>"
                            items = []
                            for c, v in row.items():
                                items.append(f"<b>{c}:</b> {v}")
                            html += ", ".join(items)
                            html += "</div>"
                        html += "</div>"
                        result = html

                    elif atype == 'missing':
                        missing = df.isnull().sum()
                        total_rows = len(df)
                        if missing.sum() > 0:
                            html = f"<div class='analysis-text-header'>Missing Data ({primary_name})</div><ul class='analysis-text-clean-list'>"
                            for col, val in missing.items():
                                if val > 0:
                                    pct = (val / total_rows) * 100
                                    html += f"<li><span class='analysis-text-label'>{col}</span> <span class='analysis-text-val-bad'>{val} ({pct:.1f}%)</span></li>"
                            html += "</ul>"
                            result = html
                        else:
                            result = "<div class='analysis-text-success'>✓ Data Clean<br><small>No missing values found</small></div>"
                    else:
                        result = "<div class='text-muted'>Select analysis logic</div>"

                else:
                    fig, ax = plt.subplots(figsize=(6, 4))
                    is_image = True

                    if atype == 'kmeans' and col_a and col_b:
                        primary_name, df = dfs[0]
                        if col_a in df.columns and col_b in df.columns:
                            k = 3
                            if param and str(param).isdigit():
                                k = int(param)

                            X = df[[col_a, col_b]].dropna()
                            kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
                            labels = kmeans.fit_predict(X)

                            scatter = ax.scatter(X[col_a], X[col_b], c=labels, cmap='viridis', alpha=0.6)
                            ax.set_xlabel(col_a)
                            ax.set_ylabel(col_b)
                            ax.set_title(f'K-Means Clustering (k={k})')
                            fig.colorbar(scatter, ax=ax, label='Cluster')
                            fig.tight_layout()

                    elif atype == 'regression' and col_a and col_b:
                        primary_name, df = dfs[0]
                        if col_a in df.columns and col_b in df.columns:
                            data = df[[col_a, col_b]].dropna()
                            X = data[col_a].values.reshape(-1, 1)
                            y = data[col_b].values.reshape(-1, 1)

                            reg = LinearRegression().fit(X, y)
                            y_pred = reg.predict(X)

                            ax.scatter(X, y, alpha=0.5, label='Data')
                            ax.plot(X, y_pred, color='red', linewidth=2, label='Regression Line')
                            ax.set_xlabel(col_a)
                            ax.set_ylabel(col_b)
                            ax.set_title(f'Linear Regression: {col_a} vs {col_b}')
                            ax.legend()
                            fig.tight_layout()

                    elif atype == 'geo' and col_a and col_b:
                        for name, df in dfs:
                            if col_a in df.columns and col_b in df.columns:
                                c = None
                                if param and param in df.columns:
                                    c = df[param]

                                scatter = ax.scatter(df[col_b], df[col_a], c=c, cmap='coolwarm', alpha=0.5, label=name)
                                if c is not None:
                                    fig.colorbar(scatter, ax=ax, label=param)

                        ax.set_xlabel('Longitude (' + col_b + ')')
                        ax.set_ylabel('Latitude (' + col_a + ')')
                        ax.set_title(f'Geo Scatter (Lat/Lon)')
                        ax.grid(True, linestyle='--', alpha=0.5)
                        fig.tight_layout()

                    elif atype == 'corr':
                        primary_name, df = dfs[0]
                        cols = [col_a, col_b]
                        if param: cols.append(param)
                        valid_cols = [c for c in cols if c in df.columns]

                        if not valid_cols:
                            valid_cols = df.select_dtypes(include=[np.number]).columns.tolist()[:5]

                        if valid_cols:
                            corr = df[valid_cols].corr()
                            im = ax.imshow(corr, cmap='coolwarm', vmin=-1, vmax=1)
                            ax.set_xticks(np.arange(len(valid_cols)))
                            ax.set_yticks(np.arange(len(valid_cols)))
                            ax.set_xticklabels(valid_cols, rotation=45)
                            ax.set_yticklabels(valid_cols)
                            fig.colorbar(im, ax=ax)
                            ax.set_title('Correlation Matrix')
                            fig.tight_layout()

                    elif atype == 'bar' and col_a and col_b:
                        for name, df in dfs:
                            if col_a in df.columns and col_b in df.columns:
                                data = df.groupby(col_a)[col_b].mean()
                                ax.bar(data.index.astype(str), data.values, alpha=0.7, label=name)
                        ax.set_title(f'{col_b} by {col_a}')
                        ax.legend()
                        ax.tick_params(axis='x', rotation=45)
                        fig.tight_layout()

                    elif atype == 'line' and col_a and col_b:
                        for name, df in dfs:
                            if col_a in df.columns and col_b in df.columns:
                                df_sorted = df.sort_values(by=col_a)
                                ax.plot(df_sorted[col_a], df_sorted[col_b], marker='o', label=name)
                        ax.set_title(f'{col_a} vs {col_b}')
                        ax.grid(True, linestyle='--', alpha=0.6)
                        ax.legend()
                        fig.tight_layout()

                    elif atype == 'scatter' and col_a and col_b:
                        for name, df in dfs:
                            if col_a in df.columns and col_b in df.columns:
                                ax.scatter(df[col_a], df[col_b], alpha=0.5, label=name)
                        ax.set_xlabel(col_a)
                        ax.set_ylabel(col_b)
                        ax.legend()
                        ax.grid(True)
                        fig.tight_layout()

                    elif atype == 'hist' and col_a:
                        for name, df in dfs:
                            if col_a in df.columns:
                                ax.hist(df[col_a].dropna(), bins=20, alpha=0.5, label=name, edgecolor='black')
                        ax.set_title(f'Distribution of {col_a}')
                        ax.legend()
                        fig.tight_layout()

                    elif atype == 'pie' and col_a:
                        name, df = dfs[0]
                        if col_a in df.columns:
                            counts = df[col_a].value_counts().head(5)
                            ax.pie(counts, labels=counts.index, autopct='%1.1f%%')
                            ax.set_title(f'Top 5 {col_a} ({name})')

                    buf = io.BytesIO()
                    fig.savefig(buf, format='png', bbox_inches='tight')
                    buf.seek(0)
                    result = base64.b64encode(buf.getvalue()).decode('utf-8')
                    plt.close(fig)

                return jsonify({"status": "success", "data": result, "is_image": is_image})

            except Exception as e:
                plt.close('all')
                return jsonify({"status": "error", "msg": str(e)})

        @self.app.route('/API/logout')
        def logout():
            user = session.get('username')
            if user in self.active_sessions:
                del self.active_sessions[user]
            session.clear()
            return redirect(url_for('index_route'))

    def run(self):
        conf = self.sys_man.load_config().get('server', {})
        self.app.config['TEMPLATES_AUTO_RELOAD'] = True
        self.app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
        self.app.run(host='0.0.0.0', port=conf.get('port', 5000), debug=bool(conf.get('debug_mode', True)))


if __name__ == "__main__":
    web = webserver()
    web.run()
