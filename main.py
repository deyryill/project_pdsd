import os, secrets, sys, time, threading, smtplib, random
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
        if not path.exists(): return data
        current_section = None
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                if line.startswith("[") and line.endswith("]"):
                    current_section = line[1:-1]
                    data[current_section] = {}
                elif "=" in line and current_section:
                    k, v = line.split("=", 1)
                    val = v.strip()
                    if val.isdigit():
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
                "security": {"block_common_usernames": "root,system"},
                "server": {"port": 5000, "debug_mode": "false"}
            }
            self.save_sysriot(self.system_conf_path, default_config)
        if not list(self.dir_db.glob("*.sysriot")):
            defaults = {
                "admin": {"info": {"password": "admin", "level": 2, "theme": "default", "email": ""}},
            }
            for u, cfg in defaults.items():
                self.save_sysriot(self.dir_db / f"{u}.sysriot", cfg)

    def load_users(self):
        users = {}
        for f in self.dir_db.glob("*.sysriot"):
            if f.parent == self.system_dir: continue
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
        if not conf: return False
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
                <p style="color: #a0aec0; font-size: 11px; margin: 0;">&copy; {time.strftime("%Y")} RIOT System.</p>
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
        token = secrets.token_hex(16)
        session['token'] = token
        self.active_sessions[username] = token

    def routes(self):
        @self.app.before_request
        def session_management():
            if request.endpoint == 'static': return
            if 'username' in session:
                c_user = session['username']
                c_token = session.get('token')
                if c_user not in self.active_sessions or self.active_sessions[c_user] != c_token:
                    session.clear()
                    return redirect(url_for('index_route'))

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
                    if username in users and str(users[username]['password']) == str(password):
                        if users[username].get('2fa', True):
                            otp_code = secrets.token_hex(3).upper()
                            session['pending_2fa'] = True
                            session['temp_user'] = username
                            session['active_otp_data'] = {"otp": otp_code, "time": time.time(), "type": "2fa", "email": users[username].get('email')}
                            threading.Thread(target=self.send_otp, args=(users[username]['email'], otp_code)).start()
                            return redirect(url_for('index_route'))
                        self.create_session(username, users[username].get('level', 0))
                        return redirect(url_for('home'))
                    error = "Invalid Credentials"
                    mode = 'login'

                elif action == 'signup':
                    username = request.form.get('username', '').strip()
                    email = request.form.get('email', '').strip()
                    password = request.form.get('password')
                    confirm = request.form.get('confirm_password')
                    agree = request.form.get('agree')
                    users = self.sys_man.load_users()
                    domain = email.split('@')[1] if '@' in email else ''
                    if not agree:
                        error = "You must agree to the Terms & Conditions"
                    elif password != confirm:
                        error = "Passwords do not match"
                    elif 'unikom' not in domain.lower() and 'duck.com' not in domain.lower():
                        error = "Email domain not allowed (unikom or duck.com only)"
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

        @self.app.route('/upgrade_account', methods=['POST'])
        def upgrade_account():
            if 'username' not in session or session.get('level') > 0:
                return redirect(url_for('home'))
            users = self.sys_man.load_users()
            user_data = users.get(session['username'])
            otp_code = secrets.token_hex(3).upper()
            session['active_otp_data'] = {"otp": otp_code, "time": time.time()}
            if self.send_otp(user_data['email'], otp_code):
                return redirect(url_for('index_route'))
            return "Failed to send OTP", 500

        @self.app.route('/home.html')
        def home():
            if 'username' not in session: return redirect(url_for('index_route'))
            return self.render_page('home.html', use_frame=True)

        @self.app.route('/database.html')
        def database():
            if 'username' not in session: return redirect(url_for('index_route'))
            return self.render_page('database.html', use_frame=True)

        @self.app.route('/analysis.html')
        def analysis():
            if 'username' not in session: return redirect(url_for('index_route'))
            return self.render_page('analysis.html', use_frame=True)

        @self.app.route('/user_settings.html', methods=['GET', 'POST'])
        def user_settings():
            if 'username' not in session: return redirect(url_for('index_route'))
            users = self.sys_man.load_users()
            target_user = request.args.get('edit_user', session['username'])
            if session.get('level') < 2: target_user = session['username']
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
                        if session['username'] != 'admin': session['username'] = new_username
                self.sys_man.save_sysriot(self.sys_man.dir_db / f"{target_user}.sysriot", {"info": u_data})
                return redirect(url_for('user_settings', edit_user=target_user, content=1))
            themes = {f.stem.lower() for f in (Path(self.app.static_folder) / "themes").glob("*.css")}
            if 'default' in themes:
                themes.remove('default')
            themes = sorted(list(themes))
            themes.insert(0, 'Default')

            return self.render_page('user_settings.html', use_frame=True, themes=themes, target_user=target_user, target_data=users.get(target_user, {}))

        @self.app.route('/admin_settings.html')
        def admin_settings():
            if 'username' not in session: return redirect(url_for('index_route'))
            if session.get('level', 0) < 2: return "Unauthorized", 403
            logs = []
            log_path = self.sys_man.system_dir / "logs.sysriot"
            if log_path.exists():
                with open(log_path, "r") as f:
                    logs = [line.strip() for line in f.readlines()[-50:]]
            themes = [f.stem for f in (Path(self.app.static_folder) / "themes").glob("*.css")]
            return self.render_page('admin_settings.html', use_frame=True, users_list=self.sys_man.load_users(), themes=themes, logs=logs)

        @self.app.route('/API/admin/system_status', methods=['GET'])
        def api_system_status():
            if session.get('level', 0) < 2: return jsonify({"status": "error"}), 403
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
            if session.get('level', 0) < 2: return jsonify({"status": "error"}), 403
            data = request.json
            username = data.get('username', '').lower().strip()
            email = data.get('email', '').lower().strip()
            password = data.get('password')
            level = data.get('level', 0)
            if not username or not password or not email:
                return jsonify({"status": "error"}), 400
            if (self.sys_man.dir_db / f"{username}.sysriot").exists():
                return jsonify({"status": "exists"}), 400
            new_user_data = {"info": {"password": password, "email": email, "level": int(level), "theme": "default"}}
            self.sys_man.save_sysriot(self.sys_man.dir_db / f"{username}.sysriot", new_user_data)
            self.sys_man.write_log(session['username'], "create_user", f"Created: {username}")
            return jsonify({"status": "success"})

        @self.app.route('/API/admin/save_config', methods=['POST'])
        def api_save_config():
            if session.get('level', 0) < 2: return jsonify({"status": "error"}), 403
            self.sys_man.save_config(request.json)
            self.sys_man.write_log(session['username'], "config_update", "Config changed")
            return jsonify({"status": "success"})

        @self.app.route('/API/admin/batch_delete', methods=['POST'])
        def api_batch_delete():
            if session.get('level', 0) < 2: return jsonify({"status": "error"}), 403
            usernames = request.json.get('users', [])
            current_admin = session.get('username')
            deleted = []
            for u in usernames:
                if u == current_admin or u == 'admin': continue
                u_path = self.sys_man.dir_db / f"{u}.sysriot"
                if u_path.exists():
                    os.remove(u_path)
                    deleted.append(u)
            if deleted:
                self.sys_man.write_log(current_admin, "batch_delete", f"Deleted: {', '.join(deleted)}")
            return jsonify({"status": "success"})

        @self.app.route('/API/admin/batch_level', methods=['POST'])
        def api_batch_level():
            if session.get('level', 0) < 2: return jsonify({"status": "error"}), 403
            usernames = request.json.get('users', [])
            new_level = request.json.get('level')
            if new_level is None: return jsonify({"status": "error"}), 400
            users = self.sys_man.load_users()
            updated = []
            for u in usernames:
                if u in users:
                    users[u]['level'] = int(new_level)
                    self.sys_man.save_sysriot(self.sys_man.dir_db / f"{u}.sysriot", {"info": users[u]})
                    updated.append(u)
            if updated:
                self.sys_man.write_log(session['username'], "batch_level", f"Set level {new_level} for: {', '.join(updated)}")
            return jsonify({"status": "success"})

        @self.app.route('/API/admin/upload_theme', methods=['POST'])
        def api_upload_theme():
            if session.get('level', 0) < 2: return jsonify({"status": "error"}), 403
            file = request.files.get('theme_file')
            if file and file.filename.endswith('.css'):
                filename = secure_filename(file.filename)
                file.save(Path(self.app.static_folder) / "themes" / filename)
                return jsonify({"status": "success"})
            return jsonify({"status": "error"}), 400

        @self.app.route('/API/admin/delete_theme', methods=['POST'])
        def api_delete_theme():
            if session.get('level', 0) < 2: return jsonify({"status": "error"}), 403
            theme_name = request.json.get('theme')
            if theme_name and theme_name != 'default':
                theme_path = Path(self.app.static_folder) / "themes" / f"{theme_name}.css"
                if theme_path.exists():
                    os.remove(theme_path)
                    return jsonify({"status": "success"})
            return jsonify({"status": "error"}), 400

        @self.app.route('/logout')
        def logout():
            user = session.get('username')
            if user in self.active_sessions: del self.active_sessions[user]
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