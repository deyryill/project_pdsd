import os, secrets, sys, time, threading, smtplib, json
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
                "admin": {"info": {"password": "admin", "level": 2, "theme": "default", "email": "admin@duck.com"}},
                "user": {"info": {"password": "user", "level": 1, "theme": "default", "email": "user@duck.com"}},
                "guest": {"info": {"password": "guest", "level": 0, "theme": "default", "email": "guest@duck.com"}}
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

        # Implementation from dev_emu.py to fix double frame
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
                    return redirect(url_for('login_page'))

        @self.app.route('/', methods=['GET', 'POST'])
        @self.app.route('/index.html', methods=['GET', 'POST'])
        def login_page():
            if 'username' in session and not session.get('pending_2fa'):
                return redirect(url_for('home'))
            error = None
            if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                users = self.sys_man.load_users()
                if username in users and str(users[username]['password']) == str(password):
                    if users[username].get('2fa', True):
                        otp_code = secrets.token_hex(3).upper()
                        session['pending_2fa'] = True
                        session['temp_user'] = username
                        session['active_otp_data'] = {"otp": otp_code, "time": time.time(), "type": "2fa"}
                        self.send_otp(users[username]['email'], otp_code)
                        return redirect(url_for('verify_otp'))
                    self.create_session(username, users[username].get('level', 0))
                    return redirect(url_for('home'))
                error = "Invalid Credentials"
            return self.render_page('index.html', use_frame=False, error=error)

        @self.app.route('/signup', methods=['GET', 'POST'])
        def signup_page():
            if 'username' in session: return redirect(url_for('home'))
            error = None
            if request.method == 'POST':
                username = request.form['username'].lower().strip()
                email = request.form['email'].lower().strip()
                password = request.form['password']
                verify_now = request.form.get('verify_now') == 'true'
                users = self.sys_man.load_users()
                if any(u.get('email') == email for u in users.values()):
                    error = "Email already linked"
                elif (self.sys_man.dir_db / f"{username}.sysriot").exists():
                    error = "Username unavailable"
                else:
                    if verify_now:
                        otp_code = secrets.token_hex(3).upper()
                        reg_id = secrets.token_hex(8)
                        self.pending_registrations[reg_id] = {"username": username, "email": email, "password": password, "otp": otp_code, "time": time.time()}
                        session['reg_id'] = reg_id
                        if self.send_otp(email, otp_code): return redirect(url_for('verify_otp'))
                    else:
                        new_user = {"info": {"password": password, "email": email, "level": 0, "theme": "default", "2fa": False}}
                        self.sys_man.save_sysriot(self.sys_man.dir_db / f"{username}.sysriot", new_user)
                        self.create_session(username, 0)
                        return redirect(url_for('home'))
            return self.render_page('signup.html', use_frame=False, error=error)

        @self.app.route('/verify', methods=['GET', 'POST'])
        def verify_otp():
            error = None
            reg_id = session.get('reg_id')
            pending = self.pending_registrations.get(reg_id) if reg_id else None
            active_otp = session.get('active_otp_data')
            if not pending and not active_otp and 'username' not in session:
                return redirect(url_for('signup_page'))
            otp_data = pending if pending else active_otp
            remaining = 0
            if otp_data:
                elapsed = time.time() - otp_data['time']
                remaining = max(0, int(300 - elapsed))
            if request.method == 'POST':
                user_input = request.form.get('otp').upper()
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
                        return redirect(url_for('home'))
                    elif active_otp.get('type') == '2fa':
                        target_user = session.get('temp_user')
                        self.create_session(target_user, users[target_user].get('level', 0))
                        session.pop('pending_2fa', None)
                        session.pop('temp_user', None)
                        session.pop('active_otp_data', None)
                        return redirect(url_for('home'))
                    else:
                        target_user = session['username']
                        u_data = users[target_user]
                        u_data['level'] = 1
                        session['level'] = 1
                        self.sys_man.save_sysriot(self.sys_man.dir_db / f"{target_user}.sysriot", {"info": u_data})
                        session.pop('active_otp_data', None)
                        return redirect(url_for('home'))
                else:
                    error = "Invalid code"
            return self.render_page('verify.html', use_frame=False, error=error, remaining=remaining)

        @self.app.route('/resend_otp', methods=['POST'])
        def resend_otp():
            now = time.time()
            last_time = session.get('last_otp_time', 0)
            current_delay = session.get('resend_delay', 30)
            if now - last_time < current_delay:
                return f"Please wait {int(current_delay - (now - last_time))} seconds.", 429
            session['last_otp_time'] = now
            session['resend_delay'] = min(current_delay + 30, 900)
            target_email = None
            otp_code = secrets.token_hex(3).upper()
            if 'reg_id' in session:
                reg_id = session['reg_id']
                if reg_id in self.pending_registrations:
                    self.pending_registrations[reg_id]['otp'] = otp_code
                    self.pending_registrations[reg_id]['time'] = now
                    target_email = self.pending_registrations[reg_id]['email']
            elif 'active_otp_data' in session:
                session['active_otp_data']['otp'] = otp_code
                session['active_otp_data']['time'] = now
                users = self.sys_man.load_users()
                user_key = session.get('temp_user') or session.get('username')
                if user_key in users:
                    target_email = users[user_key]['email']
            if target_email and self.send_otp(target_email, otp_code):
                return redirect(url_for('verify_otp'))
            return "Failed to resend OTP", 500

        @self.app.route('/upgrade_account', methods=['POST'])
        def upgrade_account():
            if 'username' not in session or session.get('level') > 0:
                return redirect(url_for('home'))
            users = self.sys_man.load_users()
            user_data = users.get(session['username'])
            otp_code = secrets.token_hex(3).upper()
            session['active_otp_data'] = {"otp": otp_code, "time": time.time()}
            if self.send_otp(user_data['email'], otp_code):
                return redirect(url_for('verify_otp'))
            return "Failed to send OTP", 500

        @self.app.route('/home.html')
        def home():
            if 'username' not in session: return redirect(url_for('login_page'))
            return self.render_page('home.html', use_frame=True)

        @self.app.route('/user_settings.html', methods=['GET', 'POST'])
        def user_settings():
            if 'username' not in session: return redirect(url_for('login_page'))
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
            themes = [f.stem for f in (Path(self.app.static_folder) / "themes").glob("*.css")]
            return self.render_page('user_settings.html', use_frame=True, themes=themes, target_user=target_user, target_data=users.get(target_user, {}))

        @self.app.route('/admin_settings.html')
        def admin_settings():
            if 'username' not in session: return redirect(url_for('login_page'))
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
            return redirect(url_for('login_page'))

    def run(self):
        conf = self.sys_man.load_config().get('server', {})
        self.app.run(host='0.0.0.0', port=conf.get('port', 5000), debug=bool(conf.get('debug_mode', False)))


if __name__ == "__main__":
    web = webserver()
    web.run()