import os, secrets, sys
from flask import Flask, request, redirect, url_for, session, render_template, jsonify
from pathlib import Path
from werkzeug.utils import secure_filename


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
                "admin": {"info": {"password": "admin", "level": 2, "theme": "default"}},
                "user": {"info": {"password": "user", "level": 1, "theme": "default"}},
                "guest": {"info": {"password": "guest", "level": 0, "theme": "default"}}
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


class webserver:
    def __init__(self):
        self.sys_man = man_system()
        self.app = Flask(__name__, template_folder='static', static_folder='static')
        self.app.secret_key = "DEVKEY"
        self.active_sessions = {}
        self.routes()

    def render_page(self, template_name, **kwargs):
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
        return render_template(template_name, **kwargs)

    def routes(self):
        @self.app.route('/API/admin/batch_delete', methods=['POST'])
        def api_batch_delete():
            if session.get('level', 0) < 2: return jsonify({"status": "error"}), 403
            usernames = request.json.get('users', [])
            current_admin = session.get('username')
            for u in usernames:
                if u == current_admin or u == 'admin': continue
                u_path = self.sys_man.dir_db / f"{u}.sysriot"
                if u_path.exists():
                    os.remove(u_path)
            return jsonify({"status": "success"})

        @self.app.route('/API/admin/batch_level', methods=['POST'])
        def api_batch_level():
            if session.get('level', 0) < 2: return jsonify({"status": "error"}), 403
            usernames = request.json.get('users', [])
            new_level = request.json.get('level')
            if new_level is None: return jsonify({"status": "error"}), 400
            users = self.sys_man.load_users()
            for u in usernames:
                if u in users:
                    users[u]['level'] = int(new_level)
            self.sys_man.save_users(users)
            return jsonify({"status": "success"})

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
            if 'username' in session:
                return redirect(url_for('home'))
            error = None
            if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                users = self.sys_man.load_users()
                if username in users and users[username]['password'] == password:
                    session['username'] = username
                    session['level'] = users[username].get('level', 0)
                    token = secrets.token_hex(16)
                    session['token'] = token
                    self.active_sessions[username] = token
                    return redirect(url_for('home'))
                else:
                    error = "Invalid Credentials"
            return self.render_page('index.html', error=error)

        @self.app.route('/home.html')
        def home():
            if 'username' not in session: return redirect(url_for('login_page'))
            return self.render_page('home.html')

        @self.app.route('/user_settings.html', methods=['GET', 'POST'])
        def user_settings():
            if 'username' not in session: return redirect(url_for('login_page'))
            if session.get('level', 0) < 1: return "Access Denied", 403
            users = self.sys_man.load_users()
            target_user = request.args.get('edit_user', session['username'])
            if session.get('level') < 2:
                target_user = session['username']
            if request.method == 'POST':
                new_pass = request.form.get('password')
                new_theme = request.form.get('theme')
                new_level = request.form.get('level')
                if new_pass: users[target_user]['password'] = new_pass
                if new_theme: users[target_user]['theme'] = new_theme
                if new_level and session.get('level') >= 2:
                    users[target_user]['level'] = int(new_level)
                self.sys_man.save_users(users)
                return redirect(url_for('user_settings', edit_user=target_user))
            themes = [f.stem for f in (Path(self.app.static_folder) / "themes").glob("*.css")]
            return self.render_page('user_settings.html', themes=themes, target_user=target_user, target_data=users.get(target_user, {}))

        @self.app.route('/admin_settings.html')
        def admin_settings():
            if 'username' not in session: return redirect(url_for('login_page'))
            if session.get('level', 0) < 2: return "Unauthorized", 403
            themes = [f.stem for f in (Path(self.app.static_folder) / "themes").glob("*.css")]
            return self.render_page('admin_settings.html', users_list=self.sys_man.load_users(), themes=themes)

        @self.app.route('/API/admin/save_config', methods=['POST'])
        def api_save_config():
            if session.get('level', 0) < 2: return jsonify({"status": "error"}), 403
            self.sys_man.save_config(request.json)
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
        self.app.run(host='0.0.0.0', port=conf.get('port', 5000), debug=conf.get('debug_mode', False))


if __name__ == "__main__":
    web = webserver()
    web.run()
