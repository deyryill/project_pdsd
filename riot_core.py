import hashlib,portalocker,os,json,subprocess,psutil,shutil
from datetime import datetime

class RIOTRE_COMPONENTS:
    def __init__(self):
        pass

    def create_ram_disk(self, mount_point, size_mb=256):
        try:
            os.makedirs(mount_point, exist_ok=True)
            subprocess.run(f"umount {mount_point}", shell=True, check=False)
            command = f"mount -t tmpfs -o size={size_mb}M tmpfs {mount_point}"
            result = self.run_execute(command)
            return "success" in result.lower()
        except Exception as e:
            return f"Error creating RAM disk: {e}"

    def copy_files(self, src_dir, dest_dir):
        try:
            if os.path.exists(dest_dir):
                for item in os.listdir(src_dir):
                    s = os.path.join(src_dir, item)
                    d = os.path.join(dest_dir, item)
                    if os.path.isdir(s):
                        shutil.copytree(s, d, symlinks=False, ignore=None, dirs_exist_ok=True)
                    else:
                        shutil.copy2(s, d)
            else:
                shutil.copytree(src_dir, dest_dir)
            return True
        except Exception as e:
            return f"Error copying files: {e}"

    def manage_log_backup(self, log_file):
        if os.path.exists(log_file):
            backup_file = log_file + ".bak"
            if os.path.exists(backup_file):
                os.remove(backup_file)
            os.rename(log_file, backup_file)
            return f"Log backed up to {backup_file}"
        return "No existing log file to back up."

    def get_dir_checksum(self, directory):
        sha256 = hashlib.sha256()
        if not os.path.exists(directory):
            return None

        for root, _, files in os.walk(directory):
            for names in sorted(files):
                filepath = os.path.join(root, names)
                try:
                    with open(filepath, 'rb') as f:
                        while True:
                            data = f.read(65536)
                            if not data:
                                break
                            sha256.update(data)
                except IOError:
                    pass
        return sha256.hexdigest()

    def debug_stresstest(self):
        for _ in range(100000000):
            _ = 2 * 2

    def read(self, file="mems.RDF"):
        try:
            with open(file, 'r') as f:
                portalocker.lock(f, portalocker.LOCK_SH)
                data = json.load(f)
                portalocker.unlock(f)
            return data
        except (json.JSONDecodeError, IOError) as e:
            print(e)
            return None

    def write(self, file="mems", data=None):
        with open(file + '.RDF', 'w') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            json.dump(data, f)
            portalocker.unlock(f)

    def run_script(self, data):
        subprocess.Popen(['python3', data + '.py'])

    def run_bash(self, data):
        subprocess.Popen(['sudo', 'bash', data])

    def run_binary(self, data):
        subprocess.Popen(["./" + data])

    def run_loader(self, data):
        os.system("./" + data)

    def set_core(self, data):
        pid = os.getpid()
        p = psutil.Process(pid)
        p.cpu_affinity(data)

    def program_kill(self, data):
        try:
            subprocess.run(["pkill", data], check=False)
        except:
            pass

    def program_check(self, data):
        for process in psutil.process_iter(['pid', 'name']):
            if process.info['name'] == data:
                return True
        return False

    def log_event(self, log_file):
        log_dir = os.path.dirname(log_file)
        try:
            os.makedirs(log_dir, exist_ok=True)
        except:
            pass

    def run_execute(self, command):
        try:
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            return f"BOOTLOADER_ERROR:{e.returncode}:\n{e.stderr}"

    def log_write(self, log_file, data):
        if data != "":
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(log_file, "a") as f:
                f.write(f"{current_time} - {data}\n")