import os,shutil,time,serial
from riot_core import RIOTRE_COMPONENTS

RIOT_CORE_PATH = "/etc/riot/"
TEMP_MOUNT_POINT = "/mnt/riot-overlay"
LOG_DIR_RELATIVE = "/tmp"
src_system = "/etc/riot/system"
src_userdata = "/etc/riot/userdata"
POST_COPY_DELAY_SECONDS = 2
def main():
    try:
        RIOTRE_COMPONENTS().run_execute("mpg123 /etc/riot/system-boot.mp3 &")
    except:
        pass
    os.makedirs(LOG_DIR_RELATIVE, exist_ok=True)
    LOG_FILE_RELATIVE = os.path.join(LOG_DIR_RELATIVE, "log.txt")
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE,"BOOTLOADER (BUILD-26/01/26) START")
    RIOTRE_COMPONENTS().create_ram_disk(TEMP_MOUNT_POINT)
    time.sleep(POST_COPY_DELAY_SECONDS)
    try:
        ser = serial.Serial('/dev/ttyS4', 115200, timeout=2)
        ser.setDTR(False)
        ser.setRTS(False)
        time.sleep(0.1)
        ser.setDTR(True)
        ser.setRTS(True)
        ser.close()
        RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE, "UART OK")
    except Exception as e:
        RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE, f"UART FAILED: {str(e)}")
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE,f'{RIOTRE_COMPONENTS().run_execute("echo 71 > /sys/class/gpio/export",)}')
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE,f'{RIOTRE_COMPONENTS().run_execute("echo 72 > /sys/class/gpio/export", )}')
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE,f'{RIOTRE_COMPONENTS().run_execute("echo 75> /sys/class/gpio/export", )}')
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE,f'{RIOTRE_COMPONENTS().run_execute("echo 156 > /sys/class/gpio/export", )}')
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE,f'{RIOTRE_COMPONENTS().run_execute("echo out > /sys/class/gpio/gpio71/direction", )}')
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE,f'{RIOTRE_COMPONENTS().run_execute("echo out > /sys/class/gpio/gpio72/direction", )}')
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE,f'{RIOTRE_COMPONENTS().run_execute("echo out > /sys/class/gpio/gpio75/direction", )}')
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE,f'{RIOTRE_COMPONENTS().run_execute("echo out > /sys/class/gpio/gpio156/direction", )}')
    time.sleep(0.1)
    if os.path.exists(src_system):
        for root, dirs, files in os.walk(src_system):
            rel_path = os.path.relpath(root, src_system)
            dest_path = os.path.join(TEMP_MOUNT_POINT, rel_path)
            os.makedirs(dest_path, exist_ok=True)
            for file in files:
                if not file.endswith((".py", ".sh")):
                    shutil.copy2(os.path.join(root, file), os.path.join(dest_path, file))
    dst_database = os.path.join(TEMP_MOUNT_POINT, "database")
    os.makedirs(dst_database, exist_ok=True)
    if os.path.exists(src_userdata):
        for root, dirs, files in os.walk(src_userdata):
            rel_path = os.path.relpath(root, src_userdata)
            dest_path = os.path.join(dst_database, rel_path)
            os.makedirs(dest_path, exist_ok=True)
            for file in files:
                shutil.copy2(os.path.join(root, file), os.path.join(dest_path, file))
    os.chdir(TEMP_MOUNT_POINT)
    time.sleep(POST_COPY_DELAY_SECONDS)

    RIOTRE_COMPONENTS().manage_log_backup(LOG_FILE_RELATIVE)
    time.sleep(0.2)
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE, "--- BOOTLOADER START ---")
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE, f"Current working directory: {os.getcwd()}")
    if os.path.exists("os.bin"):
        RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE, "Found os.bin, executing...")
        RIOTRE_COMPONENTS().run_binary("os.bin")
    elif os.path.exists("RIOT.py"):
        RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE, "Found RIOT.py, executing...")
        RIOTRE_COMPONENTS().run_script("RIOT")
    elif os.path.exists("main.py"):
        RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE, "Found main.py, executing...")
        RIOTRE_COMPONENTS().run_script("main")
    else:
        RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE, "ERROR: RIOT INIT FAIL")
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE, "--- BOOTLOADER FINISHED ---")
    RIOTRE_COMPONENTS().log_write(LOG_FILE_RELATIVE, "Switch to RIOT ")

if __name__ == "__main__":
    main()


