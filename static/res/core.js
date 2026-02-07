function startTimer(duration, displayId) {
    let timer = duration, minutes, seconds;
    const display = document.getElementById(displayId);
    if (!display) return;

    const interval = setInterval(function () {
        minutes = parseInt(timer / 60, 10);
        seconds = parseInt(timer % 60, 10);

        minutes = minutes < 10 ? "0" + minutes : minutes;
        seconds = seconds < 10 ? "0" + seconds : seconds;

        display.textContent = minutes + ":" + seconds;

        if (--timer < 0) {
            clearInterval(interval);
            display.textContent = "EXPIRED";
            display.style.color = "#dc3545";
        }
    }, 1000);
}

function showEula(eulaUrl) {
    const modal = document.getElementById('eulaModal');
    if (modal) {
        modal.style.display = 'block';
        if(eulaUrl) {
            fetch(eulaUrl)
                .then(r => r.text())
                .then(t => {
                    const content = document.getElementById('eulaContent');
                    if(content) content.innerText = t;
                });
        }
    }
}

function closeEula() {
    const modal = document.getElementById('eulaModal');
    if (modal) modal.style.display = 'none';
}

function showVerifyPopup() {
    const modal = document.getElementById('verifyModal');
    if (modal) modal.style.display = 'block';
}

function submitSignup(verifyNow) {
    const input = document.getElementById('verify_now');
    const form = document.getElementById('signupForm');
    if (input && form) {
        input.value = verifyNow;
        form.submit();
    }
}

function createUser() {
    const username = document.getElementById('new-user-name').value;
    const email = document.getElementById('new-user-email').value;
    const password = document.getElementById('new-user-pass').value;
    const level = document.getElementById('new-user-level').value;

    if(!username || !password || !email) {
        alert('Please fill all fields');
        return;
    }

    fetch('/API/admin/create_user', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, email, password, level})
    }).then(res => {
        if(res.status === 400) alert('User already exists or missing data');
        else location.reload();
    });
}

function filterUsers() {
    const query = document.getElementById('user-search').value.toLowerCase();
    const level = document.getElementById('level-filter').value;
    const rows = document.querySelectorAll('.user-row');

    rows.forEach(row => {
        const name = row.querySelector('.user-name').textContent.toLowerCase();
        const email = row.querySelector('.user-email').textContent.toLowerCase();
        const userLevel = row.querySelector('.user-level').textContent;

        const matchesSearch = name.includes(query) || email.includes(query);
        const matchesLevel = level === "" || userLevel === level;

        row.style.display = (matchesSearch && matchesLevel) ? "" : "none";

        if(row.style.display === 'none') {
            const cb = row.querySelector('.user-checkbox');
            if(cb) cb.checked = false;
        }
    });
}

function toggleAll(master) {
    document.querySelectorAll('.user-checkbox').forEach(cb => {
        if(cb.closest('tr').style.display !== 'none') {
            cb.checked = master.checked;
        }
    });
}

function getSelectedUsers() {
    return Array.from(document.querySelectorAll('.user-checkbox:checked')).map(cb => cb.value);
}

function batchDelete() {
    const users = getSelectedUsers();
    if(!users.length) return alert('Select users first');
    if(confirm(`Permanently delete ${users.length} users?`)) {
        fetch('/API/admin/batch_delete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({users})
        }).then(() => location.reload());
    }
}

function batchSetLevel(lvl) {
    const users = getSelectedUsers();
    if(!users.length) return alert('Select users first');
    fetch('/API/admin/batch_level', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({users, level: lvl})
    }).then(() => location.reload());
}

function saveSysConfig() {
    try {
        const config = JSON.parse(document.getElementById('sys-config').value);
        fetch('/API/admin/save_config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(config)
        }).then(() => alert('System Updated'));
    } catch(e) { alert('Invalid JSON format'); }
}

function uploadTheme() {
    const file = document.getElementById('theme-upload').files[0];
    if(!file) return alert('Select a CSS file');
    const formData = new FormData();
    formData.append('theme_file', file);
    fetch('/API/admin/upload_theme', {method: 'POST', body: formData})
    .then(() => location.reload());
}

function deleteTheme(name) {
    if(confirm('Delete theme ' + name + '?')) {
        fetch('/API/admin/delete_theme', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({theme: name})
        }).then(() => location.reload());
    }
}

document.addEventListener("DOMContentLoaded", function() {
    const logBox = document.getElementById('log-container');
    if(logBox) logBox.scrollTop = logBox.scrollHeight;

    const timerDisplay = document.getElementById('timer');
    if(timerDisplay) {
        const remaining = parseInt(timerDisplay.getAttribute('data-remaining') || 0);
        startTimer(remaining, 'timer');
    }

    const frameBody = document.querySelector('.frame-body');
    if (frameBody) {
        const initTarget = frameBody.getAttribute('data-init-target');
        const navItems = document.querySelectorAll('.nav-links .nav-item');

        if (initTarget) {
            navItems.forEach(item => {
                const page = item.getAttribute('data-page');
                if (page && initTarget.indexOf(page) !== -1) {
                    item.classList.add('active');
                }
            });
        }

        navItems.forEach(item => {
            item.addEventListener('click', function(e) {
                const href = this.getAttribute('href');
                if (!href || href === '#' || href === 'javascript:void(0)') {
                    e.preventDefault();
                    return;
                }
                navItems.forEach(nav => nav.classList.remove('active'));
                this.classList.add('active');
            });
        });
    }
});