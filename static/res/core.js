function startTimer(duration,displayId){let timer=duration,minutes,seconds;const display=document.getElementById(displayId);if(!display)return;const interval=setInterval(function(){minutes=parseInt(timer/60,10);seconds=parseInt(timer%60,10);minutes=minutes<10?"0"+minutes:minutes;seconds=seconds<10?"0"+seconds:seconds;display.textContent=minutes+":"+seconds;if(--timer<0){clearInterval(interval);display.textContent="EXPIRED";display.style.color="#dc3545"}},1000)}
function showEula(eulaUrl){const modal=document.getElementById('eulaModal');if(modal){modal.style.display='flex';if(eulaUrl){fetch(eulaUrl).then(r=>r.text()).then(t=>{const content=document.getElementById('eulaContent');if(content)content.innerText=t})}}}
function closeEula(){const modal=document.getElementById('eulaModal');if(modal)modal.style.display='none'}
function showVerifyPopup(){const modal=document.getElementById('verifyModal');if(modal)modal.style.display='block'}
function submitSignup(verifyNow){const input=document.getElementById('verify_now');const form=document.getElementById('signupForm');if(input&&form){input.value=verifyNow;form.submit()}}
function createUser(){const username=document.getElementById('new-user-name').value;const email=document.getElementById('new-user-email').value;const password=document.getElementById('new-user-pass').value;const level=document.getElementById('new-user-level').value;if(!username||!password||!email){alert('Please fill all fields');return}
fetch('/API/admin/create_user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,email,password,level})}).then(res=>{if(res.status===400)alert('User already exists or missing data');else location.reload()})}
function filterUsers(){const query=document.getElementById('user-search').value.toLowerCase();const level=document.getElementById('level-filter').value;const rows=document.querySelectorAll('.user-row');rows.forEach(row=>{const name=row.querySelector('.user-name').textContent.toLowerCase();const email=row.querySelector('.user-email').textContent.toLowerCase();const userLevel=row.querySelector('.user-level').textContent;const matchesSearch=name.includes(query)||email.includes(query);const matchesLevel=level===""||userLevel===level;row.style.display=(matchesSearch&&matchesLevel)?"":"none";if(row.style.display==='none'){const cb=row.querySelector('.user-checkbox');if(cb)cb.checked=!1}})}
function toggleAll(master){document.querySelectorAll('.user-checkbox').forEach(cb=>{if(cb.closest('tr').style.display!=='none'){cb.checked=master.checked}})}
function getSelectedUsers(){return Array.from(document.querySelectorAll('.user-checkbox:checked')).map(cb=>cb.value)}
function batchDelete(){const users=getSelectedUsers();if(!users.length)return alert('Select users first');if(confirm(`Permanently delete ${users.length} users?`)){fetch('/API/admin/batch_delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({users})}).then(res=>{if(res.ok){location.reload()}else{alert('Server error during deletion')}}).catch(err=>alert('Network error: '+err.message))}}
function batchSetLevel(lvl){const users=getSelectedUsers();if(!users.length)return alert('Select users first');let actionName=lvl==0?"BAN":(lvl==1?"SET USER":"SET ADMIN");if(confirm(`${actionName} ${users.length} users?`)){fetch('/API/admin/batch_level',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({users,level:lvl})}).then(()=>location.reload())}}
function saveSysConfig(){try{const config=JSON.parse(document.getElementById('sys-config').value);fetch('/API/admin/save_config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(config)}).then(()=>alert('System Updated'))}catch(e){alert('Invalid JSON format')}}
function saveNewConfig(){const config={server:{port:parseInt(document.getElementById('conf-server-port').value),debug_mode:document.getElementById('conf-server-debug').value,session_timeout_minutes:parseInt(document.getElementById('conf-server-timeout').value)},security:{block_common_usernames:document.getElementById('conf-sec-block').value,allowed_email_domains:document.getElementById('conf-sec-allow').value,blocked_emails:document.getElementById('conf-sec-deny').value},mail:{}};const mailHost=document.getElementById('conf-mail-host');if(mailHost){config.mail={host:mailHost.value,port:parseInt(document.getElementById('conf-mail-port').value),user:document.getElementById('conf-mail-user').value,pass:document.getElementById('conf-mail-pass').value}}
fetch('/API/admin/save_config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(config)}).then(()=>alert('Configuration Saved'))}
function openStatModal(category,identifier){currentModalCategory=category;currentModalId=identifier;document.getElementById('statModalTitle').innerText=category==='user'?'User Files: '+identifier:'System Files';document.getElementById('statModalSubtitle').innerText=category.toUpperCase();const tbody=document.getElementById('statModalList');tbody.innerHTML='<tr><td colspan="3" class="text-center">Loading...</td></tr>';const modal=document.getElementById('statDetailModal');if(modal)modal.style.display='flex';fetch('/API/admin/stat_details',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({category,identifier})}).then(r=>r.json()).then(res=>{tbody.innerHTML='';if(res.status==='success'){res.files.forEach(f=>{const tr=document.createElement('tr');let actionBtn='';if(f.can_delete){const safePath=f.path_id.replace(/\\/g,'/');actionBtn=`<button class="btn btn-danger btn-sm" onclick="deleteStatFile('${safePath}')">Delete</button>`}else{actionBtn='<span class="badge badge-info">Protected</span>'}
tr.innerHTML=`<td>${f.name}</td><td>${(f.size/1024).toFixed(2)} KB</td><td>${actionBtn}</td>`;tbody.appendChild(tr)});if(res.files.length===0){tbody.innerHTML='<tr><td colspan="3" class="text-muted text-center">No files found</td></tr>'}}else{tbody.innerHTML='<tr><td colspan="3" class="text-error">Failed to load</td></tr>'}})}
function uploadTheme(){const file=document.getElementById('theme-upload').files[0];if(!file)return alert('Select a CSS file');const formData=new FormData();formData.append('theme_file',file);fetch('/API/admin/upload_theme',{method:'POST',body:formData}).then(()=>location.reload())}
function deleteTheme(name){if(confirm('Delete theme '+name+'?')){fetch('/API/admin/delete_theme',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({theme:name})}).then(()=>location.reload())}}
function showLoading(){const overlay=document.getElementById('loadingOverlay');if(overlay)overlay.style.display='flex'}
function handleOtp(el){el.value=el.value.replace(/[^a-zA-Z0-9]/g,'').toUpperCase();if(el.value.length>=1){const next=el.nextElementSibling;if(next)next.focus();}
updateRealOtp()}
function handleBackspace(el,e){if(e.key==='Backspace'&&el.value.length===0){const prev=el.previousElementSibling;if(prev)prev.focus();}
setTimeout(updateRealOtp,10)}
function handlePaste(e){e.preventDefault();const data=(e.clipboardData||window.clipboardData).getData('text').toUpperCase().replace(/[^A-Z0-9]/g,'');const inputs=document.querySelectorAll('.otp-box');for(let i=0;i<Math.min(data.length,inputs.length);i++){inputs[i].value=data[i]}
if(data.length>0){const focusIndex=Math.min(data.length,inputs.length-1);inputs[focusIndex].focus()}
updateRealOtp()}
function updateRealOtp(){const inputs=document.querySelectorAll('.otp-box');let otp='';inputs.forEach(i=>otp+=i.value);const real=document.getElementById('real_otp');if(real)real.value=otp}
function submitOtp(){updateRealOtp();const form=document.getElementById('otpForm');if(form){showLoading();form.submit()}}
function submitResend(){const form=document.getElementById('resendForm');if(form){showLoading();form.submit()}}
function initOtpTimer(remaining){let timeLeft=parseInt(remaining);const timerText=document.getElementById('timerText');const resendBtn=document.getElementById('resendBtn');function update(){if(timeLeft>0){if(timerText)timerText.textContent="("+timeLeft+"s)";timeLeft--;setTimeout(update,1000)}else{if(timerText)timerText.style.display='none';if(resendBtn)resendBtn.disabled=!1}}
update();const firstBox=document.querySelector('.otp-box');if(firstBox)firstBox.focus();}
document.addEventListener("DOMContentLoaded",function(){const logBox=document.getElementById('log-container');if(logBox)logBox.scrollTop=logBox.scrollHeight;const timerDisplay=document.getElementById('timer');if(timerDisplay){const remaining=parseInt(timerDisplay.getAttribute('data-remaining')||0);startTimer(remaining,'timer')}
const frameBody=document.querySelector('.frame-body');if(frameBody){const initTarget=frameBody.getAttribute('data-init-target');const navItems=document.querySelectorAll('.nav-links .nav-item');if(initTarget){navItems.forEach(item=>{const page=item.getAttribute('data-page');if(page&&initTarget.indexOf(page)!==-1){item.classList.add('active')}})}
navItems.forEach(item=>{item.addEventListener('click',function(e){const href=this.getAttribute('href');if(!href||href==='#'||href==='javascript:void(0)'){e.preventDefault();return}
navItems.forEach(nav=>nav.classList.remove('active'));this.classList.add('active')})})}});let currentModalCategory='';let currentModalId='';function closeStatModal(){const modal=document.getElementById('statDetailModal');if(modal)modal.style.display='none'}
function deleteStatFile(pathId){if(!confirm('Are you sure you want to delete this file?'))return;fetch('/API/admin/stat_delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path_id:pathId})}).then(r=>r.json()).then(res=>{if(res.status==='success'){openStatModal(currentModalCategory,currentModalId);const totalSizeEl=document.getElementById('total-db-size');if(totalSizeEl)totalSizeEl.textContent=res.new_size}else{alert('Delete failed')}})}
function togglePublicUpload(show){const area=document.getElementById('public-upload-area');if(area)area.style.display=show?'flex':'none'}
function uploadPublicFile(){const fileInput=document.getElementById('public-file-upload');if(!fileInput||!fileInput.files.length)return alert('Please select a file');const formData=new FormData();formData.append('file',fileInput.files[0]);fetch('/API/admin/upload_public',{method:'POST',body:formData}).then(r=>r.json()).then(res=>{if(res.status==='success'){alert('Uploaded successfully');location.reload()}else{alert('Upload failed')}})}
function openModal(id){document.getElementById(id).classList.add('show')}
function closeModal(id){document.getElementById(id).classList.remove('show')}
function openEditModal(btn){const id=btn.getAttribute('data-id');let name=btn.getAttribute('data-name');const note=btn.getAttribute('data-note');if(name.toLowerCase().endsWith('.csv')){name=name.slice(0,-4)}
document.getElementById('editName').value=name;document.getElementById('editNote').value=note;document.getElementById('editForm').action="/API/db/edit_data/"+id;openModal('editModal')}
window.onclick=function(event){if(event.target.classList.contains('modal-wrapper')){event.target.classList.remove('show')}}
function initDeleteAccount(){closeModal('deleteConfirmModal');showLoading();fetch('/API/user/init_delete',{method:'POST'}).then(r=>r.json()).then(res=>{document.getElementById('loadingOverlay').style.display='none';if(res.status==='success'){openModal('deleteOtpModal')}else{alert('Failed to initiate deletion')}}).catch(e=>{document.getElementById('loadingOverlay').style.display='none';alert('Error')})}
function confirmDeleteAccount(){const otp=document.getElementById('delete_otp_input').value;if(!otp)return alert('Enter OTP');showLoading();fetch('/API/user/confirm_delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({otp:otp})}).then(r=>r.json()).then(res=>{if(res.status==='success'){window.top.location.href='/'}else{document.getElementById('loadingOverlay').style.display='none';alert(res.msg||'Failed')}})}

document.addEventListener("DOMContentLoaded", function() {
    if (window.location.pathname.includes('analysis.html')) {
        initAnalysisPage();
    }
});

let analysisSources = [];
let fileAssignments = {};

function initAnalysisPage() {
    fetch('/API/analysis/get_sources')
        .then(r => r.json())
        .then(res => {
            if (res.status === 'success') {
                analysisSources = res.sources;
                for(let i=1; i<=11; i++) fileAssignments[`data${i}`] = [];
                if (res.config) {
                    for (let key in res.config) {
                        if (res.config[key].assigned_files) {
                            fileAssignments[key] = res.config[key].assigned_files;
                        }
                    }
                }
                renderConfigForm(res.config);
                loadTablePreview(res.sources);
            }
        });

    const applyBtn = document.getElementById('applyAnalysisBtn');
    if(applyBtn) applyBtn.addEventListener('click', runAllAnalysis);

    const saveBtn = document.getElementById('saveAnalysisBtn');
    if(saveBtn) saveBtn.addEventListener('click', saveAnalysisConfig);
}

function loadTablePreview(sources) {
    const tbody = document.querySelector('.data-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (sources.length === 0) {
        tbody.innerHTML = '<tr><td colspan="2" class="text-center text-muted">No databases found</td></tr>';
        return;
    }
    sources.forEach(src => {
        const tr = document.createElement('tr');
        const badge = src.origin === 'public' ? '<span class="badge badge-info badge-sm">Public</span>' : '';
        tr.innerHTML = `<td>${src.name} ${badge}</td><td class="text-center"><button class="btn btn-primary-alt btn-sm badge-sm" onclick="openAssignModal('${src.id}', '${src.name}')">Assign</button></td>`;
        tbody.appendChild(tr);
    });
}

let currentAssignFile = null;
function openAssignModal(fileId, fileName) {
    currentAssignFile = fileId;
    document.getElementById('assignModalTitle').innerText = 'Assign: ' + fileName;
    for (let i = 1; i <= 11; i++) {
        const slot = `data${i}`;
        const cb = document.getElementById(`assign-chk-${i}`);
        if(cb) cb.checked = fileAssignments[slot].includes(fileId);
    }
    document.getElementById('assignModal').classList.add('show');
}

function saveAssignment() {
    if (!currentAssignFile) return;
    for (let i = 1; i <= 11; i++) {
        const slot = `data${i}`;
        const cb = document.getElementById(`assign-chk-${i}`);
        const idx = fileAssignments[slot].indexOf(currentAssignFile);
        if (cb.checked) {
            if (idx === -1) fileAssignments[slot].push(currentAssignFile);
        } else {
            if (idx !== -1) fileAssignments[slot].splice(idx, 1);
        }
    }
    document.getElementById('assignModal').classList.remove('show');
    renderConfigForm(getCurrentConfig());
}

function renderConfigForm(savedConfig) {
    const container = document.getElementById('config-form-container');
    if (!container) return;
    container.innerHTML = '';
    savedConfig = savedConfig || {};

    for (let i = 1; i <= 11; i++) {
        const slotId = `data${i}`;
        const config = savedConfig[slotId] || {};
        const isTextOnly = i <= 3;
        const assigned = fileAssignments[slotId] || [];
        const div = document.createElement('div');
        div.className = 'analysis-config-item';

        let fileTags = '';
        if (assigned.length > 0) {
            assigned.forEach(f => fileTags += `<div class="analysis-file-tag"><span>${f}</span></div>`);
        } else {
            fileTags = '<span class="text-muted" style="font-style:italic">No files assigned</span>';
        }

        let typeOptions = '<option value="">Select Logic...</option>';
        const textTypes = [{v:'summary', l:'Summary Stats'},{v:'head', l:'Data Preview'},{v:'missing', l:'Missing Check'}];
        const chartTypes = [
            {v:'bar', l:'Bar Chart (Multi)'},
            {v:'line', l:'Line Chart (Multi)'},
            {v:'scatter', l:'Scatter Plot'},
            {v:'hist', l:'Histogram'},
            {v:'pie', l:'Pie Chart (First)'},
            {v:'kmeans', l:'K-Means Clustering'},
            {v:'regression', l:'Linear Regression'},
            {v:'geo', l:'Geo Scatter (Lat/Lon)'},
            {v:'corr', l:'Correlation Matrix'}
        ];
        const types = isTextOnly ? textTypes : chartTypes;

        types.forEach(t => {
            const selected = config.type === t.v ? 'selected' : '';
            typeOptions += `<option value="${t.v}" ${selected}>${t.l}</option>`;
        });

        const colAVal = config.col_a || '';
        const colBVal = config.col_b || '';
        const paramVal = config.param || '';

        div.innerHTML = `
            <div class="analysis-config-header">
                <h4>Data ${i}</h4>
                <span class="badge badge-sm ${isTextOnly?'badge-warning':'badge-success'}">${isTextOnly?'TEXT':'CHART'}</span>
            </div>
            <div class="analysis-assigned-list">${fileTags}</div>
            <div class="analysis-config-row">
                <select class="input input-sm" id="conf-type-${i}" ${assigned.length===0 ? 'disabled' : ''}>${typeOptions}</select>
            </div>
            ${!isTextOnly ? `
            <div class="analysis-config-row">
                <input type="text" class="input input-sm" id="conf-col-a-${i}" placeholder="X Axis / Lat / Cat" value="${colAVal}" ${assigned.length===0 ? 'disabled' : ''}>
                <input type="text" class="input input-sm" id="conf-col-b-${i}" placeholder="Y Axis / Lon / Val" value="${colBVal}" ${assigned.length===0 ? 'disabled' : ''}>
            </div>
            <div class="analysis-config-row">
                <input type="text" class="input input-sm" id="conf-param-${i}" placeholder="Param (K / Color)" value="${paramVal}" ${assigned.length===0 ? 'disabled' : ''}>
            </div>` : ''}
        `;
        container.appendChild(div);
    }
}

function getCurrentConfig() {
    const config = {};
    for (let i = 1; i <= 11; i++) {
        const id = `data${i}`;
        const isChart = i > 3;
        const typeEl = document.getElementById(`conf-type-${i}`);
        config[id] = {
            assigned_files: fileAssignments[id],
            type: typeEl ? typeEl.value : '',
            col_a: isChart ? document.getElementById(`conf-col-a-${i}`).value : null,
            col_b: isChart ? document.getElementById(`conf-col-b-${i}`).value : null,
            param: isChart ? document.getElementById(`conf-param-${i}`).value : null
        };
    }
    return config;
}

function saveAnalysisConfig() {
    const config = getCurrentConfig();
    fetch('/API/analysis/save_config', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(config)
    }).then(r => r.json()).then(res => {
        if(res.status === 'success') alert('Configuration Saved');
    });
}

function runAllAnalysis() {
    const config = getCurrentConfig();
    for (let i = 1; i <= 11; i++) {
        const slotId = `data${i}`;
        const cfg = config[slotId];
        const outputDiv = document.getElementById(`${slotId}-output`);

        if (!cfg.assigned_files || cfg.assigned_files.length === 0 || !cfg.type) {
            if(outputDiv) outputDiv.innerHTML = '<span class="text-muted" style="font-size:0.8rem">Empty</span>';
            continue;
        }

        if(outputDiv) outputDiv.innerHTML = '<div class="analysis-loader"></div>';

        fetch('/API/analysis/execute', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                slot_id: slotId,
                sources: cfg.assigned_files,
                type: cfg.type,
                col_a: cfg.col_a,
                col_b: cfg.col_b,
                param: cfg.param
            })
        })
        .then(r => r.json())
        .then(res => {
            if (res.status === 'success') {
                if (res.is_image) {
                    outputDiv.innerHTML = `<img src="data:image/png;base64,${res.data}" style="width:100%;height:100%;object-fit:contain">`;
                } else {
                    outputDiv.innerHTML = `<div style="width:100%;height:100%;overflow-y:auto;padding:5px;">${res.data}</div>`;
                }
            } else {
                outputDiv.innerHTML = `<span class="text-error" style="font-size:0.8rem">${res.msg}</span>`;
            }
        })
        .catch(err => {
            if(outputDiv) outputDiv.innerHTML = '<span class="text-error">Error</span>';
        });
    }
}


function filterData(){
    const query = document.getElementById('data-search').value.toLowerCase();
    const rows = document.querySelectorAll('.data-row');

    rows.forEach(row=>{
        const name = row.querySelector('.file-name').textContent.toLowerCase();

        const matchesSearch = name.includes(query);

        row.style.display = (matchesSearch) ? "" : "none";
    });
}
