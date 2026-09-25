async function apiCall(endpoint, payload) {
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return await response.json();
    } catch (err) {
        return { status: 'error', message: 'Lỗi kết nối Server API: ' + err.message };
    }
}

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = type === 'success' ? 'toast-success' : 'toast-error';
    toast.style.display = 'block';
    setTimeout(() => { toast.style.display = 'none'; }, 3000);
}

function copyText(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.value || el.innerText;
    if (!text) {
        showToast('Không có dữ liệu để copy!', 'error');
        return;
    }
    navigator.clipboard.writeText(text);
    showToast('Đã copy vào Clipboard!');
}

function clearFields(...elementIds) {
    elementIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') el.value = '';
            else el.innerText = '';
        }
    });
}