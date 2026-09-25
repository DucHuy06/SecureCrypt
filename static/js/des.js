async function generateDESKey() {
    const res = await fetch('/api/des/generate-key');
    const data = await res.json();
    if (data.status === 'success') {
        document.getElementById('desKey').value = data.key;
        showToast('Đã tạo khóa DES ngẫu nhiên!');
    }
}

async function runDESEncrypt() {
    const plaintext = document.getElementById('desPlaintext').value;
    const key = document.getElementById('desKey').value;
    if (!plaintext || !key) return showToast('Vui lòng nhập Plaintext và Key!', 'error');
    const data = await apiCall('/api/des/encrypt', { plaintext, key });
    if (data.status === 'success') {
        document.getElementById('desCiphertext').value = data.ciphertext;
        showToast('Mã hóa DES thành công!');
    } else showToast(data.message, 'error');
}

async function runDESDecrypt() {
    const ciphertext = document.getElementById('desCiphertext').value;
    const key = document.getElementById('desKey').value;
    if (!ciphertext || !key) return showToast('Vui lòng nhập Ciphertext và Key!', 'error');
    const data = await apiCall('/api/des/decrypt', { ciphertext, key });
    if (data.status === 'success') {
        document.getElementById('desPlaintext').value = data.plaintext;
        showToast('Giải mã DES thành công!');
    } else showToast(data.message, 'error');
}