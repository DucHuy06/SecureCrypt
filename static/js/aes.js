async function generateAESKey(bits = 256) {
    const data = await apiCall('/api/aes/generate-key', { bits });
    if (data.status === 'success') {
        document.getElementById('aesKey').value = data.key;
        showToast(`Đã tạo khóa AES-${bits} ngẫu nhiên!`);
    }
}

async function runAESEncrypt() {
    const plaintext = document.getElementById('aesPlaintext').value;
    const key = document.getElementById('aesKey').value;
    if (!plaintext || !key) return showToast('Vui lòng nhập Plaintext và Key!', 'error');
    const data = await apiCall('/api/aes/encrypt', { plaintext, key });
    if (data.status === 'success') {
        document.getElementById('aesCiphertext').value = data.ciphertext;
        showToast('Mã hóa AES thành công!');
    } else showToast(data.message, 'error');
}

async function runAESDecrypt() {
    const ciphertext = document.getElementById('aesCiphertext').value;
    const key = document.getElementById('aesKey').value;
    if (!ciphertext || !key) return showToast('Vui lòng nhập Ciphertext và Key!', 'error');
    const data = await apiCall('/api/aes/decrypt', { ciphertext, key });
    if (data.status === 'success') {
        document.getElementById('aesPlaintext').value = data.plaintext;
        showToast('Giải mã AES thành công!');
    } else showToast(data.message, 'error');
}

async function runAESFileEncrypt() {
    const fileInput = document.getElementById('aesFile');
    const key = document.getElementById('aesKey').value;
    if (!fileInput.files[0] || !key) return showToast('Vui lòng chọn File và nhập Key!', 'error');

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('key', key);

    try {
        const res = await fetch('/api/file/aes/encrypt', { method: 'POST', body: formData });
        if (!res.ok) throw new Error('Mã hóa file thất bại');
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `encrypted_${fileInput.files[0].name}.enc`;
        a.click();
        showToast('Mã hóa File thành công! Đã tải về.');
    } catch (e) { showToast(e.message, 'error'); }
}

async function runAESFileDecrypt() {
    const fileInput = document.getElementById('aesFile');
    const key = document.getElementById('aesKey').value;
    if (!fileInput.files[0] || !key) return showToast('Vui lòng chọn File và nhập Key!', 'error');

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('key', key);

    try {
        const res = await fetch('/api/file/aes/decrypt', { method: 'POST', body: formData });
        if (!res.ok) throw new Error('Giải mã file thất bại! Kiểm tra khóa AES.');
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileInput.files[0].name.replace('.enc', '').replace('encrypted_', 'decrypted_');
        a.click();
        showToast('Giải mã File thành công! Đã tải về.');
    } catch (e) { showToast(e.message, 'error'); }
}