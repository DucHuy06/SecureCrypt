async function runMD5Hash() {
    const plaintext = document.getElementById('md5Input').value;
    if (!plaintext) return showToast('Nhập văn bản cần băm!', 'error');
    const data = await apiCall('/api/md5/hash', { plaintext });
    if (data.status === 'success') {
        document.getElementById('md5Output').value = data.hash;
        showToast('Tính băm MD5 thành công!');
    }
}

async function compareMD5() {
    const input1 = document.getElementById('md5Input').value;
    const input2 = document.getElementById('md5CompareHash').value;
    if (!input1 || !input2) return showToast('Nhập đủ dữ liệu để so sánh!', 'error');
    const data = await apiCall('/api/md5/compare', { input1, input2 });
    showToast(data.message, data.match ? 'success' : 'error');
}