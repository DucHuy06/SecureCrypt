async function runSHA256Hash() {
    const plaintext = document.getElementById('shaInput').value;
    if (!plaintext) return showToast('Nhập văn bản cần băm!', 'error');
    const data = await apiCall('/api/sha256/hash', { plaintext });
    if (data.status === 'success') {
        document.getElementById('shaOutput').value = data.hash;
        showToast('Tính băm SHA-256 thành công!');
    }
}

async function compareSHA256() {
    const input1 = document.getElementById('shaInput').value;
    const input2 = document.getElementById('shaCompareHash').value;
    if (!input1 || !input2) return showToast('Nhập đủ dữ liệu để so sánh!', 'error');
    const data = await apiCall('/api/sha256/compare', { input1, input2 });
    showToast(data.message, data.match ? 'success' : 'error');
}