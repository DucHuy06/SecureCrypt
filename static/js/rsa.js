async function generateRSAKeys() {
    const bits = parseInt(document.getElementById('rsaBits').value);
    showToast('Đang sinh cặp khóa RSA (2048-bit)...');
    const data = await apiCall('/api/rsa/generate-keys', { bits });
    if (data.status === 'success') {
        document.getElementById('rsaPublicKey').value = data.public_key;
        document.getElementById('rsaPrivateKey').value = data.private_key;
        showToast('Sinh cặp khóa RSA thành công!');
    } else showToast(data.message, 'error');
}

async function runRSAEncrypt() {
    const plaintext = document.getElementById('rsaPlaintext').value;
    const public_key = document.getElementById('rsaPublicKey').value;
    if (!plaintext || !public_key) return showToast('Vui lòng nhập Plaintext và Public Key!', 'error');
    const data = await apiCall('/api/rsa/encrypt', { plaintext, public_key });
    if (data.status === 'success') {
        document.getElementById('rsaCiphertext').value = data.ciphertext;
        showToast('Mã hóa RSA thành công!');
    } else showToast(data.message, 'error');
}

async function runRSADecrypt() {
    const ciphertext = document.getElementById('rsaCiphertext').value;
    const private_key = document.getElementById('rsaPrivateKey').value;
    if (!ciphertext || !private_key) return showToast('Vui lòng nhập Ciphertext và Private Key!', 'error');
    const data = await apiCall('/api/rsa/decrypt', { ciphertext, private_key });
    if (data.status === 'success') {
        document.getElementById('rsaPlaintext').value = data.plaintext;
        showToast('Giải mã RSA thành công!');
    } else showToast(data.message, 'error');
}