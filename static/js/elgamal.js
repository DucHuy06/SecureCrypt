async function generateElGamalKeys() {
    showToast('Đang tạo cặp khóa ElGamal...');
    const data = await apiCall('/api/elgamal/generate-keys', { bits: 512 });
    if (data.status === 'success') {
        document.getElementById('elgamalPublicKey').value = data.public_key;
        document.getElementById('elgamalPrivateKey').value = data.private_key;
        showToast('Tạo khóa ElGamal thành công!');
    } else showToast(data.message, 'error');
}

async function runElGamalEncrypt() {
    const plaintext = document.getElementById('elgamalPlaintext').value;
    const public_key = document.getElementById('elgamalPublicKey').value;
    if (!plaintext || !public_key) return showToast('Nhập Plaintext và Public Key!', 'error');
    const data = await apiCall('/api/elgamal/encrypt', { plaintext, public_key });
    if (data.status === 'success') {
        document.getElementById('elgamalCiphertext').value = data.ciphertext;
        showToast('Mã hóa ElGamal thành công!');
    } else showToast(data.message, 'error');
}

async function runElGamalDecrypt() {
    const ciphertext = document.getElementById('elgamalCiphertext').value;
    const private_key = document.getElementById('elgamalPrivateKey').value;
    if (!ciphertext || !private_key) return showToast('Nhập Ciphertext và Private Key!', 'error');
    const data = await apiCall('/api/elgamal/decrypt', { ciphertext, private_key });
    if (data.status === 'success') {
        document.getElementById('elgamalPlaintext').value = data.plaintext;
        showToast('Giải mã ElGamal thành công!');
    } else showToast(data.message, 'error');
}