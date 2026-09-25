async function runFullDemo() {
    const plaintext = document.getElementById('demoInput').value;
    if (!plaintext) return showToast('Nhập văn bản thử nghiệm!', 'error');

    showToast('Đang chạy toàn bộ 6 thuật toán...');
    const data = await apiCall('/api/demo/full', { plaintext });
    
    if (data.status === 'success') {
        document.getElementById('demoAESKey').innerText = data.step1_aes.session_key_hex;
        document.getElementById('demoAESCipher').innerText = data.step1_aes.ciphertext;
        document.getElementById('demoRSAEncKey').innerText = data.step2_rsa.encrypted_session_key;
        document.getElementById('demoElGamalEncKey').innerText = data.step3_elgamal.encrypted_session_key;
        document.getElementById('demoMD5').innerText = data.step4_md5;
        document.getElementById('demoSHA256').innerText = data.step5_sha256;
        document.getElementById('demoResultPanel').style.display = 'block';
        showToast('Demo thành công 6/6 thuật toán!');
    } else showToast(data.message, 'error');
}