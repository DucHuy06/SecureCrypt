async function checkFileIntegrity() {
    const fileInput = document.getElementById('integrityFile');
    if (!fileInput.files[0]) return showToast('Vui lòng chọn tập tin!', 'error');

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    try {
        const res = await fetch('/api/integrity/hash-file', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.status === 'success') {
            document.getElementById('fileMD5').innerText = data.md5;
            document.getElementById('fileSHA256').innerText = data.sha256;
            document.getElementById('fileResultCard').style.display = 'block';
            showToast('Tính toán mã Hash tập tin thành công!');
        }
    } catch (e) { showToast('Lỗi đọc file!', 'error'); }
}