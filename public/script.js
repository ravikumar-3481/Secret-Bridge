       const API_URL = "https://secret-bridge-2.onrender.com/api";
        const API_KEY = "super_secret_bridge_api_key_2024";

        let activeTab = 'home'; 
        let selectedFiles = []; 
        let downloadedMetadata = null;
        let globalEntropy = ""; 

        // Toast Notification System
        function showToast(message, type = 'error') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            const icon = type === 'error' ? 'solar:danger-triangle-bold-duotone' : 'solar:check-circle-bold-duotone';
            const color = type === 'error' ? 'bg-red-500' : 'bg-green-500';
            
            toast.className = `flex items-center gap-3 px-4 py-3 rounded-xl shadow-xl text-white text-sm font-bold slide-up pointer-events-auto ${color}`;
            toast.innerHTML = `<span class="iconify w-5 h-5" data-icon="${icon}"></span> ${message}`;
            
            container.appendChild(toast);
            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateY(10px)';
                toast.style.transition = 'all 0.3s ease';
                setTimeout(() => toast.remove(), 300);
            }, 4000);
        }

        // Navigation
        function navigateTo(view) {
            document.getElementById('view-home').classList.toggle('hidden', view !== 'home');
            document.getElementById('view-vault').classList.toggle('hidden', view === 'home');
            if(view !== 'home') switchTab(view);
        }

        function switchTab(tab) {
            document.getElementById('tab-content-send').classList.toggle('hidden', tab !== 'send');
            document.getElementById('tab-content-receive').classList.toggle('hidden', tab !== 'receive');
            
            const btnSend = document.getElementById('tab-btn-send');
            const btnReceive = document.getElementById('tab-btn-receive');
            
            if (tab === 'send') {
                btnSend.className = "flex-1 py-3 rounded-xl text-sm font-bold bg-white text-brand-600 shadow-sm flex items-center justify-center gap-2 transition-all";
                btnReceive.className = "flex-1 py-3 rounded-xl text-sm font-bold text-zinc-500 flex items-center justify-center gap-2 hover:text-zinc-700 hover:bg-white/50 transition-all";
            } else {
                btnReceive.className = "flex-1 py-3 rounded-xl text-sm font-bold bg-white text-brand-600 shadow-sm flex items-center justify-center gap-2 transition-all";
                btnSend.className = "flex-1 py-3 rounded-xl text-sm font-bold text-zinc-500 flex items-center justify-center gap-2 hover:text-zinc-700 hover:bg-white/50 transition-all";
            }
        }

        // Drag and Drop Logic
        const dropZone = document.getElementById('drop-zone');
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
        });
        function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.add('drag-active'), false);
        });
        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('drag-active'), false);
        });
        dropZone.addEventListener('drop', (e) => {
            selectedFiles = [...selectedFiles, ...Array.from(e.dataTransfer.files)];
            updateFilesUI();
        }, false);

        // File Selection UI
        function handleFilesSelect(event) {
            selectedFiles = [...selectedFiles, ...Array.from(event.target.files)];
            updateFilesUI();
            document.getElementById('file-input').value = '';
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function updateFilesUI() {
            const container = document.getElementById('selected-files-container');
            if (!selectedFiles.length) {
                container.classList.add('hidden');
                return;
            }
            container.classList.remove('hidden');
            container.innerHTML = selectedFiles.map((f, i) => `
                <div class="flex justify-between items-center bg-white border border-zinc-200 p-2.5 rounded-xl shadow-sm fade-in">
                    <div class="flex items-center gap-3 overflow-hidden">
                        <div class="bg-brand-50 p-2 rounded-lg"><span class="iconify w-4 h-4 text-brand-500" data-icon="solar:file-bold-duotone"></span></div>
                        <div class="flex flex-col truncate pr-2">
                            <span class="text-sm font-bold text-zinc-800 truncate">${f.name}</span>
                            <span class="text-[10px] font-semibold text-zinc-400">${formatBytes(f.size)}</span>
                        </div>
                    </div>
                    <button onclick="selectedFiles.splice(${i}, 1); updateFilesUI();" class="text-zinc-400 hover:text-red-500 bg-zinc-50 hover:bg-red-50 p-2 rounded-lg transition-colors">
                        <span class="iconify w-4 h-4" data-icon="solar:trash-bin-trash-bold"></span>
                    </button>
                </div>
            `).join('');
        }

        // OTP Input Logic
        const otpInputs = document.querySelectorAll('.otp-input');
        otpInputs.forEach((input, index) => {
            input.addEventListener('input', (e) => {
                let val = e.target.value.replace(/\D/g, '');
                e.target.value = val.substring(val.length - 1);
                if (e.target.value) {
                    input.classList.add('border-brand-500');
                    if (index < 5) otpInputs[index + 1].focus();
                }
            });
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace' && !e.target.value && index > 0) {
                    otpInputs[index - 1].focus();
                    otpInputs[index - 1].classList.remove('border-brand-500');
                }
            });
            input.addEventListener('paste', (e) => {
                e.preventDefault();
                const text = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '');
                for (let i = 0; i < 6; i++) {
                    if (index + i < 6 && text[i]) {
                        otpInputs[index + i].value = text[i];
                        otpInputs[index + i].classList.add('border-brand-500');
                    }
                }
                if (index + text.length < 6) otpInputs[index + text.length].focus();
                else otpInputs[5].focus();
            });
        });

        // URL Hash Routing
        window.addEventListener('DOMContentLoaded', () => {
            if (window.location.hash.startsWith('#vault=')) {
                const mobile = window.location.hash.split('=')[1];
                navigateTo('receive');
                document.getElementById('receive-mobile-input').value = mobile;
                setTimeout(() => otpInputs[0].focus(), 500);
            }
        });

        function copyShareLink() {
            const input = document.getElementById('share-link-input');
            input.select();
            document.execCommand('copy');
            showToast("Link copy ho gaya!", "success");
        }
        
        function copyDecryptedText() {
            const text = document.getElementById('decrypted-text-display');
            text.select();
            document.execCommand('copy');
            showToast("Text copy ho gaya!", "success");
        }

        // ==========================================
        // 🚀 PRODUCTION CRYPTO ENGINE (Uint8Array)
        // ==========================================
        async function sha256Hash(text) {
            const data = new TextEncoder().encode(text);
            const hash = await crypto.subtle.digest('SHA-256', data);
            return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        async function deriveKey(password, salt) {
            const enc = new TextEncoder().encode(password);
            const keyMat = await crypto.subtle.importKey("raw", enc, { name: "PBKDF2" }, false, ["deriveKey"]);
            return crypto.subtle.deriveKey(
                { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
                keyMat, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
            );
        }

        async function compressData(uint8Array) {
            const stream = new Blob([uint8Array]).stream().pipeThrough(new CompressionStream('gzip'));
            return new Uint8Array(await new Response(stream).arrayBuffer());
        }
        
        async function decompressData(uint8Array) {
            const stream = new Blob([uint8Array]).stream().pipeThrough(new DecompressionStream('gzip'));
            return new Uint8Array(await new Response(stream).arrayBuffer());
        }

        async function encryptBuffer(dataUint8Array, password) {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const key = await deriveKey(password, salt);
            const encryptedBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, dataUint8Array);
            
            const combined = new Uint8Array(16 + 12 + encryptedBuffer.byteLength);
            combined.set(salt, 0); combined.set(iv, 16);
            combined.set(new Uint8Array(encryptedBuffer), 28);
            return combined;
        }

        async function decryptBuffer(combinedUint8Array, password) {
            const salt = combinedUint8Array.slice(0, 16);
            const iv = combinedUint8Array.slice(16, 28);
            const data = combinedUint8Array.slice(28);
            const key = await deriveKey(password, salt);
            return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, data));
        }

        function bufferToBase64(buf) {
            const bin = Array.from(buf).map(b => String.fromCharCode(b)).join('');
            return window.btoa(bin);
        }
        
        function base64ToBuffer(b64) {
            const bin = window.atob(b64);
            const buf = new Uint8Array(bin.length);
            for(let i=0; i<bin.length; i++) buf[i] = bin.charCodeAt(i);
            return buf;
        }

        async function runParallel(tasks, limit = 5) {
            const results = [];
            const executing = new Set();
            for (const task of tasks) {
                const p = Promise.resolve().then(() => task());
                results.push(p);
                executing.add(p);
                const clean = () => executing.delete(p);
                p.then(clean).catch(clean);
                if (executing.size >= limit) await Promise.race(executing);
            }
            return Promise.all(results);
        }

        // ==========================================
        // 🚀 CHUNKING UPLOAD LOGIC
        // ==========================================
        async function executeUpload() {
            const mobile = document.getElementById('send-mobile-input').value;
            const pin = document.getElementById('send-code-input').value;
            const textData = document.getElementById('send-textarea').value.trim();
            
            if(!mobile || pin.length < 6) return showToast("Sahi ID aur 6-digit PIN darj karein.");
            if(!textData && selectedFiles.length === 0) return showToast("Koi text ya file add karein.");

            startProcessing(5, "Data compress aur encrypt ho raha hai...");
            const entropyKey = mobile + pin;
            const recordId = await sha256Hash(entropyKey);

            try {
                let encryptedTextStr = null;
                if (textData) {
                    const compText = await compressData(new TextEncoder().encode(textData));
                    const encText = await encryptBuffer(compText, entropyKey);
                    encryptedTextStr = bufferToBase64(encText);
                }

                await fetch(`${API_URL}/vault/init`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
                    body: JSON.stringify({ id: recordId, text_ciphertext: encryptedTextStr })
                });

                const CHUNK_SIZE = 5 * 1024 * 1024; // 5 MB chunks
                let totalUploadTasks = [];
                
                for (let i = 0; i < selectedFiles.length; i++) {
                    const file = selectedFiles[i];
                    updateProgress(10 + (i*10), `${file.name} encrypt ho raha hai...`);
                    
                    const fileId = await sha256Hash(recordId + file.name + i);
                    const fileBuffer = new Uint8Array(await file.arrayBuffer());
                    const compBuffer = await compressData(fileBuffer);
                    const encBuffer = await encryptBuffer(compBuffer, entropyKey);
                    
                    const totalChunks = Math.ceil(encBuffer.byteLength / CHUNK_SIZE);
                    
                    for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
                        const start = chunkIndex * CHUNK_SIZE;
                        const chunkSlice = encBuffer.slice(start, start + CHUNK_SIZE);
                        
                        totalUploadTasks.push(async () => {
                            const formData = new FormData();
                            formData.append('vault_id', recordId);
                            formData.append('file_id', fileId);
                            formData.append('chunk_index', chunkIndex);
                            formData.append('total_chunks', totalChunks);
                            formData.append('file_name', file.name);
                            formData.append('mime_type', file.type || 'application/octet-stream');
                            formData.append('file_size', file.size);
                            formData.append('chunk', new Blob([chunkSlice]), 'chunk.enc');

                            await fetch(`${API_URL}/vault/chunk`, { 
                                method: 'POST', 
                                headers: { 'X-API-Key': API_KEY },
                                body: formData 
                            });
                        });
                    }
                }

                if(totalUploadTasks.length > 0) {
                    updateProgress(50, "Chunks parallel me upload ho rahe hain...");
                    let completedTasks = 0;
                    const wrappedTasks = totalUploadTasks.map(task => async () => {
                        await task();
                        completedTasks++;
                        updateProgress(50 + (completedTasks / totalUploadTasks.length * 40), `Uploading chunks (${completedTasks}/${totalUploadTasks.length})`);
                    });
                    await runParallel(wrappedTasks, 5);
                }

                updateProgress(100, "Secured.");
                setTimeout(() => {
                    document.getElementById('vault-uploading').classList.add('hidden');
                    
                    // Setup QR & Link
                    const link = `${window.location.origin}${window.location.pathname}#vault=${mobile}`;
                    document.getElementById('share-link-input').value = link;
                    document.getElementById('qrcode').innerHTML = '';
                    new QRCode(document.getElementById('qrcode'), {
                        text: link, width: 140, height: 140, colorDark : "#27272a", colorLight : "#f8fafc", correctLevel : QRCode.CorrectLevel.L
                    });

                    document.getElementById('vault-success').classList.remove('hidden');
                    selectedFiles = []; updateFilesUI();
                }, 600);

            } catch (err) {
                showToast(err.message);
                resetVaultState();
            }
        }

        // ==========================================
        // 📥 STREAMING DOWNLOAD LOGIC
        // ==========================================
        async function executeDownload() {
            const mobile = document.getElementById('receive-mobile-input').value;
            const pin = Array.from(document.querySelectorAll('.otp-input')).map(i => i.value).join('');
            if(!mobile || pin.length < 6) return showToast("Sahi ID aur 6-digit PIN darj karein.");

            globalEntropy = mobile + pin;
            const recordId = await sha256Hash(globalEntropy);

            startProcessing(30, "Vault Metadata dhundh rahe hain...");

            try {
                const res = await fetch(`${API_URL}/vault/metadata/${recordId}`, { headers: { 'X-API-Key': API_KEY } });
                if (!res.ok) throw new Error("Vault jal chuka hai ya credentials galat hain.");
                downloadedMetadata = await res.json();

                updateProgress(70, "Text Decrypt ho raha hai...");
                
                document.getElementById('vault-uploading').classList.add('hidden');
                document.getElementById('vault-preview').classList.remove('hidden');

                if (downloadedMetadata.text_ciphertext) {
                    try {
                        const encBuf = base64ToBuffer(downloadedMetadata.text_ciphertext);
                        const decBuf = await decryptBuffer(encBuf, globalEntropy);
                        const rawText = new TextDecoder().decode(await decompressData(decBuf));
                        document.getElementById('preview-text-container').classList.remove('hidden');
                        document.getElementById('decrypted-text-display').value = rawText;
                    } catch(e) { showToast("Text decrypt karne me error."); }
                }

                if (downloadedMetadata.files && downloadedMetadata.files.length > 0) {
                    document.getElementById('preview-files-container').classList.remove('hidden');
                    document.getElementById('files-grid').innerHTML = downloadedMetadata.files.map((f) => `
                        <div class="flex justify-between items-center bg-white border border-zinc-200 p-3 rounded-xl shadow-sm">
                            <div class="flex items-center gap-3 overflow-hidden">
                                <div class="bg-brand-50 p-2 rounded-lg"><span class="iconify w-5 h-5 text-brand-500" data-icon="solar:file-bold-duotone"></span></div>
                                <div class="flex flex-col truncate pr-2">
                                    <span class="text-sm font-bold text-zinc-800 truncate">${f.file_name}</span>
                                    <span class="text-[10px] font-semibold text-zinc-400">${formatBytes(f.file_size)}</span>
                                </div>
                            </div>
                            <button onclick="downloadSingleFile('${f.file_id}', '${f.file_name}', this)" class="bg-zinc-800 hover:bg-zinc-700 text-white text-xs px-4 py-2.5 rounded-lg font-bold transition-colors shadow-md">
                                Download
                            </button>
                        </div>
                    `).join('');
                } else if(!downloadedMetadata.text_ciphertext) {
                    showToast("Vault me koi data nahi mila.");
                }

            } catch (err) {
                showToast(err.message);
                resetVaultState();
            }
        }

        async function downloadSingleFile(fileId, fileName, btnElement) {
            try {
                const originalText = btnElement.innerText;
                btnElement.innerText = "Downloading..."; 
                btnElement.disabled = true;
                btnElement.classList.add('opacity-50', 'cursor-not-allowed');

                const res = await fetch(`${API_URL}/vault/download/${fileId}`, { headers: { 'X-API-Key': API_KEY } });
                if(!res.ok) throw new Error("File server par nahi mili ya jal chuki hai.");
                
                const encBuffer = new Uint8Array(await res.arrayBuffer());
                btnElement.innerText = "Decrypting...";
                const decBuffer = await decryptBuffer(encBuffer, globalEntropy);
                
                btnElement.innerText = "Extracting...";
                const rawBuffer = await decompressData(decBuffer);

                const blob = new Blob([rawBuffer]);
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = fileName;
                a.click();

                btnElement.innerText = "Done ✓";
                btnElement.classList.replace('bg-zinc-800', 'bg-green-600');
                btnElement.classList.remove('opacity-50', 'cursor-not-allowed');
            } catch (err) {
                showToast(err.message);
                btnElement.innerText = "Failed";
                btnElement.classList.replace('bg-zinc-800', 'bg-red-500');
            }
        }

        // --- Utils ---
        function startProcessing(progress, text) {
            document.getElementById('vault-idle').classList.add('hidden');
            document.getElementById('vault-uploading').classList.remove('hidden');
            updateProgress(progress, text);
        }
        function updateProgress(val, text) {
            document.getElementById('progress-fill').style.width = `${val}%`;
            document.getElementById('progress-text').innerText = `${Math.round(val)}%`;
            document.getElementById('progress-detail').innerText = text;
        }
        function resetVaultState() { location.reload(); }
        function wipeAndClose() { globalEntropy = ""; downloadedMetadata = null; resetVaultState(); }
 
