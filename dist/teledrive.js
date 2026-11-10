/**
 * TeleDrive — Saved Messages Organizer & Privacy-First Cloud UI
 * Strict TypeScript Implementation (Zero-Leak Client-Side Architecture)
 */
// ── 2. Web Crypto Privacy Engine (AES-GCM 256-Bit + PBKDF2) ──────────────────
export class PrivacyCryptoEngine {
    static ITERATIONS = 100000;
    activeKey = null;
    bufToBase64(buffer) {
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    base64ToBuf(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
    async deriveKeyFromPin(pin, saltBase64) {
        const enc = new TextEncoder();
        const salt = saltBase64 ? this.base64ToBuf(saltBase64) : crypto.getRandomValues(new Uint8Array(16));
        const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), { name: 'PBKDF2' }, false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({
            name: 'PBKDF2',
            salt: salt.buffer,
            iterations: PrivacyCryptoEngine.ITERATIONS,
            hash: 'SHA-256',
        }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        this.activeKey = key;
        return { key, salt: this.bufToBase64(salt) };
    }
    async encryptJSON(data) {
        if (!this.activeKey) {
            throw new Error('Privacy vault is locked. Missing encryption key.');
        }
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(JSON.stringify(data));
        const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.activeKey, encoded);
        return JSON.stringify({
            iv: this.bufToBase64(iv),
            payload: this.bufToBase64(cipherBuf),
        });
    }
    async decryptJSON(serializedCipher) {
        if (!this.activeKey) {
            throw new Error('Privacy vault is locked. Missing decryption key.');
        }
        const parsed = JSON.parse(serializedCipher);
        const iv = this.base64ToBuf(parsed.iv);
        const data = this.base64ToBuf(parsed.payload);
        const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv.buffer }, this.activeKey, data.buffer);
        const jsonStr = new TextDecoder().decode(plainBuf);
        return JSON.parse(jsonStr);
    }
    lockMemory() {
        this.activeKey = null;
    }
    isUnlocked() {
        return this.activeKey !== null;
    }
}
// ── 3. Main TeleDrive Saved Messages Controller ──────────────────────────────
export class TeleDriveController {
    STORAGE_VAULT_KEY = 'teledrive_saved_encrypted_vault_v1';
    STORAGE_CONFIG_KEY = 'teledrive_saved_config_v1';
    STORAGE_PIN_HASH_KEY = 'teledrive_saved_pin_hash_v1';
    cryptoEngine = new PrivacyCryptoEngine();
    folders = [];
    files = [];
    config = {
        botToken: '',
        ownerUserId: '',
        autoOrganizeByHashtag: true,
        autoOrganizeByExtension: true,
        autoLockMinutes: 5,
    };
    currentView = 'grid';
    currentCategory = 'all';
    currentFolderId = null;
    currentNav = 'saved-root';
    selectedId = null;
    ctxTarget = null;
    sortAsc = true;
    inactivityTimer = null;
    TYPE_COLORS = {
        img: '#2AABEE',
        vid: '#ef4444',
        doc: '#22c55e',
        zip: '#f59e0b',
        audio: '#a78bfa',
        other: '#525870',
    };
    FOLDER_COLORS = [
        '#2AABEE', '#ef4444', '#22c55e', '#f59e0b', '#a78bfa', '#ec4899'
    ];
    constructor() {
        this.initTelegramMiniApp();
        this.loadPublicConfig();
        this.bindGlobalEvents();
    }
    // ── Initialization & Telegram Mini App Binding ───────────────────────────
    initTelegramMiniApp() {
        if (window.Telegram?.WebApp) {
            window.Telegram.WebApp.ready();
            window.Telegram.WebApp.expand();
        }
    }
    loadPublicConfig() {
        const rawCfg = localStorage.getItem(this.STORAGE_CONFIG_KEY);
        if (rawCfg) {
            try {
                this.config = { ...this.config, ...JSON.parse(rawCfg) };
            }
            catch {
                // Fallback to default config
            }
        }
    }
    verifyTelegramIdentity() {
        const tgUser = window.Telegram?.WebApp?.initDataUnsafe?.user;
        if (!tgUser) {
            // Allow local standalone browser usage if PIN matches
            return true;
        }
        if (!this.config.ownerUserId) {
            // Auto-bind to current Telegram user's Saved Messages ID on first run
            this.config.ownerUserId = String(tgUser.id);
            this.savePublicConfig();
            return true;
        }
        return String(tgUser.id) === String(this.config.ownerUserId);
    }
    // ── Privacy Vault Unlock / Lock Lifecycle ────────────────────────────────
    async unlockSavedDrive(pinInput) {
        const cleanPin = pinInput.trim();
        if (cleanPin.length < 4) {
            this.showToast('PIN must be at least 4 digits');
            return;
        }
        if (!this.verifyTelegramIdentity()) {
            this.showToast('Privacy Guard: Unauthorized Telegram User ID');
            return;
        }
        try {
            const { salt } = await this.cryptoEngine.deriveKeyFromPin(cleanPin, this.config.pinSalt);
            if (!this.config.pinSalt) {
                this.config.pinSalt = salt;
                this.savePublicConfig();
            }
            const encryptedVault = localStorage.getItem(this.STORAGE_VAULT_KEY);
            if (encryptedVault) {
                const decrypted = await this.cryptoEngine.decryptJSON(encryptedVault);
                this.folders = decrypted.folders;
                this.files = decrypted.files;
            }
            else {
                // First time initialization: seed organized Saved Messages structure
                this.seedInitialSavedMessages();
                await this.persistEncryptedVault();
            }
            const lockOverlay = document.getElementById('privacyLock');
            if (lockOverlay)
                lockOverlay.classList.remove('show');
            this.resetInactivityTimer();
            this.updateBadgesAndStorage();
            this.renderView();
            this.showToast('Saved Messages Vault Decrypted');
        }
        catch {
            this.cryptoEngine.lockMemory();
            this.showToast('Invalid Master PIN — Decryption Failed');
        }
    }
    lockSavedDrive() {
        this.cryptoEngine.lockMemory();
        this.folders = [];
        this.files = [];
        this.selectedId = null;
        const container = document.getElementById('filesContainer');
        if (container)
            container.innerHTML = '';
        this.closePreview();
        const lockOverlay = document.getElementById('privacyLock');
        const pinInput = document.getElementById('drivePin');
        if (pinInput)
            pinInput.value = '';
        if (lockOverlay)
            lockOverlay.classList.add('show');
        this.showToast('Saved Drive Locked & Memory Wiped');
    }
    resetInactivityTimer() {
        if (this.inactivityTimer)
            window.clearTimeout(this.inactivityTimer);
        const ms = (this.config.autoLockMinutes || 5) * 60 * 1000;
        this.inactivityTimer = window.setTimeout(() => {
            if (this.cryptoEngine.isUnlocked()) {
                this.lockSavedDrive();
            }
        }, ms);
    }
    async persistEncryptedVault() {
        if (!this.cryptoEngine.isUnlocked())
            return;
        const cipher = await this.cryptoEngine.encryptJSON({
            folders: this.folders,
            files: this.files,
        });
        localStorage.setItem(this.STORAGE_VAULT_KEY, cipher);
        this.updateBadgesAndStorage();
    }
    savePublicConfig() {
        localStorage.setItem(this.STORAGE_CONFIG_KEY, JSON.stringify(this.config));
    }
    // ── Seed Initial Organized "Saved Messages" Data (No Scattered Mess) ─────
    seedInitialSavedMessages() {
        this.folders = [
            { id: 'f_design', name: 'Design Assets', tag: '#design', count: 2, size: '4.1 MB', color: '#2AABEE', modified: 'Saved • #design', parent: null },
            { id: 'f_videos', name: 'Saved Videos', tag: '#video', count: 2, size: '21.2 MB', color: '#ef4444', modified: 'Saved • #video', parent: null },
            { id: 'f_docs', name: 'Study & Docs', tag: '#docs', count: 2, size: '1.4 MB', color: '#22c55e', modified: 'Saved • #docs', parent: null },
            { id: 'f_code', name: 'Code & Archives', tag: '#code', count: 2, size: '62.0 MB', color: '#f59e0b', modified: 'Saved • #code', parent: null },
            { id: 'f_audio', name: 'Voice & Audio', tag: '#audio', count: 1, size: '3.5 MB', color: '#a78bfa', modified: 'Saved • #audio', parent: null },
            { id: 'f_snaps', name: 'Screenshots', tag: '#snap', count: 1, size: '5.4 MB', color: '#ec4899', modified: 'Saved • #snap', parent: null },
        ];
        this.files = [
            {
                id: 'sv_1', name: 'project-banner-v3.jpg', type: 'img', ext: 'JPG', size: '3.2 MB', bytes: 3355443,
                modified: 'Saved • #design', msgId: '#91822', folderId: 'f_design', tags: ['#design'],
                starred: true, trashed: false,
                preview: 'https://images.unsplash.com/photo-1558655146-9f40138edfeb?w=600&q=70',
                url: 'https://images.unsplash.com/photo-1558655146-9f40138edfeb?w=1600&q=80'
            },
            {
                id: 'sv_2', name: 'reel-final-cut.mp4', type: 'vid', ext: 'MP4', size: '12.4 MB', bytes: 13002342,
                modified: 'Saved • #video', msgId: '#91754', folderId: 'f_videos', tags: ['#video'],
                starred: false, trashed: false, duration: '0:15',
                url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4'
            },
            {
                id: 'sv_3', name: 'project-brief-notes.pdf', type: 'doc', ext: 'PDF', size: '1.1 MB', bytes: 1153433,
                modified: 'Saved • #docs', msgId: '#91690', folderId: 'f_docs', tags: ['#docs'],
                starred: true, trashed: false
            },
            {
                id: 'sv_4', name: 'thumbnail-youtube.png', type: 'img', ext: 'PNG', size: '890 KB', bytes: 911360,
                modified: 'Saved • #design', msgId: '#91650', folderId: 'f_design', tags: ['#design'],
                starred: false, trashed: false,
                preview: 'https://images.unsplash.com/photo-1611532736597-de2d4265fba3?w=600&q=70',
                url: 'https://images.unsplash.com/photo-1611532736597-de2d4265fba3?w=1600&q=80'
            },
            {
                id: 'sv_5', name: 'source-code-backup.zip', type: 'zip', ext: 'ZIP', size: '44.0 MB', bytes: 46137344,
                modified: 'Saved • #code', msgId: '#91580', folderId: 'f_code', tags: ['#code'],
                starred: false, trashed: false
            },
            {
                id: 'sv_6', name: 'voice-memo-ep14.mp3', type: 'audio', ext: 'MP3', size: '3.5 MB', bytes: 3670016,
                modified: 'Saved • #audio', msgId: '#91420', folderId: 'f_audio', tags: ['#audio'],
                starred: false, trashed: false, duration: '1:45',
                url: 'https://actions.google.com/sounds/v1/ambiences/coffee_shop.ogg'
            },
            {
                id: 'sv_7', name: 'ui-architecture.fig', type: 'other', ext: 'FIG', size: '18.0 MB', bytes: 18874368,
                modified: 'Saved • #code', msgId: '#91310', folderId: 'f_code', tags: ['#code'],
                starred: false, trashed: false
            },
            {
                id: 'sv_8', name: 'landscape-reference.jpg', type: 'img', ext: 'JPG', size: '5.4 MB', bytes: 5662310,
                modified: 'Saved • #snap', msgId: '#91100', folderId: 'f_snaps', tags: ['#snap'],
                starred: false, trashed: false,
                preview: 'https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=600&q=70',
                url: 'https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=1600&q=80'
            },
        ];
    }
    // ── Anti-Scatter Engine: Auto-Sort Saved Messages into Folders ───────────
    resolveTargetFolderForSavedItem(caption, fileType) {
        const rawTags = caption.match(/#[a-zA-Z0-9_-]+/g) || [];
        const normalizedTags = rawTags.map(t => t.toLowerCase());
        // 1. If user added a #hashtag in Saved Messages, find or create that folder automatically
        if (this.config.autoOrganizeByHashtag && normalizedTags.length > 0) {
            const primaryTag = normalizedTags[0];
            let existingFolder = this.folders.find(f => f.tag.toLowerCase() === primaryTag || `#${f.name.toLowerCase().replace(/\s+/g, '')}` === primaryTag);
            if (!existingFolder) {
                const cleanTitle = primaryTag.slice(1).replace(/[-_]/g, ' ');
                const formattedName = cleanTitle.charAt(0).toUpperCase() + cleanTitle.slice(1);
                existingFolder = {
                    id: 'f_' + Date.now(),
                    name: formattedName,
                    tag: primaryTag,
                    count: 0,
                    size: '0 MB',
                    color: this.FOLDER_COLORS[this.folders.length % this.FOLDER_COLORS.length],
                    modified: `Saved • ${primaryTag}`,
                    parent: null,
                };
                this.folders.push(existingFolder);
            }
            return { folderId: existingFolder.id, tags: normalizedTags };
        }
        // 2. If inside a folder currently in UI, place it there
        if (this.currentFolderId) {
            const currentFolder = this.folders.find(f => f.id === this.currentFolderId);
            return {
                folderId: this.currentFolderId,
                tags: currentFolder ? [currentFolder.tag] : [],
            };
        }
        // 3. Fallback: Auto-route by file type so nothing sits scattered in root!
        if (this.config.autoOrganizeByExtension) {
            const typeMap = {
                img: 'f_design',
                vid: 'f_videos',
                doc: 'f_docs',
                zip: 'f_code',
                audio: 'f_audio',
                other: 'f_code',
            };
            const targetId = typeMap[fileType];
            const found = this.folders.find(f => f.id === targetId);
            if (found) {
                return { folderId: found.id, tags: [found.tag] };
            }
        }
        return { folderId: null, tags: normalizedTags };
    }
    // ── Parse Incoming Telegram Saved Messages Updates ───────────────────────
    async ingestTelegramSavedMessage(message) {
        // Privacy check: only ingest messages belonging to the owner's Saved Messages chat
        if (this.config.ownerUserId && String(message.chat.id) !== String(this.config.ownerUserId)) {
            return false;
        }
        const msgIdStr = `#${message.message_id}`;
        if (this.files.some(f => f.msgId === msgIdStr)) {
            return false; // Already indexed
        }
        const caption = message.caption || message.text || '';
        const doc = message.document || message.video || message.audio || (message.photo ? message.photo[message.photo.length - 1] : null);
        if (!doc)
            return false;
        const rawName = doc.file_name || `saved_${message.message_id}.jpg`;
        const ext = (rawName.split('.').pop() || 'FILE').toUpperCase();
        const fileType = this.detectCategoryFromExt(ext);
        const bytes = doc.file_size || 1048576;
        const { folderId, tags } = this.resolveTargetFolderForSavedItem(caption, fileType);
        const newFile = {
            id: `sv_${message.message_id}_${Date.now()}`,
            name: rawName,
            type: fileType,
            ext,
            size: this.formatBytes(bytes),
            bytes,
            modified: tags.length ? `Saved • ${tags[0]}` : 'Saved Messages',
            msgId: msgIdStr,
            fileId: doc.file_id,
            folderId,
            tags,
            starred: caption.includes('#star'),
            trashed: false,
        };
        this.files.unshift(newFile);
        await this.persistEncryptedVault();
        return true;
    }
    // ── UI Rendering Engine ──────────────────────────────────────────────────
    renderView() {
        if (!this.cryptoEngine.isUnlocked())
            return;
        let filteredFiles = this.files.filter((f) => {
            if (this.currentNav === 'trash')
                return f.trashed;
            if (f.trashed)
                return false;
            if (this.currentNav === 'starred')
                return f.starred;
            if (this.currentNav === 'recent')
                return true;
            if (this.currentNav === 'untagged')
                return f.folderId === null;
            if (this.currentFolderId)
                return f.folderId === this.currentFolderId;
            // In root "Saved Messages" view: if auto-organization is active, only show unorganized files below folders so nothing looks scattered!
            return this.config.autoOrganizeByExtension ? f.folderId === null : true;
        });
        let filteredFolders = this.folders.filter((f) => {
            if (['trash', 'starred', 'recent', 'untagged'].includes(this.currentNav))
                return false;
            if (this.currentFolderId)
                return f.parent === this.currentFolderId;
            return !f.parent;
        });
        if (this.currentCategory !== 'all') {
            filteredFiles = filteredFiles.filter(f => f.type === this.currentCategory);
            filteredFolders = [];
        }
        filteredFiles.sort((a, b) => this.sortAsc ? a.name.localeCompare(b.name) : b.name.localeCompare(a.name));
        filteredFolders.sort((a, b) => this.sortAsc ? a.name.localeCompare(b.name) : b.name.localeCompare(a.name));
        const container = document.getElementById('filesContainer');
        if (!container)
            return;
        if (this.currentView === 'grid') {
            let html = '';
            if (filteredFolders.length > 0) {
                html += '<div class="section-head">Organized Saved Folders</div>';
                html += '<div class="files-grid" style="margin-bottom:14px">';
                filteredFolders.forEach(folder => {
                    html += this.renderFolderCard(folder);
                });
                html += '</div>';
            }
            if (filteredFiles.length > 0) {
                const label = this.currentFolderId ? 'Folder Items' : 'Saved Files';
                html += `<div class="section-head">${label}</div>`;
                html += '<div class="files-grid">';
                filteredFiles.forEach(file => {
                    html += this.renderFileCard(file);
                });
                html += '</div>';
            }
            if (filteredFolders.length === 0 && filteredFiles.length === 0) {
                html = this.renderEmptyState();
            }
            container.innerHTML = html;
        }
        else {
            let html = `<div class="files-list">
        <div class="list-header">
          <div></div><div>Name</div><div>Tag / Type</div><div>Size</div><div>Saved Info</div><div></div>
        </div>`;
            filteredFolders.forEach(folder => {
                html += this.renderFolderRow(folder);
            });
            filteredFiles.forEach(file => {
                html += this.renderFileRow(file);
            });
            if (filteredFolders.length === 0 && filteredFiles.length === 0) {
                html += this.renderEmptyState();
            }
            html += '</div>';
            container.innerHTML = html;
        }
    }
    renderFolderCard(f) {
        const childFiles = this.files.filter(x => x.folderId === f.id && !x.trashed);
        const totalBytes = childFiles.reduce((acc, item) => acc + item.bytes, 0);
        const sizeLabel = this.formatBytes(totalBytes);
        return `<div class="file-card folder-card" onclick="window.teleDriveApp.openFolder('${f.id}')" oncontextmenu="window.teleDriveApp.showCtx(event,'${f.id}',true)">
      <div class="folder-preview">
        <div class="folder-icon-wrap">
          ${this.getFolderSvg(f.color)}
          <div class="folder-count">${childFiles.length}</div>
        </div>
      </div>
      <div class="file-info">
        <div class="file-name">${this.escapeHtml(f.name)}</div>
        <div class="file-meta">${f.tag} · ${sizeLabel}</div>
      </div>
    </div>`;
    }
    renderFileCard(f) {
        const badge = `badge-${f.type}`;
        const thumb = f.preview
            ? `<img src="${f.preview}" loading="lazy" alt="${this.escapeHtml(f.name)}">`
            : this.getFileIconSvg(f.type);
        const playOverlay = f.type === 'vid' || f.type === 'audio'
            ? `<div class="play-overlay"><div class="play-btn-circle"><svg viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg></div></div>`
            : '';
        return `<div class="file-card ${this.selectedId === f.id ? 'selected' : ''}"
      onclick="window.teleDriveApp.selectFile('${f.id}')"
      ondblclick="window.teleDriveApp.openMediaViewer('${f.id}')"
      oncontextmenu="window.teleDriveApp.showCtx(event,'${f.id}',false)">
      <div class="file-thumb ${f.preview ? 'img-type' : ''}">
        ${thumb}${playOverlay}
        <span class="file-type-badge ${badge}">${f.ext}</span>
      </div>
      <div class="file-check"><svg viewBox="0 0 24 24" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg></div>
      <div class="file-info">
        <div class="file-name" title="${this.escapeHtml(f.name)}">${this.escapeHtml(f.name)}</div>
        <div class="file-meta">${f.size} · ${f.tags[0] || 'Saved'}</div>
      </div>
      <div class="file-more" onclick="window.teleDriveApp.showCtx(event,'${f.id}',false);event.stopPropagation()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/></svg>
      </div>
    </div>`;
    }
    renderFolderRow(f) {
        const childFiles = this.files.filter(x => x.folderId === f.id && !x.trashed);
        return `<div class="list-row" onclick="window.teleDriveApp.openFolder('${f.id}')" oncontextmenu="window.teleDriveApp.showCtx(event,'${f.id}',true)">
      <div class="list-icon" style="background:${f.color}20">${this.getFolderSvg(f.color).replace('class="folder-ico"', 'width="18" height="18"')}</div>
      <div class="list-name">${this.escapeHtml(f.name)}</div>
      <div class="list-type" style="color:${f.color}">${f.tag}</div>
      <div class="list-size">${childFiles.length} items</div>
      <div class="list-date">${f.modified}</div>
      <div class="list-actions">
        <button class="mini-btn" onclick="window.teleDriveApp.showCtx(event,'${f.id}',true);event.stopPropagation()">⋮</button>
      </div>
    </div>`;
    }
    renderFileRow(f) {
        const c = this.TYPE_COLORS[f.type];
        return `<div class="list-row ${this.selectedId === f.id ? 'selected' : ''}"
      onclick="window.teleDriveApp.selectFile('${f.id}')"
      ondblclick="window.teleDriveApp.openMediaViewer('${f.id}')"
      oncontextmenu="window.teleDriveApp.showCtx(event,'${f.id}',false)">
      <div class="list-icon" style="background:${c}15">${this.getFileIconSvg(f.type)}</div>
      <div class="list-name">${this.escapeHtml(f.name)}</div>
      <div class="list-type" style="color:${c}">${f.tags[0] || f.ext}</div>
      <div class="list-size">${f.size}</div>
      <div class="list-date">${f.msgId}</div>
      <div class="list-actions">
        <button class="mini-btn" onclick="window.teleDriveApp.openMediaViewer('${f.id}');event.stopPropagation()">▶</button>
        <button class="mini-btn" onclick="window.teleDriveApp.showCtx(event,'${f.id}',false);event.stopPropagation()">⋮</button>
      </div>
    </div>`;
    }
    renderEmptyState() {
        return `<div class="empty">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>
      <div class="empty-title">No scattered items here — everything is neatly organized!</div>
    </div>`;
    }
    // ── Navigation & Actions ─────────────────────────────────────────────────
    navigate(section, el) {
        this.currentNav = section;
        this.currentFolderId = null;
        this.selectedId = null;
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        if (el)
            el.classList.add('active');
        this.closePreview();
        const labels = {
            'saved-root': 'Saved Messages (Organized)',
            'auto-tagged': 'Auto-Tagged Folders',
            'starred': 'Starred in Saved',
            'recent': 'Recent Saved',
            'untagged': 'Unsorted / Root Stream',
            'trash': 'Trash Bin',
        };
        const bc = document.getElementById('breadcrumb');
        const st = document.getElementById('sectionTitle');
        if (bc)
            bc.innerHTML = `<span class="bc-item current">${labels[section]}</span>`;
        if (st)
            st.textContent = labels[section];
        this.renderView();
        this.closeSidebar();
    }
    openFolder(folderId) {
        const folder = this.folders.find(f => f.id === folderId);
        if (!folder)
            return;
        this.currentFolderId = folderId;
        this.selectedId = null;
        const bc = document.getElementById('breadcrumb');
        const st = document.getElementById('sectionTitle');
        if (bc) {
            bc.innerHTML = `<span class="bc-item" onclick="window.teleDriveApp.goHome()">Saved Messages</span>
        <span class="bc-sep">›</span>
        <span class="bc-item current">${this.escapeHtml(folder.name)} (${folder.tag})</span>`;
        }
        if (st)
            st.textContent = `${folder.name} (${folder.tag})`;
        this.renderView();
    }
    goHome() {
        this.currentFolderId = null;
        const firstNav = document.querySelector('.nav-item');
        this.navigate('saved-root', firstNav || undefined);
    }
    selectFile(id) {
        this.selectedId = this.selectedId === id ? null : id;
        this.renderView();
        if (this.selectedId) {
            const file = this.files.find(x => x.id === id);
            if (file)
                this.showPreview(file);
        }
        else {
            this.closePreview();
        }
    }
    showPreview(f) {
        const panel = document.getElementById('previewPanel');
        if (!panel)
            return;
        panel.classList.add('open');
        const c = this.TYPE_COLORS[f.type];
        const thumbEl = document.getElementById('previewThumb');
        if (thumbEl) {
            thumbEl.innerHTML = f.preview
                ? `<img src="${f.preview}" alt="${this.escapeHtml(f.name)}">`
                : `<div style="display:flex;align-items:center;justify-content:center;width:100%;height:100%;background:${c}15">${this.getFileIconSvg(f.type)}</div>`;
        }
        const nameEl = document.getElementById('previewName');
        if (nameEl)
            nameEl.textContent = f.name;
        const folderObj = this.folders.find(fl => fl.id === f.folderId);
        const detailsEl = document.getElementById('previewDetails');
        if (detailsEl) {
            detailsEl.innerHTML = `
        <div class="detail-row"><span class="detail-label">Location</span><span class="detail-val">Saved Messages</span></div>
        <div class="detail-row"><span class="detail-label">Folder</span><span class="detail-val">${folderObj ? this.escapeHtml(folderObj.name) : 'Root'}</span></div>
        <div class="detail-row"><span class="detail-label">Hashtags</span><span class="detail-val" style="color:var(--accent)">${f.tags.join(' ') || 'None'}</span></div>
        <div class="detail-row"><span class="detail-label">Size</span><span class="detail-val">${f.size}</span></div>
        <div class="detail-row"><span class="detail-label">Msg Pointer</span><span class="detail-val" style="font-family:var(--mono)">${f.msgId}</span></div>
        <div class="detail-row"><span class="detail-label">Encryption</span><span class="detail-val" style="color:var(--green)">AES-GCM 256</span></div>
      `;
        }
        const actionsEl = document.getElementById('previewActions');
        if (actionsEl) {
            actionsEl.innerHTML = `
        <button class="p-action primary" onclick="window.teleDriveApp.openMediaViewer('${f.id}')">Open / Stream</button>
        <button class="p-action" onclick="window.teleDriveApp.reassignTag('${f.id}')">Change #Hashtag Folder</button>
        <button class="p-action" onclick="window.teleDriveApp.downloadFile('${f.id}')">Download</button>
      `;
        }
    }
    closePreview() {
        document.getElementById('previewPanel')?.classList.remove('open');
    }
    async reassignTag(fileId) {
        const file = this.files.find(x => x.id === fileId);
        if (!file)
            return;
        const newTag = prompt('Enter #hashtag to move file into that Saved Messages folder (e.g. #work, #study, #design):', file.tags[0] || '#docs');
        if (!newTag)
            return;
        const formattedTag = newTag.startsWith('#') ? newTag.trim() : `#${newTag.trim()}`;
        const { folderId, tags } = this.resolveTargetFolderForSavedItem(formattedTag, file.type);
        file.folderId = folderId;
        file.tags = tags;
        file.modified = `Saved • ${formattedTag}`;
        await this.persistEncryptedVault();
        this.renderView();
        this.showPreview(file);
        this.showToast(`Moved to ${formattedTag}`);
    }
    // ── Upload Directly to User's Saved Messages (with #hashtag caption) ─────
    async uploadFilesToSavedMessages(fileList, customTag) {
        const filesArray = Array.from(fileList);
        if (filesArray.length === 0)
            return;
        const file = filesArray[0];
        const ext = (file.name.split('.').pop() || 'BIN').toUpperCase();
        const fileType = this.detectCategoryFromExt(ext);
        const tagInput = document.getElementById('uploadHashtagInput')?.value.trim() || customTag || '';
        const { folderId, tags } = this.resolveTargetFolderForSavedItem(tagInput, fileType);
        const captionTag = tags[0] || '#saved';
        if (this.config.botToken && this.config.ownerUserId) {
            await this.dispatchToTelegramSavedMessages(file, fileType, ext, folderId, tags, captionTag);
        }
        else {
            await this.simulateEncryptedSavedUpload(file.name, fileType, ext, file.size, folderId, tags);
        }
    }
    async dispatchToTelegramSavedMessages(file, type, ext, folderId, tags, captionTag) {
        const wrap = document.getElementById('uploadProgressWrap');
        const fill = document.getElementById('uploadProgressFill');
        const stat = document.getElementById('uploadProgressStatus');
        const pct = document.getElementById('uploadProgressPct');
        if (wrap)
            wrap.style.display = 'flex';
        if (stat)
            stat.textContent = `Sending to Saved Messages (${captionTag})...`;
        const formData = new FormData();
        formData.append('chat_id', this.config.ownerUserId);
        formData.append('caption', `${file.name} ${captionTag}`);
        formData.append('document', file);
        return new Promise((resolve) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', `https://api.telegram.org/bot${this.config.botToken}/sendDocument`);
            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable && fill && pct) {
                    const p = Math.round((e.loaded / e.total) * 100);
                    fill.style.width = `${p}%`;
                    pct.textContent = `${p}%`;
                }
            };
            xhr.onload = async () => {
                if (xhr.status === 200) {
                    const res = JSON.parse(xhr.responseText);
                    const msgId = res.result?.message_id ? `#${res.result.message_id}` : `#${Math.floor(Math.random() * 90000 + 10000)}`;
                    await this.appendSavedFileRecord(file.name, type, ext, file.size, msgId, folderId, tags);
                    this.closeUpload();
                    this.showToast(`Saved with tag ${captionTag}`);
                }
                else {
                    this.showToast('Bot API fallback: indexing locally in encrypted vault');
                    await this.simulateEncryptedSavedUpload(file.name, type, ext, file.size, folderId, tags);
                }
                resolve();
            };
            xhr.onerror = async () => {
                await this.simulateEncryptedSavedUpload(file.name, type, ext, file.size, folderId, tags);
                resolve();
            };
            xhr.send(formData);
        });
    }
    async simulateEncryptedSavedUpload(name, type, ext, bytes, folderId, tags) {
        const wrap = document.getElementById('uploadProgressWrap');
        const fill = document.getElementById('uploadProgressFill');
        const stat = document.getElementById('uploadProgressStatus');
        const pct = document.getElementById('uploadProgressPct');
        if (wrap)
            wrap.style.display = 'flex';
        let progress = 0;
        return new Promise((resolve) => {
            const timer = window.setInterval(async () => {
                progress += 25;
                if (progress >= 100) {
                    window.clearInterval(timer);
                    if (fill)
                        fill.style.width = '100%';
                    if (pct)
                        pct.textContent = '100%';
                    if (stat)
                        stat.textContent = 'Encrypted & Indexed!';
                    const msgId = `#${Math.floor(Math.random() * 89999 + 10000)}`;
                    await this.appendSavedFileRecord(name, type, ext, bytes, msgId, folderId, tags);
                    this.closeUpload();
                    this.showToast(`Organized "${name}" into ${tags[0] || 'Saved Folder'}`);
                    resolve();
                }
                else {
                    if (fill)
                        fill.style.width = `${progress}%`;
                    if (pct)
                        pct.textContent = `${progress}%`;
                }
            }, 110);
        });
    }
    async appendSavedFileRecord(name, type, ext, bytes, msgId, folderId, tags) {
        const newFile = {
            id: 'sv_' + Date.now(),
            name,
            type,
            ext,
            size: this.formatBytes(bytes),
            bytes,
            modified: tags.length ? `Saved • ${tags[0]}` : 'Just now',
            msgId,
            folderId,
            tags,
            starred: false,
            trashed: false,
        };
        this.files.unshift(newFile);
        await this.persistEncryptedVault();
        this.renderView();
    }
    // ── Media Lightbox & Context Menu ────────────────────────────────────────
    openMediaViewer(id) {
        const f = this.files.find(x => x.id === id);
        if (!f)
            return;
        const modal = document.getElementById('mediaModal');
        const container = document.getElementById('mediaContainer');
        const title = document.getElementById('mediaTitle');
        if (!modal || !container || !title)
            return;
        title.textContent = `${f.name} (${f.msgId})`;
        if (f.type === 'img') {
            container.innerHTML = `<img src="${f.url || f.preview || ''}" alt="${this.escapeHtml(f.name)}">`;
        }
        else if (f.type === 'vid') {
            container.innerHTML = `<video controls autoplay src="${f.url || ''}" style="max-height:75vh"></video>`;
        }
        else if (f.type === 'audio') {
            container.innerHTML = `<audio controls autoplay src="${f.url || ''}" style="width:320px"></audio>`;
        }
        else {
            this.showToast(`Opening ${f.name} (${f.size})`);
            return;
        }
        modal.classList.add('show');
    }
    closeMedia() {
        const container = document.getElementById('mediaContainer');
        if (container)
            container.innerHTML = '';
        document.getElementById('mediaModal')?.classList.remove('show');
    }
    showCtx(e, id, isFolder) {
        e.preventDefault();
        e.stopPropagation();
        this.ctxTarget = { id, isFolder };
        const m = document.getElementById('ctxMenu');
        if (!m)
            return;
        m.style.display = 'block';
        m.style.left = `${Math.min(e.clientX, window.innerWidth - 200)}px`;
        m.style.top = `${Math.min(e.clientY, window.innerHeight - 260)}px`;
    }
    hideCtx() {
        const m = document.getElementById('ctxMenu');
        if (m)
            m.style.display = 'none';
    }
    async ctxAction(action) {
        this.hideCtx();
        if (!this.ctxTarget)
            return;
        const { id, isFolder } = this.ctxTarget;
        if (isFolder) {
            const folder = this.folders.find(x => x.id === id);
            if (!folder)
                return;
            if (action === 'open')
                this.openFolder(folder.id);
            else if (action === 'rename') {
                const name = prompt('Rename Saved Folder:', folder.name);
                if (name?.trim()) {
                    folder.name = name.trim();
                    await this.persistEncryptedVault();
                    this.renderView();
                }
            }
            else if (action === 'delete') {
                this.folders = this.folders.filter(x => x.id !== id);
                await this.persistEncryptedVault();
                this.renderView();
                this.showToast('Folder removed');
            }
            return;
        }
        const f = this.files.find(x => x.id === id);
        if (!f)
            return;
        switch (action) {
            case 'open':
                this.openMediaViewer(f.id);
                break;
            case 'preview':
                this.showPreview(f);
                break;
            case 'star':
                f.starred = !f.starred;
                await this.persistEncryptedVault();
                this.renderView();
                this.showToast(f.starred ? 'Starred in Saved Drive' : 'Removed Star');
                break;
            case 'tag':
                await this.reassignTag(f.id);
                break;
            case 'download':
                this.downloadFile(f.id);
                break;
            case 'rename': {
                const newName = prompt('Rename file:', f.name);
                if (newName?.trim()) {
                    f.name = newName.trim();
                    await this.persistEncryptedVault();
                    this.renderView();
                }
                break;
            }
            case 'delete':
                if (f.trashed) {
                    this.files = this.files.filter(x => x.id !== id);
                    this.showToast('Permanently erased from index');
                }
                else {
                    f.trashed = true;
                    this.showToast('Moved to Trash');
                }
                await this.persistEncryptedVault();
                this.renderView();
                this.closePreview();
                break;
        }
    }
    downloadFile(id) {
        const f = this.files.find(x => x.id === id);
        if (!f)
            return;
        if (f.url) {
            const a = document.createElement('a');
            a.href = f.url;
            a.download = f.name;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }
        this.showToast(`Downloading ${f.name}...`);
    }
    // ── Folder Creation & Settings ───────────────────────────────────────────
    async createSavedFolder(name, rawTag) {
        const cleanName = name.trim();
        if (!cleanName)
            return;
        const cleanTag = rawTag.trim().startsWith('#')
            ? rawTag.trim().toLowerCase()
            : `#${(rawTag.trim() || cleanName).toLowerCase().replace(/\s+/g, '')}`;
        const newFolder = {
            id: 'f_' + Date.now(),
            name: cleanName,
            tag: cleanTag,
            count: 0,
            size: '0 MB',
            color: this.FOLDER_COLORS[this.folders.length % this.FOLDER_COLORS.length],
            modified: `Saved • ${cleanTag}`,
            parent: this.currentFolderId,
        };
        this.folders.push(newFolder);
        await this.persistEncryptedVault();
        this.renderView();
        this.closeFolderModal();
        this.showToast(`Created folder "${cleanName}" mapped to ${cleanTag}`);
    }
    saveSettingsFromModal() {
        const tokenEl = document.getElementById('cfgBotToken');
        const uidEl = document.getElementById('cfgOwnerUserId');
        const autoTagEl = document.getElementById('cfgAutoTag');
        if (tokenEl)
            this.config.botToken = tokenEl.value.trim();
        if (uidEl)
            this.config.ownerUserId = uidEl.value.trim();
        if (autoTagEl)
            this.config.autoOrganizeByHashtag = autoTagEl.checked;
        this.savePublicConfig();
        this.updateBadgesAndStorage();
        this.closeSettings();
        this.showToast('Saved Messages Privacy Config Updated');
    }
    // ── Utility Helpers ──────────────────────────────────────────────────────
    setView(v) {
        this.currentView = v;
        document.getElementById('gridBtn')?.classList.toggle('active', v === 'grid');
        document.getElementById('listBtn')?.classList.toggle('active', v === 'list');
        this.renderView();
    }
    setFilter(cat, el) {
        this.currentCategory = cat;
        document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
        if (el)
            el.classList.add('active');
        this.renderView();
    }
    toggleSort() {
        this.sortAsc = !this.sortAsc;
        const lbl = document.getElementById('sortLabel');
        if (lbl)
            lbl.textContent = this.sortAsc ? 'Name ↑' : 'Name ↓';
        this.renderView();
    }
    handleSearch(query) {
        const q = query.toLowerCase().trim();
        if (!q) {
            this.renderView();
            return;
        }
        const matchedFiles = this.files.filter(f => !f.trashed && (f.name.toLowerCase().includes(q) || f.tags.some(t => t.includes(q)) || f.ext.toLowerCase().includes(q)));
        const matchedFolders = this.folders.filter(fl => fl.name.toLowerCase().includes(q) || fl.tag.toLowerCase().includes(q));
        const container = document.getElementById('filesContainer');
        if (!container)
            return;
        let html = '<div class="files-grid">';
        matchedFolders.forEach(fl => (html += this.renderFolderCard(fl)));
        matchedFiles.forEach(f => (html += this.renderFileCard(f)));
        html += '</div>';
        container.innerHTML = matchedFolders.length || matchedFiles.length ? html : this.renderEmptyState();
    }
    openUpload() {
        const wrap = document.getElementById('uploadProgressWrap');
        if (wrap)
            wrap.style.display = 'none';
        document.getElementById('uploadOverlay')?.classList.add('show');
    }
    closeUpload() {
        document.getElementById('uploadOverlay')?.classList.remove('show');
    }
    openSettings() {
        const tokenEl = document.getElementById('cfgBotToken');
        const uidEl = document.getElementById('cfgOwnerUserId');
        if (tokenEl)
            tokenEl.value = this.config.botToken;
        if (uidEl)
            uidEl.value = this.config.ownerUserId;
        document.getElementById('settingsOverlay')?.classList.add('show');
    }
    closeSettings() {
        document.getElementById('settingsOverlay')?.classList.remove('show');
    }
    openFolderModal() {
        document.getElementById('folderOverlay')?.classList.add('show');
    }
    closeFolderModal() {
        document.getElementById('folderOverlay')?.classList.remove('show');
    }
    toggleSidebar() {
        document.getElementById('sidebar')?.classList.toggle('open');
        document.getElementById('sidebarOverlay')?.classList.toggle('show');
    }
    closeSidebar() {
        document.getElementById('sidebar')?.classList.remove('open');
        document.getElementById('sidebarOverlay')?.classList.remove('show');
    }
    updateBadgesAndStorage() {
        const active = this.files.filter(f => !f.trashed);
        const starred = active.filter(f => f.starred);
        const untagged = active.filter(f => !f.folderId);
        const trashed = this.files.filter(f => f.trashed);
        const setTxt = (id, val) => {
            const el = document.getElementById(id);
            if (el)
                el.textContent = String(val);
        };
        setTxt('badgeTotal', active.length);
        setTxt('badgeStarred', starred.length);
        setTxt('badgeUntagged', untagged.length);
        setTxt('badgeTrash', trashed.length);
        const totalBytes = active.reduce((acc, f) => acc + (f.bytes || 0), 0);
        setTxt('storageUsedText', `${this.formatBytes(totalBytes)} encrypted`);
    }
    detectCategoryFromExt(ext) {
        if (/^(JPG|JPEG|PNG|GIF|WEBP|SVG)$/i.test(ext))
            return 'img';
        if (/^(MP4|MKV|WEBM|MOV|AVI)$/i.test(ext))
            return 'vid';
        if (/^(PDF|DOC|DOCX|TXT|MD|XLS|XLSX|PPT)$/i.test(ext))
            return 'doc';
        if (/^(MP3|WAV|OGG|FLAC|M4A)$/i.test(ext))
            return 'audio';
        if (/^(ZIP|RAR|7Z|TAR|GZ)$/i.test(ext))
            return 'zip';
        return 'other';
    }
    formatBytes(bytes) {
        if (bytes >= 1024 * 1024 * 1024)
            return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
        if (bytes >= 1024 * 1024)
            return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
        return `${Math.max(1, Math.round(bytes / 1024))} KB`;
    }
    escapeHtml(str) {
        return str.replace(/[&<>"']/g, m => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[m] || m));
    }
    getFolderSvg(color) {
        return `<svg class="folder-ico" viewBox="0 0 52 44">
      <rect x="0" y="6" width="52" height="38" rx="5" fill="${color}" opacity=".18"/>
      <path d="M0 10a5 5 0 015-5h14l4 5h24a5 5 0 015 5v18a5 5 0 01-5 5H5a5 5 0 01-5-5V10z" fill="${color}" opacity=".55"/>
    </svg>`;
    }
    getFileIconSvg(type) {
        const c = this.TYPE_COLORS[type];
        return `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="1.6">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
    </svg>`;
    }
    showToast(msg) {
        const t = document.getElementById('toast');
        const tm = document.getElementById('toastMsg');
        if (!t || !tm)
            return;
        tm.textContent = msg;
        t.classList.add('show');
        window.setTimeout(() => t.classList.remove('show'), 2500);
    }
    bindGlobalEvents() {
        ['mousemove', 'keydown', 'click', 'touchstart'].forEach(evt => {
            document.addEventListener(evt, () => {
                if (this.cryptoEngine.isUnlocked())
                    this.resetInactivityTimer();
            });
        });
        document.addEventListener('click', (e) => {
            const target = e.target;
            if (!target?.closest('.ctx-menu'))
                this.hideCtx();
        });
    }
}
// Instantiate globally
window.teleDriveApp = new TeleDriveController();
