/**
 * iexported logic - shortcuts & phone averaging
 */
class MessagesApp {
    constructor() {
        this.snapshots = [];
        this.processedChats = [];
        this.commonPrefix = "";
        this.currentFilter = 'all';
        this.selectedListItem = null;
        this.currentChat = null;
        this.openMenu = null;
        this.isLoadingData = false;
        this.els = this.cacheElements();
        this.init();
    }

    handleUnauthorized() {
        this.els.app.classList.add('hidden');
        this.els.loginOverlay.classList.remove('hidden');

        requestAnimationFrame(() => {
            try {
                this.els.passInput.focus();
            } catch (_) {
            }
        });
    }

    async fetchWithAuth(url, options) {
        const res = await fetch(url, options);
        if (res && res.status === 401) {
            this.handleUnauthorized();
            throw new Error('unauthorized');
        }
        return res;
    }

    cacheElements() {
        return {
            app: document.getElementById('app'),
            loginOverlay: document.getElementById('loginOverlay'),
            offlineOverlay: document.getElementById('offlineOverlay'),
            passInput: document.getElementById('passInput'),
            loginSubmit: document.getElementById('loginSubmit'),
            offlineReload: document.getElementById('offlineReload'),
            modalOverlay: document.getElementById('modalOverlay'),
            alertOk: document.getElementById('alertOk'),
            conversationList: document.getElementById('conversationList'),
            searchInput: document.getElementById('searchInput'),
            searchClear: document.getElementById('searchClear'),
            filterBtn: document.getElementById('filterBtn'),
            filterMenu: document.getElementById('filterMenu'),
            listView: document.getElementById('listView'),
            detailView: document.getElementById('detailView'),
            chatTitle: document.getElementById('chatTitle'),
            titleGroup: document.getElementById('titleGroupContainer'),
            participantMenu: document.getElementById('participantMenu'),
            backBtn: document.getElementById('backBtn'),
            infoBtn: document.getElementById('infoBtn'),
            rescanBtn: document.getElementById('rescanBtn'),
            menuTrigger: document.getElementById('menuTrigger'),
            dateMenu: document.getElementById('dateMenu'),
            listScroll: document.getElementById('listScroll'),
            stickyHeader: document.getElementById('stickyHeader'),
            chatFrame: document.getElementById('chatFrame'),
            emptyState: document.getElementById('emptyState')
        };
    }

    showOfflineOverlay() {
        this.els.app.classList.add('hidden');
        this.els.loginOverlay.classList.add('hidden');
        this.els.offlineOverlay.classList.remove('hidden');
    }

    hideOfflineOverlay() {
        this.els.offlineOverlay.classList.add('hidden');
    }

    async retryLoadDataIfOnline() {
        if (this.isLoadingData) return;
        if (typeof navigator !== 'undefined' && navigator && navigator.onLine === false) {
            this.showOfflineOverlay();
            return;
        }

        this.hideOfflineOverlay();
        this.els.app.classList.remove('hidden');
        await this.loadData();
    }

    // Escape potentially unsafe text for insertion as textContent
    escapeHTML(str) {
        if (str == null) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    async init() {
        this.bindEvents();
        await this.loadData();
    }

    bindEvents() {
        // global keys
        window.onkeydown = (e) => {
            const inInput = e.target.tagName === 'INPUT';
            
            // Handle Login Enter Key
            if (e.target === this.els.passInput && e.key === 'Enter') {
                this.handleLogin();
                return;
            }

            if (this.els.modalOverlay.classList.contains('visible') && e.key === 'Enter') return this.closeAlert();
            if (inInput) return;

            const isDetail = this.els.detailView.classList.contains('slide-in');
            if (e.key === 'Backspace') this.toggleView(false);
            
            if (isDetail) {
                // Detail view shortcuts: s=snapshots, p=participants
                if (e.key === 's') {
                    if (this.openMenu === 'snapshots') {
                        this.closeAllMenus();
                        this.openMenu = null;
                    } else {
                        this.toggleMenuIfClosed(this.els.dateMenu);
                        this.openMenu = 'snapshots';
                    }
                }
                if (e.key === 'p') {
                    if (this.currentChat?.is_group) {
                        if (this.openMenu === 'participants') {
                            this.closeAllMenus();
                            this.openMenu = null;
                        } else {
                            this.toggleMenuIfClosed(this.els.participantMenu);
                            this.openMenu = 'participants';
                        }
                    }
                }
            } else {
                // List view shortcuts: f=filter, i=info
                if (e.key === 'f') {
                    this.els.filterBtn.click();
                }
                if (e.key === 'i') {
                    this.els.infoBtn.click();
                }
            }
        };

        this.els.loginSubmit.onclick = () => this.handleLogin();
        this.els.offlineReload.onclick = () => this.retryLoadDataIfOnline();
        this.els.rescanBtn.onclick = () => this.handleRescan();
        this.els.backBtn.onclick = () => this.toggleView(false);
        this.els.alertOk.onclick = () => this.closeAlert();
        this.els.infoBtn.onclick = () => this.showAlert('About', 'iExported let\'s you view iMessage exports created using ReagentX\'s imessage-exporter right from your browser.');

        this.els.filterBtn.onclick = (e) => {
            e.stopPropagation();
            this.toggleMenuIfClosed(this.els.filterMenu);
        };
        this.els.filterMenu.querySelectorAll('.menu-item').forEach(i => {
            i.onclick = (e) => {
                this.currentFilter = e.currentTarget.dataset.filter;
                this.selectMenuItem(this.els.filterMenu, e.currentTarget);
                this.renderConversations();
                // When filter changes, scroll back to top of the list
                if (this.els.listScroll) {
                    this.els.listScroll.scrollTop = 0;
                }
            };
        });

        this.els.searchInput.oninput = (e) => {
            this.els.searchClear.style.display = e.target.value ? 'block' : 'none';
            this.handleSearch(e.target.value);
        };
        this.els.searchClear.onclick = () => {
            this.els.searchInput.value = '';
            this.els.searchClear.style.display = 'none';
            this.handleSearch('');
        };

        this.els.listScroll.onscroll = () => {
            const t = this.els.listScroll.scrollTop;
            this.els.stickyHeader.classList.toggle('scrolled', t > 40);
        };

        this.els.menuTrigger.onclick = (e) => {
            e.stopPropagation();
            this.toggleMenuIfClosed(this.els.dateMenu);
        };
        this.els.titleGroup.onclick = (e) => {
            if (this.currentChat?.is_group) {
                e.stopPropagation();
                this.els.participantMenu.classList.toggle('show');
            }
        };

        window.onclick = () => this.closeAllMenus();

        window.addEventListener('offline', () => {
            this.showOfflineOverlay();
        });

        window.addEventListener('online', () => {
            this.retryLoadDataIfOnline();
        });

        this.els.chatFrame.onload = () => {
            const doc = this.els.chatFrame.contentDocument;
            if (doc) {
                doc.documentElement.scrollTop = doc.documentElement.scrollHeight;
                doc.body.scrollTop = doc.body.scrollHeight;
                doc.addEventListener('click', () => {
                    this.closeAllMenus();
                });
                // Mark iframe as loaded to show it and hide spinner
                this.els.chatFrame.classList.add('loaded');
                this.els.chatFrame.parentElement.classList.add('loaded');
            }
        };
    }

    closeAllMenus() {
        document.querySelectorAll('.dropdown').forEach(d => d.classList.remove('show'));
        this.openMenu = null;
    }

    toggleMenu(menu) {
        this.closeAllMenus();
        menu.classList.add('show');
    }

    toggleMenuIfClosed(menu) {
        const isOpen = menu.classList.contains('show');
        this.closeAllMenus();
        if (!isOpen) menu.classList.add('show');
    }

    selectMenuItem(menu, item) {
        menu.querySelectorAll('.menu-item').forEach(x => x.classList.remove('selected'));
        item.classList.add('selected');
    }

    createMenuItem(text, isSelected = false, onClickHandler = null) {
        const div = document.createElement('div');
        div.className = `menu-item ${isSelected ? 'selected' : ''}`;
        div.innerText = text;
        if (onClickHandler) div.onclick = onClickHandler;
        return div;
    }

    async handleLogin() {
        try {
            // Get CSRF token first
            const csrfRes = await fetch('/api/csrf');
            if (!csrfRes.ok) {
                this.shakeLogin();
                return;
            }
            const csrfData = await csrfRes.json();

            // Send login with CSRF token
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    password: this.els.passInput.value,
                    csrf_token: csrfData.token
                })
            });
            if (res.ok) {
                this.els.app.classList.remove('hidden');
                this.els.loginOverlay.classList.add('fade-out');
                setTimeout(() => {
                    this.els.loginOverlay.classList.add('hidden');
                    this.els.loginOverlay.classList.remove('fade-out');
                    this.showSkeleton();
                    this.loadData();
                }, 400);
            } else {
                this.shakeLogin();
            }
        } catch (e) {
            this.shakeLogin();
        }
    }

    shakeLogin() {
        this.els.passInput.classList.add('shake');
        this.els.passInput.value = '';
        setTimeout(() => {
            this.els.passInput.classList.remove('shake');
            this.els.passInput.focus();
        }, 500);
    }

    async handleRescan() {
        try {
            // Get CSRF token for rescan
            const csrfRes = await this.fetchWithAuth('/api/csrf');
            if (!csrfRes.ok) return;
            const csrfData = await csrfRes.json();

            const res = await this.fetchWithAuth('/api/rescan', {
                method: 'POST',
                headers: { 'X-CSRF-Token': csrfData.token }
            });
            if (!res.ok) return;
            this.loadData();
        } catch (e) {
            if (String(e && e.message) === 'unauthorized') return;
            console.error('rescan error:', e);
        }
    }

    async loadData() {
        this.showSkeleton();
        this.isLoadingData = true;
        try {
            const res = await this.fetchWithAuth('/api/snapshots');
            if (!res.ok) {
                throw new Error('failed to load snapshots');
            }

            const data = await res.json();

            if (data && data.authenticated === false) {
                this.handleUnauthorized();
                return;
            }

            if (res.status === 401) {
                this.handleUnauthorized();
                return;
            }

            // Authenticated: hide login overlay and render data
            this.els.loginOverlay.classList.add('hidden');
            this.hideOfflineOverlay();
            this.els.app.classList.remove('hidden');
            this.snapshots = data;
            this.calcPhoneAveraging();
            this.processChats();
            this.renderConversations();
        } catch (e) {
            if (String(e && e.message) === 'unauthorized') return;
            console.error('loadData error:', e);

            const msg = String(e && (e.message || e));
            const isOffline = (typeof navigator !== 'undefined' && navigator && navigator.onLine === false);
            const isNetworkFailure = e instanceof TypeError || /failed to fetch/i.test(msg) || /networkerror/i.test(msg);

            if (isOffline || isNetworkFailure) {
                this.showOfflineOverlay();
                return;
            }

            // On other errors, fall back to showing login overlay
            this.handleUnauthorized();
        } finally {
            this.isLoadingData = false;
        }
    }

    calcPhoneAveraging() {
        const pMap = {};
        this.snapshots.forEach(s => s.data.chats.forEach(c => {
            if (c.display_name.startsWith('+')) {
                const pre = c.display_name.substring(0, 2);
                pMap[pre] = (pMap[pre] || 0) + 1;
            }
        }));
        this.commonPrefix = Object.keys(pMap).sort((a,b) => pMap[b] - pMap[a])[0] || "";
    }

    showSkeleton() {
        this.els.conversationList.innerHTML = '';
        for(let i=0; i<8; i++) {
            const div = document.createElement('div');
            div.className = 'skeleton-row';
            div.innerHTML = `<div class="sk-line" style="width:60%"></div><div class="sk-line" style="width:40%"></div>`;
            this.els.conversationList.appendChild(div);
        }
    }

    processChats() {
        const chatMap = new Map();
        this.snapshots.forEach(s => s.data.chats.forEach(c => {
            if (!chatMap.has(c.filename)) chatMap.set(c.filename, { ...c, snapshots: [], totalMessages: 0 });
            const entry = chatMap.get(c.filename);
            entry.snapshots.push({ folder: s.name, count: c.message_count });
            entry.totalMessages += c.message_count;
        }));
        this.processedChats = Array.from(chatMap.values()).sort((a,b) => {
            const getRank = (x) => {
                if (x.is_contact) return 1;
                if (x.is_email) return 4;
                if (!isNaN(x.display_name)) {
                    return x.display_name.length < 7 ? 3 : 2; // service numbers (short) = 3, regular = 2
                }
                return 2;
            };
            return getRank(a) - getRank(b) || a.display_name.localeCompare(b.display_name);
        });
    }

    normalizePhone(num) {
        if (!num || num.includes('@')) return null;
        return ('' + num).replace(/\D/g, '');
    }

    formatPhone(num) {
        if (!num || num.includes('@')) return num;
        let s = num;
        if (this.commonPrefix && s.startsWith(this.commonPrefix)) s = s.replace(this.commonPrefix, "");
        let clean = ('' + s).replace(/\D/g, '');
        if (clean.length === 10) return `(${clean.substring(0,3)}) ${clean.substring(3,6)}-${clean.substring(6)}`;
        return s;
    }

    getChatDisplayName(chat, limit = 1, isDetailView = false) {
        if (!chat.is_group) return chat.is_contact || chat.is_email ? chat.display_name : this.formatPhone(chat.display_name);
        
        const isMobile = window.innerWidth < 768;
        if (isMobile && isDetailView) {
            const count = chat.participants.length;
            return `${count} people`;
        }
        
        // filter truncations
        const valid = chat.participants.filter(p => !p.includes('...') && !p.includes('…'));
        const names = valid.filter(p => isNaN(p));
        const nums = valid.filter(p => !isNaN(p));

        if (names.length > 0) {
            let list;
            // Dynamically fit names based on available space (both mobile and desktop)
            if (!isDetailView) {
                list = this.fitNamesToWidth(names, chat.participants.length);
            } else {
                list = names.slice(0, limit);
            }
            // Use 'and' for exactly 2 names, otherwise comma-separate
            let s = list.length === 2 ? list.join(' and ') : list.join(', ');
            const diff = chat.participants.length - list.length;
            if (diff > 0) s += ` and ${diff} others`;
            return s;
        } else {
            const t = nums.length > 1 ? nums[1] : nums[0];
            let s = this.formatPhone(t);
            const diff = chat.participants.length - 1;
            if (diff > 0) s += ` and ${diff} others`;
            return s;
        }
    }

    fitNamesToWidth(names, totalCount) {
        // Reuse canvas context if available, otherwise create new
        if (!this.canvasCtx) {
            const canvas = document.createElement('canvas');
            this.canvasCtx = canvas.getContext('2d');
            this.canvasCtx.font = '15px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto';
        }
        
        const ctx = this.canvasCtx;
        const maxWidth = window.innerWidth - 160;
        let result = [];
        let currentWidth = 0;
        
        for (let i = 0; i < names.length; i++) {
            const name = names[i];
            const separator = i === 0 ? '' : ', ';
            const text = separator + name;
            const metrics = ctx.measureText(text);
            
            const othersCount = totalCount - (result.length + 1);
            const othersWidth = othersCount > 0 ? 80 : 0;
            
            if (currentWidth + metrics.width + othersWidth > maxWidth && result.length > 0) break;
            result.push(name);
            currentWidth += metrics.width;
        }
        
        return result.length > 0 ? result : names.slice(0, 1);
    }

    renderConversations() {
        this.els.conversationList.innerHTML = '';
        const term = this.els.searchInput.value || '';
        const q = term.toLowerCase();
        const normalizedQuery = this.normalizePhone(term);

        const filtered = this.processedChats.filter(chat => {
            if (this.currentFilter === 'contacts' && !chat.is_contact) return false;
            if (this.currentFilter === 'groups' && !chat.is_group) return false;
            if (this.currentFilter === 'unknown' && (chat.is_contact || chat.is_group)) return false;
            if (!q) return true;

            const displayName = (chat.display_name || '').toLowerCase();
            if (displayName.includes(q)) return true;

            if (chat.is_group) {
                for (let i = 0; i < chat.participants.length; i++) {
                    const p = chat.participants[i];
                    if (p.toLowerCase().includes(q)) return true;
                    if (normalizedQuery) {
                        const normalized = this.normalizePhone(p);
                        if (normalized && normalized.includes(normalizedQuery)) return true;
                    }
                }
                return false;
            } else {
                if (normalizedQuery) {
                    const normalized = this.normalizePhone(chat.display_name);
                    if (normalized && normalized.includes(normalizedQuery)) return true;
                }
                return false;
            }
        });

        this.visibleChats = filtered;
        this.chatBatchIndex = 0;

        const frag = document.createDocumentFragment();
        const batchSize = 50;
        const end = Math.min(this.visibleChats.length, batchSize);
        for (let i = 0; i < end; i++) {
            const chat = this.visibleChats[i];
            const div = this.createChatListItem(chat);
            frag.appendChild(div);
        }
        this.els.conversationList.appendChild(frag);
        this.chatBatchIndex = end;

        this.els.listScroll.onscroll = () => {
            const t = this.els.listScroll.scrollTop;
            this.els.stickyHeader.classList.toggle('scrolled', t > 40);
            this.lazyLoadChats();
        };
    }

    createChatListItem(chat) {
        const div = document.createElement('div');
        div.className = 'list-item';
        const displayName = this.getChatDisplayName(chat, 1, false);
        const container = document.createElement('div');
        container.className = 'item-content';
        const top = document.createElement('div');
        top.className = 'top-row';
        const nameEl = document.createElement('span');
        nameEl.className = 'contact-name';
        nameEl.textContent = displayName; // safe text
        const timeEl = document.createElement('span');
        timeEl.className = 'timestamp';
        timeEl.textContent = `${chat.snapshots.length} snapshot${chat.snapshots.length === 1 ? '' : 's'}`;
        const preview = document.createElement('div');
        preview.className = 'preview-text';
        preview.textContent = `${chat.totalMessages.toLocaleString()} total messages`;
        top.appendChild(nameEl);
        top.appendChild(timeEl);
        container.appendChild(top);
        container.appendChild(preview);
        div.appendChild(container);
        div.onclick = (e) => this.openChat(chat, e.currentTarget);
        div._chatData = chat;
        return div;
    }

    lazyLoadChats() {
        if (!this.visibleChats || this.chatBatchIndex >= this.visibleChats.length) return;

        const scrollPos = this.els.listScroll.scrollTop + this.els.listScroll.clientHeight;
        const scrollHeight = this.els.listScroll.scrollHeight;

        if (scrollHeight - scrollPos < 500) {
            const frag = document.createDocumentFragment();
            const batchSize = 20;
            const endIdx = Math.min(this.chatBatchIndex + batchSize, this.visibleChats.length);

            for (let i = this.chatBatchIndex; i < endIdx; i++) {
                const div = this.createChatListItem(this.visibleChats[i]);
                frag.appendChild(div);
            }

            this.els.conversationList.appendChild(frag);
            this.chatBatchIndex = endIdx;
        }
    }

    openChat(chat, listItem) {
        this.currentChat = chat;
        this.els.chatTitle.innerText = this.getChatDisplayName(chat, 1, true);
        this.els.titleGroup.classList.toggle('group-chat', chat.is_group);
        
        // Handle selected state for desktop sidebar
        if (this.selectedListItem) this.selectedListItem.classList.remove('selected');
        if (listItem) {
            listItem.classList.add('selected');
            this.selectedListItem = listItem;
        }
        
        // Mark detail view as having a chat (for desktop empty state)
        this.els.detailView.classList.add('has-chat');
        
        if (chat.is_group) {
            this.els.participantMenu.innerHTML = '';
            chat.participants.forEach(p => {
                const item = this.createMenuItem(isNaN(p) ? p : this.formatPhone(p));
                this.els.participantMenu.appendChild(item);
            });
        }
        this.els.dateMenu.innerHTML = '';
        [...chat.snapshots].reverse().forEach((s, i) => {
            const div = document.createElement('div');
            div.className = `menu-item ${i === 0 ? 'selected' : ''}`;
            const span = document.createElement('span');
            span.textContent = s.folder;
            const svgNS = 'http://www.w3.org/2000/svg';
            const svg = document.createElementNS(svgNS, 'svg');
            svg.setAttribute('class', 'check-icon');
            svg.setAttribute('viewBox', '0 0 17.1875 17.2363');
            const path = document.createElementNS(svgNS, 'path');
            path.setAttribute('d', 'M6.36719 17.2363C6.78711 17.2363 7.11914 17.0508 7.35352 16.6895L16.582 2.1582C16.7578 1.875 16.8262 1.66016 16.8262 1.43555C16.8262 0.898438 16.4746 0.546875 15.9375 0.546875C15.5469 0.546875 15.332 0.673828 15.0977 1.04492L6.32812 15.0195L1.77734 9.0625C1.5332 8.7207 1.28906 8.58398 0.9375 8.58398C0.380859 8.58398 0 8.96484 0 9.50195C0 9.72656 0.0976562 9.98047 0.283203 10.2148L5.35156 16.6699C5.64453 17.0508 5.94727 17.2363 6.36719 17.2363Z');
            path.setAttribute('fill', 'currentColor');
            svg.appendChild(path);
            div.appendChild(span);
            div.appendChild(svg);
            div.onclick = (e) => {
                this.selectMenuItem(this.els.dateMenu, e.currentTarget);
                this.loadIframe(s.folder, chat.filename);
            };
            this.els.dateMenu.appendChild(div);
        });
        this.loadIframe(chat.snapshots[chat.snapshots.length-1].folder, chat.filename);
        this.toggleView(true);
    }

    loadIframe(f, n) { 
        this.els.chatFrame.classList.remove('loaded');
        this.els.chatFrame.parentElement.classList.remove('loaded');
        const safeF = encodeURIComponent(f);
        const safeN = encodeURIComponent(n);
        this.els.chatFrame.src = `/view/${safeF}/${safeN}`; 
    }
    handleSearch(term) {
        this.renderConversations();
    }
    showAlert(title, message) {
        document.getElementById('mTitle').innerText = title;
        const msgEl = document.getElementById('mMsg');
        msgEl.textContent = message;
        this.els.modalOverlay.classList.add('visible');
    }

    closeAlert() {
        this.els.modalOverlay.classList.remove('visible');
    }

    toggleView(show) {
        this.els.listView.classList.toggle('slide-out', show);
        this.els.detailView.classList.toggle('slide-in', show);
    }
}
document.addEventListener('DOMContentLoaded', () => new MessagesApp());

if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(err => console.log('SW registration failed:', err));
}