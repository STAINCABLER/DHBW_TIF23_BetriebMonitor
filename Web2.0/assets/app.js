const state = {
  token: window.localStorage.getItem('altebank_session') || null,
  account: null,
  transactions: [],
  filters: {
    type: '',
    from: '',
    to: '',
    min: '',
    max: '',
  },
  activeSection: 'overview',
  historyRange: '30',
  sectionNeedsUpdate: {
    overview: false,
    history: false,
  },
};

const qs = (selector, scope = document) => scope.querySelector(selector);
const qa = (selector, scope = document) => Array.from(scope.querySelectorAll(selector));

function getFormValues(form) {
  return Object.fromEntries(
    Array.from(new FormData(form).entries()).map(([key, value]) => [key, typeof value === 'string' ? value.trim() : value]),
  );
}

const elements = {
  brand: qs('.brand'),
  brandLogoWrapper: qs('.brand__logo-wrapper'),
  brandTextBlock: qs('.brand__text'),
  guestNav: qs('#guestNav'),
  userNav: qs('#userNav'),
  navSectionButtons: qa('[data-nav-section]'),
  dashboardSections: qa('.dashboard-section'),
  heroBalance: qs('#heroBalance'),
  balanceValue: qs('#balanceValue'),
  dashboard: qs('#dashboard'),
  landing: qs('.landing'),
  guestActions: qs('#guestActions'),
  userActions: qs('#userActions'),
  userInitial: qs('#userInitial'),
  currentUser: qs('#currentUser'),
  openAccountSettingsBtn: qs('[data-open-account-settings]'),
  accountSettingsModal: qs('#accountSettingsModal'),
  accountSettingsFeedback: qs('#accountSettingsFeedback'),
  profileForm: qs('#profileForm'),
  passwordForm: qs('#passwordForm'),
  settingsTabButtons: qa('[data-settings-tab]'),
  settingsPanels: qa('[data-settings-panel]'),
  accountHolder: qs('#accountHolder'),
  accountIban: qs('#accountIban'),
  accountEmail: qs('#accountEmail'),
  autoRefreshIndicator: qs('#autoRefreshIndicator'),
  transactionList: qs('#transactionList'),
  transactionModal: qs('#transactionModal'),
  transactionTabs: qa('[data-transaction-tab]'),
  transactionForms: qa('.transaction-form'),
  panelDepositForm: qs('#panelDepositForm'),
  panelWithdrawForm: qs('#panelWithdrawForm'),
  panelTransferForm: qs('#panelTransferForm'),
  transactionPanelButtons: qa('[data-transaction-panel-btn]'),
  transactionPanelForms: qa('[data-transaction-panel]'),
  closeTransactionBtns: qa('[data-close-transaction]'),
  transactionFilters: qs('#transactionFilters'),
  historyButtons: qa('[data-history-range]'),
  balanceChart: qs('#balanceChart'),
  copyIbanBtn: qs('[data-action="copy-iban"]'),
  advisorPhoto: qs('#advisorPhoto'),
  advisorName: qs('#advisorName'),
  advisorTitle: qs('#advisorTitle'),
  advisorPhone: qs('#advisorPhone'),
  advisorEmail: qs('#advisorEmail'),
  publicContactSection: qs('#kontakt'),
  authModal: qs('#authModal'),
  authTitle: qs('#authTitle'),
  authSubtitle: qs('#authSubtitle'),
  loginForm: qs('#loginForm'),
  registerForm: qs('#registerForm'),
  authFeedback: qs('#authFeedback'),
  toast: qs('#toast'),
};

const transactionLabels = {
  deposit: 'Einzahlung',
  withdraw: 'Auszahlung',
  transfer_in: 'Überweisung Eingang',
  transfer_out: 'Überweisung Ausgang',
};

const ADVISOR_FALLBACK = {
  name: 'Sven Meyer',
  title: 'Senior Kundenberater',
  phone: '0711 204010',
  email: 'sven.meyer@altebank.de',
  image: 'assets/advisors/advisor-1.svg',
};

const euro = new Intl.NumberFormat('de-DE', { style: 'currency', currency: 'EUR' });
const AUTO_REFRESH_INTERVAL = 15000;

let toastTimer = null;
let autoRefreshTimer = null;
let loadAccountInFlight = null;
let lastRefreshAt = null;
let balanceChartInstance = null;

function showToast(message, type = 'info') {
  if (!elements.toast) return;
  const toast = elements.toast;
  toast.textContent = message;
  toast.classList.remove('hidden', 'toast--error', 'toast--success');
  if (type === 'error') {
    toast.classList.add('toast--error');
  } else if (type === 'success') {
    toast.classList.add('toast--success');
  }
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    toast.classList.add('hidden');
    toast.classList.remove('toast--error', 'toast--success');
  }, 3200);
}

function formatCurrency(value) {
  if (value === undefined || value === null) return euro.format(0);
  const parsed = Number(value);
  if (Number.isNaN(parsed)) return euro.format(0);
  return euro.format(parsed);
}

function formatDisplayName(profile) {
  if (!profile) return '';
  const first = (profile.firstName ?? profile.first_name ?? '').trim();
  const last = (profile.lastName ?? profile.last_name ?? '').trim();
  const combined = [first, last].filter(Boolean).join(' ').trim();
  if (combined) {
    return combined;
  }
  const fallback = (profile.email ?? profile.username ?? '').trim();
  return fallback;
}

function formatInitial(label) {
  return label?.trim().charAt(0)?.toUpperCase() || 'A';
}

function syncBodyScrollLock() {
  const modals = [elements.authModal, elements.transactionModal, elements.accountSettingsModal];
  const lock = modals.some((modal) => modal && !modal.classList.contains('hidden'));
  document.body.style.overflow = lock ? 'hidden' : '';
}

function syncBrandLogoSize() {
  const brand = elements.brand;
  const textBlock = elements.brandTextBlock;
  if (!brand || !textBlock) {
    return;
  }

  const textRect = textBlock.getBoundingClientRect();
  const textHeight = textRect.height;
  if (!textHeight) {
    return;
  }

  const targetSize = Math.max(32, textHeight - 10);
  const offset = -Math.max(12, Math.round(targetSize * 0.35));
  brand.style.setProperty('--brand-logo-size', `${targetSize}px`);
  brand.style.setProperty('--brand-logo-offset', `${offset}px`);
}

function activateSection(key, { scroll = true } = {}) {
  if (!elements.dashboardSections.length) {
    return;
  }

  const previous = state.activeSection;
  const hasChanged = previous !== key;
  state.activeSection = key;

  elements.dashboardSections.forEach((section) => {
    const isActive = section.dataset.section === key;
    section.classList.toggle('hidden', !isActive);
    if (isActive && scroll && hasChanged) {
      section.scrollIntoView({ block: 'start', behavior: 'smooth' });
    }
  });

  elements.navSectionButtons.forEach((button) => {
    const isActive = button.dataset.navSection === key;
    button.classList.toggle('is-active', isActive);
    button.setAttribute('aria-pressed', String(isActive));
  });

  if (key === 'overview' && (hasChanged || state.sectionNeedsUpdate.overview)) {
    refreshTransactionList();
    state.sectionNeedsUpdate.overview = false;
  }

  if (key === 'history' && (hasChanged || state.sectionNeedsUpdate.history)) {
    updateHistoryChart();
    state.sectionNeedsUpdate.history = false;
  }
}

function sanitizeIban(value) {
  if (typeof value !== 'string') {
    return '';
  }
  return value.replace(/\s+/g, '').toUpperCase();
}

function formatIbanForDisplay(value) {
  const sanitized = sanitizeIban(value);
  if (!sanitized) {
    return '';
  }
  const grouped = sanitized.match(/.{1,4}/g);
  return grouped ? grouped.join(' ') : sanitized;
}

async function apiFetch(path, { method = 'GET', body, headers } = {}) {
  const config = {
    method,
    headers: {
      ...(headers || {}),
    },
  };
  if (body !== undefined) {
    config.headers['Content-Type'] = 'application/json';
    config.body = JSON.stringify(body);
  }
  if (state.token) {
    config.headers.Authorization = `Bearer ${state.token}`;
  }
  const response = await fetch(path, config);
  const isJson = response.headers.get('content-type')?.includes('application/json');
  const payload = isJson ? await response.json() : {};
  if (!response.ok) {
    const message = payload?.error || `Request fehlgeschlagen (${response.status})`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function setFormBusy(form, busy) {
  if (!form) return;
  qa('input, button', form).forEach((el) => {
    el.disabled = busy;
  });
}

function openModal(mode = 'login') {
  if (!elements.authModal) return;
  switchAuthMode(mode);
  elements.authModal.classList.remove('hidden');
  syncBodyScrollLock();
  window.requestAnimationFrame(() => {
    if (mode === 'login') {
      elements.loginForm?.querySelector('input')?.focus();
    } else {
      elements.registerForm?.querySelector('input')?.focus();
    }
  });
}

function closeModal() {
  if (!elements.authModal) return;
  elements.authModal.classList.add('hidden');
  syncBodyScrollLock();
}

function switchAuthMode(mode) {
  if (!elements.loginForm || !elements.registerForm) return;
  const isLogin = mode === 'login';
  elements.authTitle.textContent = isLogin ? 'Willkommen zurück' : 'In wenigen Sekunden startklar';
  elements.authSubtitle.textContent = isLogin
    ? 'Melde dich mit deinen Zugangsdaten an.'
    : 'Erstelle ein Konto und starte mit deinem Wunschguthaben.';
  elements.loginForm.classList.toggle('hidden', !isLogin);
  elements.registerForm.classList.toggle('hidden', isLogin);
  elements.authFeedback.textContent = '';
  elements.authModal.dataset.mode = mode;
}

function updateAuthState(isAuthenticated, profile, options = {}) {
  const { preserveSection = false } = options;
  const wasAuthenticated = document.body.classList.contains('is-authenticated');

  document.body.classList.toggle('is-authenticated', isAuthenticated);
  elements.landing?.classList.toggle('hidden', isAuthenticated);
  elements.guestNav?.classList.toggle('hidden', isAuthenticated);
  elements.userNav?.classList.toggle('hidden', !isAuthenticated);
  elements.publicContactSection?.classList.toggle('hidden', isAuthenticated);

  if (isAuthenticated) {
    elements.guestActions?.classList.add('hidden');
    elements.userActions?.classList.remove('hidden');
    elements.dashboard?.classList.remove('hidden');
    const displayName = formatDisplayName(profile) || 'Konto';
    const initial = formatInitial(displayName || 'K');
    elements.userInitial.textContent = initial;
    elements.currentUser.textContent = displayName;

    if (!preserveSection || !wasAuthenticated) {
      state.activeSection = 'overview';
    }
    activateSection(state.activeSection, { scroll: !preserveSection || !wasAuthenticated });
  } else {
    elements.guestActions?.classList.remove('hidden');
    elements.userActions?.classList.add('hidden');
    elements.dashboard?.classList.add('hidden');
    elements.userInitial.textContent = 'A';
    elements.currentUser.textContent = 'Konto';
    state.activeSection = 'overview';
    elements.navSectionButtons.forEach((button) => {
      button.classList.remove('is-active');
      button.setAttribute('aria-pressed', 'false');
    });
  }
}

function clearSession(options = { silent: false }) {
  stopAutoRefresh();
  state.token = null;
  state.account = null;
  state.transactions = [];
  state.sectionNeedsUpdate = {
    overview: false,
    history: false,
  };
  state.sectionNeedsUpdate = {
    overview: false,
    history: false,
  };
  resetFilters();
  window.localStorage.removeItem('altebank_session');
  lastRefreshAt = null;
  if (balanceChartInstance) {
    balanceChartInstance.destroy();
    balanceChartInstance = null;
  }
  updateAuthState(false, null);
  updateBalances();
  updateAccountMeta();
  updateAdvisorCard();
  updateAutoRefreshIndicator();
  closeTransactionModal();
  if (!options.silent) {
    showToast('Du wurdest abgemeldet.', 'info');
  }
}

function updateBalances() {
  const balance = state.account?.balance ?? '0.00';
  elements.balanceValue.textContent = formatCurrency(balance);
  elements.heroBalance.textContent = formatCurrency(balance);
}

function updateAccountMeta() {
  if (!elements.accountHolder || !elements.accountIban || !elements.accountEmail) {
    return;
  }
  const placeholder = '-';
  const account = state.account;
  if (!account) {
    elements.accountHolder.textContent = placeholder;
    elements.accountIban.textContent = placeholder;
    elements.accountEmail.textContent = placeholder;
    if (elements.copyIbanBtn) {
      elements.copyIbanBtn.disabled = true;
    }
    return;
  }

  const displayName = formatDisplayName(account) || placeholder;
  elements.accountHolder.textContent = displayName;
  elements.accountIban.textContent = formatIbanForDisplay(account.iban) || placeholder;
  elements.accountEmail.textContent = account.email || placeholder;
  if (elements.copyIbanBtn) {
    elements.copyIbanBtn.disabled = !account.iban;
  }
}

function updateAdvisorCard() {
  if (!elements.advisorName || !elements.advisorTitle || !elements.advisorPhone || !elements.advisorEmail || !elements.advisorPhoto) {
    return;
  }

  const advisor = state.account?.advisor || null;
  const profile = advisor || ADVISOR_FALLBACK;

  elements.advisorName.textContent = profile.name || ADVISOR_FALLBACK.name;
  elements.advisorTitle.textContent = profile.title || ADVISOR_FALLBACK.title;
  elements.advisorPhone.textContent = profile.phone || ADVISOR_FALLBACK.phone;

  const email = profile.email || ADVISOR_FALLBACK.email;
  elements.advisorEmail.textContent = email;
  elements.advisorEmail.setAttribute('href', `mailto:${email}`);

  const imageSrc = profile.image || ADVISOR_FALLBACK.image;
  elements.advisorPhoto.setAttribute('src', imageSrc);
  const altLabel = profile.name ? `Porträt von ${profile.name}` : 'Beratungsteam der AlteBank';
  elements.advisorPhoto.setAttribute('alt', altLabel);
}

function updateAutoRefreshIndicator() {
  if (!elements.autoRefreshIndicator) {
    return;
  }
  if (!state.token) {
    elements.autoRefreshIndicator.textContent = 'Nicht angemeldet';
    return;
  }
  if (!lastRefreshAt) {
    elements.autoRefreshIndicator.textContent = 'Automatische Aktualisierung aktiv';
    return;
  }
  const formatted = new Intl.DateTimeFormat('de-DE', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(lastRefreshAt);
  elements.autoRefreshIndicator.textContent = `Zuletzt aktualisiert: ${formatted}`;
}

function startAutoRefresh() {
  if (!state.token || autoRefreshTimer) {
    return;
  }
  autoRefreshTimer = window.setInterval(() => {
    if (!state.token || document.hidden) {
      return;
    }
    loadAccount({ silent: true });
  }, AUTO_REFRESH_INTERVAL);
  updateAutoRefreshIndicator();
}

function stopAutoRefresh() {
  if (autoRefreshTimer) {
    window.clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
}

function applyTransactionFilters(transactions) {
  const { type, from, to, min, max } = state.filters;
  const parsedFrom = from ? new Date(`${from}T00:00:00`) : null;
  const parsedTo = to ? new Date(`${to}T23:59:59.999`) : null;
  const fromDate = parsedFrom && !Number.isNaN(parsedFrom.getTime()) ? parsedFrom : null;
  const toDate = parsedTo && !Number.isNaN(parsedTo.getTime()) ? parsedTo : null;
  const minAmount = min === '' ? null : Number(min);
  const maxAmount = max === '' ? null : Number(max);

  return transactions.filter((txn) => {
    if (type && txn.type !== type) {
      return false;
    }

    const txnDate = txn.createdAt ? new Date(txn.createdAt) : null;
    if (fromDate && (!txnDate || txnDate < fromDate)) {
      return false;
    }
    if (toDate && (!txnDate || txnDate > toDate)) {
      return false;
    }

    const amount = Number(txn.amount);
    const absAmount = Math.abs(amount);
    if (minAmount !== null && !Number.isNaN(minAmount) && absAmount < minAmount) {
      return false;
    }
    if (maxAmount !== null && !Number.isNaN(maxAmount) && absAmount > maxAmount) {
      return false;
    }

    return true;
  });
}

function refreshTransactionList() {
  const list = elements.transactionList;
  if (!list) return;

  const transactions = applyTransactionFilters(state.transactions || []);
  list.innerHTML = '';

  if (!transactions.length) {
    const item = document.createElement('li');
    item.className = 'transaction transaction--empty';
    item.textContent = 'Keine Transaktionen für den aktuellen Filter.';
    list.appendChild(item);
    return;
  }

  transactions.forEach((txn) => {
    const amountNumber = Number(txn.amount);
    const item = document.createElement('li');
    item.className = `transaction ${amountNumber >= 0 ? 'transaction--positive' : 'transaction--negative'}`;

    const header = document.createElement('div');
    header.className = 'transaction__header';
    const label = transactionLabels[txn.type] || 'Transaktion';
    header.innerHTML = `<span>${label}</span><time datetime="${txn.createdAt}">${formatDate(txn.createdAt)}</time>`;

    const amount = document.createElement('div');
    amount.className = 'transaction__amount';
    amount.textContent = formatCurrency(amountNumber);

    const memo = document.createElement('div');
    memo.className = 'transaction__memo';
    memo.textContent = txn.memo || '';

    const counterpartyName = txn.counterpartyName || '';
    const counterpartyIban = txn.counterpartyIban || '';
    let counterparty;
    if (counterpartyName || counterpartyIban) {
      counterparty = document.createElement('div');
      counterparty.className = 'transaction__counterparty';
      const parts = [];
      if (counterpartyName) {
        parts.push(counterpartyName);
      }
      if (counterpartyIban) {
        parts.push(counterpartyIban);
      }
      counterparty.textContent = parts.join(' · ');
    }

    const balance = document.createElement('div');
    balance.className = 'transaction__balance';
    balance.textContent = `Neues Guthaben: ${formatCurrency(txn.balance)}`;

    if (counterparty) {
      item.append(header, amount, memo, counterparty, balance);
    } else {
      item.append(header, amount, memo, balance);
    }
    list.appendChild(item);
  });
}

function formatDate(isoString) {
  if (!isoString) return '';
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat('de-DE', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

async function loadAccount({ silent = false } = {}) {
  if (!state.token) {
    return undefined;
  }
  if (loadAccountInFlight) {
    return loadAccountInFlight;
  }

  loadAccountInFlight = (async () => {
    try {
      const data = await apiFetch('/api/accounts/me');
      const normalized = {
        ...data,
        firstName: data.firstName ?? data.first_name ?? '',
        lastName: data.lastName ?? data.last_name ?? '',
        transactions: Array.isArray(data.transactions) ? data.transactions : [],
      };
      const hadAccount = Boolean(state.account);
      normalized.email = (data.email ?? '').toString().trim().toLowerCase();
      normalized.iban = sanitizeIban(normalized.iban ?? data.iban);
      normalized.advisor = data.advisor || null;
      state.account = normalized;
      state.transactions = normalized.transactions;
      updateAuthState(true, normalized, { preserveSection: hadAccount });
      updateBalances();
      updateAccountMeta();
      updateAdvisorCard();
      populateAccountSettingsForms();

      if (state.activeSection === 'overview') {
        refreshTransactionList();
        state.sectionNeedsUpdate.overview = false;
      } else {
        state.sectionNeedsUpdate.overview = true;
      }

      if (state.activeSection === 'history') {
        updateHistoryChart();
        state.sectionNeedsUpdate.history = false;
      } else {
        state.sectionNeedsUpdate.history = true;
      }

      lastRefreshAt = new Date();
      updateAutoRefreshIndicator();
      startAutoRefresh();
      if (!silent) {
        showToast('Dashboard aktualisiert.', 'success');
      }
      return normalized;
    } catch (error) {
      if (error.status === 401) {
        clearSession({ silent: true });
        return null;
      }
      showToast(error.message, 'error');
      throw error;
    } finally {
      loadAccountInFlight = null;
    }
  })();

  return loadAccountInFlight;
}

function persistToken(token) {
  state.token = token;
  window.localStorage.setItem('altebank_session', token);
}

function attachModalHandlers() {
  qa('[data-open-auth]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const mode = btn.dataset.openAuth || 'login';
      openModal(mode);
    });
  });

  qa('[data-close-modal]').forEach((btn) => {
    btn.addEventListener('click', () => {
      closeModal();
    });
  });

  qa('[data-switch-form]').forEach((btn) => {
    btn.addEventListener('click', () => {
      switchAuthMode(btn.dataset.switchForm);
    });
  });

  elements.authModal?.addEventListener('click', (event) => {
    if (event.target.dataset?.closeModal !== undefined) {
      closeModal();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !elements.authModal.classList.contains('hidden')) {
      closeModal();
    }
  });
}

function switchTransactionTab(key = 'deposit') {
  if (!key) return;
  elements.transactionTabs.forEach((tab) => {
    const isActive = tab.dataset.transactionTab === key;
    tab.classList.toggle('is-active', isActive);
    tab.setAttribute('aria-selected', String(isActive));
    tab.setAttribute('tabindex', isActive ? '0' : '-1');
  });

  elements.transactionForms.forEach((form) => {
    const isActive = form.dataset.transactionPanel === key;
    form.classList.toggle('hidden', !isActive);
    form.setAttribute('aria-hidden', String(!isActive));
    if (isActive && !elements.transactionModal?.classList.contains('hidden')) {
      window.requestAnimationFrame(() => {
        form.querySelector('input, select, button')?.focus();
      });
    }
  });
}

function switchDashboardTransaction(type = 'transfer') {
  if (!type) {
    return;
  }

  elements.transactionPanelButtons.forEach((button) => {
    const isActive = button.dataset.transactionPanelBtn === type;
    button.classList.toggle('is-active', isActive);
    button.setAttribute('aria-pressed', String(isActive));
    button.setAttribute('aria-selected', String(isActive));
    button.setAttribute('tabindex', isActive ? '0' : '-1');
  });

  elements.transactionPanelForms.forEach((form) => {
    const isActive = form.dataset.transactionPanel === type;
    form.classList.toggle('hidden', !isActive);
    form.setAttribute('aria-hidden', String(!isActive));
    if (isActive && state.activeSection === 'transactions') {
      window.requestAnimationFrame(() => {
        form.querySelector('input, select, button')?.focus({ preventScroll: false });
      });
    }
  });
}

function openTransactionModal(defaultTab = 'deposit') {
  if (!elements.transactionModal) return;
  if (!state.token) {
    openModal('login');
    return;
  }
  elements.transactionModal.classList.remove('hidden');
  syncBodyScrollLock();
  switchTransactionTab(defaultTab);
}

function closeTransactionModal() {
  if (!elements.transactionModal) return;
  elements.transactionModal.classList.add('hidden');
  syncBodyScrollLock();
}

function attachTransactionModalHandlers() {
  elements.closeTransactionBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      closeTransactionModal();
    });
  });

  elements.transactionModal?.addEventListener('click', (event) => {
    if (event.target.dataset?.closeTransaction !== undefined) {
      closeTransactionModal();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !elements.transactionModal?.classList.contains('hidden')) {
      closeTransactionModal();
    }
  });

  elements.transactionTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      switchTransactionTab(tab.dataset.transactionTab);
    });
  });

  switchTransactionTab('deposit');
}

function attachDashboardTransactionHandlers() {
  if (!elements.transactionPanelButtons.length) {
    return;
  }

  elements.transactionPanelButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const type = button.dataset.transactionPanelBtn;
      if (!type) {
        return;
      }
      switchDashboardTransaction(type);
    });
  });

  switchDashboardTransaction('transfer');
}

function handleFilterChange(event) {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) && !(target instanceof HTMLSelectElement)) {
    return;
  }
  if (!target.name) return;
  state.filters = {
    ...state.filters,
    [target.name]: target.value,
  };
  refreshTransactionList();
}

function resetFilters(event) {
  event?.preventDefault();
  state.filters = {
    type: '',
    from: '',
    to: '',
    min: '',
    max: '',
  };
  elements.transactionFilters?.reset();
  refreshTransactionList();
}

function attachFilterHandlers() {
  if (!elements.transactionFilters) return;
  elements.transactionFilters.addEventListener('input', handleFilterChange);
  elements.transactionFilters.addEventListener('change', handleFilterChange);

  const resetBtn = qs('[data-action="reset-filters"]');
  resetBtn?.addEventListener('click', resetFilters);
}

function attachNavigationHandlers() {
  if (!elements.navSectionButtons.length) {
    return;
  }
  elements.navSectionButtons.forEach((button) => {
    button.addEventListener('click', () => {
      if (!state.token) {
        openModal('login');
        return;
      }
      activateSection(button.dataset.navSection || 'overview');
    });
  });
}

function attachAccountMetaHandlers() {
  elements.copyIbanBtn?.addEventListener('click', async () => {
    const iban = sanitizeIban(state.account?.iban);
    if (!iban) {
      showToast('Keine IBAN verfügbar.', 'error');
      return;
    }

    try {
      const clipboard = window.navigator?.clipboard;
      if (clipboard?.writeText) {
        await clipboard.writeText(iban);
      } else {
        const scratch = document.createElement('textarea');
        scratch.value = iban;
        scratch.setAttribute('readonly', 'true');
        scratch.style.position = 'absolute';
        scratch.style.left = '-9999px';
        document.body.appendChild(scratch);
        scratch.select();
        document.execCommand('copy');
        document.body.removeChild(scratch);
      }
      showToast('IBAN kopiert.', 'success');
    } catch (error) {
      showToast('IBAN konnte nicht kopiert werden.', 'error');
    }
  });
}

function setAccountSettingsFeedback(message = '', type = 'info') {
  if (!elements.accountSettingsFeedback) {
    return;
  }
  elements.accountSettingsFeedback.textContent = message;
  elements.accountSettingsFeedback.classList.remove('form-feedback--error', 'form-feedback--success');
  if (!message) {
    return;
  }
  if (type === 'error') {
    elements.accountSettingsFeedback.classList.add('form-feedback--error');
  } else if (type === 'success') {
    elements.accountSettingsFeedback.classList.add('form-feedback--success');
  }
}

function populateAccountSettingsForms() {
  if (!state.account) {
    return;
  }
  if (elements.profileForm) {
    const firstNameInput = elements.profileForm.querySelector('#settingsFirstName');
    const lastNameInput = elements.profileForm.querySelector('#settingsLastName');
    const emailInput = elements.profileForm.querySelector('#settingsEmail');
    if (firstNameInput) {
      firstNameInput.value = state.account.firstName || '';
    }
    if (lastNameInput) {
      lastNameInput.value = state.account.lastName || '';
    }
    if (emailInput) {
      emailInput.value = state.account.email || '';
    }
  }
}

function switchAccountSettingsTab(key = 'profile') {
  if (!elements.settingsTabButtons.length || !elements.settingsPanels.length) {
    return;
  }

  elements.settingsTabButtons.forEach((button) => {
    const isActive = button.dataset.settingsTab === key;
    button.classList.toggle('is-active', isActive);
    button.setAttribute('aria-pressed', String(isActive));
    button.setAttribute('aria-selected', String(isActive));
    button.setAttribute('tabindex', isActive ? '0' : '-1');
  });

  elements.settingsPanels.forEach((panel) => {
    const isActive = panel.dataset.settingsPanel === key;
    panel.classList.toggle('hidden', !isActive);
    panel.setAttribute('aria-hidden', String(!isActive));
  });
}

function openAccountSettings() {
  if (!elements.accountSettingsModal) {
    return;
  }
  if (!state.token) {
    openModal('login');
    return;
  }
  populateAccountSettingsForms();
  elements.passwordForm?.reset();
  setAccountSettingsFeedback('');
  switchAccountSettingsTab('profile');
  elements.accountSettingsModal.classList.remove('hidden');
  syncBodyScrollLock();
  window.requestAnimationFrame(() => {
    elements.profileForm?.querySelector('input')?.focus();
  });
}

function closeAccountSettings() {
  if (!elements.accountSettingsModal) {
    return;
  }
  elements.accountSettingsModal.classList.add('hidden');
  syncBodyScrollLock();
}

function attachAccountSettingsHandlers() {
  elements.openAccountSettingsBtn?.addEventListener('click', openAccountSettings);

  qa('[data-close-account-settings]').forEach((btn) => {
    btn.addEventListener('click', closeAccountSettings);
  });

  elements.settingsTabButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const tab = button.dataset.settingsTab;
      if (!tab) {
        return;
      }
      switchAccountSettingsTab(tab);
    });
  });

  elements.accountSettingsModal?.addEventListener('click', (event) => {
    if (event.target.dataset?.closeAccountSettings !== undefined) {
      closeAccountSettings();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && elements.accountSettingsModal && !elements.accountSettingsModal.classList.contains('hidden')) {
      closeAccountSettings();
    }
  });

  elements.profileForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!state.token) {
      openModal('login');
      return;
    }
    const formData = getFormValues(elements.profileForm);
    setAccountSettingsFeedback('');
    setFormBusy(elements.profileForm, true);
    try {
      await apiFetch('/api/accounts/me', {
        method: 'PUT',
        body: formData,
      });
      showToast('Profil aktualisiert.', 'success');
      setAccountSettingsFeedback('Profil aktualisiert.', 'success');
      await loadAccount({ silent: true });
      populateAccountSettingsForms();
    } catch (error) {
      setAccountSettingsFeedback(error.message, 'error');
      showToast(error.message, 'error');
    } finally {
      setFormBusy(elements.profileForm, false);
    }
  });

  elements.passwordForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!state.token) {
      openModal('login');
      return;
    }
    const formData = getFormValues(elements.passwordForm);
    if (formData.newPassword !== formData.confirmPassword) {
      setAccountSettingsFeedback('Neue Passwörter stimmen nicht überein.', 'error');
      return;
    }
    setAccountSettingsFeedback('');
    setFormBusy(elements.passwordForm, true);
    try {
      await apiFetch('/api/auth/password', {
        method: 'PUT',
        body: {
          currentPassword: formData.currentPassword,
          newPassword: formData.newPassword,
        },
      });
      elements.passwordForm.reset();
      setAccountSettingsFeedback('Passwort aktualisiert.', 'success');
      showToast('Passwort aktualisiert.', 'success');
    } catch (error) {
      setAccountSettingsFeedback(error.message, 'error');
      showToast(error.message, 'error');
    } finally {
      setFormBusy(elements.passwordForm, false);
    }
  });
}

function attachFormHandlers() {
  elements.loginForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const formData = getFormValues(elements.loginForm);
    setFormBusy(elements.loginForm, true);
    elements.authFeedback.textContent = '';
    try {
      const result = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: formData,
      });
      persistToken(result.token);
      closeModal();
      const profile = {
        firstName: result.firstName,
        lastName: result.lastName,
        email: formData.email,
      };
      const greeting = formatDisplayName(profile) || 'zurück';
      showToast(`Willkommen zurück, ${greeting}!`, 'success');
      await loadAccount({ silent: true });
    } catch (error) {
      elements.authFeedback.textContent = error.message;
      showToast(error.message, 'error');
    } finally {
      setFormBusy(elements.loginForm, false);
    }
  });

  elements.registerForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const formData = getFormValues(elements.registerForm);
    setFormBusy(elements.registerForm, true);
    elements.authFeedback.textContent = '';
    if (!formData.initialDeposit) {
      delete formData.initialDeposit;
    }
    try {
      const result = await apiFetch('/api/auth/register', {
        method: 'POST',
        body: formData,
      });
      persistToken(result.token);
      closeModal();
      const profile = {
        firstName: formData.firstName || result.firstName,
        lastName: formData.lastName || result.lastName,
        email: formData.email,
      };
      const greeting = formatDisplayName(profile) || 'bei AlteBank';
      const ibanMessage = result.iban ? ` Deine IBAN: ${result.iban}` : '';
      showToast(`Schön, dass du da bist, ${greeting}!${ibanMessage}`, 'success');
      await loadAccount({ silent: true });
    } catch (error) {
      elements.authFeedback.textContent = error.message;
      showToast(error.message, 'error');
    } finally {
      setFormBusy(elements.registerForm, false);
    }
  });

  const logoutBtn = qs('[data-action="logout"]');
  logoutBtn?.addEventListener('click', async () => {
    if (!state.token) {
      clearSession({ silent: true });
      return;
    }
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch (error) {
      // Ignorieren, Session wird clientseitig beendet.
    } finally {
      clearSession();
    }
  });

  const refreshBtn = qs('[data-action="refresh"]');
  refreshBtn?.addEventListener('click', () => {
    loadAccount();
  });

  const transactionForms = [
    {
      form: qs('#depositForm'),
      endpoint: '/api/accounts/deposit',
      successMessage: 'Einzahlung verbucht.',
      closeModalOnSuccess: true,
    },
    {
      form: qs('#withdrawForm'),
      endpoint: '/api/accounts/withdraw',
      successMessage: 'Auszahlung ausgeführt.',
      closeModalOnSuccess: true,
    },
    {
      form: qs('#transferForm'),
      endpoint: '/api/accounts/transfer',
      successMessage: 'Überweisung gesendet.',
      closeModalOnSuccess: true,
      beforeSubmit: (data) => ({
        ...data,
        targetIban: sanitizeIban(data.targetIban),
      }),
      onInit: (cfg) => {
        const ibanInput = cfg.form?.querySelector('input[name="targetIban"]');
        ibanInput?.addEventListener('input', () => {
          const raw = sanitizeIban(ibanInput.value);
          const grouped = raw.match(/.{1,4}/g)?.join(' ') ?? raw;
          ibanInput.value = grouped;
        });
      },
    },
    {
      form: elements.panelDepositForm,
      endpoint: '/api/accounts/deposit',
      successMessage: 'Einzahlung verbucht.',
      previewType: 'deposit',
    },
    {
      form: elements.panelWithdrawForm,
      endpoint: '/api/accounts/withdraw',
      successMessage: 'Auszahlung ausgeführt.',
      previewType: 'withdraw',
    },
    {
      form: elements.panelTransferForm,
      endpoint: '/api/accounts/transfer',
      successMessage: 'Überweisung gesendet.',
      previewType: 'transfer',
      beforeSubmit: (data) => ({
        ...data,
        targetIban: sanitizeIban(data.targetIban),
      }),
      onInit: (cfg) => {
        const ibanInput = cfg.form?.querySelector('input[name="targetIban"]');
        ibanInput?.addEventListener('input', () => {
          const raw = sanitizeIban(ibanInput.value);
          const grouped = raw.match(/.{1,4}/g)?.join(' ') ?? raw;
          ibanInput.value = grouped;
        });
      },
    },
  ];

  transactionForms.forEach((config) => {
    setupTransactionForm(config);
  });
}

function getCurrentBalanceNumber() {
  const raw = state.account?.balance ?? '0';
  const parsed = Number(raw);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function updateBalancePreview(type, amountValue) {
  const previewElement = qs(`[data-preview="${type}"] span`);
  const container = qs(`[data-preview="${type}"]`);
  if (!previewElement) {
    return;
  }
  const amount = Number(amountValue);
  const isValid = !Number.isNaN(amount) && amount > 0 && Boolean(state.account);
  if (!isValid) {
    previewElement.textContent = '–';
    container?.classList.add('hidden');
    container?.classList.toggle('balance-preview--negative', false);
    return;
  }
  const currentBalance = getCurrentBalanceNumber();
  let projected = currentBalance;
  if (type === 'deposit') {
    projected += amount;
  } else {
    projected -= amount;
  }
  previewElement.textContent = formatCurrency(projected);
  container?.classList.remove('hidden');
  container?.classList.toggle('balance-preview--negative', projected < 0);
}

function setupTransactionForm({
  form,
  endpoint,
  successMessage,
  closeModalOnSuccess = false,
  beforeSubmit,
  previewType,
  onInit,
}) {
  if (!form) {
    return;
  }

  if (typeof onInit === 'function') {
    onInit({ form });
  }

  const amountInput = form.querySelector('input[name="amount"]');
  if (previewType && amountInput) {
    const refresh = () => updateBalancePreview(previewType, amountInput.value);
    amountInput.addEventListener('input', refresh);
    refresh();
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!state.token) {
      openModal('login');
      return;
    }

    const baseData = getFormValues(form);
    const payload = beforeSubmit ? beforeSubmit(baseData) : baseData;

    setFormBusy(form, true);
    try {
      await apiFetch(endpoint, {
        method: 'POST',
        body: payload,
      });
      form.reset();
      if (previewType && amountInput) {
        updateBalancePreview(previewType, '');
      }
      showToast(successMessage, 'success');
      await loadAccount({ silent: true });
      if (closeModalOnSuccess) {
        closeTransactionModal();
      }
    } catch (error) {
      showToast(error.message, 'error');
    } finally {
      setFormBusy(form, false);
    }
  });
}

function formatChartLabel(date) {
  return new Intl.DateTimeFormat('de-DE', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

function buildHistorySeries(rangeKey) {
  const transactions = Array.isArray(state.transactions) ? [...state.transactions] : [];
  const rangeDays = rangeKey === 'all' ? null : Number(rangeKey);
  let rangeStart = null;
  if (rangeDays && Number.isFinite(rangeDays)) {
    rangeStart = new Date();
    if (rangeDays <= 1) {
      rangeStart.setTime(rangeStart.getTime() - 24 * 60 * 60 * 1000);
    } else {
      rangeStart.setHours(0, 0, 0, 0);
      rangeStart.setDate(rangeStart.getDate() - rangeDays);
    }
  }

  const sorted = transactions
    .filter((txn) => txn && txn.createdAt)
    .map((txn) => ({
      ...txn,
      createdAt: new Date(txn.createdAt),
    }))
    .filter((txn) => !Number.isNaN(txn.createdAt.getTime()))
    .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

  const filtered = rangeStart
    ? sorted.filter((txn) => txn.createdAt.getTime() >= rangeStart.getTime())
    : sorted;

  const labels = [];
  const values = [];
  filtered.forEach((txn) => {
    const balanceNumber = Number(txn.balance);
    if (Number.isNaN(balanceNumber)) {
      return;
    }
    labels.push(formatChartLabel(txn.createdAt));
    values.push(balanceNumber);
  });

  if (!labels.length && state.account) {
    labels.push(formatChartLabel(new Date()));
    values.push(getCurrentBalanceNumber());
  }

  return { labels, values };
}

function updateHistoryButtons() {
  elements.historyButtons.forEach((button) => {
    const isActive = button.dataset.historyRange === state.historyRange;
    button.classList.toggle('is-active', isActive);
    button.setAttribute('aria-pressed', String(isActive));
    button.setAttribute('aria-selected', String(isActive));
  });
}

function updateHistoryChart() {
  if (!elements.balanceChart || typeof window.Chart === 'undefined') {
    return;
  }

  const { labels, values } = buildHistorySeries(state.historyRange);

  const dataset = {
    labels,
    datasets: [
      {
        label: 'Kontostand (€)',
        data: values,
        borderColor: 'rgba(37, 99, 235, 0.85)',
        backgroundColor: 'rgba(37, 99, 235, 0.18)',
        fill: 'start',
        tension: 0.25,
        pointRadius: 3,
        pointHoverRadius: 5,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        ticks: {
          callback: (value) => formatCurrency(value),
        },
      },
      x: {
        ticks: {
          maxRotation: 45,
          minRotation: 0,
        },
      },
    },
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        callbacks: {
          label(context) {
            const val = context.parsed.y;
            return formatCurrency(val);
          },
        },
      },
    },
  };

  if (!balanceChartInstance) {
    balanceChartInstance = new window.Chart(elements.balanceChart, {
      type: 'line',
      data: dataset,
      options,
    });
  } else {
    balanceChartInstance.data.labels = dataset.labels;
    balanceChartInstance.data.datasets[0].data = dataset.datasets[0].data;
    balanceChartInstance.update();
  }
}

function attachHistoryHandlers() {
  if (!elements.historyButtons.length) {
    return;
  }
  elements.historyButtons.forEach((button) => {
    button.addEventListener('click', () => {
      state.historyRange = button.dataset.historyRange || 'all';
      updateHistoryButtons();
      updateHistoryChart();
    });
  });
  updateHistoryButtons();
}

function initFromHash() {
  if (window.location.hash === '#auth') {
    openModal('login');
  }
}

function init() {
  attachModalHandlers();
  attachFormHandlers();
  attachTransactionModalHandlers();
  attachDashboardTransactionHandlers();
  attachFilterHandlers();
  attachNavigationHandlers();
  attachAccountMetaHandlers();
  attachHistoryHandlers();
  attachAccountSettingsHandlers();
  switchAccountSettingsTab('profile');
  syncBrandLogoSize();
  window.addEventListener('resize', syncBrandLogoSize);
  if (document.fonts?.ready) {
    document.fonts.ready.then(() => {
      syncBrandLogoSize();
    }).catch(() => {
      syncBrandLogoSize();
    });
  } else {
    window.setTimeout(syncBrandLogoSize, 0);
  }
  updateAuthState(Boolean(state.token), state.account);
  updateBalances();
  updateAccountMeta();
  updateAdvisorCard();
  updateAutoRefreshIndicator();
  state.transactions = [];
  refreshTransactionList();

  if (state.token) {
    loadAccount({ silent: true });
  }

  initFromHash();

  window.addEventListener('hashchange', () => {
    if (window.location.hash === '#auth') {
      openModal(elements.authModal?.dataset.mode || 'login');
    }
  });

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      stopAutoRefresh();
      if (elements.autoRefreshIndicator) {
        elements.autoRefreshIndicator.textContent = 'Aktualisierung pausiert (Tab inaktiv)';
      }
      return;
    }
    if (state.token) {
      loadAccount({ silent: true });
      startAutoRefresh();
    }
  });
}

init();
