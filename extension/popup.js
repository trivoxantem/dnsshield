/**
 * NGShield Extension - Popup UI Controller
 */

document.addEventListener('DOMContentLoaded', initPopup);

let config = {
  serverUrl: null,
  apiKey: null,
  blocklist: [],
  monitoredDomains: []
};

function initPopup() {
  // Load configuration from storage
  chrome.storage.sync.get(['serverUrl', 'apiKey', 'blocklist', 'monitoredDomains', 'lastUpdate'], (items) => {
    config.serverUrl = items.serverUrl;
    config.apiKey = items.apiKey;
    config.blocklist = items.blocklist || [];
    config.monitoredDomains = items.monitoredDomains || [];

    if (!config.apiKey) {
      // Show setup panel
      document.getElementById('setup-panel').classList.remove('hidden');
      document.getElementById('main-panel').classList.add('hidden');
    } else {
      // Show main panel
      document.getElementById('setup-panel').classList.add('hidden');
      document.getElementById('main-panel').classList.remove('hidden');
      updateDisplay(items.lastUpdate);
    }
  });

  // Event listeners
  document.getElementById('save-config-btn').addEventListener('click', saveConfiguration);
  document.getElementById('refresh-btn').addEventListener('click', refreshBlocklist);
  document.getElementById('settings-btn').addEventListener('click', openSettings);
  document.getElementById('report-btn').addEventListener('click', reportIssue);
}

function saveConfiguration() {
  const serverUrl = document.getElementById('server-url').value.trim();
  const apiKey = document.getElementById('api-key').value.trim();
  const messageEl = document.getElementById('config-message');

  if (!serverUrl || !apiKey) {
    showMessage(messageEl, 'Please fill in all fields', 'error');
    return;
  }

  // Save to storage
  chrome.storage.sync.set({ serverUrl, apiKey }, () => {
    showMessage(messageEl, 'Configuration saved! Refreshing blocklist...', 'success');
    
    // Trigger refresh in background script
    chrome.runtime.sendMessage({ action: 'refreshBlocklist' }, () => {
      setTimeout(() => {
        // Reload popup
        initPopup();
      }, 1000);
    });
  });
}

function updateDisplay(lastUpdate) {
  // Update stats
  document.getElementById('blocked-count').textContent = config.blocklist.length;
  document.getElementById('domains-count').textContent = config.monitoredDomains.length;

  // Update blocklist
  const blocklistEl = document.getElementById('blocklist');
  if (config.blocklist.length === 0) {
    blocklistEl.innerHTML = '<li class="empty">No ads blocked yet</li>';
  } else {
    blocklistEl.innerHTML = config.blocklist
      .slice(0, 10) // Show top 10
      .map(url => `<li title="${url}">${truncate(url, 50)}</li>`)
      .join('');
    if (config.blocklist.length > 10) {
      blocklistEl.innerHTML += `<li class="more">...and ${config.blocklist.length - 10} more</li>`;
    }
  }

  // Update domains
  const domainsEl = document.getElementById('domains-list');
  if (config.monitoredDomains.length === 0) {
    domainsEl.innerHTML = '<li class="empty">No domains configured</li>';
  } else {
    domainsEl.innerHTML = config.monitoredDomains
      .map(domain => `<li>✓ ${domain}</li>`)
      .join('');
  }

  // Update last update time
  if (lastUpdate) {
    const date = new Date(lastUpdate);
    document.getElementById('last-update').textContent = `Last updated: ${date.toLocaleString()}`;
  }
}

function refreshBlocklist() {
  const btn = document.getElementById('refresh-btn');
  btn.disabled = true;
  btn.textContent = 'Refreshing...';

  chrome.runtime.sendMessage({ action: 'updateBlocklist' }, () => {
    btn.disabled = false;
    btn.textContent = 'Refresh Blocklist';
    // Reload popup display
    initPopup();
  });
}

function openSettings() {
  document.getElementById('main-panel').classList.add('hidden');
  document.getElementById('setup-panel').classList.remove('hidden');
  document.getElementById('server-url').value = config.serverUrl || '';
  document.getElementById('api-key').value = config.apiKey ? config.apiKey.substring(0, 10) + '...' : '';
}

function reportIssue() {
  const url = prompt('Enter the URL you want to report as an ad:');
  if (!url) return;

  chrome.runtime.sendMessage({ action: 'reportAd', url }, (response) => {
    if (response && response.success) {
      alert('Thank you! Your report has been sent to NGShield.');
    } else {
      alert('Failed to report. Please try again.');
    }
  });
}

function showMessage(el, text, type) {
  el.textContent = text;
  el.className = `message ${type === 'error' ? 'error' : 'success'}`;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 5000);
}

function truncate(str, length) {
  return str.length > length ? str.substring(0, length) + '...' : str;
}
