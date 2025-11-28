/**
 * NGShield Extension - Background Service Worker
 */

let CONFIG = {
  serverUrl: 'http://localhost:8000',
  apiKey: null,
  blocklist: [],
  adultBlocklist: [],
  refreshInterval: 3600000
};

chrome.storage.sync.get(['serverUrl', 'apiKey'], (items) => {
  if (items.serverUrl) CONFIG.serverUrl = items.serverUrl;
  if (items.apiKey) CONFIG.apiKey = items.apiKey;
});

console.log('NGShield loaded');
updateBlocklist();
setInterval(updateBlocklist, CONFIG.refreshInterval);

async function updateBlocklist() {
  try {
    const r = await fetch(CONFIG.serverUrl + '/api/extension/adult-blocklist/');
    if (r.ok) {
      const data = await r.json();
      CONFIG.adultBlocklist = data.adult_blocklist || [];
      console.log('OK Loaded', CONFIG.adultBlocklist.length, 'domains');
    }
  } catch (e) {
    console.error('Error:', e);
  }
}

function isUrlBlocked(url) {
  try {
    const h = new URL(url).hostname;
    for (const item of CONFIG.adultBlocklist) {
      const d = item.domain || item;
      if (h === d || h.endsWith('.' + d)) {
        return { blocked: true, reason: item.category || 'porn' };
      }
    }
    return { blocked: false };
  } catch (e) {
    return { blocked: false };
  }
}

chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId !== 0 || d.url.includes('blocked.html')) return;
  const r = isUrlBlocked(d.url);
  if (r.blocked) {
    // Report blocked attempt to backend
    fetch(CONFIG.serverUrl + '/api/extension/report-blocked-attempt/', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: d.url, reason: 'Blocked by extension', category: r.reason })
    }).catch(() => {});
    chrome.tabs.update(d.tabId, {
      url: chrome.runtime.getURL('blocked.html') + '?url=' + encodeURIComponent(d.url) + '&reason=' + encodeURIComponent(r.reason)
    });
  }
});

chrome.runtime.onMessage.addListener((req, sender, res) => {
  if (req.action === 'checkUrl') res(isUrlBlocked(req.url));
  if (req.action === 'getConfig') res(CONFIG);
});
