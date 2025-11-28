/**
 * NGShield Extension - Content Script
 * Injects into web pages to hide ads and block malicious elements
 */

// Check current page URL immediately
if (window.location.href) {
  chrome.runtime.sendMessage(
    { action: 'blockPage', url: window.location.href },
    (response) => {
      if (response && response.blocked) {
        console.log('NGShield blocked page:', response.reason);
        // Page will be redirected by background script
      }
    }
  );
}

// Request config from background script for ad blocking
chrome.runtime.sendMessage({ action: 'getConfig' }, (response) => {
  if (response && response.blocklist) {
    initAdBlocker(response.blocklist, response.adultBlocklist, response.monitoredDomains);
  }
});

/**
 * Initialize ad blocker on the page
 */
function initAdBlocker(blocklist, adultBlocklist, monitoredDomains) {
  // Common ad selectors to hide
  const adSelectors = [
    '[class*="ad"]',
    '[id*="ad"]',
    '[class*="advertisement"]',
    '[id*="advertisement"]',
    '.banner',
    '.promotional',
    '[data-ad-format]',
    'ins.adsbygoogle',
    '.advert'
  ];

  // Hide elements matching common ad selectors
  adSelectors.forEach(selector => {
    try {
      const elements = document.querySelectorAll(selector);
      elements.forEach(el => {
        if (el && el.parentNode) {
          el.style.display = 'none';
          el.setAttribute('data-ngshield-blocked', 'true');
        }
      });
    } catch (e) {
      // Invalid selector, skip
    }
  });

  // Block iframes with ad domains
  const iframes = document.querySelectorAll('iframe');
  iframes.forEach(iframe => {
    try {
      const src = iframe.src || iframe.getAttribute('data-src') || '';
      if (shouldBlockUrl(src, blocklist)) {
        iframe.style.display = 'none';
        iframe.setAttribute('data-ngshield-blocked', 'true');
      }
    } catch (e) {
      // Skip CORS errors
    }
  });

  // Monitor for dynamically added ads (via MutationObserver)
  const observer = new MutationObserver((mutations) => {
    mutations.forEach(mutation => {
      if (mutation.addedNodes.length) {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === 1) { // Element node
            // Check if it matches ad selectors
            if (node.matches && adSelectors.some(sel => node.matches(sel))) {
              node.style.display = 'none';
              node.setAttribute('data-ngshield-blocked', 'true');
            }
            // Check children
            const children = node.querySelectorAll ? node.querySelectorAll(adSelectors.join(',')) : [];
            children.forEach(child => {
              child.style.display = 'none';
              child.setAttribute('data-ngshield-blocked', 'true');
            });
          }
        });
      }
    });
  });

  // Start observing the document
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: false
  });

  console.log('NGShield ad blocker initialized');
}

/**
 * Check if a URL should be blocked
 */
function shouldBlockUrl(url, blocklist) {
  if (!url) return false;
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    
    for (const blocked of blocklist) {
      if (hostname.includes(blocked) || url.includes(blocked)) {
        return true;
      }
    }
    return false;
  } catch (e) {
    return false;
  }
}

/**
 * Listen for right-click context menu to report ads
 */
document.addEventListener('contextmenu', (e) => {
  const target = e.target;
  
  // Check if user right-clicked on an image or iframe (potential ad)
  if (target.tagName === 'IMG' || target.tagName === 'IFRAME' || target.tagName === 'A') {
    const url = target.src || target.href || target.getAttribute('data-src') || '';
    if (url) {
      // Store for potential report
      sessionStorage.setItem('ngshield_last_clicked_url', url);
    }
  }
}, true);
