import { runAllChecks } from './checks/check-runner.js';

function getCacheKey(url) {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'runChecks') {
    runAllChecks(message.url, (progress) => {
      chrome.runtime.sendMessage({
        action: 'progress',
        ...progress,
      }).catch(() => {
        // Popup may have closed - ignore
      });
    })
      .then((results) => {
        // Cache results for this session
        const key = getCacheKey(message.url);
        const entry = { data: results, timestamp: Date.now() };
        chrome.storage.session.set({ [key]: entry });

        sendResponse({ success: true, data: results, cached: false });
      })
      .catch((error) => {
        sendResponse({ success: false, error: error.message });
      });

    return true;
  }

  if (message.action === 'getCached') {
    const key = getCacheKey(message.url);
    chrome.storage.session.get(key, (result) => {
      const entry = result[key];
      if (entry) {
        sendResponse({ success: true, data: entry.data, timestamp: entry.timestamp, cached: true });
      } else {
        sendResponse({ success: false });
      }
    });

    return true;
  }

  if (message.action === 'clearCached') {
    const key = getCacheKey(message.url);
    chrome.storage.session.remove(key, () => {
      sendResponse({ success: true });
    });

    return true;
  }
});
