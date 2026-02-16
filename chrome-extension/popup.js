document.addEventListener('DOMContentLoaded', async () => {
  const urlDisplay = document.getElementById('site-url');
  const runButton = document.getElementById('run-button');
  const resultsContainer = document.getElementById('results');
  const progressEl = document.getElementById('progress');
  const versionSection = document.getElementById('version-section');
  const versionValue = document.getElementById('version-value');
  const cacheNotice = document.getElementById('cache-notice');
  const cacheTime = document.getElementById('cache-time');

  // Get active tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const siteUrl = tab?.url || '';
  urlDisplay.textContent = siteUrl;

  if (!siteUrl.startsWith('http')) {
    resultsContainer.innerHTML = '<p class="error">Not a valid HTTP/HTTPS page</p>';
    runButton.disabled = true;
    return;
  }

  // Check for cached results
  chrome.runtime.sendMessage(
    { action: 'getCached', url: siteUrl },
    (response) => {
      if (response?.success) {
        renderResults(response.data);
        showCacheNotice(response.timestamp);
        runButton.textContent = 'Re-run Checks';
      }
    }
  );

  // Listen for progress updates from service worker
  chrome.runtime.onMessage.addListener((message) => {
    if (message.action === 'progress') {
      progressEl.textContent = `Running check ${message.step}/${message.total}: ${message.name}...`;
    }
  });

  runButton.addEventListener('click', () => {
    runButton.disabled = true;
    resultsContainer.innerHTML = '';
    versionSection.classList.add('hidden');
    cacheNotice.classList.add('hidden');
    progressEl.classList.remove('hidden');
    progressEl.textContent = 'Starting checks...';

    chrome.runtime.sendMessage(
      { action: 'runChecks', url: siteUrl },
      (response) => {
        progressEl.classList.add('hidden');
        runButton.disabled = false;

        if (response?.success) {
          renderResults(response.data);
          if (response.cached) {
            showCacheNotice(Date.now());
          } else {
            cacheNotice.classList.add('hidden');
          }
          runButton.textContent = 'Re-run Checks';
        } else {
          resultsContainer.innerHTML = `<p class="error">Error: ${response?.error || 'Unknown error'}</p>`;
        }
      }
    );
  });

  function showCacheNotice(timestamp) {
    cacheNotice.classList.remove('hidden');
    cacheTime.textContent = formatTimestamp(timestamp);
  }
});

function formatTimestamp(ts) {
  const date = new Date(ts);
  const now = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return 'just now';
  if (diffMins === 1) return '1 minute ago';
  if (diffMins < 60) return `${diffMins} minutes ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours === 1) return '1 hour ago';
  if (diffHours < 24) return `${diffHours} hours ago`;

  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function getBadgeInfo(outcome) {
  if (outcome === 'Pass') return { cls: 'badge-pass', icon: '\u2713' };
  if (outcome === 'Warn') return { cls: 'badge-warn', icon: '!' };
  return { cls: 'badge-fail', icon: '\u2717' };
}

function renderResults(data) {
  const resultsContainer = document.getElementById('results');
  const versionSection = document.getElementById('version-section');
  const versionValue = document.getElementById('version-value');

  // Show version
  versionSection.classList.remove('hidden');
  versionValue.textContent = data.sitecoreVersion;

  if (data.sitecoreVersion.startsWith('Probably')) {
    versionValue.className = 'version-probably';
  } else if (data.sitecoreVersion === 'Unknown' || data.sitecoreVersion === 'Connection failed') {
    versionValue.className = 'version-unknown';
  } else {
    versionValue.className = 'version-known';
  }

  // Render each check result
  resultsContainer.innerHTML = '';

  // Show skipped notice for XM Cloud sites
  if (data.isXMCloud) {
    const notice = document.createElement('div');
    notice.className = 'xm-cloud-notice';
    notice.textContent = 'XM Cloud site detected. XM/XP hardening checks do not apply.';
    resultsContainer.appendChild(notice);
  }

  for (const result of data.siteResults) {
    const item = document.createElement('div');
    item.className = 'check-item';

    const hasSubTests = result.tests && result.tests.length > 0;
    const badgeInfo = getBadgeInfo(result.outcome);

    // Header row
    const header = document.createElement('div');
    header.className = 'check-header';
    header.innerHTML = `
      <span class="badge ${badgeInfo.cls}">${badgeInfo.icon}</span>
      <span class="check-title">${escapeHtml(result.title)}</span>
      ${result.details ? `<span class="check-details">${escapeHtml(result.details)}</span>` : ''}
      ${hasSubTests ? '<span class="expand-icon">\u25B6</span>' : ''}
    `;

    item.appendChild(header);

    // Sub-tests (collapsible)
    if (hasSubTests) {
      const subTests = document.createElement('div');
      subTests.className = 'sub-tests';

      for (const test of result.tests) {
        const subBadge = getBadgeInfo(test.outcome);
        const sub = document.createElement('div');
        sub.className = 'sub-test';
        sub.innerHTML = `
          <span class="sub-badge ${subBadge.cls}">${subBadge.icon}</span>
          <div>
            <div class="sub-test-title">${escapeHtml(test.title)}</div>
            ${test.details ? `<div class="sub-test-details">${escapeHtml(test.details)}</div>` : ''}
          </div>
        `;
        subTests.appendChild(sub);
      }

      item.appendChild(subTests);

      // Toggle sub-tests on header click
      header.addEventListener('click', () => {
        subTests.classList.toggle('open');
        header.querySelector('.expand-icon').classList.toggle('expanded');
      });
    }

    resultsContainer.appendChild(item);
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
