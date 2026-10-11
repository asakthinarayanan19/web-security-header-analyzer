const form = document.querySelector('#scan-form');
const urlInput = document.querySelector('#url-input');
const analyzeButton = document.querySelector('#analyze-button');
const loadingState = document.querySelector('#loading-state');
const errorMessage = document.querySelector('#error-message');
const results = document.querySelector('#results');
let latestResult = null;

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
}

function setLoading(loading) {
  loadingState.hidden = !loading;
  analyzeButton.disabled = loading;
  analyzeButton.querySelector('span:first-child').textContent = loading ? 'Analyzing…' : 'Analyze website';
}

function textCell(text) {
  const cell = document.createElement('td');
  cell.textContent = text;
  return cell;
}

function renderFindings(result) {
  const body = document.querySelector('#findings-body');
  const riskList = document.querySelector('#risk-list');
  body.replaceChildren();
  riskList.replaceChildren();

  result.findings.forEach((finding, index) => {
    const row = document.createElement('tr');
    row.append(textCell(finding.name));

    const stateCell = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = `status-badge status-${finding.status.toLowerCase()}`;
    badge.textContent = finding.status;
    const value = document.createElement('span');
    value.className = 'header-value';
    value.textContent = finding.value || 'Not set';
    stateCell.append(badge, value);
    row.append(stateCell, textCell(finding.purpose), textCell(finding.recommendation));
    body.append(row);

    const item = document.createElement('div');
    item.className = `risk-item${finding.status === 'Present' ? ' is-present' : ''}`;
    const marker = document.createElement('span');
    marker.className = 'risk-marker';
    marker.textContent = String(index + 1).padStart(2, '0');
    const name = document.createElement('span');
    name.className = 'risk-name';
    name.textContent = finding.name;
    const copy = document.createElement('span');
    copy.className = 'risk-copy';
    copy.textContent = finding.status === 'Present' ? finding.risk : `${finding.risk} ${finding.recommendation}`;
    item.append(marker, name, copy);
    riskList.append(item);
  });
}

function renderResult(result) {
  latestResult = result;
  document.querySelector('#score').textContent = result.score;
  document.querySelector('#assessment').textContent = result.assessment;
  document.querySelector('#score-bar').style.width = `${result.score}%`;
  document.querySelector('#checked-count').textContent = result.headers_checked;
  document.querySelector('#present-count').textContent = result.present_count;
  document.querySelector('#attention-count').textContent = result.weak_count + result.missing_count;
  document.querySelector('#attention-detail').textContent = `${result.weak_count} weak · ${result.missing_count} missing`;
  document.querySelector('#http-status').textContent = `HTTP ${result.http_status}`;
  document.querySelector('#scan-meta').textContent = `${result.target_url} · ${new Date(result.scanned_at).toLocaleString()}`;
  const notice = document.querySelector('#scan-notice');
  notice.textContent = result.notice || '';
  notice.hidden = !result.notice;
  renderFindings(result);
  results.hidden = false;
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  results.hidden = true;
  setLoading(true);
  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: urlInput.value }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'The scan could not be completed.');
    renderResult(data);
  } catch (error) {
    showError(error.message || 'The website could not be reached. Check the address and try again.');
  } finally {
    setLoading(false);
  }
});

document.querySelector('#scan-again').addEventListener('click', () => {
  results.hidden = true;
  urlInput.focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

document.querySelector('#download-report').addEventListener('click', async (event) => {
  if (!latestResult) return;
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const response = await fetch('/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ result: latestResult }),
    });
    if (!response.ok) throw new Error('The report could not be generated.');
    const blob = await response.blob();
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = 'security-header-report.html';
    link.click();
    URL.revokeObjectURL(objectUrl);
  } catch (error) {
    showError(error.message || 'The report could not be downloaded.');
  } finally {
    button.disabled = false;
  }
});