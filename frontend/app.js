async function postJson(url, body) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const text = await resp.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (!resp.ok) {
    const detail = data && (data.detail || data.error || data.raw);
    throw new Error(detail ? String(detail) : `HTTP ${resp.status}`);
  }
  return data;
}

async function getJson(url) {
  const resp = await fetch(url, { method: 'GET' });
  const text = await resp.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }
  if (!resp.ok) {
    const detail = data && (data.detail || data.error || data.raw);
    throw new Error(detail ? String(detail) : `HTTP ${resp.status}`);
  }
  return data;
}

function $(id) {
  return document.getElementById(id);
}

function setStatus(msg) {
  $('status').textContent = msg;
}

function setButtonsDisabled(disabled) {
  const ids = ['btn_scan_files', 'btn_scan_logs', 'btn_evaluate'];
  for (const id of ids) {
    const el = $(id);
    if (el) el.disabled = !!disabled;
  }
}

function showProgress(visible) {
  const wrap = $('progress_wrap');
  if (!wrap) return;
  wrap.style.display = visible ? '' : 'none';
  wrap.setAttribute('aria-hidden', visible ? 'false' : 'true');
}

function setProgressState({ text, percent }) {
  const textEl = $('progress_text');
  const pctEl = $('progress_pct');
  const track = document.querySelector('.progress_track');
  const inner = $('progress_inner');
  if (textEl) textEl.textContent = text || '—';

  const hasPct = (percent === 0 || percent);
  const pct = hasPct ? Math.max(0, Math.min(100, Number(percent))) : null;
  if (pctEl) pctEl.textContent = hasPct ? `${pct}%` : '—';
  if (inner) inner.style.width = hasPct ? `${pct}%` : '0%';
  if (track) track.setAttribute('aria-valuenow', hasPct ? String(pct) : '0');
}

function setOutput(obj) {
  $('output').textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
}

function appendOutput(line) {
  const out = $('output');
  const text = (line == null ? '' : String(line));
  out.textContent = out.textContent ? (out.textContent + '\n' + text) : text;
}

function nowTime() {
  const d = new Date();
  return d.toLocaleTimeString('zh-CN', { hour12: false });
}

function val(id) {
  return $(id).value.trim();
}

$('btn_clear').addEventListener('click', () => {
  setOutput('');
  setStatus('就绪');
  showProgress(false);
  setProgressState({ text: '—', percent: null });
});

let pollTimer = null;
let lastLogCount = 0;
let currentJobId = null;

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  currentJobId = null;
  lastLogCount = 0;
  setButtonsDisabled(false);
}

function renderJobStatus(job) {
  const cur = job.current || {};
  const pct = (cur.progress === 0 || cur.progress) ? `(${cur.progress}%)` : '';
  const msg = cur.message || '';
  const kind = job.kind || '任务';
  setStatus(`${kind}：${job.status} ${pct} ${msg}`.trim());

  showProgress(true);
  const text = msg || (cur.stage ? `阶段：${cur.stage}` : '正在执行...');
  setProgressState({ text, percent: (cur.progress === 0 || cur.progress) ? cur.progress : null });
}

async function startAndPoll(endpoint, body, startLabel, doneLabel) {
  stopPolling();
  appendOutput(`[${nowTime()}] ${startLabel}`);
  setStatus('已提交任务...');
  setButtonsDisabled(true);
  showProgress(true);
  setProgressState({ text: '已提交任务，等待执行...', percent: null });

  const data = await postJson(endpoint, body);

  // Backward compatible: if backend returns final result synchronously.
  if (!data || !data.job_id) {
    appendOutput(`[${nowTime()}] ${doneLabel}`);
    appendOutput(typeof data === 'string' ? data : JSON.stringify(data, null, 2));
    setStatus(doneLabel);
    setProgressState({ text: doneLabel, percent: 100 });
    setButtonsDisabled(false);
    return;
  }

  currentJobId = data.job_id;
  lastLogCount = 0;
  appendOutput(`[${nowTime()}] 任务已创建：${currentJobId}`);

  const pollOnce = async () => {
    const job = await getJson(`/api/jobs/${currentJobId}`);
    renderJobStatus(job);

    const logs = Array.isArray(job.logs) ? job.logs : [];
    if (logs.length > lastLogCount) {
      for (let i = lastLogCount; i < logs.length; i++) {
        const entry = logs[i];
        if (entry && typeof entry === 'object') {
          appendOutput(`[${new Date((entry.ts || 0) * 1000).toLocaleTimeString('zh-CN', { hour12: false })}] ${entry.message}`);
        } else {
          appendOutput(String(entry));
        }
      }
      lastLogCount = logs.length;
    }

    if (job.status === 'succeeded') {
      stopPolling();
      appendOutput(`[${nowTime()}] ${doneLabel}`);
      if (job.result) {
        appendOutput(JSON.stringify(job.result, null, 2));
      }
      setStatus(doneLabel);
      setProgressState({ text: doneLabel, percent: 100 });
    } else if (job.status === 'failed') {
      stopPolling();
      appendOutput(`[${nowTime()}] 任务失败：${job.error || '未知错误'}`);
      setStatus('任务失败');
      setProgressState({ text: `任务失败：${job.error || '未知错误'}`, percent: null });
    }
  };

  // Immediately poll once so users see feedback quickly.
  await pollOnce();
  pollTimer = setInterval(() => {
    pollOnce().catch((e) => {
      appendOutput(`[${nowTime()}] 进度查询失败：${String(e.message || e)}`);
      setStatus('进度查询失败');
      showProgress(true);
      setProgressState({ text: `进度查询失败：${String(e.message || e)}`, percent: null });
    });
  }, 800);
}

$('btn_scan_files').addEventListener('click', async () => {
  try {
    setStatus('正在创建文件扫描任务...');
    const body = {
      target: val('sf_target'),
      yara_rules_dir: val('sf_rules') || null,
      out_path: val('sf_out') || null,
      threads: Number(val('sf_threads') || '4'),
    };
    if (!body.target) throw new Error('请填写目标路径');

    await startAndPoll('/api/scan-files', body, '开始文件扫描（YARA）', '文件扫描完成');
  } catch (e) {
    setStatus('文件扫描失败');
    appendOutput(`[${nowTime()}] 文件扫描失败：${String(e.message || e)}`);
  }
});

$('btn_scan_logs').addEventListener('click', async () => {
  try {
    setStatus('正在创建日志扫描任务...');
    const body = {
      events_path: val('sl_events'),
      sigma_rules_dir: val('sl_rules') || null,
      out_path: val('sl_out') || null,
      max_events: Number(val('sl_max') || '0'),
    };
    if (!body.events_path) throw new Error('请填写事件文件路径');

    await startAndPoll('/api/scan-logs', body, '开始日志扫描（Sigma/Zircolite）', '日志扫描完成');
  } catch (e) {
    setStatus('日志扫描失败');
    appendOutput(`[${nowTime()}] 日志扫描失败：${String(e.message || e)}`);
  }
});

$('btn_evaluate').addEventListener('click', async () => {
  try {
    setStatus('正在创建指标评测任务...');
    const body = {
      truth_csv: val('ev_truth'),
      scan_json: val('ev_scan'),
      out_path: val('ev_out') || null,
    };
    if (!body.truth_csv) throw new Error('请填写 truth.csv 路径');
    if (!body.scan_json) throw new Error('请填写 scan 输出 JSON 路径');

    await startAndPoll('/api/evaluate', body, '开始计算指标（evaluate）', '指标计算完成');
  } catch (e) {
    setStatus('指标计算失败');
    appendOutput(`[${nowTime()}] 指标计算失败：${String(e.message || e)}`);
  }
});
