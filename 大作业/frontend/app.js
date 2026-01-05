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

function $(id) {
  return document.getElementById(id);
}

function setStatus(msg) {
  $('status').textContent = msg;
}

function setOutput(obj) {
  $('output').textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
}

function val(id) {
  return $(id).value.trim();
}

$('btn_clear').addEventListener('click', () => {
  setOutput('');
  setStatus('就绪');
});

$('btn_scan_files').addEventListener('click', async () => {
  try {
    setStatus('正在扫描文件...');
    const body = {
      target: val('sf_target'),
      yara_rules_dir: val('sf_rules') || null,
      out_path: val('sf_out') || null,
      threads: Number(val('sf_threads') || '4'),
    };
    if (!body.target) throw new Error('请填写目标路径');

    const data = await postJson('/api/scan-files', body);
    setOutput(data);
    setStatus('文件扫描完成');
  } catch (e) {
    setStatus('文件扫描失败');
    setOutput({ error: String(e.message || e) });
  }
});

$('btn_scan_logs').addEventListener('click', async () => {
  try {
    setStatus('正在扫描日志...');
    const body = {
      events_path: val('sl_events'),
      sigma_rules_dir: val('sl_rules') || null,
      out_path: val('sl_out') || null,
      max_events: Number(val('sl_max') || '0'),
    };
    if (!body.events_path) throw new Error('请填写事件文件路径');

    const data = await postJson('/api/scan-logs', body);
    setOutput(data);
    setStatus('日志扫描完成');
  } catch (e) {
    setStatus('日志扫描失败');
    setOutput({ error: String(e.message || e) });
  }
});

$('btn_evaluate').addEventListener('click', async () => {
  try {
    setStatus('正在计算指标...');
    const body = {
      truth_csv: val('ev_truth'),
      scan_json: val('ev_scan'),
      out_path: val('ev_out') || null,
    };
    if (!body.truth_csv) throw new Error('请填写 truth.csv 路径');
    if (!body.scan_json) throw new Error('请填写 scan 输出 JSON 路径');

    const data = await postJson('/api/evaluate', body);
    setOutput(data);
    setStatus('指标计算完成');
  } catch (e) {
    setStatus('指标计算失败');
    setOutput({ error: String(e.message || e) });
  }
});
