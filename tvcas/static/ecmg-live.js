/* One bounded request at a time, only while this ECMG view is visible. */
(() => {
  'use strict';
  const listing = document.querySelector('[data-ecmg-list]');
  const log = document.querySelector('[data-ecmg-log]');
  const root = listing || log;
  if (!root) return;
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const date = value => {
    if (value === null || value === undefined || value === '') return '—';
    const d = new Date(Number(value) * 1000);
    if (Number.isNaN(d.getTime())) return '—';
    const pad = number => String(number).padStart(2, '0');
    return `${pad(d.getDate())}.${pad(d.getMonth()+1)}.${d.getFullYear()} at ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };
  for (const el of root.querySelectorAll('[data-timezone]')) el.textContent = `Часова зона: ${zone}.`;
  for (const el of root.querySelectorAll('[data-epoch]')) el.textContent = date(el.dataset.epoch);
  const node = (tag, text, className) => {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = String(text);
    if (className) element.className = className;
    return element;
  };
  const error = root.querySelector('[data-live-error]');
  const peerLine = (peer, logUrl) => {
    const line = node('div', undefined, `peer-line${peer.connected ? '' : ' peer-disconnected'}`);
    line.append(node('span', `${date(peer.connected_at)} — `), node('span', peer.address, 'mono'),
      node('span', `, cw=${peer.cw_count}, ecm=${peer.ecm_count} `));
    if (logUrl) {
      const link = node('a', '[log]');
      const url = new URL(logUrl, location.origin);
      url.searchParams.set('peer_id', peer.peer_id);
      link.href = url.href;
      line.append(link);
    }
    if (!peer.connected) line.append(node('small', `Връзката е затворена · ${date(peer.disconnected_at)}`));
    return line;
  };
  let selectedPeer = log ? log.dataset.peerId : '';
  let paused = false;
  let stopped = false;
  let authFailed = false;
  let timer = null;
  let controller = null;
  let refreshSoon = false;
  const interval = log ? 3000 : 5000;
  const renderListing = data => {
    const generators = new Map((data.ecmg || []).map(item => [String(item.id), item]));
    for (const cell of listing.querySelectorAll('[data-ecmg-peers]')) {
      const generator = generators.get(cell.dataset.ecmgPeers);
      const peers = generator ? generator.peers || [] : [];
      const fragment = document.createDocumentFragment();
      for (const peer of peers) fragment.append(peerLine(peer, cell.dataset.logUrl));
      if (!peers.length) fragment.append(node('span', generator && generator.running ? 'Няма свързани пиъри.' : 'Генераторът не работи.', 'muted'));
      cell.replaceChildren(fragment);
    }
    for (const cell of listing.querySelectorAll('[data-ecmg-activity]')) {
      const generator = generators.get(cell.dataset.ecmgActivity);
      cell.textContent = date(generator && generator.last_ecm);
    }
  };
  const renderLog = data => {
    const peers = data.peers || [];
    const select = log.querySelector('[data-peer-filter]');
    const options = [new Option('Всички пиъри', '')];
    for (const peer of peers) options.push(new Option(`${peer.address} · ${date(peer.connected_at)}${peer.connected ? '' : ' · затворен'}`, peer.peer_id));
    if (selectedPeer && !peers.some(peer => peer.peer_id === selectedPeer)) options.push(new Option(`${selectedPeer} · извън текущата история`, selectedPeer));
    select.replaceChildren(...options);
    select.value = selectedPeer;
    const peerNodes = document.createDocumentFragment();
    for (const peer of peers) if (!selectedPeer || peer.peer_id === selectedPeer) peerNodes.append(peerLine(peer));
    if (!peerNodes.childNodes.length) peerNodes.append(node('p', 'Няма пиъри за този избор.', 'muted'));
    log.querySelector('[data-log-peers]').replaceChildren(peerNodes);
    const state = log.querySelector('[data-generator-state]');
    state.textContent = data.running ? 'Работи' : (data.state === 'error' ? 'Грешка' : (data.state === 'unavailable' ? 'Няма отговор' : 'Не работи'));
    state.classList.toggle('on', Boolean(data.running));
    const entries = (data.entries || []).slice(0, Number(log.dataset.limit));
    const rows = document.createDocumentFragment();
    for (const entry of entries) {
      const row = node('div', undefined, 'ecm-log-entry');
      const main = node('div');
      main.append(node('span', `${date(entry.time)}, Access criteria: `), node('code', entry.access_criteria),
        node('span', ', cw1: '), node('code', entry.cw1, 'cw-word'), node('span', ', cw2: '), node('code', entry.cw2, 'cw-word'));
      row.append(main, node('small', `${entry.address} · Channel ${entry.channel_id} / Stream ${entry.stream_id} / CP ${entry.cp_number}`));
      rows.append(row);
    }
    if (!entries.length) rows.append(node('p', 'Все още няма ECM заявки за този избор.', 'muted'));
    log.querySelector('[data-log-entries]').replaceChildren(rows);
    log.querySelector('[data-log-count]').textContent = `${entries.length} записа · най-новите първо`;
    log.querySelector('[data-retention]').textContent = String(data.retention_limit || 1000);
    if (data.error) throw new Error(data.error);
  };
  const schedule = delay => {
    clearTimeout(timer);
    if (!stopped && !paused && !authFailed && !document.hidden) timer = setTimeout(refresh, delay);
  };
  async function refresh() {
    if (stopped || paused || authFailed || document.hidden || controller) return;
    controller = new AbortController();
    let timedOut = false;
    const requestPeer = selectedPeer;
    const timeout = setTimeout(() => { timedOut = true; controller?.abort(); }, 5000);
    try {
      const url = new URL(log ? log.dataset.apiUrl : listing.dataset.statusUrl, location.origin);
      if (log) {
        if (requestPeer) url.searchParams.set('peer_id', requestPeer);
        url.searchParams.set('limit', log.dataset.limit);
      }
      const response = await fetch(url, {signal: controller.signal, credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) authFailed = true;
        throw new Error(authFailed ? 'Сесията е изтекла или нямаш достъп. ' : `Неуспешно обновяване (HTTP ${response.status}).`);
      }
      const data = await response.json();
      if (stopped || paused || document.hidden || requestPeer !== selectedPeer) return;
      if (log) renderLog(data); else renderListing(data);
      error.hidden = true;
    } catch (exc) {
      if (exc.name !== 'AbortError' || timedOut) {
        error.textContent = timedOut ? 'Няма отговор навреме. Повторен опит след малко.' : exc.message;
        if (authFailed) {
          const link = node('a', 'Влез отново.');
          link.href = root.dataset.loginUrl;
          error.append(link);
        }
        error.hidden = false;
        if (log) {
          const state = log.querySelector('[data-generator-state]');
          state.textContent = authFailed ? 'Нужен е вход' : 'Няма актуални данни';
          state.classList.remove('on');
        }
      }
    } finally {
      clearTimeout(timeout);
      controller = null;
      schedule(refreshSoon ? 0 : interval);
      refreshSoon = false;
    }
  }
  const resume = () => {
    if (controller) refreshSoon = true;
    else schedule(0);
  };
  document.addEventListener('visibilitychange', () => {
    clearTimeout(timer);
    if (document.hidden) controller?.abort(); else resume();
  });
  window.addEventListener('pagehide', () => { stopped = true; clearTimeout(timer); controller?.abort(); });
  window.addEventListener('pageshow', () => { stopped = false; resume(); });
  if (log) {
    const button = log.querySelector('[data-pause]');
    button.addEventListener('click', () => {
      paused = !paused;
      button.textContent = paused ? 'Продължи' : 'Пауза';
      button.setAttribute('aria-pressed', String(paused));
      if (paused) { clearTimeout(timer); controller?.abort(); } else resume();
    });
    log.querySelector('[data-peer-filter]').addEventListener('change', event => {
      selectedPeer = event.target.value;
      const url = new URL(location.href);
      if (selectedPeer) url.searchParams.set('peer_id', selectedPeer); else url.searchParams.delete('peer_id');
      history.replaceState(null, '', url);
      // Remove the previous peer's CWs immediately while the new request loads.
      log.querySelector('[data-log-entries]').replaceChildren(node('p', 'Зареждане…', 'muted'));
      controller?.abort();
      resume();
    });
  }
  schedule(0);
})();
