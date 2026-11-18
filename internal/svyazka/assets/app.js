'use strict';

// Wire colours of the sources: each source keeps its colour everywhere.
const COLORS = ['#d93025', '#1f6feb', '#2e9d57', '#e0a100', '#8e44ad', '#00897b', '#ef6c00', '#795548'];
const colorOf = (i) => COLORS[((i % COLORS.length) + COLORS.length) % COLORS.length];
const SVGNS = 'http://www.w3.org/2000/svg';

let S = null; // the last state from the server
let timer = 0;
let loginShown = false;
const ui = {
  keys: {},
  filter: 'all',
  query: '',
  showLink: false,
  adding: false,
  addDraft: null,
  addErr: '',
  editing: null,
  editDraft: null,
  editErr: '',
  rulesDirty: false,
  rulesErr: '',
  setDirty: false,
  setErr: '',
  pwErr: '',
  journalOpen: false,
  limit: 300,
};

const app = document.getElementById('app');
const $ = (sel, root = document) => root.querySelector(sel);

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'vars') for (const [n, x] of Object.entries(v)) el.style.setProperty(n, x);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (['value', 'checked', 'disabled', 'open', 'hidden', 'required', 'autofocus'].includes(k)) el[k] = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat(3)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}

function logo(size) {
  const el = svg('svg', { viewBox: '0 0 32 32', width: size, height: size, 'aria-hidden': 'true', class: 'logo' });
  const wires = [['M3 7c6 0 7 9 13 9', '#d93025'], ['M3 16h13', '#1f6feb'], ['M3 25c6 0 7-9 13-9', '#2e9d57']];
  for (const [d, c] of wires) el.append(svg('path', { d, stroke: c, 'stroke-width': 3, fill: 'none', 'stroke-linecap': 'round' }));
  el.append(svg('path', { d: 'M16 16h13', stroke: 'currentColor', 'stroke-width': 5, 'stroke-linecap': 'round' }));
  el.append(svg('rect', { x: 13, y: 10, width: 5, height: 12, rx: 1.5, fill: 'currentColor' }));
  return el;
}

function svg(tag, attrs) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  return el;
}

/* ---------- formatting ---------- */

function plural(n, one, few, many) {
  const a = Math.abs(n) % 100, b = a % 10;
  if (a > 10 && a < 20) return many;
  if (b === 1) return one;
  if (b >= 2 && b <= 4) return few;
  return many;
}
const count = (n, one, few, many) => `${n} ${plural(n, one, few, many)}`;
const servers = (n) => count(n, 'сервер', 'сервера', 'серверов');
const nf = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 });
function bytes(n) {
  const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${nf.format(n)} ${u[i]}`;
}
const dtf = new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
const dayf = new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'long' });
function ago(t) {
  if (!t) return '';
  const d = (new Date(S.now) - new Date(t)) / 1000;
  if (d < 60) return 'только что';
  if (d < 3600) return `${Math.floor(d / 60)} мин назад`;
  if (d < 86400) return `${Math.floor(d / 3600)} ч назад`;
  return dtf.format(new Date(t));
}
function usage(u) {
  if (!u) return '';
  let t = `трафик ${bytes(u.upload + u.download)}`;
  if (u.total) t += ` из ${bytes(u.total)}`;
  if (u.expire) t += `, до ${dayf.format(new Date(u.expire * 1000))}`;
  return t;
}
function appName(ua) {
  const known = [[/happ/i, 'Happ'], [/v2raytun/i, 'v2RayTun'], [/v2rayng/i, 'v2rayNG'], [/hiddify/i, 'Hiddify'],
    [/streisand/i, 'Streisand'], [/shadowrocket/i, 'Shadowrocket'], [/clash[.-]?meta|mihomo/i, 'mihomo'],
    [/clash/i, 'Clash'], [/sing-?box/i, 'sing-box'], [/neko/i, 'NekoBox'], [/karing/i, 'Karing'],
    [/mozilla/i, 'браузер'], [/curl|wget/i, 'curl']];
  for (const [re, name] of known) if (re.test(ua || '')) return name;
  return ua ? ua.split(/[/ ;(]/)[0] : 'без названия';
}
const sourceIndex = (id) => S.sources.findIndex((x) => x.id === id);
const sourceName = (id) => (S.sources.find((x) => x.id === id) || {}).name || '';
function why(reason) {
  if (reason === 'повтор') return 'повтор: такой же сервер уже есть выше';
  if (reason.startsWith('не сервер')) return 'служебная запись источника, а не сервер';
  if (reason.startsWith('по слову')) return 'скрыт ' + reason;
  return reason;
}

/* ---------- talking to the service ---------- */

async function api(method, path, body) {
  const opt = { method, credentials: 'same-origin', cache: 'no-store', headers: {} };
  if (method !== 'GET') {
    opt.headers['X-Sv'] = '1';
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body === undefined ? {} : body);
  }
  let res;
  try {
    res = await fetch('api/' + path, opt);
  } catch {
    throw new Error('нет связи со Связкой — проверьте интернет или сервер');
  }
  let data = null;
  try { data = await res.json(); } catch { /* not JSON */ }
  if (res.status === 401 && path !== 'login') {
    showLogin();
    throw new Error('нужно войти');
  }
  if (!res.ok) throw new Error((data && data.error) || `ошибка ${res.status}`);
  return data;
}

async function act(method, path, body, okText) {
  try {
    const v = await api(method, path, body);
    apply(v);
    if (okText) toast(typeof okText === 'function' ? okText(v) : okText);
    return true;
  } catch (e) {
    if (e.message !== 'нужно войти') toast(e.message, true);
    return false;
  }
}

function toast(text, bad) {
  const t = $('#toast');
  t.textContent = text;
  t.className = 'show' + (bad ? ' bad' : '');
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { t.className = bad ? 'bad' : ''; }, bad ? 6000 : 3000);
}

async function load() {
  try {
    apply(await api('GET', 'state'));
  } catch (e) {
    if (!loginShown && e.message !== 'нужно войти') toast(e.message, true);
  }
  schedule();
}

function schedule() {
  clearTimeout(timer);
  if (loginShown) return;
  const busy = S && S.sources.some((s) => s.fetching);
  timer = setTimeout(load, document.hidden ? 60000 : busy ? 1500 : 6000);
}

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && S && !loginShown) load();
});

/* ---------- login ---------- */

function showLogin(msg) {
  loginShown = true;
  clearTimeout(timer);
  const pw = h('input', { type: 'password', id: 'pw', autocomplete: 'current-password', required: true });
  app.replaceChildren(h('main', { class: 'login' },
    h('h1', null, logo(30), 'Связка'),
    h('form', { class: 'form', onsubmit: doLogin },
      h('label', { class: 'field' }, h('span', null, 'Пароль'), pw),
      h('div', { class: 'form-actions' }, h('button', { class: 'primary', type: 'submit' }, 'Войти'),
        msg ? h('span', { class: 'err', role: 'alert' }, msg) : null)),
    h('p', { class: 'hint' }, 'Пароль показал установщик. Если забыли, выполните на сервере ', h('code', null, 'svyazka passwd'), ' — он покажет новый.')));
  pw.focus();
}

async function doLogin(e) {
  e.preventDefault();
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  try {
    await api('POST', 'login', { password: $('#pw').value });
    loginShown = false;
    S = null;
    ui.keys = {};
    load();
  } catch (err) {
    showLogin(err.message);
  }
}

async function logout() {
  try { await api('POST', 'logout'); } catch { /* ignore */ }
  showLogin();
}

/* ---------- rendering ---------- */

function apply(v) {
  if (!v || !v.sources) return;
  const first = !S;
  S = v;
  if (first || !$('#hero')) shell();
  renderTop();
  renderHero();
  renderSources();
  renderServers();
  renderRules();
  renderSettings();
  renderJournal();
  $('#foot').textContent = `Связка ${S.version || ''}`;
}

function shell() {
  loginShown = false;
  ui.keys = {};
  app.replaceChildren(
    h('header', { class: 'top' },
      h('h1', null, logo(26), 'Связка'),
      h('div', { class: 'top-meta', id: 'top-meta' }),
      h('button', { class: 'quiet', onclick: logout }, 'Выйти')),
    h('section', { class: 'hero', id: 'hero', 'aria-label': 'Ссылка подписки' }),
    h('section', { class: 'block', id: 'sources' }),
    serversShell(),
    h('section', { class: 'block', id: 'rules' }),
    h('section', { class: 'block', id: 'settings' }),
    h('section', { class: 'block', id: 'journal' }),
    h('footer', { class: 'foot', id: 'foot' }));
}

// section re-renders a part of the page when its data changed, but never
// under the user's fingers: not while they type in it.
function section(id, key, build) {
  const el = document.getElementById(id);
  if (!el || ui.keys[id] === key) return;
  const a = document.activeElement;
  if (a && el.contains(a) && a.matches('input:not([type=checkbox]), textarea')) return;
  const fk = a && el.contains(a) && a.dataset ? a.dataset.fk : null;
  ui.keys[id] = key;
  el.replaceChildren(...[build()].flat(3).filter(Boolean));
  if (fk) {
    const again = el.querySelector(`[data-fk="${CSS.escape(fk)}"]`);
    if (again) again.focus();
  }
}

function minuteKey() { return Math.floor(new Date(S.now) / 60000); }

function renderTop() {
  const el = $('#top-meta');
  const c = S.cert;
  el.className = 'top-meta';
  if (!c) el.textContent = 'без HTTPS: режим проверки';
  else if (c.self_signed) { el.textContent = 'сертификат пока временный'; el.className = 'top-meta warn'; }
  else el.textContent = `${S.ip} · сертификат до ${dtf.format(new Date(c.not_after))}`;
}

/* hero */

function feedsOf() {
  return S.sources.map((s, i) => ({
    name: s.name, color: colorOf(i), served: s.served, enabled: s.enabled,
    bad: s.enabled && !!s.err && !s.count, loading: s.enabled && s.fetching && !s.count && !s.err,
  }));
}

function renderHero() {
  const feeds = feedsOf();
  const key = JSON.stringify([feeds, S.sub_url, ui.showLink, S.served, S.servers.length, S.userinfo,
    S.hits.slice(0, 4).map((x) => [x.ua, x.at]), minuteKey()]);
  section('hero', key, () => {
    if (!S.sources.length) {
      return h('div', { class: 'hero-empty' },
        h('h2', null, 'Соберите подписки в одну ссылку'),
        h('p', { class: 'hint' }, 'Добавьте ссылки на подписки, которые нужно объединить. Связка будет сама скачивать их, переименовывать и скрывать серверы по вашим правилам и отдавать одну ссылку для Лазейки и телефона.'),
        h('button', { class: 'primary', onclick: () => { ui.adding = true; ui.keys.sources = null; renderSources(); setTimeout(() => $('#add-url')?.focus(), 0); } }, 'Добавить источник'));
    }
    const list = h('ul', { class: 'feeds' }, feeds.map((f) => h('li', {
      class: 'feed' + (f.enabled ? '' : ' off') + (f.bad ? ' bad' : ''), vars: { '--c': f.color },
    }, h('span', { class: 'feed-name', title: f.name }, f.name),
    h('span', { class: 'feed-n' }, !f.enabled ? 'выкл.' : f.bad ? 'нет связи' : f.loading ? '…' : String(f.served)))));
    const wires = svg('svg', { class: 'braid', 'aria-hidden': 'true', focusable: 'false' });
    const grid = h('div', { class: 'hero-grid' }, list, wires, h('div', { class: 'outlet' }, linkBox(), stats(), hits()));
    grid._feeds = feeds;
    requestAnimationFrame(() => drawWires(grid));
    return grid;
  });
}

// drawWires: each source's wire runs from its row to a zip tie and then the
// wires twist together into the link.
function drawWires(grid) {
  const box = grid.querySelector('.braid');
  if (!box || !box.isConnected) return;
  const feeds = grid._feeds || [];
  const r = box.getBoundingClientRect();
  const W = Math.max(r.width, 1), H = Math.max(r.height, 1);
  box.setAttribute('viewBox', `0 0 ${W} ${H}`);
  box.replaceChildren();
  const n = feeds.length;
  if (!n) return;
  const narrow = H < 50;
  const link = grid.querySelector('.link').getBoundingClientRect();
  const midY = narrow ? H / 2 : Math.min(Math.max(link.top + link.height / 2 - r.top, 10), H - 10);
  const rows = [...grid.querySelectorAll('.feed')].map((li) => {
    const b = li.getBoundingClientRect();
    return b.top + b.height / 2 - r.top;
  });
  const knot = narrow ? 16 : Math.min(Math.max(W * 0.42, 34), 120);
  const amp = n > 1 ? Math.min(2 + n * 0.7, 5) : 0;
  const wave = 30;
  const live = (f) => f.enabled && !f.bad;
  feeds.forEach((f, k) => {
    const phase = (k / n) * Math.PI * 2;
    const yTie = midY + amp * Math.sin(phase);
    let d = '';
    if (!narrow) {
      const y0 = rows[k] ?? midY;
      d = `M0 ${y0.toFixed(1)} C${(knot * 0.6).toFixed(1)} ${y0.toFixed(1)} ${(knot * 0.4).toFixed(1)} ${yTie.toFixed(1)} ${knot} ${yTie.toFixed(1)}`;
    } else {
      d = `M0 ${yTie.toFixed(1)} L${knot} ${yTie.toFixed(1)}`;
    }
    for (let x = knot + 3; x <= W + 0.5; x += 3) {
      const y = midY + amp * Math.sin(((x - knot) / wave) * Math.PI * 2 + phase);
      d += ` L${x.toFixed(1)} ${y.toFixed(1)}`;
    }
    const p = svg('path', {
      d, fill: 'none', stroke: live(f) ? f.color : 'currentColor',
      'stroke-width': live(f) ? 2.6 : 1.6, 'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    });
    if (!live(f)) { p.setAttribute('stroke-dasharray', '3 5'); p.setAttribute('opacity', '0.45'); }
    box.append(p);
  });
  // the zip tie
  const tieH = amp * 2 + 14;
  box.append(svg('rect', { x: knot - 5, y: midY - tieH / 2, width: 10, height: tieH, rx: 2.5, class: 'tie' }));
  box.append(svg('rect', { x: knot - 7, y: midY + tieH / 2 - 6, width: 14, height: 8, rx: 2, class: 'tie' }));
  for (const t of box.querySelectorAll('.tie')) t.setAttribute('fill', getComputedStyle(document.body).color);
  box.style.color = getComputedStyle(document.body).color;
}

let resizeT = 0;
window.addEventListener('resize', () => {
  clearTimeout(resizeT);
  resizeT = setTimeout(() => { const g = $('.hero-grid'); if (g) drawWires(g); }, 80);
});

function maskedLink() {
  const i = S.sub_url.indexOf('/s/');
  return i < 0 ? S.sub_url : S.sub_url.slice(0, i + 3) + '•'.repeat(12);
}

function linkBox() {
  return h('div', { class: 'linkbox' },
    h('div', { class: 'link-label' }, 'Ссылка для приложений'),
    h('code', { class: 'link', id: 'sub-link' }, ui.showLink ? S.sub_url : maskedLink()),
    h('div', { class: 'link-actions' },
      h('button', { class: 'primary', onclick: copyLink }, 'Копировать'),
      h('button', { onclick: showQR }, 'QR-код'),
      h('button', { class: 'quiet', onclick: () => { ui.showLink = !ui.showLink; renderHero(); } },
        ui.showLink ? 'Спрятать' : 'Показать')));
}

function stats() {
  const total = S.servers.length;
  if (!total) {
    const loading = S.sources.some((s) => s.fetching);
    return h('p', { class: 'stats' }, loading ? 'Загружаю источники…' : 'Серверов пока нет: источники не загрузились. Подробности — в списке источников ниже.');
  }
  let text = `Отдаётся ${servers(S.served)} из ${total}.`;
  if (S.userinfo) text += ` ${usage(S.userinfo).replace(/^т/, 'Т')}.`;
  return h('p', { class: 'stats' }, text);
}

function hits() {
  if (!S.hits.length) return h('p', { class: 'hits' }, 'Ссылку ещё не загружало ни одно приложение.');
  return h('p', { class: 'hits' }, 'Загружали: ', S.hits.slice(0, 4).map((x, i) => [i ? ', ' : '',
    h('span', { title: `${x.ua || 'без User-Agent'}, ${x.ip}, ${count(x.count, 'раз', 'раза', 'раз')}` }, appName(x.ua)), ' ', ago(x.at)]));
}

async function copyLink() {
  try {
    await navigator.clipboard.writeText(S.sub_url);
  } catch {
    const t = h('textarea', { value: S.sub_url });
    document.body.append(t);
    t.select();
    document.execCommand('copy');
    t.remove();
  }
  toast('Ссылка скопирована');
}

function showQR() {
  const d = h('dialog', { class: 'qr', 'aria-label': 'QR-код ссылки подписки' },
    h('img', { src: 'api/qr?' + Date.now(), alt: 'QR-код ссылки подписки', width: 300, height: 300 }),
    h('p', null, 'В приложении на телефоне выберите добавление подписки по QR-коду и наведите камеру: так умеют Happ, v2rayNG, Hiddify, Streisand.'),
    h('form', { method: 'dialog', class: 'form-actions' }, h('button', { class: 'primary' }, 'Закрыть')));
  document.body.append(d);
  d.addEventListener('close', () => d.remove());
  d.showModal();
}

/* sources */

function renderSources() {
  const key = JSON.stringify([S.sources, minuteKey(), ui.adding, ui.addErr, ui.editing, ui.editErr]);
  section('sources', key, () => [
    h('div', { class: 'block-head' }, h('h2', null, 'Источники'),
      S.sources.length ? h('button', { onclick: () => refresh(''), disabled: !S.sources.some((s) => s.enabled) }, 'Обновить все') : null,
      h('button', { class: ui.adding ? 'quiet' : 'primary', onclick: toggleAdd }, ui.adding ? 'Отмена' : 'Добавить источник')),
    S.sources.length > 1 ? h('p', { class: 'hint' }, 'Порядок важен: если один и тот же сервер есть в двух источниках, остаётся тот, что выше.') : null,
    ui.adding ? addForm() : null,
    S.sources.length ? h('ul', { class: 'rows' }, S.sources.map((s, i) => (ui.editing === s.id ? editForm(s, i) : sourceRow(s, i)))) : null,
  ]);
}

function toggleAdd() {
  ui.adding = !ui.adding;
  ui.addErr = '';
  if (!ui.adding) ui.addDraft = null;
  ui.keys.sources = null;
  renderSources();
  if (ui.adding) setTimeout(() => $('#add-url')?.focus(), 0);
}

function sourceRow(s, i) {
  const st = [];
  if (!s.enabled) st.push('выключен');
  else if (s.fetching && !s.fetched_at) st.push('загружается…');
  else {
    if (s.fetched_at) st.push(`${servers(s.count)}, в подписке ${s.served}`, `обновлён ${ago(s.fetched_at)}`);
    if (s.fetching) st.push('обновляется…');
  }
  return h('li', { class: 'row src' + (s.enabled ? '' : ' off'), vars: { '--c': colorOf(i) } },
    h('div', { class: 'src-main' },
      h('div', { class: 'src-title' }, h('strong', null, s.name), h('span', { class: 'muted' }, s.host)),
      st.length ? h('div', { class: 'muted' }, st.join('; ')) : null,
      s.userinfo ? h('div', { class: 'muted' }, usage(s.userinfo).replace(/^т/, 'Т')) : null,
      s.err && s.enabled ? h('div', { class: 'err' }, s.err + (s.count ? `. В подписке пока прошлая копия от ${dtf.format(new Date(s.fetched_at))}.` : '')) : null),
    h('div', { class: 'src-actions' },
      h('label', { class: 'switch' }, h('input', {
        type: 'checkbox', checked: s.enabled, 'data-fk': `on-${s.id}`, vars: { '--c': colorOf(i) },
        onchange: (e) => act('PATCH', 'sources/' + s.id, { enabled: e.target.checked }),
      }), 'включён'),
      h('button', { class: 'quiet', disabled: !s.enabled || s.fetching, 'data-fk': `rf-${s.id}`, onclick: () => refresh(s.id) }, 'Обновить'),
      h('button', { class: 'quiet', onclick: () => startEdit(s) }, 'Изменить'),
      i > 0 ? h('button', { class: 'quiet', title: 'Поднять выше', 'aria-label': `Поднять «${s.name}» выше`, 'data-fk': `up-${s.id}`, onclick: () => act('PATCH', 'sources/' + s.id, { move: -1 }) }, '↑') : null,
      i < S.sources.length - 1 ? h('button', { class: 'quiet', title: 'Опустить ниже', 'aria-label': `Опустить «${s.name}» ниже`, 'data-fk': `dn-${s.id}`, onclick: () => act('PATCH', 'sources/' + s.id, { move: 1 }) }, '↓') : null,
      h('button', { class: 'quiet danger', onclick: () => removeSource(s) }, 'Удалить')));
}

function refresh(id) {
  act('POST', 'refresh', { id }, id ? null : 'Обновляю все источники');
}

function removeSource(s) {
  if (!confirm(`Удалить источник «${s.name}»? Его серверы пропадут из подписки.`)) return;
  act('DELETE', 'sources/' + s.id, undefined, 'Источник удалён');
}

function bound(draft, name, attrs) {
  return h('input', Object.assign({ value: draft[name] || '', oninput: (e) => { draft[name] = e.target.value; } }, attrs));
}

function field(label, control, note) {
  return h('label', { class: 'field' }, h('span', null, label), control, note ? h('small', null, note) : null);
}

function randomHWID() {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return 'svyazka-' + [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function moreFields(d) {
  return h('details', { class: 'more', open: !!(d.prefix || d.user_agent || d.hwid) },
    h('summary', null, 'Дополнительно'),
    h('div', { class: 'form' },
      field('Приставка к именам', bound(d, 'prefix', { placeholder: 'например: 🅰 ', maxlength: 30 }),
        'Ставится перед именем каждого сервера из этого источника.'),
      field('User-Agent', bound(d, 'user_agent', { placeholder: 'v2rayNG/1.10.5', spellcheck: 'false' }),
        'Как Связка представляется источнику. Менять, только если он отдаёт не ссылки, а настройки Clash или sing-box.'),
      field('HWID', h('span', { class: 'unit' }, bound(d, 'hwid', { spellcheck: 'false', id: 'hwid-' + (d.id || 'new') }),
        h('button', { type: 'button', onclick: () => { d.hwid = randomHWID(); $('#hwid-' + (d.id || 'new')).value = d.hwid; } }, 'Создать')),
      'Нужен, если источник ограничивает число устройств: Связка будет для него одним устройством.')));
}

function addForm() {
  const d = (ui.addDraft ||= { url: '', name: '', prefix: '', user_agent: '', hwid: '' });
  return h('div', { class: 'addbox' }, h('form', { class: 'form', onsubmit: submitAdd },
    field('Ссылка на подписку', bound(d, 'url', { id: 'add-url', type: 'url', required: true, placeholder: 'https://…', autocomplete: 'off', spellcheck: 'false' })),
    field('Название', bound(d, 'name', { placeholder: 'необязательно, например: Основная', maxlength: 60 })),
    moreFields(d),
    h('div', { class: 'form-actions' }, h('button', { class: 'primary', type: 'submit' }, 'Добавить'),
      ui.addErr ? h('span', { class: 'err', role: 'alert' }, ui.addErr) : null)));
}

async function submitAdd(e) {
  e.preventDefault();
  const d = ui.addDraft;
  try {
    const v = await api('POST', 'sources', d);
    ui.adding = false;
    ui.addDraft = null;
    ui.addErr = '';
    apply(v);
    toast('Источник добавлен, загружаю');
  } catch (err) {
    ui.addErr = err.message;
    ui.keys.sources = null;
    renderSources();
  }
}

function startEdit(s) {
  ui.editing = s.id;
  ui.editErr = '';
  ui.editDraft = { id: s.id, name: s.name, url: s.url, prefix: s.prefix, user_agent: s.user_agent, hwid: s.hwid };
  ui.keys.sources = null;
  renderSources();
}

function editForm(s, i) {
  const d = ui.editDraft;
  return h('li', { class: 'row src-edit', vars: { '--c': colorOf(i) } }, h('form', { class: 'form', onsubmit: submitEdit },
    field('Название', bound(d, 'name', { maxlength: 60, required: true })),
    field('Ссылка на подписку', bound(d, 'url', { type: 'url', required: true, spellcheck: 'false', autocomplete: 'off' })),
    moreFields(d),
    h('div', { class: 'form-actions' },
      h('button', { class: 'primary', type: 'submit' }, 'Сохранить'),
      h('button', { type: 'button', class: 'quiet', onclick: () => { ui.editing = null; ui.keys.sources = null; renderSources(); } }, 'Отмена'),
      ui.editErr ? h('span', { class: 'err', role: 'alert' }, ui.editErr) : null)));
}

async function submitEdit(e) {
  e.preventDefault();
  const d = ui.editDraft;
  try {
    const v = await api('PATCH', 'sources/' + d.id, { name: d.name, url: d.url, prefix: d.prefix, user_agent: d.user_agent, hwid: d.hwid });
    ui.editing = null;
    ui.editDraft = null;
    apply(v);
    toast('Источник сохранён');
  } catch (err) {
    ui.editErr = err.message;
    ui.keys.sources = null;
    renderSources();
  }
}

/* servers */

function serversShell() {
  return h('section', { class: 'block', id: 'servers-block' },
    h('div', { class: 'block-head' }, h('h2', null, 'Серверы'), h('div', { class: 'filters', id: 'filters', role: 'group', 'aria-label': 'Какие серверы показать' })),
    h('p', { class: 'hint' }, 'Галочка — сервер попадает в подписку. Снимите её, чтобы скрыть сервер: он останется скрытым и после обновления источника.'),
    h('div', { class: 'searchbar' },
      h('input', { type: 'search', id: 'q', value: ui.query, placeholder: 'Найти по имени, адресу, протоколу или источнику', 'aria-label': 'Поиск серверов',
        oninput: (e) => { ui.query = e.target.value; ui.limit = 300; renderServers(); } }),
      h('div', { class: 'bulk', id: 'bulk' })),
    h('div', { id: 'serverlist' }));
}

function matches(s, q) {
  if (!q) return true;
  const hay = [s.name, s.original, s.host, s.kind, sourceName(s.source)].join('\n').toLowerCase();
  return q.toLowerCase().split(/\s+/).filter(Boolean).every((w) => hay.includes(w));
}

function renderServers() {
  const all = S.servers;
  const served = all.filter((s) => !s.hidden).length;
  const filters = [['all', 'Все', all.length], ['served', 'В подписке', served], ['hidden', 'Скрытые', all.length - served]];
  section('filters', JSON.stringify([filters, ui.filter]), () => filters.map(([id, label, n]) => h('button', {
    'aria-pressed': ui.filter === id ? 'true' : 'false', 'data-fk': 'f-' + id,
    onclick: () => { ui.filter = id; ui.limit = 300; renderServers(); },
  }, `${label} ${n}`)));

  const shown = all.filter((s) => (ui.filter === 'all' || (ui.filter === 'served') === !s.hidden) && matches(s, ui.query));
  const canHide = shown.filter((s) => !s.hidden).map((s) => s.key);
  const canShow = shown.filter((s) => s.hidden === 'скрыт вручную').map((s) => s.key);
  section('bulk', JSON.stringify([ui.query, canHide, canShow]), () => (ui.query.trim() ? [
    canHide.length ? h('button', { onclick: () => setHidden(canHide, true, `Скрыто: ${canHide.length}`) }, `Скрыть найденные (${canHide.length})`) : null,
    canShow.length ? h('button', { onclick: () => setHidden(canShow, false, `Возвращено: ${canShow.length}`) }, `Вернуть найденные (${canShow.length})`) : null,
  ] : []));

  const names = S.sources.map((x) => [x.id, x.name]);
  section('serverlist', JSON.stringify([shown, names, ui.limit]), () => {
    if (!all.length) return h('div', { class: 'rows' }, h('p', { class: 'empty' }, 'Серверы появятся, когда загрузится хотя бы один источник.'));
    if (!shown.length) return h('div', { class: 'rows' }, h('p', { class: 'empty' }, 'Ничего не нашлось.'));
    const seen = {};
    const rows = shown.slice(0, ui.limit).map((s) => serverRow(s, seen));
    if (shown.length > ui.limit) {
      rows.push(h('li', { class: 'row srv-more' }, h('button', { onclick: () => { ui.limit += 500; renderServers(); } }, `Показать ещё ${Math.min(500, shown.length - ui.limit)}`)));
    }
    return h('ul', { class: 'rows' }, rows);
  });
}

function serverRow(s, seen) {
  const n = (seen[s.key] = (seen[s.key] || 0) + 1);
  const id = `sv-${s.key}-${n}`;
  const manual = s.hidden === 'скрыт вручную';
  const forced = !!s.hidden && !manual;
  return h('li', { class: 'row srv' + (s.hidden ? ' hidden' : ''), vars: { '--c': colorOf(sourceIndex(s.source)) } },
    h('input', {
      type: 'checkbox', id, checked: !s.hidden, disabled: forced, 'data-fk': id,
      'aria-describedby': forced ? id + '-why' : null,
      onchange: (e) => setHidden([s.key], !e.target.checked),
    }),
    h('label', { class: 'srv-main', for: id },
      h('span', { class: 'srv-name' }, s.name),
      s.renamed ? h('span', { class: 'srv-was muted' }, 'в источнике: ' + s.original) : null,
      forced ? h('span', { class: 'srv-why', id: id + '-why' }, why(s.hidden)) : null),
    h('span', { class: 'srv-meta' },
      h('span', { class: 'srv-kind muted' }, s.kind),
      h('span', { class: 'srv-src muted', title: `${s.host}:${s.port}` }, sourceName(s.source))));
}

function setHidden(keys, hidden, okText) {
  act('POST', 'hidden', { keys, hidden }, okText);
}

/* names and filters */

function renderRules() {
  if (ui.rulesDirty) return;
  section('rules', JSON.stringify([S.rename_text, S.hide_text, ui.rulesErr]), () => [
    h('div', { class: 'block-head' }, h('h2', null, 'Имена и фильтры')),
    h('div', { class: 'cols' },
      h('div', { class: 'col' },
        h('label', { class: 'lbl', for: 'rn' }, 'Переименование'),
        h('textarea', { id: 'rn', rows: 9, spellcheck: 'false', value: S.rename_text, oninput: rulesEdited,
          placeholder: 'Netherlands → Нидерланды\nGermany → Германия\n[Premium] →\n/^\\d+\\. / →' }),
        h('p', { class: 'hint' }, 'Одно правило в строке: что → на что. Пустая правая часть удаляет текст, регистр букв не важен. Пробелы по краям сохраняются в кавычках: " | " → ", ". Текст в /косых/ — регулярное выражение, в замене можно $1. Правила применяются сверху вниз.')),
      h('div', { class: 'col' },
        h('label', { class: 'lbl', for: 'hw' }, 'Скрывать серверы, в имени которых есть'),
        h('textarea', { id: 'hw', rows: 9, spellcheck: 'false', value: S.hide_text, oninput: rulesEdited }),
        h('p', { class: 'hint' }, 'Слова через запятую или с новой строки. Ищутся и в исходном имени, и в новом. Короткие латинские слова (RU, NL) ищутся целиком: RU не скроет Peru.'))),
    h('div', { class: 'form-actions' },
      h('button', { class: 'primary', onclick: saveRules }, 'Сохранить имена и фильтры'),
      h('button', { class: 'quiet', id: 'rules-undo', hidden: true, onclick: undoRules }, 'Отменить правки'),
      ui.rulesErr ? h('span', { class: 'err', role: 'alert' }, ui.rulesErr) : null),
  ]);
}

function rulesEdited() {
  ui.rulesDirty = true;
  const u = $('#rules-undo');
  if (u) u.hidden = false;
}

function undoRules() {
  ui.rulesDirty = false;
  ui.rulesErr = '';
  ui.keys.rules = null;
  renderRules();
}

async function saveRules() {
  try {
    const v = await api('PUT', 'rules', { rename: $('#rn').value, hide: $('#hw').value });
    ui.rulesDirty = false;
    ui.rulesErr = '';
    ui.keys.rules = null;
    apply(v);
    const renamed = v.servers.filter((s) => s.renamed).length;
    const hidden = v.servers.filter((s) => s.hidden).length;
    toast(`Сохранено: переименовано ${renamed}, скрыто ${hidden}`);
  } catch (err) {
    ui.rulesErr = err.message;
    const box = $('#rules .form-actions');
    box.querySelector('.err')?.remove();
    box.append(h('span', { class: 'err', role: 'alert' }, err.message));
  }
}

/* settings */

function renderSettings() {
  if (ui.setDirty) return;
  const certKey = S.cert ? [S.cert.self_signed, S.cert.error, S.cert.not_after] : null;
  section('settings', JSON.stringify([S.title, S.update_hours, S.refresh_min, certKey, S.ip]), () => [
    h('div', { class: 'block-head' }, h('h2', null, 'Настройки')),
    certBlock(),
    h('form', { class: 'panel', onsubmit: saveSettings, oninput: () => { ui.setDirty = true; } },
      h('div', { class: 'settings-grid' },
        field('Название подписки в приложениях', h('input', { name: 'title', value: S.title, maxlength: 60, required: true })),
        field('Приложения обновляют подписку раз в', h('span', { class: 'unit' }, h('input', { name: 'update_hours', type: 'number', min: 1, max: 168, value: S.update_hours, required: true }), 'ч')),
        field('Связка проверяет источники раз в', h('span', { class: 'unit' }, h('input', { name: 'refresh_min', type: 'number', min: 10, max: 1440, value: S.refresh_min, required: true }), 'мин'))),
      h('div', { class: 'form-actions' }, h('button', { class: 'primary', type: 'submit' }, 'Сохранить настройки'))),
    h('form', { class: 'panel', onsubmit: changePassword },
      h('h3', null, 'Пароль панели'),
      h('div', { class: 'pw-grid' },
        field('Текущий пароль', h('input', { type: 'password', name: 'old', autocomplete: 'current-password', required: true })),
        field('Новый пароль', h('input', { type: 'password', name: 'new', autocomplete: 'new-password', minlength: 8, required: true }), 'Не короче 8 символов. Другие устройства придётся заново войти.')),
      h('div', { class: 'form-actions' }, h('button', { type: 'submit' }, 'Сменить пароль'))),
    h('div', { class: 'panel danger-zone' },
      h('div', null, h('h3', null, 'Новая ссылка подписки'),
        h('p', { class: 'hint' }, 'Если ссылка попала к посторонним. Старая сразу перестанет работать, новую нужно будет заново добавить во все приложения.')),
      h('button', { class: 'danger', onclick: rotateLink }, 'Заменить ссылку')),
  ]);
}

function certBlock() {
  const c = S.cert;
  if (!c) return h('div', { class: 'panel cert' }, h('h3', null, 'Без HTTPS'), h('p', { class: 'hint' }, 'Служба запущена в режиме проверки, сертификат не используется.'));
  if (c.self_signed) {
    return h('div', { class: 'cert warn', role: 'status' },
      h('h3', null, 'Сертификат пока временный'),
      h('p', null, `Let's Encrypt ещё не выдал сертификат для ${S.ip}. До этого браузер предупреждает о небезопасном подключении, а приложения не примут ссылку.`),
      c.error ? h('p', { class: 'err' }, 'Последняя попытка: ' + c.error) : h('p', { class: 'hint' }, 'Связка пробует получить его сама.'),
      h('p', { class: 'hint' }, `Для проверки Let's Encrypt заходит на http://${S.ip} — порт 80 должен быть открыт в файрволе сервера и в панели хостера.`),
      h('button', { onclick: () => act('POST', 'cert', {}, 'Пробую получить сертификат') }, 'Попробовать сейчас'));
  }
  return h('div', { class: 'panel cert' }, h('h3', null, "Сертификат Let's Encrypt"),
    h('p', { class: 'hint' }, `Выписан на ${S.ip}, действует до ${dtf.format(new Date(c.not_after))}. Такие сертификаты живут неделю, Связка продлевает их сама.`),
    c.error ? h('p', { class: 'err' }, 'Последнее продление не удалось: ' + c.error) : null);
}

async function saveSettings(e) {
  e.preventDefault();
  const f = e.target;
  try {
    const v = await api('PUT', 'settings', { title: f.title.value, update_hours: +f.update_hours.value, refresh_min: +f.refresh_min.value });
    ui.setDirty = false;
    ui.keys.settings = null;
    apply(v);
    toast('Настройки сохранены');
  } catch (err) {
    toast(err.message, true);
  }
}

async function changePassword(e) {
  e.preventDefault();
  const f = e.target;
  try {
    const v = await api('POST', 'password', { old: f.old.value, new: f.new.value });
    f.reset();
    apply(v);
    toast('Пароль изменён');
  } catch (err) {
    toast(err.message, true);
  }
}

function rotateLink() {
  if (!confirm('Заменить ссылку подписки? Старая перестанет работать во всех приложениях сразу.')) return;
  act('POST', 'rotate', {}, 'Ссылка заменена — добавьте новую в приложения');
}

/* journal */

function renderJournal() {
  const ev = S.events.slice(0, 60);
  section('journal', JSON.stringify([ev.map((e) => [e.at, e.text]), ui.journalOpen]), () => h('details', {
    class: 'journal', open: ui.journalOpen, ontoggle: (e) => { ui.journalOpen = e.target.open; },
  }, h('summary', null, 'Журнал'),
  ev.length ? h('ol', { class: 'events' }, ev.map((e) => h('li', { class: e.bad ? 'bad' : '' },
    h('time', { datetime: e.at }, dtf.format(new Date(e.at))), e.text)))
    : h('p', { class: 'hint' }, 'Пока пусто.')));
}

load();
