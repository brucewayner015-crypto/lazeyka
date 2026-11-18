'use strict';

/* ---------- helpers ---------------------------------------------------------- */

const $ = (sel, root = document) => root.querySelector(sel);

// Android: the same UI on a phone; zapret's job is done by ByeDPI there and
// Windows-only parts are hidden. tx() adapts texts.
let ANDROID = false;
const TX = [[/zapret/g, 'ByeDPI'], [/компьютере/g, 'телефоне'], [/компьютера/g, 'телефона'], [/компьютер/g, 'телефон'],
  [/в трее/g, 'в уведомлении'], [/Скачать отчёт/g, 'Сохранить отчёт']];
function tx(v) {
  if (!ANDROID || typeof v !== 'string') return v;
  for (const [re, to] of TX) v = v.replace(re, to);
  return v;
}
function setPlatform(st) {
  if (ANDROID || st.platform !== 'android') return;
  ANDROID = true;
  document.body.classList.add('android');
  for (const q of QUICK) for (const o of q.opts) if (o[2] === 'zapret') o[0] = 'ByeDPI';
  document.querySelectorAll('.nav').forEach(b => { b.textContent = tx(b.textContent); });
  const n = document.querySelector('.nav[data-tab="zapret"]');
  if (n) n.textContent = 'Обход DPI';
}

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else if (k === 'text') el.textContent = tx(v);
    else if (k === 'title' || k === 'aria-label' || k === 'placeholder') el.setAttribute(k, tx(v));
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(tx(String(c))));
  }
  return el;
}

// put replaces el's children, skipping null/false/undefined (which the DOM
// would otherwise print as the text "null").
function put(el, ...kids) {
  el.replaceChildren(...kids.flat(Infinity).filter(k => k !== null && k !== undefined && k !== false));
  return el;
}

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Lz': '1' },
    body: JSON.stringify(body),
  };
  let r;
  try {
    r = await fetch('/api/' + path, opt);
  } catch (e) {
    throw new Error('Лазейка не отвечает — возможно, приложение закрыто');
  }
  let data = null;
  try { data = await r.json(); } catch (e) { /* not json */ }
  if (!r.ok) throw new Error((data && data.error) || ('Ошибка ' + r.status));
  return data;
}

let toastTimer;
function toast(msg, isErr) {
  const t = $('#toast');
  t.textContent = tx(msg);
  t.className = 'toast' + (isErr ? ' err' : '');
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, isErr ? 7000 : 3500);
}

async function act(fn, okMsg) {
  try {
    const r = await fn();
    if (okMsg) toast(okMsg);
    return r;
  } catch (e) {
    toast(e.message, true);
    e.shown = true; // stops the caller; already reported to the user
    throw e;
  }
}
window.addEventListener('unhandledrejection', ev => {
  if (ev.reason && ev.reason.shown) ev.preventDefault();
});

function fmtSpeed(n) {
  if (!n || n < 1024) return '0 КБ/с';
  if (n < 1024 * 1024) return Math.round(n / 1024) + ' КБ/с';
  return (n / 1048576).toFixed(1).replace('.', ',') + ' МБ/с';
}
function fmtBytes(n) {
  if (!n) return '0';
  if (n < 1073741824) return (n / 1048576).toFixed(0) + ' МБ';
  return (n / 1073741824).toFixed(1).replace('.', ',') + ' ГБ';
}
// A server mihomo has not checked yet has no delay but is not dead: alive
// turns false only after a failed check. For a dead server the core says
// why, after connecting to it directly: "недоступен" (no connection from
// this network), "блокируется" (TLS cut: DPI), "нет ответа" (the server is
// there, the VPN through it fails).
function deadText(n) { return (n && n.reach_text) || 'нет ответа'; }
function deadTitle(n) { return (n && n.reach_note) || 'Проверка через сервер не прошла'; }
function delayEl(d, alive, n) {
  if (!d && alive === false) return h('span', { class: 'delay dead', title: deadTitle(n) }, deadText(n));
  if (!d) return h('span', { class: 'delay', title: 'Ещё не проверялся' }, '—');
  const cls = d < 300 ? 'good' : d < 800 ? 'slow' : 'dead';
  return h('span', { class: 'delay ' + cls }, d + ' мс');
}
function ago(iso) {
  if (!iso) return 'ещё не обновлялась';
  const t = new Date(iso).getTime();
  if (!t || t < 86400000) return 'ещё не обновлялась';
  const m = Math.round((Date.now() - t) / 60000);
  if (m < 1) return 'обновлена только что';
  if (m < 60) return 'обновлена ' + m + ' мин назад';
  const hrs = Math.round(m / 60);
  if (hrs < 48) return 'обновлена ' + hrs + ' ч назад';
  return 'обновлена ' + new Date(t).toLocaleDateString('ru-RU');
}
function plural(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20)) return few;
  return many;
}
function lines(arr) { return (arr || []).join('\n'); }
// first sentence of a long message, for narrow places
function brief(s) {
  if (!s) return '';
  const cut = s.split(/\n|\. /)[0];
  return cut.length > 110 ? cut.slice(0, 108) + '…' : cut;
}
// text with clickable https links (they open in the regular browser)
function linkify(s) {
  return String(s || '').split(/(https:\/\/[^\s«»"]+)/).map((part, i) =>
    i % 2 ? h('a', { href: part, target: '_blank', rel: 'noopener' }, part) : part);
}
function unlines(text) { return text.split('\n').map(s => s.trim()).filter(Boolean); }

/* ---------- state ------------------------------------------------------------ */

const S = {
  tab: 'home',
  status: null,
  settings: null,
  groups: null,
  nodes: null,
  logSince: 0,
  logs: [],
  logFilter: '',
  logErrors: false,
  homeSig: '',
  jobsSeen: {},
  qpSig: '',
  strats: null,   // zapret strategies, the ones that worked first
  stratsAt: 0,
  exit: null,     // country of the blocked-sites exit
  exitAt: 0,
};

const QUICK = [
  { g: 'YOUTUBE', name: 'YouTube', hint: 'видео и сайт', field: 'youtube',
    opts: [['DIRECT', 'Через zapret', 'zapret'], ['AUTO', 'Через сервер', 'vpn']] },
  { g: 'DISCORD', name: 'Discord', hint: 'чаты и голос', field: 'discord',
    opts: [['DIRECT', 'Через zapret', 'zapret'], ['VOICE', 'Через сервер', 'vpn']] },
  { g: 'MESSENGERS', name: 'Telegram и WhatsApp', hint: 'сообщения и звонки', field: 'messengers',
    opts: [['VOICE', 'Через сервер', 'vpn'], ['DIRECT', 'Напрямую', 'direct']] },
  { g: 'AI', name: 'ИИ-сервисы', hint: 'ChatGPT, Claude, Gemini', field: 'ai',
    opts: [['OWN', 'Только свои серверы', 'own'], ['AUTO', 'Любой сервер', 'vpn']] },
  { g: 'OTHER', name: 'Всё остальное', hint: 'что не попало в списки', field: 'other',
    opts: [['DIRECT', 'Напрямую', 'direct'], ['AUTO', 'Через сервер', 'vpn']] },
];

/* ---------- navigation ------------------------------------------------------- */

const RENDER = {};

function showTab(tab) {
  S.tab = tab;
  document.querySelectorAll('.nav').forEach(b => {
    if (b.dataset.tab === tab) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });
  document.querySelectorAll('.tab').forEach(s => { s.hidden = s.id !== 'tab-' + tab; });
  S.homeSig = '';
  RENDER[tab] && RENDER[tab]();
}

document.querySelectorAll('.nav').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));

/* ---------- jobs bar & footer ------------------------------------------------- */

function renderJobs() {
  const box = $('#jobs');
  const jobs = (S.status && S.status.jobs) || {};
  const now = Date.now();
  const items = [];
  for (const [id, j] of Object.entries(jobs)) {
    const fin = j.finished ? new Date(j.finished).getTime() : 0;
    if (!j.running && !(j.error && now - fin < 15000)) continue;
    const bar = h('div', { class: 'bar' + (j.running && j.progress < 0 ? ' unknown' : '') }, h('i'));
    if (j.progress >= 0) bar.firstChild.style.width = Math.round(j.progress * 100) + '%';
    items.push(h('div', { class: 'job' },
      h('div', { class: 'job-title' }, j.title),
      h('div', { class: 'job-msg' + (j.error ? ' no' : '') }, linkify(j.error || j.message || 'Работаю…')),
      j.running ? bar : null));
  }
  put(box, ...items);
  box.hidden = items.length === 0;
  // react to finished jobs
  for (const [id, j] of Object.entries(jobs)) {
    const key = id + ':' + (j.finished || '');
    if (!j.running && j.finished && !S.jobsSeen[key]) {
      S.jobsSeen[key] = true;
      if (Object.keys(S.jobsSeen).length > 1) onJobFinished(id, j);
    }
  }
}

function onJobFinished(id, j) {
  if (id === 'zapret-test') {
    if (j.error) toast(j.error, true);
    else if (j.result && j.result.best) toast('Выбрана стратегия ' + j.result.best.replace(/\.bat$/i, ''));
  }
  if (id === 'mihomo' && !j.error) toast('mihomo загружен');
  if (id === 'zapret-install' && !j.error) toast('zapret загружен');
  if (id === 'zapret-test' || id === 'zapret-check' || id === 'zapret-install') S.stratsAt = 0;
  if (S.tab === 'zapret' || S.tab === 'settings') RENDER[S.tab]();
}

function renderFoot() {
  const st = S.status;
  if (!st) return;
  const running = st.jobs && st.jobs['self-update'] && st.jobs['self-update'].running;
  put($('#side-foot'),
    h('div', {}, 'Версия ', h('b', {}, st.version)),
    st.update ? h('button', { class: 'qp-act', disabled: running, onclick: startSelfUpdate }, running ? 'Обновляю…' : 'Обновить до ' + st.update) : null,
    st.dev ? h('div', {}, 'режим разработки') : null,
    !st.admin && !st.dev ? h('div', { class: 'no' }, 'без прав администратора') : null,
  );
}

/* ---------- import box ------------------------------------------------------- */

function pickFile(cb) {
  const inp = $('#file-input');
  inp.value = '';
  inp.onchange = () => {
    const f = inp.files[0];
    if (!f) return;
    if (f.size > 4 * 1024 * 1024) { toast('Файл слишком большой', true); return; }
    const rd = new FileReader();
    rd.onload = () => cb(f.name, String(rd.result));
    rd.readAsText(f);
  };
  inp.click();
}

function importBox(onAdded) {
  let filename = '';
  const ta = h('textarea', {
    rows: 5, spellcheck: 'false',
    placeholder: 'Вставьте одну или несколько строк: vless://…, hysteria2://…, trojan://…, vpn://… из AmneziaVPN, конфиг AmneziaWG целиком или адрес подписки https://…',
  });
  const out = h('div');
  async function parse() {
    if (!ta.value.trim()) { toast('Сначала вставьте ссылку или конфиг', true); return; }
    const r = await act(() => api('import', { text: ta.value, filename }));
    renderPreview(r);
  }
  function renderPreview(r) {
    const items = r.items || [];
    const checks = items.map(() => h('input', { type: 'checkbox', checked: true }));
    const rows = items.map((it, i) => {
      const s = it.server, sub = it.subscription;
      return h('div', { class: 'item' },
        checks[i],
        h('div', {},
          h('div', { class: 'item-name' }, s ? s.name : sub.name),
          h('div', { class: 'item-meta' }, s ? (s.info + ', ' + s.host + ':' + s.port) : ('подписка, ' + sub.url.replace(/^(https?:\/\/[^/]+).*/, '$1/…'))),
          it.note ? h('div', { class: 'item-note' }, it.note) : null));
    });
    const add = h('button', {
      class: 'btn primary', onclick: async () => {
        const sel = items.filter((_, i) => checks[i].checked);
        if (!sel.length) return;
        const res = await act(() => api('servers/add', { items: sel }));
        toast(res.added ? 'Добавлено: ' + res.added : 'Всё это уже было добавлено');
        ta.value = ''; filename = '';
        put(out);
        S.settings = await api('settings');
        onAdded && onAdded();
      },
    }, 'Добавить выбранное');
    put(out,
      items.length ? h('div', { class: 'list preview', style: 'margin-top:12px' }, rows) : null,
      r.errors && r.errors.length ? h('ul', { class: 'errors' }, r.errors.map(e => h('li', {}, e))) : null,
      items.length ? h('div', { class: 'row-actions', style: 'margin-top:12px' }, add) : null,
    );
  }
  return h('div', { class: 'panel' },
    ta,
    h('div', { class: 'row-actions', style: 'margin-top:10px' },
      h('button', { class: 'btn primary', onclick: parse }, 'Распознать'),
      h('button', { class: 'btn', onclick: () => pickFile((name, text) => { ta.value = text; filename = name; parse(); }) }, 'Открыть файл…'),
    ),
    out);
}

/* ---------- home ------------------------------------------------------------- */

const SHORT_CHOICE = { AUTO: 'Авто', OWN: 'Любой свой', SUB: 'Любой из подписки', DIRECT: 'Напрямую' };

function blockedLabel(o, short) {
  if (short && SHORT_CHOICE[o.name]) return SHORT_CHOICE[o.name];
  if (o.name === 'AUTO') return 'Авто: свои, затем подписка';
  if (o.name === 'OWN') return 'Любой свой сервер';
  if (o.name === 'SUB') return 'Любой из подписки';
  if (o.name === 'DIRECT') return 'Напрямую (не обходить)';
  return o.label + (o.delay ? '  ' + o.delay + ' мс' : o.alive === false ? '  ' + deadText(o) : '');
}

// The server for blocked sites (the BLOCKED group): general choices, then
// own servers, then the subscription's.
// compact (the narrow panel): short names of the general choices, and the
// chosen server without its delay when the panel shows it on its own line
function blockedSelect(blocked, attrs, compact, noDelay) {
  const fixed = [], own = [], sub = [];
  for (const o of blocked.options) {
    if (o.kind === 'reject') continue;
    (o.kind === 'own' ? own : o.kind === 'sub' ? sub : fixed).push(o);
  }
  // the subscription's servers: answering first (fastest on top), then
  // not yet checked, then dead; own servers keep their priority order
  const rank = o => o.delay ? 0 : o.alive === false ? 2 : 1;
  sub.sort((a, b) => rank(a) - rank(b) || (a.delay || 0) - (b.delay || 0));
  const opt = o => {
    const chosen = o.name === blocked.now;
    return h('option', { value: o.name, selected: chosen ? true : undefined }, noDelay && chosen && (o.kind === 'own' || o.kind === 'sub') ? o.label : blockedLabel(o, compact));
  };
  const sel = h('select', Object.assign({
    onchange: async () => {
      sel.disabled = true;
      try {
        await act(() => api('groups/select', { group: 'BLOCKED', name: sel.value }));
      } finally {
        sel.disabled = false;
        sel.blur();
      }
      await loadGroups();
      S.homeSig = ''; S.qpSig = ''; S.exitAt = 0;
      renderQuick();
      if (S.tab === 'home') renderHome();
    },
  }, attrs || {}),
  fixed.map(opt),
  own.length ? h('optgroup', { label: 'Свои серверы' }, own.map(opt)) : null,
  sub.length ? h('optgroup', { label: 'Подписка' }, sub.map(opt)) : null);
  return sel;
}

function groupByName(name) {
  return (S.groups || []).find(g => g.name === name);
}

function currentChoice(q) {
  const g = groupByName(q.g);
  if (g) return g.now;
  const r = S.settings.routing;
  const opt = q.opts.find(o => o[2] === r[q.field]) || q.opts[0];
  return opt[0];
}

async function chooseRoute(q, value) {
  if (S.status.vpn === 'on' && groupByName(q.g)) {
    await act(() => api('groups/select', { group: q.g, name: value }));
  } else {
    const r = Object.assign({}, S.settings.routing);
    r[q.field] = q.opts.find(o => o[0] === value)[2];
    await act(() => api('routing', r));
  }
  S.settings = await api('settings');
  await loadGroups();
  S.homeSig = '';
  renderHome();
}

async function loadGroups() {
  if (!S.status || S.status.vpn !== 'on') { S.groups = null; return; }
  try {
    const r = await api('groups');
    S.groups = r.off ? null : r.groups;
  } catch (e) { S.groups = null; }
}

// VPN is up but nothing to send traffic to: no subscription nodes loaded
// and no own server answering (mihomo then falls back to a direct "COMPATIBLE").
function vpnExitBroken() {
  const b = groupByName('BLOCKED');
  return !!b && (b.exit === 'COMPATIBLE' || (b.exit === 'DIRECT' && b.now !== 'DIRECT'));
}

function headline(st) {
  const zapOn = st.zapret === 'on';
  const blocked = groupByName('BLOCKED');
  switch (st.vpn) {
    case 'on': {
      if (st.vpn_broken) return ['VPN не работает', 'err', st.vpn_warn];
      if (st.vpn_warn) return ['Мешает другой VPN', 'err', st.vpn_warn];
      if (st.has_vpn && vpnExitBroken()) {
        return ['Серверы не отвечают', 'err', 'Подписка не загрузилась или ни один сервер недоступен, поэтому заблокированное пока идёт напрямую. Лазейка сама повторяет попытки; подробности на вкладке «Серверы» и в «Журнале».'];
      }
      const exit = blocked ? blocked.exit : '';
      let sub = exit && exit !== 'DIRECT' ? 'Заблокированное идёт через «' + exit + '».' : 'Заблокированное идёт через ваши серверы.';
      if (zapOn) sub += ' YouTube и Discord — через zapret.';
      if (st.zapret === 'paused') sub += ' zapret на паузе, пока включён VPN: YouTube и Discord — через сервер.';
      if (!st.has_vpn) sub = 'Серверов пока нет: работает только zapret и маршрутизация.';
      return ['Маршруты работают', 'on', sub];
    }
    case 'connecting':
      return ['Подключаюсь…', 'busy', st.vpn_error || 'Запускаю mihomo и проверяю серверы.'];
    case 'error':
      return ['VPN не работает', 'err', st.vpn_error || 'Причина в журнале.'];
    default:
      return ['VPN выключен', '', zapOn ? 'YouTube и Discord работают через zapret, остальное идёт напрямую.' : 'Весь трафик идёт напрямую, как без Лазейки.'];
  }
}

function laneZapret(st) {
  const strat = (st.strategy || '').replace(/\.bat$/i, '');
  switch (st.zapret) {
    case 'on': return ['live', 'работает', 'стратегия ' + strat];
    case 'starting': return ['idle', 'запускается…', ''];
    case 'error': return ['err', 'не работает', brief(st.zapret_error) || 'подробности на вкладке zapret'];
    case 'missing': return ['idle', 'недоступен', st.zapret_error || 'только в Windows'];
    case 'paused': return ['idle', 'на паузе', 'пока включён VPN'];
    default: return ['idle', 'выключен', st.zapret_enabled ? '' : 'включите на вкладке zapret'];
  }
}

function laneVPN(st) {
  if (!st.has_vpn) return ['idle', 'нет серверов', 'добавьте на вкладке «Серверы»'];
  switch (st.vpn) {
    case 'on': {
      if (st.vpn_broken) return ['err', 'нет связи', 'подробности вверху'];
      if (vpnExitBroken()) return ['err', 'нет связи', 'серверы не отвечают'];
      const b = groupByName('BLOCKED');
      const exit = b ? b.exit : '';
      let delay = '';
      if (b) {
        const opt = b.options.find(o => o.name === exit);
        if (opt && opt.delay) delay = opt.delay + ' мс';
      }
      return ['live', exit && exit !== 'DIRECT' ? exit : 'подключено', delay];
    }
    case 'connecting': return ['idle', 'подключаюсь…', ''];
    case 'error': return ['err', 'ошибка', 'подробности вверху'];
    default: return ['idle', 'выключено', ''];
  }
}

function lane(cls, name, what, state) {
  const [mode, title, detail] = state;
  return h('div', { class: 'lane ' + cls + ' ' + mode },
    h('div', { class: 'lane-line' }),
    h('div', {}, h('div', { class: 'lane-name' }, name), h('div', { class: 'lane-what' }, what)),
    h('div', { class: 'lane-state' }, h('b', {}, title), detail));
}

function renderHome() {
  const st = S.status, set = S.settings;
  const root = $('#tab-home');
  if (!st || !set) return;
  const sig = JSON.stringify([st.vpn, st.vpn_error, st.vpn_warn, st.vpn_broken, st.zapret, st.zapret_error, st.strategy, st.servers, st.subs, st.onboarded,
    (S.groups || []).map(g => [g.name, g.now, g.exit, g.options.length, (g.options.find(o => o.name === g.exit) || {}).delay])]);
  if (sig === S.homeSig) {
    const sp = $('#pc-speed');
    if (sp) put(sp, h('div', {}, 'загрузка ' + fmtSpeed(st.down)), h('div', {}, 'отдача ' + fmtSpeed(st.up)));
    return;
  }
  S.homeSig = sig;
  const [word, cls, sub] = headline(st);
  const on = st.vpn === 'on' || st.vpn === 'connecting';
  const power = h('button', {
    class: 'btn big ' + (on ? '' : 'primary'),
    disabled: st.vpn === 'connecting',
    onclick: async () => {
      await act(() => api(on ? 'vpn/disconnect' : 'vpn/connect', {}));
      setTimeout(tick, 400);
    },
  }, st.vpn === 'connecting' ? 'Подключаюсь…' : on ? 'Выключить VPN' : (st.vpn === 'error' ? 'Повторить' : 'Включить VPN'));

  const directWhat = set.routing.other === 'vpn' ? 'Российские сайты, игры и торренты' : 'Российские сайты, игры, торренты и всё незаблокированное';
  const route = h('div', { class: 'route' },
    h('div', { class: 'pc' },
      h('div', { class: 'pc-name' }, 'Этот компьютер'),
      h('div', { class: 'pc-speed', id: 'pc-speed' },
        h('div', {}, 'загрузка ' + fmtSpeed(st.down)), h('div', {}, 'отдача ' + fmtSpeed(st.up)))),
    h('div', { class: 'lanes' },
      lane('direct', 'Напрямую', directWhat, ['live', 'всегда', '']),
      lane('zapret', 'zapret', 'YouTube и Discord без VPN', laneZapret(st)),
      lane('vpn', 'Ваш сервер', 'Заблокированное и недоступное из России', laneVPN(st))));

  const parts = [
    h('div', { class: 'status-head' },
      h('div', {},
        h('h1', { class: 'status-word ' + cls }, word),
        h('p', { class: 'status-sub' + (cls === 'err' ? ' err' : '') }, linkify(sub))),
      power),
    route,
  ];

  if (!st.has_vpn && !st.onboarded) {
    parts.push(
      h('h2', {}, 'Добавьте свои серверы'),
      h('p', { class: 'hint' }, 'Подойдут ссылки VLESS и других протоколов, конфиги AmneziaWG (.conf), ссылки vpn:// из AmneziaVPN и адрес подписки. Свои серверы используются первыми, подписка — запасной вариант.'),
      importBox(() => { S.homeSig = ''; tick(); }),
      h('div', { class: 'row-actions', style: 'margin-top:10px' },
        h('button', { class: 'btn link', onclick: async () => { await api('app', { onboarded: true }); tick(); } }, 'Пока без серверов, только zapret')));
  }

  // quick routes
  const rows = QUICK.map(q => {
    const cur = currentChoice(q);
    const seg = h('div', { class: 'seg', role: 'group', 'aria-label': q.name },
      q.opts.map(([val, label]) => h('button', {
        'aria-pressed': String(cur === val),
        disabled: q.g === 'AI' && !st.servers && val === 'OWN',
        onclick: () => cur !== val && chooseRoute(q, val),
      }, label)));
    return h('div', { class: 'qrow' }, h('div', { class: 'qname' }, q.name, h('small', {}, q.hint)), h('div', {}, seg));
  });
  const blocked = groupByName('BLOCKED');
  const blockedCtl = blocked ? blockedSelect(blocked)
    : h('span', { class: 'hint' }, st.has_vpn ? 'Выбор сервера появится после включения VPN' : 'Сначала добавьте сервер');
  rows.unshift(h('div', { class: 'qrow' }, h('div', { class: 'qname' }, 'Заблокированное', h('small', {}, 'через какой сервер')), h('div', {}, blockedCtl)));

  parts.push(h('div', { class: 'quick' },
    h('h2', {}, 'Куда отправлять'),
    h('p', { class: 'hint' }, 'Российские сайты и программы всегда идут напрямую, чтобы они не видели адреса ваших серверов. Остальное настраивается здесь и на вкладке «Правила».'),
    h('div', { class: 'panel' }, rows)));

  put(root, ...parts);
}

/* ---------- quick panel: VPN and zapret on every page -------------------------- */

const REGION = (() => { try { return new Intl.DisplayNames(['ru'], { type: 'region' }); } catch (e) { return null; } })();
function countryName(code) {
  try { return (REGION && REGION.of(code)) || code; } catch (e) { return code; }
}

function fmtUptime(iso) {
  const t = iso ? new Date(iso).getTime() : 0;
  if (!t || t < 86400000) return '';
  const m = Math.max(0, Math.floor((Date.now() - t) / 60000));
  if (m < 1) return 'меньше минуты';
  if (m < 60) return m + ' мин';
  const hr = Math.floor(m / 60);
  if (hr < 24) return hr + ' ч ' + String(m % 60).padStart(2, '0') + ' мин';
  return Math.floor(hr / 24) + ' д ' + (hr % 24) + ' ч';
}

function delayClass(d) { return !d ? 'qp-dead' : d < 300 ? 'qp-good' : d < 800 ? 'qp-slow' : 'qp-dead'; }

async function loadStrats() {
  try { S.strats = await api('zapret/strategies'); } catch (e) { /* keep the old list */ }
  S.stratsAt = Date.now();
}

async function loadExit() {
  S.exitAt = Date.now();
  try { S.exit = await api('exit'); } catch (e) { S.exit = null; }
}

// what the panel needs besides the status (called from tick)
async function loadQuick(st) {
  const ui = (S.settings && S.settings.ui) || {};
  if (!S.strats || Date.now() - S.stratsAt > 60000 || (S.strats.current !== st.strategy && Date.now() - S.stratsAt > 3000)) await loadStrats();
  const b = groupByName('BLOCKED');
  if (st.vpn !== 'on' || !b || ui.panel_collapsed || ui.hide_country) {
    if (st.vpn !== 'on') S.exit = null;
    return;
  }
  const stale = !S.exit || S.exit.node !== b.exit;
  const wait = stale ? 2500 : (S.exit.pending ? 3000 : 20000);
  if (Date.now() - S.exitAt > wait) await loadExit();
}

function setUI(patch) {
  S.settings.ui = Object.assign({}, S.settings.ui || {}, patch);
  S.qpSig = '';
  renderQuick();
  return api('ui', patch).catch(e => toast(e.message, true));
}

function quickVPN(st, ui, blocked) {
  const on = st.vpn === 'on' || st.vpn === 'connecting';
  let mode = 'off', state = 'выключен', more = false;
  if (st.vpn === 'connecting') { mode = 'busy'; state = 'подключаюсь…'; }
  else if (st.vpn === 'error') { mode = 'err'; state = 'не подключился'; more = true; }
  else if (st.vpn === 'on') {
    if (st.vpn_broken) { mode = 'err'; state = 'не работает'; more = true; }
    else if (st.vpn_warn) { mode = 'err'; state = 'мешает другой VPN'; more = true; }
    else if (st.has_vpn && vpnExitBroken()) { mode = 'err'; state = 'серверы не отвечают'; more = true; }
    else { mode = 'on'; state = st.has_vpn ? 'работает' : 'только маршрутизация'; }
  }
  const head = h('button', {
    class: 'qp-head', role: 'switch', 'aria-checked': String(on), disabled: st.vpn === 'connecting',
    title: on ? 'Выключить VPN' : 'Включить VPN',
    onclick: async () => {
      await act(() => api(on ? 'vpn/disconnect' : 'vpn/connect', {}));
      setTimeout(tick, 400);
    },
  }, h('span', { class: 'qp-name' }, 'VPN'), h('span', { class: 'qp-knob', 'aria-hidden': 'true' }));

  const full = !ui.panel_collapsed;
  const rows = [h('div', { class: 'qp-row' },
    h('span', { class: 'qp-state' }, state),
    full && !ui.hide_uptime && st.vpn === 'on' ? h('span', { id: 'qp-uptime' }, fmtUptime(st.vpn_since)) : null)];
  if (more) {
    rows.push(h('button', { class: 'qp-act', onclick: () => showTab('home') }, 'Подробности'));
  }
  if (full && st.has_vpn && !ui.hide_server) {
    const sel = blocked ? blockedSelect(blocked, { 'aria-label': 'Сервер для заблокированного' }, true, !ui.hide_ping)
      : h('select', { disabled: true, title: 'Сервер выбирается при включённом VPN', 'aria-label': 'Сервер для заблокированного' },
        h('option', {}, SHORT_CHOICE[(S.settings.routing || {}).blocked_select || 'AUTO'] || S.settings.routing.blocked_select));
    rows.push(h('label', { class: 'qp-field' }, h('span', {}, 'Заблокированное через'), sel));
  }
  if (full && st.vpn === 'on' && blocked) {
    const exit = blocked.exit;
    const opt = blocked.options.find(o => o.name === exit);
    const ping = !ui.hide_ping && opt && exit !== 'DIRECT' && (opt.delay || opt.alive === false)
      ? h('span', { class: delayClass(opt.delay), title: opt.delay ? undefined : deadTitle(opt) }, opt.delay ? opt.delay + ' мс' : deadText(opt)) : null;
    let country = null;
    if (exit === 'DIRECT') country = 'напрямую, без сервера';
    else if (!ui.hide_country) {
      if (S.exit && S.exit.node === exit && S.exit.country) country = countryName(S.exit.country);
      else if (S.exit && S.exit.pending) country = 'определяю страну…';
    }
    const ipTitle = S.exit && S.exit.ip ? 'IP выхода: ' + S.exit.ip : undefined;
    // which server works now: worth a line when a group is chosen ("Авто")
    // or when the server list is hidden
    const named = exit && exit !== 'DIRECT' && exit !== 'COMPATIBLE' && (blocked.now !== exit || ui.hide_server);
    if (named) {
      rows.push(h('div', { class: 'qp-row' }, h('span', { title: exit }, 'сейчас ', h('b', {}, exit)), ping));
      if (country) rows.push(h('div', { class: 'qp-row' }, h('span', { title: ipTitle }, country)));
    } else if (country || ping) {
      rows.push(h('div', { class: 'qp-row' }, h('span', { title: ipTitle }, country || ''), ping));
    }
  }
  if (full && st.vpn === 'on' && !ui.hide_speed) {
    rows.push(h('div', { class: 'qp-row', 'aria-label': 'Скорость' },
      h('span', { id: 'qp-down', title: 'Загрузка' }, '↓ ' + fmtSpeed(st.down)),
      h('span', { id: 'qp-up', title: 'Отдача' }, '↑ ' + fmtSpeed(st.up))));
  }
  return h('div', { class: 'qp-block vpn ' + mode }, head, rows);
}

function strategyLabel(r) {
  if (r.failed) return r.name + '  не запустилась';
  if (r.checked && r.ok > 0) return r.name + '  ' + r.ok + ' из ' + r.total;
  if (r.checked) return r.name + '  не помогла';
  return r.name;
}

// Strategies: the ones that helped on this computer first, with their result.
function strategySelect(zs, attrs, onPicked) {
  const good = zs.list.filter(r => r.checked && !r.failed && r.ok > 0);
  const rest = zs.list.filter(r => !(r.checked && !r.failed && r.ok > 0));
  const opt = r => h('option', { value: r.file, selected: r.file === zs.current ? true : undefined }, strategyLabel(r));
  const sel = h('select', Object.assign({
    onchange: async () => {
      sel.disabled = true;
      try {
        await act(() => api('zapret/options', { strategy: sel.value }), 'Стратегия применена');
      } finally {
        sel.disabled = false;
        sel.blur();
      }
      await loadStrats();
      S.qpSig = '';
      onPicked && onPicked();
    },
  }, attrs || {}), good.length ? [h('optgroup', { label: 'Помогли на этом компьютере' }, good.map(opt)), h('optgroup', { label: 'Остальные' }, rest.map(opt))] : rest.map(opt));
  return sel;
}

function quickZapret(st, ui, zs, zt) {
  const on = !!st.zapret_enabled;
  const testing = !!(zt && zt.running);
  let mode = 'off', state = 'выключен';
  switch (st.zapret) {
    case 'on': mode = 'on'; state = 'работает'; break;
    case 'starting': mode = 'busy'; state = 'запускается…'; break;
    case 'error': mode = 'err'; state = 'не работает'; break;
    case 'paused': state = 'на паузе, пока включён VPN'; break;
    case 'missing': state = 'недоступен'; break;
  }
  const inst = (st.jobs || {})['zapret-install'];
  if (testing) { mode = 'busy'; state = 'подбираю стратегию…'; }
  else if (inst && inst.running) { mode = 'busy'; state = 'скачивается…'; }
  const head = h('button', {
    class: 'qp-head', role: 'switch', 'aria-checked': String(on), disabled: testing || st.zapret === 'missing',
    title: on ? 'Выключить zapret' : 'Включить zapret',
    onclick: async () => {
      await act(() => api('zapret/enable', { on: !on }));
      setTimeout(() => { tick(); S.stratsAt = 0; }, 1500);
    },
  }, h('span', { class: 'qp-name' }, 'zapret'), h('span', { class: 'qp-knob', 'aria-hidden': 'true' }));

  const rows = [h('div', { class: 'qp-row' }, h('span', { class: 'qp-state' }, state))];
  if (st.zapret === 'error') rows.push(h('button', { class: 'qp-act', onclick: () => showTab('zapret') }, 'Подробности'));
  if (!ui.panel_collapsed && !ui.hide_strategy && zs && zs.installed && zs.list && zs.list.length) {
    const good = zs.list.some(r => r.checked && !r.failed && r.ok > 0);
    const sel = strategySelect(zs, { 'aria-label': 'Стратегия zapret', disabled: testing }, () => {
      tick();
      if (S.tab === 'zapret') RENDER.zapret();
    });
    rows.push(h('label', { class: 'qp-field' }, h('span', {}, 'Стратегия'), sel));
    const pct = testing && zt.progress > 0 ? ' ' + Math.round(zt.progress * 100) + '%' : '';
    rows.push(h('button', {
      class: 'qp-act', disabled: testing || st.zapret === 'paused',
      title: st.zapret === 'paused' ? 'Пока zapret на паузе, подбирать не из чего' : 'Пробует все стратегии и оставляет лучшую. Пара минут; YouTube и Discord в это время могут подвисать.',
      onclick: async () => { await act(() => api('zapret/autoselect', {}), 'Подбираю стратегию, это пара минут'); tick(); },
    }, testing ? 'Подбираю…' + pct : (good ? 'Подобрать заново' : 'Подобрать')));
  }
  return h('div', { class: 'qp-block zapret ' + mode }, head, rows);
}

function renderQuick() {
  const st = S.status, set = S.settings, root = $('#qp');
  if (!st || !set || !root) return;
  const ui = set.ui || {};
  const blocked = groupByName('BLOCKED');
  const zs = S.strats;
  const zt = (st.jobs || {})['zapret-test'];
  const sig = JSON.stringify([st.vpn, st.vpn_broken, st.vpn_warn, st.has_vpn, st.zapret, st.zapret_enabled, st.strategy,
    zt && zt.running ? Math.round((zt.progress || 0) * 50) : -1,
    blocked ? [blocked.now, blocked.exit, blocked.options.map(o => o.name + ':' + o.delay + ':' + o.alive + ':' + (o.reach || ''))] : null,
    S.exit ? [S.exit.node, S.exit.country, S.exit.pending] : null,
    zs ? [zs.installed, zs.current, (zs.list || []).map(r => r.file + ':' + r.ok + ':' + r.checked)] : null,
    ui, (set.routing || {}).blocked_select]);
  const a = document.activeElement;
  const choosing = a && a.tagName === 'SELECT' && root.contains(a); // do not close an open list
  if (sig !== S.qpSig && !choosing) {
    S.qpSig = sig;
    put(root, quickVPN(st, ui, blocked), quickZapret(st, ui, zs, zt),
      h('button', {
        class: 'qp-fold', 'aria-expanded': String(!ui.panel_collapsed),
        onclick: () => setUI({ panel_collapsed: !ui.panel_collapsed }),
      }, ui.panel_collapsed ? 'Подробности' : 'Скрыть подробности'));
  }
  const up = $('#qp-uptime');
  if (up) up.textContent = fmtUptime(st.vpn_since);
  const dn = $('#qp-down'), upl = $('#qp-up');
  if (dn) dn.textContent = '↓ ' + fmtSpeed(st.down);
  if (upl) upl.textContent = '↑ ' + fmtSpeed(st.up);
}

/* ---------- servers ---------------------------------------------------------- */

// Why a subscription's servers do not answer (the core has connected to
// each dead one directly; see reach.go): one line per reason.
function reachNote(nodes) {
  const count = code => nodes.filter(n => !n.delay && n.alive === false && n.reach === code).length;
  const off = count('unreachable'), dpi = count('dpi'), open = count('open');
  const srv = n => n + ' ' + plural(n, 'сервер', 'сервера', 'серверов');
  const out = [];
  if (off) out.push(srv(off) + ' ' + plural(off, 'не открывается', 'не открываются', 'не открываются') + ' из вашей сети даже напрямую: адрес заблокирован провайдером или сервер выключен.');
  if (dpi) out.push(srv(dpi) + ': подключение есть, но провайдер обрывает защищённое соединение — блокирует протокол.');
  if (open) out.push(srv(open) + ' ' + plural(open, 'доступен', 'доступны', 'доступны') + ', но VPN через ' + plural(open, 'него', 'них', 'них') + ' не работает: обновите подписку; не поможет — проблема у сервера.');
  if (!out.length) return null;
  return h('div', { class: 'item-note' },
    out.map(l => h('div', {}, l)),
    h('div', {}, 'Лазейка это не исправит: выберите сервер, который отвечает, или попросите у владельца подписки другие адреса.'));
}

async function renderServers() {
  const root = $('#tab-servers');
  S.settings = await api('settings');
  let nodes = null;
  if (S.status && S.status.vpn === 'on') {
    try { const n = await api('nodes'); if (!n.off) nodes = n; } catch (e) { /* ignore */ }
  }
  const set = S.settings;
  const own = set.servers.map((s, i) => {
    const nv = nodes && nodes.own[s.id];
    return h('div', { class: 'item' + (s.enabled ? '' : ' off') },
      h('div', { class: 'prio', title: 'Приоритет' }, String(i + 1)),
      h('div', {},
        h('div', { class: 'item-name' }, s.name, nodes && nodes.active === (nv && nv.name) ? h('span', { class: 'item-meta' }, '  сейчас используется') : null),
        h('div', { class: 'item-meta' }, s.info + ', ' + s.host + ':' + s.port + (s.source ? ', из: ' + s.source : ''))),
      h('div', { class: 'item-side' },
        nv ? delayEl(nv.delay, nv.alive, nv) : null,
        h('button', { class: 'btn mini', title: 'Поднять приоритет', disabled: i === 0, onclick: () => patchServer({ id: s.id, move: -1 }) }, 'Выше'),
        h('button', { class: 'btn mini', title: 'Опустить приоритет', disabled: i === set.servers.length - 1, onclick: () => patchServer({ id: s.id, move: 1 }) }, 'Ниже'),
        h('button', { class: 'btn mini', onclick: () => patchServer({ id: s.id, enabled: !s.enabled }) }, s.enabled ? 'Отключить' : 'Включить'),
        h('button', {
          class: 'btn mini', onclick: () => {
            const n = prompt('Новое имя сервера', s.name);
            if (n && n.trim()) patchServer({ id: s.id, name: n.trim() });
          },
        }, 'Имя'),
        h('button', { class: 'btn mini danger', onclick: () => confirm('Удалить сервер «' + s.name + '»?') && patchServer({ id: s.id, delete: true }) }, 'Удалить')));
  });

  const subs = set.subscriptions.map(sub => {
    const sv = nodes && (nodes.subs || []).find(x => x.id === sub.id);
    if (sv) sv.nodes = sv.nodes || [];
    const alive = sv ? sv.nodes.filter(n => n.delay > 0).length : 0;
    const tested = sv ? sv.nodes.filter(n => n.delay > 0 || n.alive === false).length : 0;
    let info = '';
    if (sv && sv.info) {
      const used = (sv.info.Upload || 0) + (sv.info.Download || 0);
      if (sv.info.Total) info += 'израсходовано ' + fmtBytes(used) + ' из ' + fmtBytes(sv.info.Total);
      if (sv.info.Expire) info += (info ? ', ' : '') + 'до ' + new Date(sv.info.Expire * 1000).toLocaleDateString('ru-RU');
    }
    const host = sub.url.replace(/^(https?:\/\/[^/]+).*/, '$1/…');
    return h('div', { class: 'item' + (sub.enabled ? '' : ' off') },
      h('div', { class: 'prio' }, '·'),
      h('div', {},
        h('div', { class: 'item-name' }, sub.name),
        h('div', { class: 'item-meta' }, host + (sv ? ', ' + sv.nodes.length + ' ' + plural(sv.nodes.length, 'сервер', 'сервера', 'серверов') + ', ' + (tested ? 'отвечают ' + alive : 'ещё не проверялись') + ', ' + ago(sv.updated_at) : '')),
        info ? h('div', { class: 'item-meta' }, info) : null,
        sv && !sv.nodes.length ? h('div', { class: 'item-note' }, set.servers.length
          ? 'Пока не загрузилась: адрес подписки недоступен напрямую. Лазейка повторяет попытки и, если напрямую не выйдет, скачает её через ваш сервер.'
          : 'Не загрузилась: адрес подписки недоступен напрямую (похоже, заблокирован). Лазейка повторяет попытки через zapret; надёжнее добавить свой сервер, тогда подписка скачается через него.') : null,
        h('div', { class: 'row-actions', style: 'margin-top:6px' },
          h('label', { class: 'switch inline', title: 'Некоторые подписки без HWID не отдают серверы. Отправляется обезличенный идентификатор, а не настоящий номер компьютера.' }, h('input', { type: 'checkbox', checked: sub.hwid, onchange: e => patchSub({ id: sub.id, hwid: e.target.checked }) }), 'Отправлять HWID'),
          h('label', { class: 'switch inline', title: 'Если адрес подписки заблокирован провайдером' }, h('input', { type: 'checkbox', checked: sub.via_vpn, onchange: e => patchSub({ id: sub.id, via_vpn: e.target.checked }) }), 'Скачивать через свой сервер')),
        sv && sv.nodes.length ? h('details', {},
          h('summary', { class: 'item-meta', style: 'cursor:pointer' }, 'Серверы подписки'),
          h('div', { class: 'nodes' }, sv.nodes.map(n => h('div', {}, h('span', {}, n.name), delayEl(n.delay, n.alive, n))))) : null,
        sv ? reachNote(sv.nodes) : null,
        subSettings(sub)),
      h('div', { class: 'item-side' },
        h('button', { class: 'btn mini', disabled: !nodes, onclick: async () => { await act(() => api('subs/refresh', { id: sub.id }), 'Подписка обновлена'); renderServers(); } }, 'Обновить'),
        h('button', { class: 'btn mini', onclick: () => patchSub({ id: sub.id, enabled: !sub.enabled }) }, sub.enabled ? 'Отключить' : 'Включить'),
        h('button', { class: 'btn mini danger', onclick: () => confirm('Удалить подписку «' + sub.name + '»?') && patchSub({ id: sub.id, delete: true }) }, 'Удалить')));
  });

  put(root,
    h('h1', {}, 'Серверы'),
    h('p', { class: 'lead' }, 'Свои серверы используются первыми, сверху вниз: если верхний не отвечает, Лазейка сама переходит к следующему. Подписка подключается, только когда все свои недоступны.'),
    h('h2', {}, 'Добавить'),
    importBox(() => renderServers()),
    h('h2', {}, 'Свои серверы'),
    h('p', { class: 'hint' }, 'Сервер с UDP (AmneziaWG, Hysteria2) используется для звонков в Discord, Telegram и WhatsApp.'),
    h('div', { class: 'list' }, own.length ? own : h('div', { class: 'empty' }, 'Своих серверов пока нет. Вставьте ссылку или конфиг выше.')),
    h('h2', {}, 'Подписки'),
    h('p', { class: 'hint' }, 'Владелец подписки видит, куда вы ходите, поэтому ИИ-сервисы по умолчанию идут только через свои серверы. Российские и служебные «серверы» из подписки отфильтровываются.'),
    h('div', { class: 'list' }, subs.length ? subs : h('div', { class: 'empty' }, 'Подписок нет.')),
    h('div', { class: 'row-actions', style: 'margin-top:16px' },
      h('button', {
        class: 'btn', disabled: !nodes, onclick: async () => {
          await act(() => api('nodes/test', {}), 'Задержки обновлены');
          renderServers();
        },
      }, 'Проверить задержки'),
      !nodes ? h('span', { class: 'hint', style: 'margin:0' }, 'Задержки видны при включённом VPN') : null));
}

// Name and local filter of a subscription. Renaming and hiding for every
// device is done in Связка; here only what this computer should not use.
function subSettings(sub) {
  const name = h('input', { type: 'text', value: sub.name, maxlength: 60 });
  const hide = h('textarea', { rows: 3, spellcheck: 'false', value: (sub.hide || []).join(', ') });
  const save = h('button', {
    class: 'btn primary', onclick: async () => {
      save.disabled = true;
      try {
        await act(() => api('subs/patch', { id: sub.id, name: name.value, hide_text: hide.value }), 'Сохранено');
        renderServers();
      } finally { save.disabled = false; }
    },
  }, 'Сохранить');
  return h('details', { class: 'sub-settings' },
    h('summary', { class: 'item-meta', style: 'cursor:pointer' }, 'Название и фильтр'),
    h('div', { class: 'grid2', style: 'margin-top:10px' },
      h('div', { class: 'field' }, h('label', {}, 'Название подписки'), name),
      h('div', { class: 'field' }, h('label', {}, 'Не брать на этом компьютере серверы, в названии которых есть'), hide,
        h('small', {}, 'Через запятую. Нужно, чтобы Лазейка сама не выбрала российский сервер: через него заблокированные сайты не откроются. Переименовывать и скрывать серверы для всех устройств — в Связке.'))),
    h('div', { class: 'row-actions', style: 'margin-top:10px' }, save));
}

async function patchServer(p) {
  await act(() => api('servers/patch', p));
  renderServers();
}
async function patchSub(p) {
  await act(() => api('subs/patch', p));
  renderServers();
}

/* ---------- rules ------------------------------------------------------------ */

function choice(label, hint, value, opts, onchange) {
  let cur = value;
  const seg = h('div', { class: 'seg', role: 'group', 'aria-label': label });
  const draw = () => put(seg, ...opts.map(([v, t]) => h('button', {
    type: 'button', 'aria-pressed': String(cur === v), onclick: () => { cur = v; onchange(v); draw(); },
  }, t)));
  draw();
  return h('div', { class: 'qrow' }, h('div', { class: 'qname' }, label, hint ? h('small', {}, hint) : null), h('div', {}, seg));
}

function sw(label, hint, checked, onchange) {
  return h('label', { class: 'switch' },
    h('input', { type: 'checkbox', checked, onchange: e => onchange(e.target.checked) }),
    h('span', {}, label, hint ? h('small', {}, hint) : null));
}

function area(label, hint, value, rows) {
  const ta = h('textarea', { rows: rows || 4, spellcheck: 'false', value });
  return [h('div', { class: 'field' }, h('label', {}, label), ta, hint ? h('small', {}, hint) : null), ta];
}

// Android: apps that skip the VPN altogether (banks, Госуслуги)
function bypassApps(r) {
  const box = h('div', { class: 'panel applist' }, h('p', { class: 'hint', style: 'margin:0' }, 'Загружаю список приложений…'));
  const on = new Set(r.bypass_apps || []);
  const search = h('input', { type: 'search', placeholder: 'Найти приложение', style: 'width:100%' });
  const showSys = h('input', { type: 'checkbox' });
  let apps = [];
  const draw = () => {
    const q = search.value.trim().toLowerCase();
    const list = apps.filter(a => (showSys.checked || !a.system || on.has(a.package)) &&
      (!q || a.label.toLowerCase().includes(q) || a.package.includes(q)));
    put(box, list.length ? list.map(a => h('label', { class: 'app-row' },
      h('input', { type: 'checkbox', checked: on.has(a.package), onchange: ev => { ev.target.checked ? on.add(a.package) : on.delete(a.package); } }),
      h('span', {}, a.label, h('small', {}, a.package)))) : h('p', { class: 'hint', style: 'margin:0' }, 'Ничего не найдено'));
  };
  search.addEventListener('input', draw);
  showSys.addEventListener('change', draw);
  api('android/apps').then(d => { apps = d.apps || []; draw(); }).catch(e => put(box, h('p', { class: 'hint no', style: 'margin:0' }, e.message)));
  return [
    h('h2', {}, 'Приложения мимо VPN'),
    h('p', { class: 'hint' }, 'Их трафик вообще не заходит в Лазейку: так банки и Госуслуги не видят VPN. Российские сайты в остальных приложениях и так идут напрямую.'),
    h('div', { class: 'row-actions', style: 'margin-bottom:8px' }, search),
    h('label', { class: 'hint', style: 'display:flex;gap:8px;align-items:center;margin:0 0 8px' }, showSys, 'Показывать системные'),
    box,
    h('div', { class: 'row-actions', style: 'margin-top:12px' },
      h('button', { class: 'btn primary', onclick: async () => {
        await act(() => api('android/bypass', { packages: [...on] }), 'Сохранено, VPN перезапускается');
        r.bypass_apps = [...on];
        S.settings = await api('settings');
      } }, 'Сохранить список')),
  ];
}

async function renderRules() {
  const root = $('#tab-rules');
  S.settings = await api('settings');
  const r = JSON.parse(JSON.stringify(S.settings.routing));
  const [fVPN, taVPN] = area('Всегда через сервер', 'Домен (подходят и поддомены), IP или подсеть — по одному на строку.', lines(r.custom_vpn));
  const [fDirect, taDirect] = area('Всегда напрямую', 'Например, сайт банка, который ругается на VPN.', lines(r.custom_direct));
  const [fApps, taApps] = area('Программы, которые всегда идут напрямую', 'Имя файла программы: российские приложения, антивирус, 1С.', lines(r.direct_apps));
  const [fPaths, taPaths] = area('Папки программ, которые идут напрямую', 'Часть пути, например \\Yandex\\YandexBrowser\\', lines(r.direct_paths), 3);
  const [fTorr, taTorr] = area('Торрент-клиенты', 'Раздача идёт напрямую, чтобы хостинг не прислал жалобу; трекеры — через сервер.', lines(r.torrent_apps));
  const [fGames, taGames] = area('Игровые лаунчеры', 'Идут напрямую ради низкого пинга.', lines(r.game_apps));

  let rulesInfo = null;
  if (S.status && S.status.vpn === 'on') {
    try { const ri = await api('rules'); if (!ri.off) rulesInfo = ri; } catch (e) { /* ignore */ }
  }
  const RULE_NAMES = {
    'ru-blocked': 'Заблокированное в России', 'geoblock': 'Сервисы, закрытые для России', 'hodca': 'Сайты на «медленных» хостингах',
    'youtube': 'YouTube', 'discord': 'Discord', 'discord-ip': 'Discord (адреса)', 'telegram': 'Telegram', 'telegram-ip': 'Telegram (адреса)',
    'meta': 'Instagram, Facebook, WhatsApp', 'meta-ip': 'Meta (адреса)', 'twitter-ip': 'X/Twitter (адреса)', 'ai': 'ИИ-сервисы',
    'ru-outside': 'Работает только из России', 'ru-domains': 'Российские домены', 'ru-ip': 'Российские адреса',
  };

  const save = h('button', {
    class: 'btn primary big', onclick: async () => {
      r.custom_vpn = unlines(taVPN.value);
      r.custom_direct = unlines(taDirect.value);
      r.direct_apps = unlines(taApps.value);
      r.direct_paths = unlines(taPaths.value);
      r.torrent_apps = unlines(taTorr.value);
      r.game_apps = unlines(taGames.value);
      save.disabled = true;
      try { await act(() => api('routing', r), 'Правила сохранены и применены'); } finally { save.disabled = false; }
      S.homeSig = '';
    },
  }, 'Сохранить и применить');

  put(root,
    h('h1', {}, 'Правила'),
    h('p', { class: 'lead' }, 'Списки заблокированного и российского обновляются сами раз в сутки (itdoginfo и MetaCubeX). Здесь — то, что зависит от вас.'),
    h('h2', {}, 'Сервисы'),
    h('div', { class: 'panel' },
      choice('YouTube', 'видео и сайт', r.youtube, [['zapret', 'Через zapret'], ['vpn', 'Через сервер'], ['direct', 'Напрямую']], v => { r.youtube = v; }),
      choice('Discord', 'чаты и голос', r.discord, [['zapret', 'Через zapret'], ['vpn', 'Через сервер']], v => { r.discord = v; }),
      choice('Telegram и WhatsApp', 'сообщения и звонки', r.messengers, [['vpn', 'Через сервер'], ['direct', 'Напрямую']], v => { r.messengers = v; }),
      choice('ИИ-сервисы', 'ChatGPT, Claude, Gemini', r.ai, [['own', 'Только свои серверы'], ['vpn', 'Любой сервер']], v => { r.ai = v; }),
      choice('Всё остальное', 'что не попало в списки', r.other, [['direct', 'Напрямую'], ['vpn', 'Через сервер']], v => { r.other = v; })),
    h('p', { class: 'hint' }, 'Если zapret перестаёт работать, YouTube и Discord сами переходят на сервер, пока zapret не поднимется.'),
    h('h2', {}, 'Тонкости'),
    h('div', { class: 'panel' },
      sw('Сайты на зарубежных хостингах — через сервер', 'Hetzner, OVH, DigitalOcean, Cloudflare, AWS: из России их часто «замораживают» после 16 КБ.', r.hodca, v => { r.hodca = v; }),
      sw('Запрещать QUIC для заблокированного', 'Браузер переходит на обычный TCP, через VPN так быстрее и стабильнее.', r.block_quic, v => { r.block_quic = v; }),
      sw('Прочий UDP — напрямую', 'Игры и звонки, которых нет в списках, не нагружают сервер и не теряют пинг.', r.udp_direct, v => { r.udp_direct = v; })),
    h('h2', {}, 'Свои списки'),
    ANDROID ? h('div', { class: 'grid2' }, fVPN, fDirect) : h('div', { class: 'grid2' }, fVPN, fDirect, fApps, fPaths, fTorr, fGames),
    h('div', { class: 'row-actions', style: 'margin-top:20px' }, save),
    ANDROID ? bypassApps(r) : null,
    h('h2', {}, 'Списки маршрутизации'),
    rulesInfo ? h('div', {},
      h('table', {},
        h('tr', {}, h('th', {}, 'Список'), h('th', {}, 'Правил'), h('th', {}, 'Обновлён')),
        Object.values(rulesInfo).map(x => Object.assign({ label: RULE_NAMES[x.name] || x.name }, x))
          .sort((a, b) => a.label.localeCompare(b.label, 'ru')).map(x => h('tr', {},
          h('td', {}, x.label),
          h('td', { class: 'num' }, x.ruleCount.toLocaleString('ru-RU')),
          h('td', {}, ago(x.updatedAt).replace('обновлена ', ''))))),
      h('div', { class: 'row-actions', style: 'margin-top:12px' },
        h('button', { class: 'btn', onclick: async () => { await act(() => api('rules/refresh', {}), 'Списки обновлены'); renderRules(); } }, 'Обновить списки сейчас')))
      : h('p', { class: 'hint' }, 'Состояние списков видно при включённом VPN.'));
}

/* ---------- zapret ----------------------------------------------------------- */

function resultsTable(results) {
  return h('table', {},
    h('tr', {}, h('th', {}, 'Проверка'), h('th', {}, 'Итог'), h('th', {}, 'Время')),
    results.map(x => h('tr', {},
      h('td', {}, x.name),
      h('td', { class: x.ok ? 'yes' : 'no' }, x.ok ? 'открывается' : (x.err || 'не открывается')),
      h('td', { class: 'num' }, x.ok ? x.ms + ' мс' : ''))));
}

// strategy name for tables: ByeDPI keys get their description
function stratName(file) {
  if (!file) return '';
  const it = S.strats && S.strats.list && S.strats.list.find(x => x.file === file);
  if (ANDROID && it) return it.name;
  if (ANDROID && file.startsWith('custom:')) return 'Своя: ' + file.slice(7);
  return file.replace(/\.bat$/i, '');
}

// Android: a ByeDPI command line of your own
function customStrategy(z) {
  const cur = (z.strategy || '').startsWith('custom:') ? z.strategy.slice(7) : '';
  const inp = h('input', { type: 'text', value: cur, spellcheck: 'false', placeholder: '-d1 -s1+s -r1+s', style: 'width:100%;font-family:ui-monospace,monospace' });
  return [
    h('h2', {}, 'Своя стратегия'),
    h('div', { class: 'panel' },
      h('p', { class: 'hint', style: 'margin:0 0 8px' }, 'Параметры ByeDPI (ciadpi), как в ByeByeDPI. Адрес и порт Лазейка задаёт сама.'),
      inp,
      h('div', { class: 'row-actions', style: 'margin-top:8px' },
        h('button', { class: 'btn', onclick: async () => {
          const v = inp.value.trim();
          if (!v) return toast('Введите параметры', true);
          await act(() => api('zapret/options', { strategy: 'custom:' + v }), 'Стратегия применена');
          S.stratsAt = 0; renderZapret(); tick();
        } }, 'Применить'))),
  ];
}

async function renderZapret() {
  const root = $('#tab-zapret');
  const z = await api('zapret');
  const st = S.status;
  const jobs = st.jobs || {};
  const testing = jobs['zapret-test'] && jobs['zapret-test'].running;
  const checking = jobs['zapret-check'] && jobs['zapret-check'].running;
  const parts = [
    h('h1', {}, 'zapret'),
    ANDROID ? h('p', { class: 'lead' }, 'Открывает YouTube и Discord без сервера: ByeDPI разбивает и маскирует первые пакеты соединения, и DPI провайдера не узнаёт сайт. Root не нужен. Тяжёлое видео не идёт через сервер, и он дольше остаётся незамеченным.')
      : h('p', { class: 'lead' }, 'Открывает YouTube и Discord без VPN: обманывает DPI провайдера прямо на вашем компьютере. Тяжёлое видео не идёт через сервер, и он дольше остаётся незамеченным.'),
  ];
  const stateText = { on: 'Работает', starting: 'Запускается…', error: 'Не работает', missing: 'Недоступен', off: 'Выключен', paused: 'На паузе' }[st.zapret] || st.zapret;
  const paused = st.zapret === 'paused';
  parts.push(h('div', { class: 'status-head', style: 'margin-bottom:8px' },
    h('div', {},
      h('div', { class: 'status-word ' + (st.zapret === 'on' ? 'on' : st.zapret === 'error' ? 'err' : ''), style: 'font-size:34px' }, stateText),
      paused ? h('p', { class: 'status-sub' }, 'Пока включён VPN: на этом компьютере zapret и VPN мешают друг другу, поэтому YouTube и Discord сейчас идут через сервер. Выключите VPN — zapret включится сам.')
        : st.zapret_error ? h('p', { class: 'status-sub err' }, linkify(st.zapret_error)) : h('p', { class: 'status-sub' }, z.installed ? (ANDROID ? 'Стратегия: ' + stratName(z.strategy) : 'Версия ' + (z.version || 'неизвестна') + ', стратегия ' + (z.strategy || '').replace(/\.bat$/i, '')) : 'zapret ещё не скачан')),
    h('button', {
      class: 'btn big ' + (z.enabled ? '' : 'primary'), disabled: testing,
      onclick: async () => { await act(() => api('zapret/enable', { on: !z.enabled })); setTimeout(() => { tick().then(renderZapret); }, 1800); },
    }, z.enabled ? 'Выключить zapret' : 'Включить zapret')));

  if (!z.installed && !ANDROID) {
    parts.push(h('div', { class: 'callout' }, 'zapret скачивается с официального GitHub Flowseal при первом включении.',
      h('div', { class: 'row-actions', style: 'margin-top:8px' }, h('button', { class: 'btn', onclick: () => act(() => api('zapret/install', {}), 'Загрузка началась') }, 'Скачать сейчас'))));
  }
  if (z.conflicts && z.conflicts.length) {
    parts.push(h('div', { class: 'callout err' },
      'Мешают другие программы обхода: ' + z.conflicts.join(', ') + '. Вместе они не работают.',
      h('div', { class: 'row-actions', style: 'margin-top:8px' },
        h('button', { class: 'btn', onclick: async () => { await act(() => api('zapret/fix', {}), 'Конфликты убраны'); renderZapret(); } }, 'Убрать конфликты'))));
  }

  if (z.installed) {
    await loadStrats();
    const sel = S.strats && S.strats.list && S.strats.list.length
      ? strategySelect(S.strats, { disabled: testing }, () => { renderZapret(); tick(); })
      : h('select', { disabled: true }, h('option', {}, (z.strategy || '').replace(/\.bat$/i, '')));
    parts.push(
      h('h2', {}, 'Стратегия'),
      h('p', { class: 'hint' }, ANDROID ? 'Разные провайдеры и сети (Wi-Fi, мобильный интернет) ловят по-разному. Автоподбор по очереди пробует стратегии и оставляет ту, с которой открывается больше всего. Займёт пару минут. Сменили сеть и YouTube снова тормозит — подберите ещё раз.'
        : 'Разные провайдеры ловят по-разному. Автоподбор по очереди пробует все стратегии Flowseal и оставляет ту, с которой открывается больше всего. Займёт пару минут, YouTube и Discord в это время могут подвисать.'),
      h('div', { class: 'row-actions' }, sel,
        h('button', { class: 'btn primary', disabled: testing, onclick: async () => { await act(() => api('zapret/autoselect', {}), 'Подбор начат'); tick(); } }, testing ? 'Подбираю…' : 'Подобрать автоматически'),
        h('button', { class: 'btn', disabled: testing || checking, onclick: async () => { await act(() => api('zapret/check', {})); tick(); } }, checking ? 'Проверяю…' : 'Проверить сейчас')));

    const check = jobs['zapret-check'];
    if (check && check.result && check.result.results) {
      const sm = check.result.summary;
      parts.push(h('h2', {}, 'Последняя проверка'),
        h('p', { class: 'hint' }, 'Открывается ' + sm.ok + ' из ' + sm.total + ': YouTube ' + sm.youtube + ' из 4, Discord ' + sm.discord + ' из 4.'),
        resultsTable(check.result.results));
    }
    if (z.scores && z.scores.length) {
      const best = (jobs['zapret-test'] && jobs['zapret-test'].result) ? jobs['zapret-test'].result.best : '';
      parts.push(h('h2', {}, 'Результаты подбора'),
        h('table', {},
          h('tr', {}, h('th', {}, 'Стратегия'), h('th', {}, 'YouTube'), h('th', {}, 'Discord'), h('th', {}, 'Всего'), h('th', {}, 'Отклик')),
          z.scores.map(sc => h('tr', { class: sc.file && sc.file === best ? 'best' : '' },
            h('td', {}, sc.file ? stratName(sc.file) : 'Без zapret'),
            sc.err ? h('td', { colspan: 4, class: 'no' }, sc.err) : [
              h('td', { class: 'num' }, sc.summary.youtube + ' из 4'),
              h('td', { class: 'num' }, sc.summary.discord + ' из 4'),
              h('td', { class: 'num' }, sc.summary.ok + ' из ' + sc.summary.total),
              h('td', { class: 'num' }, sc.summary.avg_ms ? sc.summary.avg_ms + ' мс' : '—')]))));
    }

    if (ANDROID) { parts.push(customStrategy(z)); put(root, ...parts); return; }
    const gf = h('select', { onchange: () => act(() => api('zapret/options', { game_filter: gf.value }), 'Применено') },
      [['disabled', 'Выключен'], ['all', 'TCP и UDP'], ['tcp', 'Только TCP'], ['udp', 'Только UDP']].map(([v, t]) => h('option', { value: v, selected: z.game_filter === v ? true : undefined }, t)));
    const ip = h('select', { onchange: () => act(() => api('zapret/options', { ipset: ip.value }), 'Применено') },
      [['none', 'Не использовать'], ['loaded', 'Список IP Flowseal'], ['any', 'Любые адреса']].map(([v, t]) => h('option', { value: v, selected: z.ipset === v ? true : undefined }, t)));
    parts.push(
      h('h2', {}, 'Тонкая настройка'),
      h('div', { class: 'grid2' },
        h('div', { class: 'field' }, h('label', {}, 'Game Filter'), gf, h('small', {}, 'Обход для игр на портах выше 1023. Включайте, только если игра не работает: может сломать другие программы.')),
        h('div', { class: 'field' }, h('label', {}, 'IPSet'), ip, h('small', {}, 'Обход по адресам, а не только по доменам. Нужен некоторым играм и сервисам; по умолчанию выключен.'))),
      h('div', { class: 'panel', style: 'margin-top:14px' },
        sw('Только основной сетевой адаптер', 'zapret не трогает трафик внутри VPN-туннеля. Адаптер определяется сам' + (z.if_index ? ', сейчас № ' + z.if_index : '') + '; при смене сети zapret перезапускается.', z.bind_physical,
          v => act(() => api('zapret/options', { bind_physical: v }), 'Применено')),
        sw('Выключать zapret, пока работает VPN', 'На некоторых компьютерах пакеты, которые отправляет zapret, попадают в туннель VPN, и VPN перестаёт работать. Лазейка включает это сама, если заметит такое. Пока VPN включён, YouTube и Discord идут через сервер.', z.pause_with_vpn === 'on',
          v => act(() => api('zapret/options', { pause_with_vpn: v ? 'on' : 'off' }), 'Применено'))));

    const lists = [
      ['list-general-user.txt', 'Дополнительные сайты для zapret', 'Домены, которые тоже нужно «ускорять», по одному на строку.'],
      ['list-exclude-user.txt', 'Не трогать эти сайты', 'Если сайт ломается при включённом zapret.'],
      ['ipset-exclude-user.txt', 'Не трогать эти адреса', 'Адреса ваших серверов добавляются сюда сами.'],
    ];
    const listEls = await Promise.all(lists.map(async ([name, label, hint]) => {
      let text = '';
      try { text = (await api('zapret/list?name=' + encodeURIComponent(name))).text; } catch (e) { /* missing */ }
      const ta = h('textarea', { rows: 5, spellcheck: 'false', value: text });
      return h('div', { class: 'field' }, h('label', {}, label), ta, h('small', {}, hint),
        h('div', { class: 'row-actions', style: 'margin-top:6px' },
          h('button', { class: 'btn mini', onclick: () => act(() => api('zapret/list', { name, text: ta.value }), 'Сохранено') }, 'Сохранить')));
    }));
    parts.push(h('h2', {}, 'Списки'), h('div', { class: 'grid2' }, listEls),
      h('div', { class: 'row-actions', style: 'margin-top:16px' },
        h('button', { class: 'btn', onclick: () => act(() => api('zapret/ipset-update', {}), 'Список IP обновлён') }, 'Обновить список IP Flowseal'),
        h('button', { class: 'btn', onclick: () => act(() => api('zapret/install', {}), 'Обновление началось') }, 'Переустановить zapret')));
  }
  put(root, ...parts);
}

/* ---------- settings ---------------------------------------------------------- */

function selfUpdatePanel(u) {
  if (!u) return null;
  const st = S.status || {};
  const running = st.jobs && st.jobs['self-update'] && st.jobs['self-update'].running;
  let text;
  if (u.available) text = h('span', {}, 'Доступна версия ', h('b', {}, u.latest), ', у вас ', u.current, '.');
  else if (u.error) text = h('span', { class: 'no' }, u.error);
  else if (u.latest) text = h('span', {}, 'У вас последняя версия, ', h('b', {}, u.current), '.');
  else text = h('span', {}, 'У вас версия ', h('b', {}, u.current), '. Новые версии ещё не проверялись.');
  return h('div', { class: 'panel' },
    h('p', { style: 'margin:0' }, text),
    u.available && u.notes ? h('p', { class: 'hint', style: 'margin:6px 0 0' }, u.notes) : null,
    h('div', { class: 'row-actions', style: 'margin-top:10px' },
      u.available ? h('button', { class: 'btn primary', disabled: running, onclick: startSelfUpdate }, running ? 'Обновляю…' : 'Обновить до ' + u.latest) : null,
      h('button', { class: 'btn', onclick: async () => { await act(() => api('selfupdate/check', {})); renderSettings(); tick(); } }, 'Проверить сейчас')),
    h('p', { class: 'hint', style: 'margin:8px 0 0' }, 'Новая версия скачивается в папку Лазейки, сверяется по SHA-256 и ставится по кнопке. Источник — github.com/brucewayner015-crypto/lazeyka.'));
}

function defenderPanel(d) {
  if (!d || !d.supported) return null;
  const cmd = "Add-MpPreference -ExclusionPath 'C:\\ProgramData\\Lazeyka'";
  let state;
  if (!d.checked && !d.error) state = 'Проверяю…';
  else if (d.error) state = h('span', { class: 'no' }, 'Защитник Windows не ответил (нужны права администратора): ' + d.error);
  else if (!d.active) state = 'Защитник Windows сейчас не основной антивирус (' + (d.mode || 'пассивный режим') + '). Если ваш антивирус удаляет Лазейку или драйвер zapret, добавьте папку в исключения в нём.';
  else if (d.excluded) state = h('span', { style: 'color:var(--spruce)' }, 'Папка C:\\ProgramData\\Lazeyka уже в исключениях Защитника.');
  else state = 'Папка пока не в исключениях Защитника.';
  const box = h('code', { style: 'flex:1;min-width:0;overflow-x:auto;white-space:nowrap;font-family:ui-monospace,monospace;background:rgba(127,127,127,.14);padding:6px 10px;border-radius:7px' }, cmd);
  return [
    h('h2', {}, 'Защитник Windows'),
    h('div', { class: 'panel' },
      h('p', { class: 'hint', style: 'margin:0 0 10px' }, 'Защитник иногда принимает Лазейку и драйвер zapret (WinDivert) за вирус. Если это мешает — добавьте папку Лазейки в исключения сами: запустите PowerShell от имени администратора и выполните команду. Настройки антивируса Лазейка сама не меняет.'),
      h('div', { style: 'display:flex;gap:8px;align-items:center' }, box,
        h('button', { class: 'btn mini', onclick: () => navigator.clipboard.writeText(cmd).then(() => toast('Скопировано'), () => toast('Не удалось скопировать', true)) }, 'Копировать')),
      h('p', { class: 'hint', style: 'margin:10px 0 0' }, state)),
  ];
}

async function startSelfUpdate() {
  await act(() => api('selfupdate/install', {}), 'Скачиваю новую версию');
  S.updating = true;
  tick();
}

async function renderSettings() {
  const root = $('#tab-settings');
  S.settings = await api('settings');
  const e = await api('engines');
  const self = await api('selfupdate').catch(() => null);
  const def = await api('defender').catch(() => null);
  const a = S.settings.app;
  const ui = S.settings.ui || {};
  const setApp = (k, v) => act(() => api('app', { [k]: v }), 'Сохранено');
  const uiSet = patch => setUI(patch);
  const port = h('input', { type: 'number', min: 0, max: 65535, value: a.mixed_port || 0, style: 'width:120px' });
  const stack = h('select', { onchange: () => setApp('tun_stack', stack.value) },
    [['mixed', 'Смешанный (рекомендуется)'], ['system', 'Системный'], ['gvisor', 'gVisor']].map(([v, t]) => h('option', { value: v, selected: a.tun_stack === v ? true : undefined }, t)));
  const engRow = (name, cur, latest, upd, key) => h('tr', {},
    h('td', {}, name),
    h('td', {}, cur || 'не установлен'),
    h('td', {}, latest || (e.checked ? '—' : 'не проверялось')),
    h('td', {}, h('button', { class: 'btn mini', disabled: !(upd || !cur), onclick: async () => { await act(() => api('engines/update', { name: key }), 'Загрузка началась'); tick(); } }, cur ? 'Обновить' : 'Скачать')));

  put(root,
    h('h1', {}, 'Настройки'),
    h('h2', {}, 'Запуск'),
    h('div', { class: 'panel' },
      ANDROID ? null : sw('Запускать вместе с Windows', 'Без запроса прав: через планировщик задач.', a.autostart, v => setApp('autostart', v)),
      sw('Включать VPN при запуске', 'Если есть хотя бы один сервер или подписка.', a.auto_connect, v => setApp('auto_connect', v)),
      ANDROID ? null : sw('При автозапуске не открывать окно', 'Лазейка остаётся в трее, окно открывается по щелчку на значке.', a.start_minimized, v => setApp('start_minimized', v)),
      ANDROID ? null : sw('Проверять обновления', 'Лазейки — дважды в день, mihomo и zapret — раз в день, с GitHub.', a.check_updates, v => setApp('check_updates', v)),
      ANDROID ? h('p', { class: 'hint', style: 'margin:8px 0 0' }, 'Чтобы VPN включался вместе с телефоном и не выключался системой: Настройки Android → Сеть → VPN → ⚙ у Лазейки → «Постоянная VPN». Там же «Блокировать соединения без VPN», если нужно, чтобы ничего не шло мимо.') : null),
    ANDROID ? null : h('h2', {}, 'Обновление Лазейки'),
    ANDROID ? null : selfUpdatePanel(self),
    ANDROID ? null : defenderPanel(def),
    h('h2', {}, 'Панель слева'),
    h('p', { class: 'hint' }, 'Переключатели VPN и zapret видны на любой вкладке. Здесь — что показывать под ними.'),
    h('div', { class: 'panel' },
      sw('Выбор сервера', 'Через какой сервер идёт заблокированное.', !ui.hide_server, v => uiSet({ hide_server: !v })),
      sw('Страна выхода', 'Определяется через страницу Cloudflare тем же путём, что и заблокированное.', !ui.hide_country, v => uiSet({ hide_country: !v })),
      sw('Пинг сервера', 'Задержка сервера, через который сейчас идёт заблокированное.', !ui.hide_ping, v => uiSet({ hide_ping: !v })),
      sw('Скорость', 'Сколько сейчас идёт через Лазейку: загрузка и отдача.', !ui.hide_speed, v => uiSet({ hide_speed: !v })),
      sw('Время работы VPN', 'Сколько VPN включён без перерыва.', !ui.hide_uptime, v => uiSet({ hide_uptime: !v })),
      sw('Стратегия zapret', 'Список стратегий: те, что помогли на этом компьютере, — сверху.', !ui.hide_strategy, v => uiSet({ hide_strategy: !v })),
      sw('Только переключатели', 'Скрыть всё остальное. То же делает «Скрыть подробности» в самой панели.', !!ui.panel_collapsed, v => uiSet({ panel_collapsed: v }))),
    h('h2', {}, 'Движки'),
    ANDROID ? h('p', { class: 'hint' }, 'Встроены в приложение и обновляются вместе с ним: mihomo ' + (e.mihomo || '—') + ', ByeDPI.') : [
    h('p', { class: 'hint' }, 'Скачиваются только с официальных страниц GitHub, файл сверяется с контрольной суммой SHA-256 из релиза.'),
    h('table', {},
      h('tr', {}, h('th', {}, 'Движок'), h('th', {}, 'Установлен'), h('th', {}, 'Последний'), h('th', {}, '')),
      engRow('mihomo', e.mihomo, e.mihomo_latest, e.mihomo_update, 'mihomo'),
      engRow('zapret (Flowseal)', e.zapret, e.zapret_latest, e.zapret_update, 'zapret')),
    e.error ? h('p', { class: 'hint no' }, e.error) : null,
    h('div', { class: 'row-actions', style: 'margin-top:10px' },
      h('button', { class: 'btn', onclick: async () => { await act(() => api('engines/check', {})); renderSettings(); } }, 'Проверить обновления'))],
    h('h2', {}, 'Сеть'),
    h('div', { class: 'grid2' },
      h('div', { class: 'field' }, h('label', {}, 'Локальный прокси для программ'),
        h('div', { class: 'row-actions' }, port, h('button', { class: 'btn', onclick: () => setApp('mixed_port', parseInt(port.value || '0', 10)) }, 'Сохранить')),
        h('small', {}, '0 — выключен (рекомендуется). Весь трафик и так идёт через виртуальный адаптер, а открытый порт на 127.0.0.1 помогает приложениям вычислить VPN.')),
      ANDROID ? null : h('div', { class: 'field' }, h('label', {}, 'Сетевой стек туннеля'), stack, h('small', {}, 'Меняйте, только если что-то не работает в смешанном режиме.'))),
    h('h2', {}, 'Диагностика'),
    h('div', { class: 'panel' },
      sw('Подробный журнал', 'Записывает каждое соединение. Включайте только для поиска проблем.', a.verbose, v => setApp('verbose', v)),
      h('div', { class: 'row-actions', style: 'margin-top:8px' },
        h('a', { class: 'btn', href: '/api/diag', download: 'lazeyka-diag.txt' }, 'Скачать отчёт'),
        h('span', { class: 'hint', style: 'margin:0' }, 'В отчёте нет ключей, паролей и ссылок подписок.'))),
    h('h2', {}, 'Выход и удаление'),
    h('div', { class: 'row-actions' },
      h('button', { class: 'btn', onclick: () => confirm('Закрыть Лазейку? VPN и zapret выключатся.') && api('quit', {}) }, 'Выйти из Лазейки'),
      ANDROID ? null : h('button', {
        class: 'btn danger', onclick: () => {
          if (confirm('Удалить Лазейку с компьютера? Серверы, настройки, mihomo и zapret будут удалены.')) {
            api('uninstall', {}).then(() => toast('Лазейка удаляется'));
          }
        },
      }, 'Удалить Лазейку')));
}

/* ---------- log ---------------------------------------------------------------- */

function renderLog() {
  const root = $('#tab-log');
  const box = h('div', { class: 'logbox', id: 'logbox' });
  const seg = h('div', { class: 'seg' }, [['', 'Все'], ['app', 'Приложение'], ['mihomo', 'mihomo'], ['zapret', 'zapret']].map(([v, t]) =>
    h('button', { 'aria-pressed': String(S.logFilter === v), onclick: () => { S.logFilter = v; renderLog(); } }, t)));
  put(root,
    h('h1', {}, 'Журнал'),
    h('div', { class: 'filters' }, seg,
      h('label', { class: 'switch', style: 'padding:0' }, h('input', { type: 'checkbox', checked: S.logErrors, onchange: e => { S.logErrors = e.target.checked; renderLog(); } }), 'Только ошибки'),
      h('button', {
        class: 'btn mini', onclick: () => {
          navigator.clipboard.writeText(box.innerText).then(() => toast('Скопировано'), () => toast('Не удалось скопировать', true));
        },
      }, 'Копировать')),
    box);
  drawLog(true);
}

function drawLog(full) {
  const box = $('#logbox');
  if (!box) return;
  const nearBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 40;
  const want = e => (!S.logFilter || e.src === S.logFilter) && (!S.logErrors || e.level === 'error' || e.level === 'warn');
  const lineEl = e => h('div', { class: 'l-' + e.level },
    h('span', { class: 'l-src' }, new Date(e.time).toLocaleTimeString('ru-RU') + ' ' + e.src + ' '), e.msg);
  if (full) put(box, ...S.logs.filter(want).map(lineEl));
  if (nearBottom || full) box.scrollTop = box.scrollHeight;
}

async function pollLogs() {
  try {
    const rows = await api('logs?since=' + S.logSince);
    if (rows.length) {
      S.logSince = rows[rows.length - 1].id;
      S.logs.push(...rows);
      if (S.logs.length > 3000) S.logs = S.logs.slice(-3000);
      if (S.tab === 'log') {
        const box = $('#logbox');
        const want = e => (!S.logFilter || e.src === S.logFilter) && (!S.logErrors || e.level === 'error' || e.level === 'warn');
        if (box) {
          const nearBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 40;
          for (const e of rows.filter(want)) {
            box.append(h('div', { class: 'l-' + e.level }, h('span', { class: 'l-src' }, new Date(e.time).toLocaleTimeString('ru-RU') + ' ' + e.src + ' '), e.msg));
          }
          if (nearBottom) box.scrollTop = box.scrollHeight;
        }
      }
    }
  } catch (e) { /* app closed */ }
}

/* ---------- main loop ---------------------------------------------------------- */

RENDER.home = () => renderHome();
RENDER.servers = () => renderServers().catch(e => toast(e.message, true));
RENDER.rules = () => renderRules().catch(e => toast(e.message, true));
RENDER.zapret = () => renderZapret().catch(e => toast(e.message, true));
RENDER.settings = () => renderSettings().catch(e => toast(e.message, true));
RENDER.log = () => renderLog();

let lastVPN = '', lastZap = '', groupsAt = 0, offline = false;

async function tick() {
  try {
    S.status = await api('state');
    setPlatform(S.status);
    if (offline) { offline = false; toast('Лазейка снова на связи'); }
  } catch (e) {
    const updating = S.updating || (S.status && S.status.jobs && S.status.jobs['self-update'] && S.status.jobs['self-update'].running);
    if (!offline) {
      offline = true;
      // after an update the new version opens its own window: this one is done
      if (updating) {
        toast('Лазейка обновляется, окно откроется заново');
        setTimeout(() => window.close(), 6000);
      } else {
        toast(e.message, true);
      }
    }
    return;
  }
  if (!S.settings) S.settings = await api('settings');
  const st = S.status;
  const changed = st.vpn !== lastVPN || st.zapret !== lastZap;
  if (changed || Date.now() - groupsAt > 4000) {
    groupsAt = Date.now();
    await loadGroups();
  }
  renderJobs();
  renderFoot();
  await loadQuick(st);
  renderQuick();
  if (S.tab === 'home') renderHome();
  if (changed && lastVPN && (S.tab === 'servers' || S.tab === 'zapret')) RENDER[S.tab]();
  lastVPN = st.vpn; lastZap = st.zapret;
}

(async function start() {
  await tick();
  showTab('home');
  setInterval(tick, 1500);
  setInterval(pollLogs, 2000);
  pollLogs();
})();
