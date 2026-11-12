import './style.css';
import {
  AddDirect, AddExit, AddUser, AllowBridgeOnExit, BackupServer, ChooseBackupOpen, ChooseBackupSave, AutoExit, ChangeBuiltin, CheckExits, CheckReach, CheckSNI, DeleteServer, ExitLink, Health, Install, ListBuiltin, ListExits,
  ListServers, ListUsers, QRCode, RemoveExit, RemoveUser, SaveServer, ScanSNI, Status, TrustServer, Uninstall,
  CloseExit, InspectBackup, ListDirect, MigrateUsers, OpenExit, RemoveDirect, ResetUserTraffic, RestoreBackup, SetCountry, SetUserEnabled, SetUserLimit,
  LatestXray, UpdateGeodata, UpdateTool, UpdateXray, UseExit,
  ClientConnect, ClientDisconnect, ClientEnableTUN, ClientState,
  ChooseGeoFiles, ChooseXrayFile, ImportXray, UpdateGeodataFromFiles, UpdateXrayFromFile,
} from '../wailsjs/go/main/App';
import { ClipboardSetText, EventsOn, WindowSetTitle } from '../wailsjs/runtime/runtime';

const root = document.getElementById('app');
const state = { servers: [], selected: null, view: 'empty', editing: null, health: {}, healthRunning: false, client: null };
let logTarget = null;

// Весь текст попадает в страницу через textContent: данные с серверов разметкой не становятся.
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled') el[k] = Boolean(v);
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}

function modal(build) {
  return new Promise((resolve) => {
    const close = (v) => { overlay.remove(); resolve(v); };
    const overlay = h('div', { class: 'overlay' }, h('div', { class: 'modal' }, build(close)));
    document.body.append(overlay);
  });
}

function confirmDialog(title, text, okLabel = 'Продолжить', extra = null) {
  return modal((close) => [
    h('h3', {}, title), h('p', {}, text), extra,
    h('div', { class: 'modal-actions' },
      h('button', { onclick: () => close(false) }, 'Отмена'),
      h('button', { class: 'primary', onclick: () => close(true) }, okLabel)),
  ]);
}

const msg = (e) => String(e && e.message ? e.message : e);

function passwordDialog(title, text, confirm, extra = null) {
  return modal((close) => {
    const pw = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'пароль' });
    const pw2 = confirm ? h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'ещё раз', style: 'margin-top:6px' }) : null;
    const err = h('p', { class: 'fail', style: 'min-height:1.2em;margin:6px 0 0' });
    const ok = () => {
      if (pw.value.length < 8) { err.textContent = 'Пароль должен быть не короче 8 символов.'; return; }
      if (confirm && pw.value !== pw2.value) { err.textContent = 'Пароли не совпадают.'; return; }
      close(pw.value);
    };
    return [h('h3', {}, title), h('p', {}, text), pw, pw2, extra, err,
      h('div', { class: 'modal-actions' },
        h('button', { onclick: () => close(null) }, 'Отмена'),
        h('button', { class: 'primary', onclick: ok }, 'Продолжить'))];
  });
}

// Подтверждение ключа сервера при первом подключении, затем повтор действия.
async function withHost(id, action) {
  try {
    return await action();
  } catch (e) {
    const m = msg(e);
    if (m.startsWith('UNKNOWN_HOST:')) {
      const [keyType, fp] = m.slice('UNKNOWN_HOST:'.length).split(' ');
      const ok = await confirmDialog('Новый сервер',
        'Приложение подключается к этому серверу впервые. Если можете, сравните отпечаток с тем, что показывает панель хостера. Отпечаток должен быть того же типа: у сервера обычно несколько ключей, и у каждого свой отпечаток.',
        'Доверять', h('p', { class: 'mono' }, `${keyType}\n${fp}`));
      if (!ok) throw new Error('Подключение отменено: ключ сервера не подтверждён.');
      await TrustServer(id, fp);
      await refreshServers();
      return action();
    }
    if (m.startsWith('HOST_KEY_CHANGED:')) {
      throw new Error('Ключ сервера изменился, подключение остановлено. Если вы не переустанавливали сервер, это может быть перехват. '
        + 'Если переустанавливали, удалите сервер из приложения и добавьте заново.\nНовый отпечаток: '
        + m.slice('HOST_KEY_CHANGED:'.length));
    }
    throw e;
  }
}

async function refreshServers() {
  state.servers = (await ListServers()) || [];
}

function formatBytes(n) {
  if (n === null || n === undefined) return '—';
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

function formatUptime(s) {
  if (s === null || s === undefined) return '—';
  const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d} д ${hh} ч` : `${hh} ч ${m} мин`;
}

// --- Наблюдение: exitctl health на всех серверах при запуске и каждые 15 минут, пока открыто приложение.
const HEALTH_EVERY_MS = 15 * 60 * 1000;
const HEALTH_TITLES = { ok: 'проблем нет', warn: 'есть предупреждения', fail: 'есть проблемы', none: 'не настроен', unknown: 'не проверен' };
const timeStr = (d) => d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });

async function checkHealth(id) {
  let entry;
  try {
    const rep = await Health(id);
    entry = !rep.installed ? { level: 'none', problems: [], warnings: [] }
      : { level: rep.problems.length ? 'fail' : rep.warnings.length ? 'warn' : 'ok', problems: rep.problems, warnings: rep.warnings };
  } catch (e) {
    const m = msg(e);
    // Ключ сервера подтверждает только пользователь: фоновая проверка диалогов не показывает.
    entry = m.startsWith('UNKNOWN_HOST:')
      ? { level: 'unknown', problems: [], warnings: ['ключ сервера ещё не подтверждён: откройте сервер, чтобы его проверять'] }
      : { level: 'fail', warnings: [], problems: [m.startsWith('HOST_KEY_CHANGED:')
        ? 'ключ сервера изменился, подключение остановлено: откройте сервер, чтобы узнать подробности'
        : `не удалось связаться с сервером: ${m}`] };
  }
  if (!state.servers.some((s) => s.id === id)) return;
  state.health[id] = { ...entry, at: new Date() };
  updateHealthViews(id);
}

async function checkAllHealth() {
  if (state.healthRunning) return;
  state.healthRunning = true;
  updateSide();
  try {
    for (const s of [...state.servers]) await checkHealth(s.id);
  } finally {
    state.healthRunning = false;
    updateSide();
  }
}

function updateSide() {
  document.querySelector('aside.side')?.replaceWith(renderSide());
  const bad = state.servers.filter((s) => state.health[s.id]?.level === 'fail').length;
  WindowSetTitle(bad ? `Переправа — проблемы: ${bad}` : 'Переправа');
}

function updateHealthViews(id) {
  updateSide();
  document.querySelectorAll(`[data-health="${id}"]`).forEach((el) => el.replaceWith(healthNotice(id)));
}

function healthNotice(id) {
  const hs = state.health[id];
  const box = h('div', { 'data-health': id });
  if (!hs || hs.level === 'none') return box;
  if (hs.level === 'ok') {
    box.append(h('p', { class: 'hint pass', style: 'margin:0 0 10px' }, `Наблюдение: проблем нет, проверено в ${timeStr(hs.at)}.`));
    return box;
  }
  const again = h('button', { style: 'margin-top:8px' }, 'Проверить снова');
  again.addEventListener('click', () => { again.disabled = true; checkHealth(id); });
  box.append(h('div', { class: `notice${hs.level === 'fail' ? ' notice-bad' : ''}` },
    h('b', {}, hs.level === 'fail' ? 'Проблемы на сервере' : 'Стоит проверить'),
    h('ul', { class: 'health-list' }, [...hs.problems, ...hs.warnings].map((t) => h('li', {}, t))),
    h('small', {}, `Проверено в ${timeStr(hs.at)}. Приложение проверяет все серверы каждые 15 минут, пока оно открыто.`),
    h('div', {}, again)));
  return box;
}

function renderSide() {
  const last = Object.values(state.health).map((x) => x.at).sort((a, b) => b - a)[0];
  const checkBtn = h('button', { class: 'link-btn', disabled: state.healthRunning || !state.servers.length },
    state.healthRunning ? 'Проверяю серверы...' : 'Проверить все');
  checkBtn.addEventListener('click', checkAllHealth);
  return h('aside', { class: 'side' },
    h('h1', {}, 'Переправа'),
    h('button', {
      class: `server-item client-item${state.view === 'client' ? ' active' : ''}`,
      onclick: openClient,
      title: state.client?.running ? 'Клиент подключён' : 'Клиент выключен',
    }, h('span', { class: `dot dot-${state.client?.running ? 'ok' : 'unknown'}` }), 'Подключение',
    h('small', {}, state.client?.running ? `к ${state.client.name || state.client.host}` : 'выключено')),
    state.servers.map((s) => {
      const level = state.health[s.id]?.level || 'unknown';
      return h('button', {
        class: `server-item${state.selected === s.id && state.view === 'server' ? ' active' : ''}`,
        onclick: () => openServer(s.id),
        title: HEALTH_TITLES[level],
      }, h('span', { class: `dot dot-${level}` }), s.name, h('small', {}, `${s.user}@${s.host}`));
    }),
    h('button', { onclick: () => openForm(null) }, '+ Добавить сервер'),
    h('div', { class: 'side-foot' }, last && !state.healthRunning ? h('small', {}, `Проверено в ${timeStr(last)}`) : null, checkBtn));
}

function render(main) {
  root.replaceChildren(renderSide(), h('main', { class: 'main' }, main));
}

function renderEmpty() {
  render(h('div', { class: 'empty' }, state.servers.length
    ? 'Выберите сервер слева.' : 'Добавьте первый сервер: понадобится его адрес и доступ по SSH.'));
}

function openForm(server) {
  state.view = 'form';
  state.editing = server;
  const f = {
    name: h('input', { value: server?.name || '' }),
    host: h('input', { value: server?.host || '' }),
    port: h('input', { type: 'number', min: 1, max: 65535, value: server?.port || 22 }),
    user: h('input', { value: server?.user || 'root' }),
    auth: h('select', {},
      h('option', { value: 'password' }, 'Пароль'),
      h('option', { value: 'key' }, 'SSH-ключ')),
    password: h('input', { type: 'password', autocomplete: 'off' }),
    keyPath: h('input', { value: server?.keyPath || '' }),
    passphrase: h('input', { type: 'password', autocomplete: 'off' }),
    sudo: h('input', { type: 'password', autocomplete: 'off' }),
  };
  f.auth.value = server?.authType || 'password';
  const pwBox = h('label', { class: 'field' },
    h('span', {}, server?.hasPassword ? 'Пароль (оставьте пустым, чтобы не менять)' : 'Пароль'), f.password);
  const keyBox = h('div', {},
    h('label', { class: 'field' }, h('span', {}, 'Путь к файлу ключа'), f.keyPath),
    h('label', { class: 'field' }, h('span', {}, 'Пароль ключа, если есть'), f.passphrase));
  const syncAuth = () => {
    pwBox.hidden = f.auth.value !== 'password';
    keyBox.hidden = f.auth.value !== 'key';
  };
  f.auth.addEventListener('change', syncAuth);
  syncAuth();
  const errorBox = h('div');

  const save = async () => {
    errorBox.replaceChildren();
    try {
      const saved = await SaveServer({
        id: server?.id || '', name: f.name.value.trim(), host: f.host.value, port: Number(f.port.value),
        user: f.user.value, authType: f.auth.value, keyPath: f.keyPath.value, password: f.password.value,
        passphrase: f.passphrase.value, sudoPassword: f.sudo.value,
      });
      await refreshServers();
      openServer(saved.id);
    } catch (e) {
      errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
    }
  };

  render([
    h('h2', {}, server ? 'Настройки сервера' : 'Новый сервер'),
    h('p', { class: 'subtitle' }, 'Данные хранятся только на этом компьютере, пароли зашифрованы ключом вашей учётной записи Windows.'),
    h('div', { class: 'panel form' }, errorBox,
      h('label', { class: 'field' }, h('span', {}, 'Название'), f.name),
      h('div', { class: 'grid2' },
        h('label', { class: 'field' }, h('span', {}, 'Адрес'), f.host),
        h('label', { class: 'field' }, h('span', {}, 'Порт SSH'), f.port)),
      h('label', { class: 'field' }, h('span', {}, 'Пользователь'), f.user),
      h('label', { class: 'field' }, h('span', {}, 'Способ входа'), f.auth),
      pwBox, keyBox,
      h('label', { class: 'field' }, h('span', {}, 'Пароль sudo, если вход не под root'), f.sudo,
        h('p', { class: 'hint' }, 'Если пусто, используется пароль входа или sudo без пароля.')),
      h('div', { class: 'row' },
        h('button', { class: 'primary', onclick: save }, 'Сохранить'),
        h('button', { onclick: () => (server ? openServer(server.id) : goHome()) }, 'Отмена'))),
  ]);
}

function goHome() {
  state.view = 'empty';
  state.selected = null;
  renderEmpty();
}

async function openServer(id) {
  state.view = 'server';
  state.selected = id;
  const server = state.servers.find((s) => s.id === id);
  const body = h('div', {}, h('p', { class: 'subtitle' }, 'Подключаюсь к серверу...'));
  render([
    h('div', { class: 'row', style: 'justify-content: space-between' },
      h('h2', { style: 'margin:0;font-size:20px' }, server.name),
      h('div', { class: 'row' },
        h('button', { onclick: () => openServer(id) }, 'Обновить'),
        h('button', { onclick: () => openForm(server) }, 'Настройки'),
        h('button', { class: 'danger', onclick: () => removeServer(server) }, 'Убрать из списка'))),
    h('p', { class: 'subtitle' }, `${server.user}@${server.host}:${server.port}`),
    body,
  ]);
  try {
    const st = await withHost(id, () => Status(id));
    if (state.selected !== id || state.view !== 'server') return;
    renderServerBody(body, server, st);
  } catch (e) {
    if (state.selected !== id || state.view !== 'server') return;
    body.replaceChildren(h('div', { class: 'error' }, msg(e)));
  }
}

async function removeServer(server) {
  const ok = await confirmDialog('Убрать сервер из списка?',
    `«${server.name}» и сохранённые пароли будут удалены из приложения. На самом сервере ничего не изменится.`, 'Убрать');
  if (!ok) return;
  await DeleteServer(server.id);
  await refreshServers();
  goHome();
}

// Результат exitctl reach: связь между двумя серверами из списка.
function reachNotice(rep, fromName, toName) {
  if (rep.ok) return h('p', { class: 'hint pass' }, `${fromName} достаёт до ${toName}: связь есть.`);
  return h('div', { class: 'notice' }, `${fromName} не достаёт до ${toName}: ${rep.message}.`);
}

const MODE_NAMES = { simple: 'простой режим', bridge: 'мост', exit: 'выход' };

const stat = (label, value) => h('div', { class: 'stat' }, h('small', {}, label), h('b', {}, value));

function statusPanel(st) {
  const mem = st.memory;
  return h('div', { class: 'panel' }, h('h3', {}, 'Сервер'),
    h('div', { class: 'stats' },
      h('div', { class: 'stat' }, h('small', {}, 'Xray'),
        st.xray.active ? h('b', { class: 'pass' }, 'работает')
          : st.xray.version ? h('b', { class: 'fail' }, 'не работает') : h('b', {}, 'не установлен')),
      st.installed && stat('Режим', st.bridge_user ? 'выход и для клиентов' : MODE_NAMES[st.mode]),
      !st.installed && stat('Годится как', Object.keys(MODE_NAMES)
        .filter((m) => st.capabilities?.[m]).map((m) => MODE_NAMES[m]).join(', ') || 'ничего из вариантов'),
      st.installed && stat('SNI', st.sni),
      stat('Внешний IP', st.public_ip || '—'),
      stat('Система', st.os || '—'),
      stat('Работает', formatUptime(st.uptime_seconds)),
      stat('Нагрузка', st.load?.length ? `${st.load[0]} (ядер: ${st.cpu_count})` : '—'),
      stat('Память', mem ? `свободно ${formatBytes(mem.available)} из ${formatBytes(mem.total)}` : '—'),
      stat('Диск', `свободно ${formatBytes(st.disk.free)} из ${formatBytes(st.disk.total)}`)));
}

// Ограниченный исходящий трафик определяет, для чего сервер вообще годится.
function egressWarning(st) {
  const blocked = Object.entries(st.egress || {}).filter(([, ok]) => !ok).map(([host]) => host);
  if (!blocked.length || st.capabilities?.simple) return null;
  const tail = st.capabilities?.bridge
    ? 'Выходом или простым режимом он быть не может. Мостом — может, если достанет до выхода: это приложение проверит при добавлении выхода.'
    : 'Ни одна из ролей ему не подходит.';
  return h('div', { class: 'notice' },
    `У этого сервера ограничен исходящий трафик: нет связи с ${blocked.join(', ')}. ${tail}`);
}

function renderServerBody(body, server, st) {
  const panels = !st.installed ? [installPanel(server, st)]
    : st.mode === 'exit' ? [exitInfoPanel(server, st)]
      : st.mode === 'bridge' ? [exitsPanel(server), usersPanel(server, st), directPanel(server), migratePanel(server, st)]
        : [st.bridge_user && exitInfoPanel(server, st), usersPanel(server, st), migratePanel(server, st)].filter(Boolean);
  if (st.installed) panels.push(maintenancePanel(server, st));
  body.replaceChildren(...[healthNotice(server.id), egressWarning(st), statusPanel(st), ...panels].filter(Boolean));
  // Открытый сервер проверяем заново, если результат старше 5 минут.
  const hs = state.health[server.id];
  if (!hs || Date.now() - hs.at > 5 * 60 * 1000) checkHealth(server.id);
}

function maintenancePanel(server, st) {
  const log = h('div', { class: 'log', hidden: true });
  const errorBox = h('div');
  const buttons = [];
  // Кнопки, которые остаются неактивными и после операций: «Обновить Xray», когда версия последняя.
  const locked = new Set();
  let busy = false;
  const run = async (btn, fn, after) => {
    errorBox.replaceChildren();
    log.hidden = false;
    log.textContent = '';
    logTarget = log;
    busy = true;
    buttons.forEach((b) => { b.disabled = true; });
    try {
      await fn();
      await after();
    } catch (e) {
      errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
    } finally {
      busy = false;
      buttons.forEach((b) => { b.disabled = locked.has(b); });
    }
  };

  const geoBtn = h('button', {}, 'Обновить списки сайтов');
  geoBtn.addEventListener('click', () => run(geoBtn, () => UpdateGeodata(server.id),
    () => { log.textContent += 'Готово.\n'; }));
  // Когда GitHub недоступен и с компьютера: файлы, скачанные любым способом.
  const geoFileBtn = h('button', {}, 'Списки из файлов…');
  geoFileBtn.addEventListener('click', async () => {
    let paths;
    try {
      paths = await ChooseGeoFiles();
    } catch (e) {
      errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
      return;
    }
    if (!paths || !paths.length) return;
    run(geoFileBtn, () => UpdateGeodataFromFiles(server.id, paths), () => { log.textContent += 'Готово.\n'; });
  });
  const uninstallBtn = h('button', { class: 'danger' }, 'Снять настройку');
  uninstallBtn.addEventListener('click', async () => {
    const lost = st.mode === 'exit'
      ? 'Мост, который ходит через этот выход, потеряет его.'
      : 'Все выданные ссылки перестанут работать, пользователи и выходы будут удалены.';
    const ok = await confirmDialog('Снять настройку с сервера?',
      `С сервера будут удалены Xray, его настройки и файлы со ссылками и ключами. ${lost} Отменить это нельзя: после повторной установки ссылки будут другими.`,
      'Снять настройку');
    if (!ok) return;
    run(uninstallBtn, () => Uninstall(server.id), () => openServer(server.id));
  });
  const xrayBtn = h('button', {}, 'Обновить Xray');
  const xrayInfo = h('p', { class: 'hint', style: 'margin-bottom:8px' });
  let installed = xrayVersion(st.xray.version);
  let latest = null; // null — ещё узнаём, '' — узнать не удалось
  const showXray = () => {
    const upToDate = Boolean(installed && latest && compareVersions(installed, latest) >= 0);
    if (upToDate) locked.add(xrayBtn); else locked.delete(xrayBtn);
    if (!busy) xrayBtn.disabled = upToDate;
    xrayBtn.title = upToDate ? 'На сервере уже последняя версия Xray' : '';
    xrayInfo.textContent = `Xray на сервере: ${installed || 'версия неизвестна'}. `
      + (latest === null ? 'Узнаю последнюю версию...'
        : latest === '' ? 'Последнюю версию узнать не удалось, обновить всё равно можно.'
          : upToDate ? 'Это последняя версия, обновлять не нужно.' : `Можно обновить до ${latest}.`);
  };
  const xrayFileBtn = h('button', {}, 'Xray из файла…');
  xrayFileBtn.addEventListener('click', async () => {
    let path;
    try {
      path = await ChooseXrayFile();
    } catch (e) {
      errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
      return;
    }
    if (!path) return;
    const ok = await confirmDialog('Поставить Xray из файла?',
      `Xray из «${path.split(/[\\/]/).pop()}» заменит ${installed || 'текущую версию'}. Если рядом с архивом лежит файл .dgst, архив сверится с ним. Xray перезапустится, у подключённых будет короткий обрыв. Если новая версия не примет настройки или не запустится, вернётся старая.`,
      'Поставить');
    if (!ok) return;
    run(xrayFileBtn, () => UpdateXrayFromFile(server.id, path), async () => {
      log.textContent += 'Готово.\n';
      try { installed = xrayVersion((await Status(server.id)).xray.version); } catch { /* останется прежняя */ }
      showXray();
    });
  });
  showXray();
  LatestXray().then((v) => { latest = v; }, () => { latest = ''; }).then(showXray);
  xrayBtn.addEventListener('click', async () => {
    const ok = await confirmDialog('Обновить Xray?',
      `Xray ${latest || 'последней версии'} скачается на этом компьютере и заменит ${installed || 'текущую версию'}. Xray перезапустится, у подключённых будет короткий обрыв. Если новая версия не примет настройки или не запустится, вернётся старая.`,
      'Обновить');
    // Журнал не стираем: в нём итог — обновился Xray или уже был последней версии.
    if (!ok) return;
    run(xrayBtn, () => UpdateXray(server.id), async () => {
      log.textContent += 'Готово.\n';
      try { installed = xrayVersion((await Status(server.id)).xray.version); } catch { /* останется прежняя */ }
      showXray();
    });
  });
  // exitctl ставится на мост и простой сервер; приложение пользуется своей копией,
  // а установленная нужна тем, кто работает в консоли сервера.
  const toolOutdated = st.mode !== 'exit' && st.tool_sha256 && st.bundled_tool_sha256
    && st.tool_sha256 !== st.bundled_tool_sha256;
  const toolBtn = h('button', {}, 'Обновить exitctl на сервере');
  toolBtn.addEventListener('click', () => run(toolBtn, () => UpdateTool(server.id), () => openServer(server.id)));

  // Копия нужна мосту и простому серверу: на выходе нет пользователей.
  const saveBtn = h('button', {}, 'Сохранить копию…');
  saveBtn.addEventListener('click', async () => {
    const pw = await passwordDialog('Пароль для копии',
      'В копии будут пользователи, ключи Reality, выходы и сайты напрямую. Без пароля копию не открыть — запишите его отдельно. Не короче 8 символов.', true);
    if (!pw) return;
    const path = await ChooseBackupSave(server.name);
    if (!path) return;
    run(saveBtn, () => BackupServer(server.id, path, pw), () => { log.textContent += `Копия сохранена: ${path}\n`; });
  });
  const restoreBtn = h('button', {}, 'Восстановить из копии…');
  restoreBtn.addEventListener('click', async () => {
    errorBox.replaceChildren();
    let path;
    let info;
    try {
      path = await ChooseBackupOpen();
      if (!path) return;
      info = await InspectBackup(path);
    } catch (e) {
      errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
      return;
    }
    const keys = h('input', { type: 'checkbox', checked: true, style: 'width:auto;margin-right:6px' });
    const pw = await passwordDialog('Восстановить из копии?',
      `Копия сервера «${info.server}» (${info.host}) от ${new Date(info.created).toLocaleString('ru-RU')}. На этот сервер добавятся её пользователи со своими ключами (UUID)${st.mode === 'bridge' ? ', выходы и сайты напрямую' : ''}; занятые имена пропускаются. Xray перезапустится.`,
      false, h('label', { style: 'cursor:pointer;display:block;margin-top:8px' }, keys,
        'Восстановить и ключи Reality: pbk и sid в ссылках будут как раньше, но ссылки, уже выданные на этом сервере, перестанут работать'));
    if (!pw) return;
    run(restoreBtn, async () => {
      const rep = await RestoreBackup(server.id, path, pw, keys.checked);
      log.textContent += `Добавлены: ${rep.added.join(', ') || 'никто'}.\n`;
      if (rep.skipped.length) log.textContent += `Пропущены, такое имя или UUID уже есть: ${rep.skipped.join(', ')}.\n`;
      if (rep.exits_added.length || rep.direct_added) log.textContent += `Выходов: ${rep.exits_added.join(', ') || 'нет'}; сайтов напрямую: ${rep.direct_added}.\n`;
      rep.ignored.forEach((t) => { log.textContent += `Не восстановлено: ${t}.\n`; });
      log.textContent += `Ключи Reality ${rep.keys ? 'восстановлены' : 'не менялись'}. Новые ссылки — в списке пользователей после «Обновить».\n`;
    }, () => {});
  });

  // Списки сайтов нужны мосту и простому режиму: выход маршрутизацию по ним не делает.
  if (st.mode !== 'exit') buttons.push(geoBtn);
  buttons.push(xrayBtn);
  const fileButtons = [xrayFileBtn];
  if (st.mode !== 'exit') fileButtons.unshift(geoFileBtn);
  buttons.push(...fileButtons);
  if (toolOutdated) buttons.push(toolBtn);
  if (st.mode !== 'exit') buttons.push(saveBtn, restoreBtn);
  buttons.push(uninstallBtn);

  return h('div', { class: 'panel' }, h('h3', {}, 'Обслуживание'), errorBox, xrayInfo,
    st.mode !== 'exit' && h('p', { class: 'hint', style: 'margin-bottom:8px' },
      'Списки сайтов и адресов (geosite, geoip) обычно обновляются на сервере раз в неделю. Если серверу недоступен GitHub, обновляйте их отсюда.'),
    toolOutdated && h('p', { class: 'hint', style: 'margin-bottom:8px' },
      'На сервере старая версия exitctl. Приложению она не мешает, но в консоли сервера будут старые команды.'),
    h('div', { class: 'row' }, buttons.filter((b) => !fileButtons.includes(b))),
    h('p', { class: 'hint', style: 'margin:10px 0 6px' },
      'Если GitHub не отвечает, приложение возьмёт последние Xray и списки, сохранённые на этом компьютере. '
      + 'Если их нет, скачайте файлы любым способом и выберите их здесь.'),
    h('div', { class: 'row' }, fileButtons), updateHelp(st), log);
}

// Кнопка для установки без GitHub: архив Xray сохраняется на компьютере, после чего установку повторяют.
function xrayImportButton() {
  const note = h('p', { class: 'hint' });
  const btn = h('button', { style: 'margin-top:8px' }, 'Xray из файла…');
  btn.addEventListener('click', async () => {
    try {
      const path = await ChooseXrayFile();
      if (!path) return;
      const info = await ImportXray(path);
      note.textContent = `Сохранено на компьютере: ${info}. Нажмите «Установить» ещё раз.`;
    } catch (e) {
      note.textContent = msg(e);
    }
  });
  return h('div', {}, btn, note);
}

// Номер версии из первой строки `xray version`: «Xray 26.11.9 (Xray, ...) ...» → «26.11.9».
function xrayVersion(line) {
  const m = /^Xray\s+v?(\S+)/.exec(line || '');
  return m ? m[1] : '';
}

// Сравнивает версии вида 26.11.9 по числам: <0, 0, >0.
function compareVersions(a, b) {
  const pa = a.split('.').map((x) => parseInt(x, 10) || 0);
  const pb = b.split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

// Свёрнутая справка: заголовок и пункты списка.
function helpBlock(title, items) {
  return h('details', { class: 'help' }, h('summary', {}, title),
    h('ul', {}, items.filter(Boolean).map((t) => h('li', {}, t))));
}

function migrateHelp(st) {
  const bridge = st.mode === 'bridge';
  return helpBlock('Как проходит перенос и что изменится у пользователей', [
    `Подготовка: добавьте новый сервер в список и установите на нём ту же роль — ${bridge ? 'мост' : 'простой режим'}. Перенос сам ничего не устанавливает.`,
    bridge
      ? 'Переносятся пользователи с их ключами (UUID), выходы и сайты напрямую. Счётчики трафика не переносятся.'
      : 'Переносятся пользователи с их ключами (UUID). Счётчики трафика не переносятся.',
    'Адрес сервера и SNI в ссылках меняются всегда: у нового сервера они свои.',
    'С ключами Reality (галочка ниже) pbk и sid остаются прежними: пользователю достаточно поменять в клиенте адрес и SNI или импортировать новую ссылку. Без них нужна новая ссылка. Галочку ставьте, если на новом сервере ещё никому не выдавали ссылок: выданные там ссылки перестанут работать.',
    bridge && 'Выход пускает к себе только адрес старого моста. После переноса откройте «Выходы» на новом мосту: у недоступного выхода из списка серверов будет кнопка «Разрешить этот мост на выходе». Выход не из списка придётся открыть вручную на нём самом: ufw allow from АДРЕС_МОСТА to any port 443.',
    'Этот сервер не меняется и продолжает работать, поэтому пользователи могут переходить постепенно. Когда все перешли, снимите с него настройку в «Обслуживании».',
  ]);
}

function updateHelp(st) {
  const ex = st.mode === 'exit';
  return helpBlock('Что меняется при обновлении', [
    'Ссылки, ключи, пользователи и настройки при обновлениях не меняются: пользователям ничего делать не нужно.',
    `«Обновить Xray» перезапускает Xray: связь у всех обрывается на пару секунд, клиенты переподключаются сами${ex ? '' : ', накопленный трафик пользователей сохраняется'}. Если новая версия не примет настройки или не запустится, вернётся старая.`,
    !ex && '«Обновить списки сайтов» меняет только то, какие сайты сервер открывает напрямую. Xray перезапускается так же, с коротким обрывом. Если Xray не примет новые списки, останутся старые.',
    !ex && '«Обновить exitctl на сервере» заменяет только программу для консоли сервера. Xray не перезапускается, клиенты ничего не замечают.',
    ex && 'Если через этот выход ходит мост, во время перезапуска мост ненадолго переключится на другой живой выход или подождёт этот.',
    'Новая версия приложения просто заменяет старый .exe: список серверов хранится отдельно и сохраняется. Уже настроенные серверы она не переустанавливает; возможности, которым нужны новые настройки сервера (например, счётчики трафика), на серверах, поставленных старыми версиями, могут не работать.',
  ]);
}

function migratePanel(server, st) {
  const errorBox = h('div');
  const result = h('div');
  const target = h('select', { style: 'width:auto' }, h('option', { value: '' }, 'Куда перенести...'),
    state.servers.filter((s) => s.id !== server.id).map((s) => h('option', { value: s.id }, s.name)));
  const keys = h('input', { type: 'checkbox', style: 'width:auto;margin-right:6px' });
  const btn = h('button', {}, 'Перенести');
  const what = st.mode === 'bridge' ? 'пользователи, выходы и сайты напрямую' : 'пользователи';

  btn.addEventListener('click', async () => {
    const dst = state.servers.find((s) => s.id === target.value);
    if (!dst) {
      errorBox.replaceChildren(h('div', { class: 'error' }, 'Выберите сервер, куда переносить.'));
      return;
    }
    const keysText = keys.checked
      ? ` Ключи Reality на «${dst.name}» заменятся ключами этого сервера: ссылки, уже выданные на «${dst.name}», перестанут работать.`
      : '';
    const ok = await confirmDialog(`Перенести на «${dst.name}»?`,
      `На «${dst.name}» добавятся ${what} этого сервера; у пользователей сохранятся их ключи (UUID). Пользователи с уже занятым именем пропускаются. Xray на «${dst.name}» перезапустится.${keysText}`,
      'Перенести');
    if (!ok) return;
    errorBox.replaceChildren();
    result.replaceChildren(h('p', { class: 'hint' }, 'Переношу...'));
    btn.disabled = true;
    try {
      const rep = await withHost(dst.id, () => MigrateUsers(server.id, dst.id, keys.checked));
      const changed = rep.keys ? 'адрес и SNI' : 'адрес, SNI и ключи Reality (pbk, sid)';
      result.replaceChildren(h('div', { class: 'panel', style: 'margin:10px 0 0' },
        h('p', {}, `Добавлены: ${rep.added.join(', ') || 'никто'}.`),
        rep.skipped.length ? h('p', {}, `Пропущены, такое имя или UUID уже есть: ${rep.skipped.join(', ')}.`) : null,
        rep.exits_added.length || rep.direct_added ? h('p', {}, `Выходов добавлено: ${rep.exits_added.join(', ') || 'нет'}; сайтов напрямую: ${rep.direct_added}.`) : null,
        rep.ignored.map((t) => h('p', { class: 'hint' }, `Не перенесено: ${t}.`)),
        h('p', { class: 'hint' }, `Новые ссылки — в списке пользователей «${dst.name}»: в них изменились ${changed}. Раздайте их пользователям.`)));
    } catch (e) {
      result.replaceChildren();
      errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
    } finally {
      btn.disabled = false;
    }
  });

  return h('div', { class: 'panel' }, h('h3', {}, 'Перенос на другой сервер'), errorBox,
    h('p', { class: 'hint', style: 'margin-bottom:8px' },
      `Если этот сервер нужно заменить: на новый, уже настроенный сервер переедут ${what}. Этот сервер не изменится.`),
    h('div', { class: 'row', style: 'margin-bottom:8px' }, target, btn),
    h('label', { style: 'cursor:pointer' }, keys,
      'Перенести и ключи Reality, чтобы pbk и sid в ссылках не изменились'),
    migrateHelp(st), result);
}

function directPanel(server) {
  const list = h('div', {}, h('p', { class: 'hint' }, 'Загружаю список...'));
  const errorBox = h('div');
  const input = h('input', { placeholder: 'например gosuslugi.ru' });
  const addBtn = h('button', { class: 'primary' }, 'Добавить');
  const showError = (e) => errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));

  async function load() {
    const domains = (await ListDirect(server.id)) || [];
    list.replaceChildren(domains.length
      ? h('table', {}, h('tbody', {}, domains.map((d) => h('tr', {}, h('td', {}, d),
        h('td', { class: 'actions' }, h('button', { class: 'danger', onclick: () => remove(d) }, 'Убрать'))))))
      : h('p', { class: 'hint' }, 'Своих доменов нет: напрямую идут только сайты из встроенных списков ниже.'));
  }

  async function act(fn) {
    errorBox.replaceChildren();
    addBtn.disabled = true;
    try {
      await fn();
      await load();
    } catch (e) {
      showError(e);
    } finally {
      addBtn.disabled = false;
    }
  }

  function remove(d) {
    act(() => RemoveDirect(server.id, d));
  }

  addBtn.addEventListener('click', () => act(async () => {
    await AddDirect(server.id, input.value);
    input.value = '';
  }));

  load().catch((e) => { list.replaceChildren(); showError(e); });
  return h('div', { class: 'panel' }, h('h3', {}, 'Сайты напрямую'), errorBox,
    h('p', { class: 'hint', style: 'margin-bottom:8px' },
      'Эти домены мост открывает сам, не через выход: например, местный сайт, которого нет во встроенных списках, или сайт, который не пускает зарубежные адреса. Поддомены входят автоматически. Списки меняются без перезапуска Xray.'),
    h('div', { class: 'row', style: 'margin-bottom:10px' }, input, addBtn), list,
    builtinBlock(server));
}

// Встроенные списки моста: категории geosite, доменные зоны, geoip и сети.
function builtinBlock(server) {
  const box = h('div', {}, h('p', { class: 'hint' }, 'Загружаю встроенные списки...'));
  const errorBox = h('div');
  const entry = h('input', { placeholder: 'geosite:категория, domain:зона, geoip:страна или IP/сеть' });
  const addBtn = h('button', {}, 'Добавить в список');
  const [countryField, countryList] = countryInput('');
  const countryBtn = h('button', {}, 'Поставить списки страны');
  const buttons = [addBtn, countryBtn];

  const chip = (v) => h('span', { class: 'chip' }, v,
    h('button', { class: 'chip-x', title: 'Убрать', onclick: () => act(() => ChangeBuiltin(server.id, 'remove', v)) }, '×'));
  function show(data) {
    box.replaceChildren(
      h('p', { class: 'hint', style: 'margin:0 0 4px' }, 'Домены (geosite — готовые списки сайтов, domain — вся зона или домен с поддоменами):'),
      h('div', { class: 'chips' }, data.domains.length ? data.domains.map(chip) : h('span', { class: 'hint' }, 'пусто')),
      h('p', { class: 'hint', style: 'margin:8px 0 4px' }, 'Адреса (geoip — все адреса страны, private — локальные сети):'),
      h('div', { class: 'chips' }, data.ips.length ? data.ips.map(chip) : h('span', { class: 'hint' }, 'пусто')));
  }
  async function act(fn) {
    errorBox.replaceChildren();
    buttons.forEach((b) => { b.disabled = true; });
    try {
      show(await fn());
      return true;
    } catch (e) {
      errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
      return false;
    } finally {
      buttons.forEach((b) => { b.disabled = false; });
    }
  }
  addBtn.addEventListener('click', async () => {
    if (await act(() => ChangeBuiltin(server.id, 'add', entry.value))) entry.value = '';
  });
  countryBtn.addEventListener('click', async () => {
    const cc = countryField.value.trim().toLowerCase();
    if (!/^[a-z]{2}$/.test(cc)) {
      errorBox.replaceChildren(h('div', { class: 'error' }, 'Код страны — две латинские буквы, например ru или kz.'));
      return;
    }
    const ok = await confirmDialog('Заменить встроенные списки?',
      `Встроенные списки заменятся набором для страны ${COUNTRIES[cc] || cc.toUpperCase()}: её доменная зона, её адреса (geoip) и, если есть, готовый список её сайтов. Ваши правки встроенных списков пропадут, свои домены выше останутся.`, 'Заменить');
    if (ok) act(() => SetCountry(server.id, cc));
  });
  act(() => ListBuiltin(server.id));
  return h('div', { class: 'builtin' },
    h('h4', {}, 'Встроенные списки'),
    h('p', { class: 'hint', style: 'margin-bottom:8px' },
      'Всё, что под них попадает, мост тоже открывает сам. Отсюда их можно посмотреть и исправить, а не только дописать свои домены. Записи geosite и geoip берутся из списков сайтов на сервере (их обновляет «Обслуживание»).'),
    errorBox, box,
    h('div', { class: 'row', style: 'margin-top:10px' }, entry, addBtn),
    h('div', { class: 'row', style: 'margin-top:8px' }, countryField, countryList, countryBtn));
}

function exitInfoPanel(server, st) {
  const box = h('div', {}, h('p', { class: 'hint' }, 'Получаю ссылку...'));
  ExitLink(server.id).then((link) => {
    box.replaceChildren(h('p', { class: 'link' }, link), h('div', { class: 'row' },
      h('button', { onclick: (e) => { ClipboardSetText(link); e.target.textContent = 'Скопировано'; } }, 'Копировать')));
  }).catch((e) => box.replaceChildren(h('div', { class: 'error' }, msg(e))));
  const errorBox = h('div');
  const log = h('div', { class: 'log', hidden: true });
  // Открытие и закрытие перезапускают Xray; журнал остаётся на экране, если в нём есть предупреждение.
  const act = async (btn, fn) => {
    errorBox.replaceChildren();
    log.hidden = false;
    log.textContent = '';
    logTarget = log;
    btn.disabled = true;
    try {
      await fn();
      if (!log.textContent.includes('Внимание')) {
        openServer(server.id);
        return;
      }
      errorBox.replaceChildren(h('div', { class: 'notice' }, 'Готово, но посмотрите предупреждение в журнале ниже. ',
        h('button', { class: 'link-btn', onclick: () => openServer(server.id) }, 'Обновить страницу')));
    } catch (e) {
      errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
      btn.disabled = false;
    }
  };

  if (st.bridge_user) {
    const closeBtn = h('button', {}, 'Закрыть выход для клиентов…');
    closeBtn.addEventListener('click', async () => {
      const ok = await confirmDialog('Закрыть выход для клиентов?',
        'Порт 443 снова будет открыт только для моста, а мост продолжит работать через этот выход как раньше. '
        + 'Остальные пользователи перестанут подключаться, но их ссылки, сроки и накопленный трафик сохранятся на сервере: '
        + 'если открыть выход снова, они вернутся с прежними ссылками. Xray один раз перезапустится.',
        'Закрыть');
      if (ok) act(closeBtn, () => CloseExit(server.id));
    });
    return h('div', { class: 'panel' }, h('h3', {}, 'Выход: ссылка для моста'), errorBox,
      h('p', { class: 'hint', style: 'margin-bottom:8px' },
        'Этот выход открыт и для клиентов. Мост подключается к нему как пользователь «bridge»: не удаляйте и не отключайте его. Ссылка для моста прежняя.'), box,
      h('div', { style: 'margin-top:12px' }, closeBtn,
        h('p', { class: 'hint' }, 'Чтобы к выходу снова подключался только мост.')), log);
  }
  const openBtn = h('button', {}, 'Открыть выход и для клиентов…');
  openBtn.addEventListener('click', async () => {
    const ok = await confirmDialog('Открыть выход для клиентов?',
      'Клиенты смогут подключаться к этому серверу напрямую, без моста, а мост продолжит работать через него как раньше: его ссылка не изменится. '
      + 'Порт 443 откроется для всех, а на сервере появятся пользователи, сроки, лимиты и счётчики трафика, как в простом режиме; мост станет пользователем «bridge». '
      + 'Если выход уже открывали и закрывали, вернутся прежние пользователи с прежними ссылками. '
      + 'Учтите: чем больше клиентов знают адрес выхода, тем выше шанс, что его заметят и заблокируют, и тогда мост тоже потеряет этот выход. Xray один раз перезапустится.',
      'Открыть');
    if (ok) act(openBtn, () => OpenExit(server.id));
  });
  return h('div', { class: 'panel' }, h('h3', {}, 'Выход: ссылка для моста'), errorBox,
    h('p', { class: 'hint', style: 'margin-bottom:8px' }, 'Порт 443 этого сервера открыт только для адреса моста, указанного при установке.'), box,
    h('div', { style: 'margin-top:12px' }, openBtn,
      h('p', { class: 'hint' }, 'Чтобы клиенты подключались и сюда напрямую, без моста. Ссылка моста при этом не меняется.')), log);
}

function exitsPanel(server) {
  const list = h('div', {}, h('p', { class: 'hint' }, 'Загружаю выходы...'));
  const errorBox = h('div');
  const nameInput = h('input', { placeholder: 'имя, например nl1' });
  const linkInput = h('input', { placeholder: 'vless://...' });
  const addBtn = h('button', { class: 'primary' }, 'Добавить');
  const source = h('select', { style: 'width:auto' }, h('option', { value: '' }, 'Взять ссылку с сервера...'),
    state.servers.filter((s) => s.id !== server.id).map((s) => h('option', { value: s.id }, s.name)));
  const showError = (e) => errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));

  const act = async (fn) => {
    errorBox.replaceChildren();
    try {
      await fn();
      await load();
    } catch (e) {
      showError(e);
    }
  };

  async function load() {
    const [data, checks] = await Promise.all([ListExits(server.id), CheckExits(server.id)]);
    const health = Object.fromEntries((checks || []).map((c) => [c.name, c]));
    const exits = data.exits || [];
    if (!exits.length) {
      list.replaceChildren(h('p', { class: 'hint' }, 'Выходов нет: сейчас открываются только сайты, которые мост пускает напрямую, а остальные работать не будут.'));
      return;
    }
    const dead = exits.filter((x) => !health[x.name]?.ok).map((x) => x.name);
    // Выход из списка серверов, до которого мост не достаёт: возможно, его файрвол не знает этот мост.
    const allowButtons = exits.filter((x) => !health[x.name]?.ok).map((x) => {
      const exitServer = state.servers.find((s) => s.host === x.address && s.id !== server.id);
      if (!exitServer) return null;
      return h('button', {
        onclick: async (e) => {
          e.target.disabled = true;
          await act(() => withHost(exitServer.id, () => AllowBridgeOnExit(exitServer.id, server.id)));
        },
      }, `Разрешить этот мост на выходе «${exitServer.name}»`);
    }).filter(Boolean);
    // replaceChildren превращает null в текст «null», поэтому пустые элементы отфильтровываются.
    list.replaceChildren(...[
      dead.length ? h('div', { class: 'notice' }, `Мост не достаёт до: ${dead.join(', ')}. Проверьте адрес выхода и то, что файрвол выхода пускает этот мост (при установке выхода указывается IP моста). Если выход настроен верно, значит соединения режет хостер одного из серверов, и нужен выход в другой сети.`) : null,
      allowButtons.length ? h('div', { class: 'row', style: 'margin-bottom:10px' }, allowButtons) : null,
      h('p', { class: 'hint', style: 'margin-bottom:8px' }, data.pinned ? `Весь трафик идёт через «${data.pinned}».` : 'Автовыбор: самый быстрый живой выход.'),
      h('table', {},
        h('thead', {}, h('tr', {}, ['Имя', 'Адрес', 'Связь с моста', ''].map((t) => h('th', {}, t)))),
        h('tbody', {}, exits.map((x) => h('tr', {},
          h('td', {}, x.name), h('td', {}, `${x.address}:${x.port}`),
          h('td', { class: health[x.name]?.ok ? 'pass' : 'fail' }, health[x.name]?.ok ? `есть, ${health[x.name].ms} мс` : 'нет'),
          h('td', { class: 'actions' },
            data.pinned === x.name
              ? h('button', { onclick: () => act(() => AutoExit(server.id)) }, 'Автовыбор')
              : h('button', { onclick: () => act(() => UseExit(server.id, x.name)) }, 'Только через него'),
            h('button', { class: 'danger', onclick: () => remove(x) }, 'Удалить'))))))].filter(Boolean));
  }

  async function remove(x) {
    const ok = await confirmDialog('Удалить выход?',
      `Трафик перестанет идти через «${x.name}». Xray не перезапускается: соединения, которые шли через этот выход, могут оборваться и переподключатся через другой, у остальных связь не прервётся. На серверах, настроенных старой версией, первое изменение выходов или сайтов напрямую один раз перезапустит Xray.`, 'Удалить');
    if (ok) await act(() => RemoveExit(server.id, x.name));
  }

  source.addEventListener('change', async () => {
    if (!source.value) return;
    errorBox.replaceChildren();
    const exitServer = state.servers.find((s) => s.id === source.value);
    source.value = '';
    try {
      linkInput.value = await withHost(exitServer.id, () => ExitLink(exitServer.id));
      if (!nameInput.value) nameInput.value = exitServer.name.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32);
      const rep = await CheckReach(server.id, exitServer.id);
      if (!rep.ok) errorBox.replaceChildren(reachNotice(rep, 'Этот мост', `«${exitServer.name}»`));
    } catch (e) {
      showError(e);
    }
  });

  addBtn.addEventListener('click', async () => {
    addBtn.disabled = true;
    await act(async () => {
      await AddExit(server.id, linkInput.value, nameInput.value);
      linkInput.value = '';
      nameInput.value = '';
    });
    addBtn.disabled = false;
  });

  load().catch((e) => { list.replaceChildren(); showError(e); });
  return h('div', { class: 'panel' }, h('h3', {}, 'Выходы'), errorBox,
    h('div', { class: 'row', style: 'margin-bottom:6px' }, linkInput, source),
    h('div', { class: 'row', style: 'margin-bottom:10px' }, nameInput, addBtn), list);
}

function checksList(checks) {
  const marks = { pass: 'ОК', warn: 'Внимание', fail: 'Ошибка' };
  return h('ul', { class: 'checks' }, checks.map((c) => h('li', {},
    h('span', { class: c.status }, `${marks[c.status]}: `), c.message)));
}

// Страны для моста: код — для geoip и доменной зоны. Любой другой код можно ввести вручную.
const COUNTRIES = {
  ru: 'Россия', by: 'Беларусь', kz: 'Казахстан', uz: 'Узбекистан', kg: 'Киргизия', tj: 'Таджикистан',
  am: 'Армения', az: 'Азербайджан', ge: 'Грузия', md: 'Молдова', ua: 'Украина', tm: 'Туркменистан',
  tr: 'Турция', ir: 'Иран', cn: 'Китай',
};

function countryInput(value = 'ru') {
  const id = `countries-${Math.random().toString(36).slice(2)}`;
  return [h('input', { list: id, value, maxlength: 2, style: 'width:90px', placeholder: 'ru' }),
    h('datalist', { id }, Object.entries(COUNTRIES).map(([cc, name]) => h('option', { value: cc }, name)))];
}

const MODE_HINTS = {
  simple: 'Один сервер: клиенты подключаются к нему напрямую, и он сам выходит в интернет.',
  bridge: 'Клиенты подключаются сюда. Сайты страны моста открываются напрямую, остальное идёт через выходы, которые вы добавите после установки.',
  exit: 'Сервер за рубежом, через который мост выпускает трафик. Порт 443 будет открыт только для адреса моста.',
};

function installPanel(server, st) {
  let chosen = null;
  const allowed = Object.keys(MODE_NAMES).filter((m) => st.capabilities?.[m]);
  if (!allowed.length) {
    return h('div', { class: 'panel' }, h('h3', {}, 'Настройка'),
      h('div', { class: 'error' }, 'С этого сервера нет связи ни с зарубежными адресами, ни с ya.ru, поэтому настроить его нельзя. Проверьте сеть сервера и нажмите «Обновить».'));
  }
  let mode = allowed[0];
  const modeHint = h('p', { class: 'hint' }, MODE_HINTS[mode]);
  const bridgeIp = h('input', { placeholder: 'например 185.0.0.1' });
  const reachBox = h('div');
  const bridgePick = h('select', { style: 'width:auto' }, h('option', { value: '' }, 'Мост из списка...'),
    state.servers.filter((s) => s.id !== server.id).map((s) => h('option', { value: s.id }, s.name)));
  bridgePick.addEventListener('change', async () => {
    const bridge = state.servers.find((s) => s.id === bridgePick.value);
    bridgePick.value = '';
    if (!bridge) return;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bridge.host)) bridgeIp.value = bridge.host;
    reachBox.replaceChildren(h('p', { class: 'hint' }, `Проверяю, достаёт ли «${bridge.name}» до этого сервера...`));
    try {
      const rep = await withHost(bridge.id, () => CheckReach(bridge.id, server.id));
      reachBox.replaceChildren(reachNotice(rep, `«${bridge.name}»`, 'этого сервера'));
    } catch (e) {
      reachBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
    }
  });
  const bridgeBox = h('div', { hidden: mode !== 'exit', style: 'margin-top:10px' },
    h('label', { class: 'field', style: 'margin-bottom:4px' },
      h('span', {}, 'IP-адрес моста, который будет подключаться к этому выходу'),
      h('div', { class: 'row' }, bridgeIp, bridgePick)),
    h('p', { class: 'hint' }, 'Если мост уже есть в списке, выберите его: приложение заранее проверит, достаёт ли он до этого сервера.'),
    reachBox);
  const [countryField, countryList] = countryInput();
  const countryBox = h('div', { hidden: mode !== 'bridge', style: 'margin-top:10px' },
    h('label', { class: 'field', style: 'margin-bottom:4px' },
      h('span', {}, 'Страна моста: её сайты и адреса мост открывает сам, без выхода'),
      h('div', { class: 'row' }, countryField, countryList)),
    h('p', { class: 'hint' }, 'Код из двух букв: ru, by, kz… Списки потом можно поправить в «Сайтах напрямую».'));
  const modeRadios = Object.keys(MODE_NAMES).map((m) => {
    const radio = h('input', { type: 'radio', name: 'mode', checked: m === mode, disabled: !allowed.includes(m), style: 'width:auto;margin-right:6px' });
    radio.addEventListener('change', () => {
      mode = m;
      modeHint.textContent = MODE_HINTS[m];
      bridgeBox.hidden = m !== 'exit';
      countryBox.hidden = m !== 'bridge';
      results.replaceChildren();
      choose(null);
    });
    return h('label', { class: allowed.includes(m) ? '' : 'disabled-mode', style: 'margin-right:16px;cursor:pointer' }, radio, MODE_NAMES[m]);
  });
  const log = h('div', { class: 'log', hidden: true });
  const results = h('div');
  const errorBox = h('div');
  const summary = h('p', { class: 'hint' }, 'Домен не выбран.');
  const installBtn = h('button', { class: 'primary', disabled: true }, 'Установить');
  const manual = h('input', { placeholder: 'example.com' });

  const showError = (e) => errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
  const choose = (domain) => {
    chosen = domain;
    summary.textContent = domain ? `Выбран домен: ${domain}` : 'Домен не выбран.';
    installBtn.disabled = !domain;
  };
  const startLog = () => {
    log.hidden = false;
    log.textContent = '';
    logTarget = log;
  };

  const scanBtn = h('button', { class: 'primary' }, 'Подобрать автоматически');
  scanBtn.addEventListener('click', async () => {
    const ok = await confirmDialog('Просканировать соседние адреса?',
      'Приложение обойдёт до 253 соседних адресов в подсети сервера и прочитает их TLS-сертификаты. Это занимает до нескольких минут. Скан чужих адресов может вызвать жалобу хостеру.',
      'Сканировать');
    if (!ok) return;
    errorBox.replaceChildren();
    results.replaceChildren();
    choose(null);
    startLog();
    scanBtn.disabled = true;
    try {
      const rep = await ScanSNI(server.id, mode === 'simple' ? '' : mode);
      renderCandidates(rep);
    } catch (e) {
      showError(e);
    } finally {
      scanBtn.disabled = false;
    }
  });

  function renderCandidates(rep) {
    const candidates = rep.candidates || [];
    if (!candidates.length) {
      results.replaceChildren(h('div', { class: 'error' },
        `В подсети ${rep.subnet} подходящих доменов нет (отброшено имён: ${(rep.rejected || []).length}). Укажите свой домен ниже.`));
      return;
    }
    const items = candidates.map((c, i) => {
      const radio = h('input', { type: 'radio', name: 'sni', checked: i === 0 });
      const box = h('label', { class: `candidate${i === 0 ? ' selected' : ''}` }, radio,
        h('b', {}, c.domain), ` — оценка ${c.score}, ${c.ip}`,
        h('ul', {}, c.reasons.map((r) => h('li', {}, r))));
      radio.addEventListener('change', () => {
        results.querySelectorAll('.candidate').forEach((n) => n.classList.remove('selected'));
        box.classList.add('selected');
        choose(c.domain);
      });
      return box;
    });
    results.replaceChildren(...items);
    choose(candidates[0].domain);
  }

  const checkBtn = h('button', {}, 'Проверить');
  checkBtn.addEventListener('click', async () => {
    errorBox.replaceChildren();
    results.replaceChildren(h('p', { class: 'hint' }, 'Проверяю домен...'));
    choose(null);
    checkBtn.disabled = true;
    try {
      const rep = await CheckSNI(server.id, manual.value);
      const verdicts = { ok: 'Домен подходит.', warn: 'Домен подойдёт, но есть предупреждения.', fail: 'Домен не подходит.' };
      results.replaceChildren(h('div', {}, h('b', { class: rep.verdict === 'ok' ? 'pass' : rep.verdict }, verdicts[rep.verdict]),
        checksList(rep.checks)));
      if (rep.verdict !== 'fail') choose(rep.domain);
    } catch (e) {
      results.replaceChildren();
      showError(e);
    } finally {
      checkBtn.disabled = false;
    }
  });

  installBtn.addEventListener('click', async () => {
    if (mode === 'exit' && !bridgeIp.value.trim()) {
      showError('Укажите IP-адрес моста.');
      return;
    }
    const ports = mode === 'exit' ? `порт 443 только для моста ${bridgeIp.value.trim()}` : 'порт 443';
    const ok = await confirmDialog(`Настроить как: ${MODE_NAMES[mode]}?`,
      `На сервер будут установлены Xray и пакеты, включён файрвол ufw (останутся открыты порт SSH ${server.port} и ${ports}). SNI: ${chosen}`,
      'Установить');
    if (!ok) return;
    errorBox.replaceChildren();
    startLog();
    installBtn.disabled = true;
    scanBtn.disabled = true;
    try {
      await Install(server.id, mode, chosen, bridgeIp.value, countryField.value);
      openServer(server.id);
    } catch (e) {
      showError(e);
      if (msg(e).includes('Xray из файла')) errorBox.append(xrayImportButton());
      installBtn.disabled = false;
      scanBtn.disabled = false;
    }
  });

  return h('div', { class: 'panel' }, h('h3', {}, 'Настройка'),
    h('div', { style: 'margin-bottom:6px' }, modeRadios), modeHint, bridgeBox, countryBox,
    h('p', { class: 'hint', style: 'margin-top:10px' }, 'SNI — домен, под который маскируется соединение; лучше брать сайт из той же подсети, что и сервер.'),
    errorBox,
    h('div', { class: 'row', style: 'margin:12px 0' }, scanBtn),
    h('div', { class: 'row', style: 'margin-bottom:12px' }, manual, checkBtn),
    results, summary,
    h('div', { class: 'row', style: 'margin-top:10px' }, installBtn),
    log);
}

async function showLink(user) {
  let qr = null;
  try { qr = await QRCode(user.link); } catch { /* ссылку всё равно показываем */ }
  await modal((close) => [
    h('h3', {}, user.name),
    qr && h('img', { class: 'qr', src: qr, alt: 'QR-код ссылки' }),
    h('p', { class: 'link' }, user.link),
    h('div', { class: 'modal-actions' },
      h('button', { onclick: (e) => { ClipboardSetText(user.link); e.target.textContent = 'Скопировано'; } }, 'Копировать'),
      h('button', { class: 'primary', onclick: () => close() }, 'Закрыть')),
  ]);
}

const DISABLED_NAMES = { expired: 'истёк срок', traffic: 'исчерпан трафик', manual: 'отключён вручную' };

// Дата из <input type=date> как конец этого дня по времени компьютера, с поясом: сервер может жить в другом.
function endOfDayISO(date) {
  const off = -new Date(`${date}T23:59:59`).getTimezoneOffset();
  const pad = (n) => String(Math.floor(Math.abs(n))).padStart(2, '0');
  return `${date}T23:59:59${off >= 0 ? '+' : '-'}${pad(off / 60)}:${pad(off % 60)}`;
}

function dateInputValue(ts) {
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function limitsDialog(server, u) {
  return modal((close) => {
    const err = h('p', { class: 'fail', style: 'min-height:1.2em;margin:6px 0 0' });
    const date = h('input', { type: 'date', value: u.expires ? dateInputValue(u.expires) : '' });
    const noDate = h('input', { type: 'checkbox', checked: !u.expires, style: 'width:auto;margin-right:6px' });
    const gb = h('input', { type: 'number', min: '0.1', step: '0.1', value: u.limit ? +(u.limit / 1024 ** 3).toFixed(2) : '' });
    const noLimit = h('input', { type: 'checkbox', checked: !u.limit, style: 'width:auto;margin-right:6px' });
    const sync = () => { date.disabled = noDate.checked; gb.disabled = noLimit.checked; };
    noDate.addEventListener('change', sync);
    noLimit.addEventListener('change', sync);
    sync();
    const quick = (days) => h('button', { onclick: () => {
      const d = new Date(Date.now() + days * 86400000);
      date.value = dateInputValue(d / 1000);
      noDate.checked = false;
      sync();
    } }, `+${days} дн.`);
    const run = async (fn) => {
      err.textContent = '';
      try {
        await fn();
        close(true);
      } catch (e) {
        err.textContent = msg(e);
      }
    };
    const save = () => {
      if (!noDate.checked && !date.value) { err.textContent = 'Выберите дату или отметьте «Без срока».'; return; }
      const amount = noLimit.checked ? 0 : Number(gb.value);
      if (!noLimit.checked && !(amount > 0)) { err.textContent = 'Укажите лимит в гигабайтах или отметьте «Без лимита».'; return; }
      run(() => SetUserLimit(server.id, u.name, noDate.checked ? '' : endOfDayISO(date.value), amount));
    };
    return [
      h('h3', {}, `Ограничения: ${u.name}`),
      h('p', { class: 'hint' }, 'Сервер проверяет их каждые 5 минут. Вышедший за срок или лимит отключается, но его ссылка сохраняется: после продления она снова работает.'),
      h('label', { class: 'field' }, h('span', {}, 'Доступ до (включительно)'),
        h('div', { class: 'row' }, date, quick(30), quick(90))),
      h('label', { style: 'cursor:pointer;display:block;margin-bottom:10px' }, noDate, 'Без срока'),
      h('label', { class: 'field' }, h('span', {}, `Лимит трафика, ГБ (израсходовано ${formatBytes(u.total)})`), gb),
      h('label', { style: 'cursor:pointer;display:block' }, noLimit, 'Без лимита'),
      err,
      h('div', { class: 'modal-actions' },
        h('button', { onclick: () => run(() => ResetUserTraffic(server.id, u.name)) }, 'Обнулить трафик'),
        h('button', { onclick: () => close(false) }, 'Отмена'),
        h('button', { class: 'primary', onclick: save }, 'Сохранить')),
    ];
  });
}

function usersPanel(server, st = {}) {
  const list = h('div', {}, h('p', { class: 'hint' }, 'Загружаю пользователей...'));
  const errorBox = h('div');
  const nameInput = h('input', { placeholder: 'phone-anna' });
  const addBtn = h('button', { class: 'primary' }, 'Добавить');
  const showError = (e) => errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));

  async function load() {
    try {
      const users = await ListUsers(server.id);
      const activeCount = users.filter((u) => !u.disabled).length;
      list.replaceChildren(h('table', {},
        h('thead', {}, h('tr', {}, ['Имя', 'Трафик', 'Доступ до', ''].map((t) => h('th', {}, t)))),
        h('tbody', {}, users.map((u) => h('tr', { class: u.disabled ? 'off' : null },
          h('td', {}, u.name, u.disabled ? h('small', { class: 'fail', style: 'display:block' }, DISABLED_NAMES[u.disabled] || 'отключён') : null,
            u.name === 'bridge' && st.bridge_user ? h('small', { class: 'hint', style: 'display:block' }, 'это мост') : null),
          h('td', { class: u.limit && u.total >= u.limit ? 'fail' : null },
            formatBytes(u.total), u.limit ? ` из ${formatBytes(u.limit)}` : ''),
          h('td', { class: u.expires && u.expires * 1000 < Date.now() ? 'fail' : null },
            u.expires ? new Date(u.expires * 1000).toLocaleDateString('ru-RU') : '—'),
          h('td', { class: 'actions' },
            h('button', { disabled: !u.link, onclick: () => showLink(u) }, 'Ссылка и QR'),
            ...(u.name === 'bridge' && st.bridge_user ? [] : [
              h('button', { onclick: async () => { if (await limitsDialog(server, u)) load(); } }, 'Ограничения'),
              u.disabled
                ? h('button', { onclick: () => toggle(u, true) }, 'Включить')
                : h('button', { onclick: () => toggle(u, false) }, 'Отключить'),
              h('button', { class: 'danger', disabled: !u.disabled && activeCount === 1, onclick: () => remove(u) }, 'Удалить')])))))));
    } catch (e) {
      list.replaceChildren();
      showError(e);
    }
  }

  async function toggle(u, enabled) {
    if (!enabled) {
      const ok = await confirmDialog('Отключить пользователя?',
        `«${u.name}» не сможет подключиться, пока его не включат снова. Ссылка не изменится.`, 'Отключить');
      if (!ok) return;
    }
    errorBox.replaceChildren();
    try {
      await SetUserEnabled(server.id, u.name, enabled);
      await load();
    } catch (e) {
      showError(e);
    }
  }

  async function remove(u) {
    const ok = await confirmDialog('Удалить пользователя?',
      `«${u.name}» больше не сможет подключиться.`, 'Удалить');
    if (!ok) return;
    errorBox.replaceChildren();
    try {
      await RemoveUser(server.id, u.name);
      await load();
    } catch (e) {
      showError(e);
    }
  }

  addBtn.addEventListener('click', async () => {
    errorBox.replaceChildren();
    addBtn.disabled = true;
    try {
      const user = await AddUser(server.id, nameInput.value);
      nameInput.value = '';
      await load();
      if (user.link) await showLink(user);
    } catch (e) {
      showError(e);
    } finally {
      addBtn.disabled = false;
    }
  });

  load();
  return h('div', { class: 'panel' }, h('h3', {}, 'Пользователи'), errorBox,
    h('div', { class: 'row', style: 'margin-bottom:10px' }, nameInput, addBtn),
    h('p', { class: 'hint', style: 'margin-bottom:8px' }, 'Пользователи добавляются, отключаются и удаляются без обрыва связи у остальных. На серверах, настроенных старой версией, первое такое изменение один раз перезапустит Xray. Трафик считается нарастающим итогом: сервер переносит счётчики Xray в учёт каждые 5 минут и перед каждым перезапуском. Срок и лимит тоже проверяются каждые 5 минут.'),
    list);
}

// --- Встроенный клиент
const CLIENT_MODES = {
  proxy: ['Системный прокси', 'Браузеры и большинство программ пойдут через сервер. Включается в настройках системы и выключается при отключении.'],
  local: ['Только локальный прокси', 'Системные настройки не меняются: укажите прокси в нужных программах сами.'],
  tun: ['Весь трафик (TUN)', 'Через сервер идёт всё, включая игры и программы без настроек прокси. Нужны права администратора.'],
};

async function refreshClient() {
  try { state.client = await ClientState(); } catch { state.client = null; }
}

async function openClient() {
  state.view = 'client';
  state.selected = null;
  await refreshClient();
  renderClient();
}

function renderClient() {
  const cs = state.client || {};
  const saved = cs.saved || {};
  const errorBox = h('div');
  const showError = (e) => errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
  const logBox = h('div', { class: 'log', hidden: !(cs.log || []).length }, (cs.log || []).join('\n'));

  if (cs.running) {
    const offBtn = h('button', { class: 'danger' }, 'Отключиться');
    offBtn.addEventListener('click', async () => {
      offBtn.disabled = true;
      await ClientDisconnect();
      await openClient();
    });
    const mode = cs.tun ? 'tun' : cs.systemProxy ? 'proxy' : 'local';
    render(h('div', {},
      h('div', { class: 'panel' }, h('h3', {}, 'Подключено'),
        h('div', { class: 'stats' },
          stat('Сервер', `${cs.name || '—'} (${cs.host})`),
          stat('Режим', CLIENT_MODES[mode][0]),
          stat('SOCKS5', `127.0.0.1:${cs.socksPort}`),
          stat('HTTP', `127.0.0.1:${cs.httpPort}`),
          cs.country && stat('Напрямую', COUNTRIES[cs.country] || cs.country.toUpperCase())),
        h('p', { class: 'hint', style: 'margin:8px 0' }, CLIENT_MODES[mode][1]),
        h('div', { class: 'row' }, offBtn)),
      h('div', { class: 'panel' }, h('h3', {}, 'Журнал Xray'), logBox.hidden ? h('p', { class: 'hint' }, 'Пока пусто: Xray пишет сюда только предупреждения и ошибки.') : logBox)));
    return;
  }

  // Откуда ссылка: пользователь сервера из списка или своя ссылка.
  const srcServer = h('input', { type: 'radio', name: 'csrc', checked: !!saved.serverId || !saved.link, style: 'width:auto;margin-right:6px' });
  const srcLink = h('input', { type: 'radio', name: 'csrc', checked: !saved.serverId && !!saved.link, style: 'width:auto;margin-right:6px' });
  const serverSel = h('select', { style: 'width:auto' }, h('option', { value: '' }, 'Сервер...'),
    state.servers.map((s) => h('option', { value: s.id }, s.name)));
  const userSel = h('select', { style: 'width:auto', disabled: true }, h('option', { value: '' }, 'Пользователь...'));
  const linkInput = h('textarea', { rows: 3, placeholder: 'vless://...', style: 'width:100%' });
  if (!saved.serverId && saved.link) linkInput.value = saved.link;
  let users = [];
  const loadUsers = async (preselect) => {
    userSel.replaceChildren(h('option', { value: '' }, 'Загружаю...'));
    userSel.disabled = true;
    users = [];
    if (!serverSel.value) {
      userSel.replaceChildren(h('option', { value: '' }, 'Пользователь...'));
      return;
    }
    try {
      users = ((await ListUsers(serverSel.value)) || []).filter((u) => !u.disabled && u.link);
      userSel.replaceChildren(h('option', { value: '' }, users.length ? 'Пользователь...' : 'Нет активных пользователей'),
        ...users.map((u) => h('option', { value: u.name }, u.name)));
      userSel.disabled = !users.length;
      if (preselect && users.some((u) => u.name === preselect)) userSel.value = preselect;
    } catch (e) {
      userSel.replaceChildren(h('option', { value: '' }, 'Не удалось загрузить'));
      showError(e);
    }
  };
  serverSel.addEventListener('change', () => { srcServer.checked = true; errorBox.replaceChildren(); loadUsers(); });
  linkInput.addEventListener('input', () => { srcLink.checked = true; });
  if (saved.serverId && state.servers.some((s) => s.id === saved.serverId)) {
    serverSel.value = saved.serverId;
    loadUsers(saved.user);
  }

  let mode = saved.tun ? 'tun' : (saved.systemProxy === false && saved.link) ? 'local' : 'proxy';
  const modeHint = h('p', { class: 'hint' });
  const adminBox = h('div');
  const showMode = () => {
    modeHint.textContent = CLIENT_MODES[mode][1];
    adminBox.replaceChildren();
    if (mode === 'tun' && !cs.tunReady) {
      const btn = h('button', {}, cs.os === 'windows' ? 'Перезапустить от администратора' : 'Дать права для TUN');
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        try {
          await ClientEnableTUN();
          await refreshClient();
          renderClient();
        } catch (e) {
          showError(e);
          btn.disabled = false;
        }
      });
      adminBox.replaceChildren(h('div', { class: 'notice' }, `${cs.tunHint} `, btn));
    }
  };
  const modeRadios = Object.entries(CLIENT_MODES).map(([key, [label]]) => {
    const r = h('input', { type: 'radio', name: 'cmode', checked: key === mode, style: 'width:auto;margin-right:6px' });
    r.addEventListener('change', () => { mode = key; showMode(); });
    return h('label', { style: 'margin-right:16px;cursor:pointer' }, r, label);
  });
  showMode();

  const countryOn = h('input', { type: 'checkbox', checked: !!saved.country, style: 'width:auto;margin-right:6px' });
  const [countryField, countryList] = countryInput(saved.country || 'ru');

  const connectBtn = h('button', {}, 'Подключиться');
  connectBtn.addEventListener('click', async () => {
    errorBox.replaceChildren();
    let link = '';
    let serverId = '';
    let user = '';
    if (srcServer.checked) {
      const u = users.find((x) => x.name === userSel.value);
      if (!u) { showError('Выберите сервер и пользователя или вставьте ссылку.'); return; }
      link = u.link; serverId = serverSel.value; user = u.name;
    } else {
      link = linkInput.value.trim();
      if (!link) { showError('Вставьте ссылку vless://'); return; }
    }
    connectBtn.disabled = true;
    connectBtn.textContent = 'Подключаюсь...';
    logTarget = null;
    try {
      await ClientConnect({
        link, serverId, user, systemProxy: mode === 'proxy', tun: mode === 'tun',
        country: countryOn.checked ? countryField.value.trim().toLowerCase() : '',
      });
      await openClient();
    } catch (e) {
      showError(e);
      connectBtn.disabled = false;
      connectBtn.textContent = 'Подключиться';
    }
  });

  render(h('div', {},
    h('div', { class: 'panel' }, h('h3', {}, 'Подключение с этого компьютера'),
      h('p', { class: 'hint', style: 'margin-bottom:10px' },
        'Встроенный клиент: Xray запускается на этом компьютере и подключается к вашему серверу, отдельная программа вроде v2rayN не нужна. При первом подключении Xray скачается с GitHub.'),
      errorBox,
      h('label', { style: 'display:block;cursor:pointer;margin-bottom:6px' }, srcServer, 'Пользователь сервера из списка'),
      h('div', { class: 'row', style: 'margin:0 0 12px 22px' }, serverSel, userSel),
      h('label', { style: 'display:block;cursor:pointer;margin-bottom:6px' }, srcLink, 'Своя ссылка'),
      h('div', { style: 'margin:0 0 12px 22px' }, linkInput),
      h('h4', {}, 'Режим'),
      h('div', { style: 'margin-bottom:6px' }, modeRadios), modeHint, adminBox,
      h('label', { style: 'display:block;cursor:pointer;margin-top:12px' }, countryOn,
        'Сайты страны открывать напрямую, мимо сервера: ', countryField, countryList),
      h('p', { class: 'hint' }, 'Нужно для простого сервера или выхода. Мост и так открывает сайты своей страны сам.'),
      h('div', { class: 'row', style: 'margin-top:12px' }, connectBtn)),
    cs.error ? h('div', { class: 'panel' }, h('div', { class: 'error' }, cs.error), logBox) : null));
}

EventsOn('client', async () => {
  await refreshClient();
  if (state.view === 'client') renderClient();
  else if (state.view === 'server') {
    // Обновить только значок в боковой панели.
    const side = document.querySelector('.side');
    if (side) side.replaceWith(renderSide());
  }
});

EventsOn('log', (line) => {
  if (!logTarget) return;
  logTarget.textContent += `${line}\n`;
  logTarget.scrollTop = logTarget.scrollHeight;
});

(async () => {
  try {
    await refreshServers();
    await refreshClient();
    renderEmpty();
  } catch (e) {
    render(h('div', { class: 'error' }, msg(e)));
    return;
  }
  checkAllHealth();
  setInterval(checkAllHealth, HEALTH_EVERY_MS);
})();
