import './style.css';
import {
  AddDirect, AddExit, AddUser, AutoExit, CheckExits, CheckReach, CheckSNI, DeleteServer, ExitLink, Install, ListExits,
  ListServers, ListUsers, QRCode, RemoveExit, RemoveUser, SaveServer, ScanSNI, Status, TrustServer, Uninstall,
  ListDirect, RemoveDirect, UpdateGeodata, UpdateTool, UpdateXray, UseExit,
} from '../wailsjs/go/main/App';
import { ClipboardSetText, EventsOn } from '../wailsjs/runtime/runtime';

const root = document.getElementById('app');
const state = { servers: [], selected: null, view: 'empty', editing: null };
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

function renderSide() {
  return h('aside', { class: 'side' },
    h('h1', {}, 'Переправа'),
    state.servers.map((s) => h('button', {
      class: `server-item${state.selected === s.id && state.view === 'server' ? ' active' : ''}`,
      onclick: () => openServer(s.id),
    }, s.name, h('small', {}, `${s.user}@${s.host}`))),
    h('button', { onclick: () => openForm(null) }, '+ Добавить сервер'));
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

function statusPanel(st) {
  const stat = (label, value) => h('div', { class: 'stat' }, h('small', {}, label), h('b', {}, value));
  const mem = st.memory;
  return h('div', { class: 'panel' }, h('h3', {}, 'Сервер'),
    h('div', { class: 'stats' },
      h('div', { class: 'stat' }, h('small', {}, 'Xray'),
        st.xray.active ? h('b', { class: 'pass' }, 'работает')
          : st.xray.version ? h('b', { class: 'fail' }, 'не работает') : h('b', {}, 'не установлен')),
      st.installed && stat('Режим', MODE_NAMES[st.mode]),
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
    : st.mode === 'exit' ? [exitInfoPanel(server)]
      : st.mode === 'bridge' ? [exitsPanel(server), usersPanel(server, st), directPanel(server)]
        : [usersPanel(server, st)];
  if (st.installed) panels.push(maintenancePanel(server, st));
  body.replaceChildren(...[egressWarning(st), statusPanel(st), ...panels].filter(Boolean));
}

function maintenancePanel(server, st) {
  const log = h('div', { class: 'log', hidden: true });
  const errorBox = h('div');
  const buttons = [];
  const run = async (btn, fn, after) => {
    errorBox.replaceChildren();
    log.hidden = false;
    log.textContent = '';
    logTarget = log;
    buttons.forEach((b) => { b.disabled = true; });
    try {
      await fn();
      after();
    } catch (e) {
      errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));
    } finally {
      buttons.forEach((b) => { b.disabled = false; });
    }
  };

  const geoBtn = h('button', {}, 'Обновить списки сайтов');
  geoBtn.addEventListener('click', () => run(geoBtn, () => UpdateGeodata(server.id),
    () => { log.textContent += 'Готово.\n'; }));
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
  xrayBtn.addEventListener('click', async () => {
    const ok = await confirmDialog('Обновить Xray?',
      `Последняя версия Xray скачается на этом компьютере и заменит ${(st.xray.version || '').split(' ').slice(0, 2).join(' ') || 'текущую версию'}. Xray перезапустится, у подключённых будет короткий обрыв. Если новая версия не примет настройки или не запустится, вернётся старая.`,
      'Обновить');
    // Журнал не стираем: в нём итог — обновился Xray или уже был последней версии.
    if (ok) run(xrayBtn, () => UpdateXray(server.id), () => { log.textContent += 'Готово. Новую версию покажет кнопка «Обновить» вверху.\n'; });
  });
  // exitctl ставится на мост и простой сервер; приложение пользуется своей копией,
  // а установленная нужна тем, кто работает в консоли сервера.
  const toolOutdated = st.mode !== 'exit' && st.tool_sha256 && st.bundled_tool_sha256
    && st.tool_sha256 !== st.bundled_tool_sha256;
  const toolBtn = h('button', {}, 'Обновить exitctl на сервере');
  toolBtn.addEventListener('click', () => run(toolBtn, () => UpdateTool(server.id), () => openServer(server.id)));

  // Списки сайтов нужны мосту и простому режиму: выход маршрутизацию по ним не делает.
  if (st.mode !== 'exit') buttons.push(geoBtn);
  buttons.push(xrayBtn);
  if (toolOutdated) buttons.push(toolBtn);
  buttons.push(uninstallBtn);

  return h('div', { class: 'panel' }, h('h3', {}, 'Обслуживание'), errorBox,
    st.mode !== 'exit' && h('p', { class: 'hint', style: 'margin-bottom:8px' },
      'Списки российских сайтов и адресов обычно обновляются на сервере раз в неделю. Если серверу недоступен GitHub, обновляйте их отсюда.'),
    toolOutdated && h('p', { class: 'hint', style: 'margin-bottom:8px' },
      'На сервере старая версия exitctl. Приложению она не мешает, но в консоли сервера будут старые команды.'),
    h('div', { class: 'row' }, buttons), log);
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
      : h('p', { class: 'hint' }, 'Своих доменов нет: напрямую идут только сайты из встроенных списков российских сайтов.'));
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
      'Эти домены мост открывает сам, не через выход: например, российский сайт, которого нет во встроенных списках, или сайт, который не пускает зарубежные адреса. Поддомены входят автоматически. Изменение списка коротко перезапускает Xray.'),
    h('div', { class: 'row', style: 'margin-bottom:10px' }, input, addBtn), list);
}

function exitInfoPanel(server) {
  const box = h('div', {}, h('p', { class: 'hint' }, 'Получаю ссылку...'));
  ExitLink(server.id).then((link) => {
    box.replaceChildren(h('p', { class: 'link' }, link), h('div', { class: 'row' },
      h('button', { onclick: (e) => { ClipboardSetText(link); e.target.textContent = 'Скопировано'; } }, 'Копировать')));
  }).catch((e) => box.replaceChildren(h('div', { class: 'error' }, msg(e))));
  return h('div', { class: 'panel' }, h('h3', {}, 'Выход: ссылка для моста'),
    h('p', { class: 'hint', style: 'margin-bottom:8px' }, 'Порт 443 этого сервера открыт только для адреса моста, указанного при установке.'), box);
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
      list.replaceChildren(h('p', { class: 'hint' }, 'Выходов нет: сейчас открываются только российские сайты, а остальные работать не будут.'));
      return;
    }
    const dead = exits.filter((x) => !health[x.name]?.ok).map((x) => x.name);
    // replaceChildren превращает null в текст «null», поэтому пустые элементы отфильтровываются.
    list.replaceChildren(...[
      dead.length ? h('div', { class: 'notice' }, `Мост не достаёт до: ${dead.join(', ')}. Проверьте адрес выхода и то, что при его установке указан IP этого моста. Если выход настроен верно, значит соединения режет хостер одного из серверов, и нужен выход в другой сети.`) : null,
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
      `Трафик перестанет идти через «${x.name}». Xray перезапустится, у всех подключённых будет короткий обрыв.`, 'Удалить');
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

const MODE_HINTS = {
  simple: 'Один сервер: клиенты подключаются к нему напрямую, и он сам выходит в интернет.',
  bridge: 'Клиенты подключаются сюда. Российские сайты открываются напрямую, остальное идёт через выходы, которые вы добавите после установки.',
  exit: 'Сервер за рубежом, через который мост выпускает трафик. Порт 443 будет открыт только для адреса моста.',
};

function installPanel(server, st) {
  let chosen = null;
  const allowed = Object.keys(MODE_NAMES).filter((m) => st.capabilities?.[m]);
  if (!allowed.length) {
    return h('div', { class: 'panel' }, h('h3', {}, 'Настройка'),
      h('div', { class: 'error' }, 'С этого сервера нет связи ни с зарубежными, ни с российскими адресами, поэтому настроить его нельзя. Проверьте сеть сервера и нажмите «Обновить».'));
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
  const modeRadios = Object.keys(MODE_NAMES).map((m) => {
    const radio = h('input', { type: 'radio', name: 'mode', checked: m === mode, disabled: !allowed.includes(m), style: 'width:auto;margin-right:6px' });
    radio.addEventListener('change', () => {
      mode = m;
      modeHint.textContent = MODE_HINTS[m];
      bridgeBox.hidden = m !== 'exit';
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
      await Install(server.id, mode, chosen, bridgeIp.value);
      openServer(server.id);
    } catch (e) {
      showError(e);
      installBtn.disabled = false;
      scanBtn.disabled = false;
    }
  });

  return h('div', { class: 'panel' }, h('h3', {}, 'Настройка'),
    h('div', { style: 'margin-bottom:6px' }, modeRadios), modeHint, bridgeBox,
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

function usersPanel(server) {
  const list = h('div', {}, h('p', { class: 'hint' }, 'Загружаю пользователей...'));
  const errorBox = h('div');
  const nameInput = h('input', { placeholder: 'phone-anna' });
  const addBtn = h('button', { class: 'primary' }, 'Добавить');
  const showError = (e) => errorBox.replaceChildren(h('div', { class: 'error' }, msg(e)));

  async function load() {
    try {
      const users = await ListUsers(server.id);
      list.replaceChildren(h('table', {},
        h('thead', {}, h('tr', {}, ['Имя', 'Принято', 'Отдано', ''].map((t) => h('th', {}, t)))),
        h('tbody', {}, users.map((u) => h('tr', {},
          h('td', {}, u.name), h('td', {}, formatBytes(u.uplink)), h('td', {}, formatBytes(u.downlink)),
          h('td', { class: 'actions' },
            h('button', { disabled: !u.link, onclick: () => showLink(u) }, 'Ссылка и QR'),
            h('button', { class: 'danger', disabled: users.length === 1, onclick: () => remove(u) }, 'Удалить')))))));
    } catch (e) {
      list.replaceChildren();
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
    h('p', { class: 'hint', style: 'margin-bottom:8px' }, 'Пользователи добавляются и удаляются без обрыва связи. На серверах, настроенных старой версией, первое такое изменение один раз перезапустит Xray. Трафик считается с последнего перезапуска Xray.'),
    list);
}

EventsOn('log', (line) => {
  if (!logTarget) return;
  logTarget.textContent += `${line}\n`;
  logTarget.scrollTop = logTarget.scrollHeight;
});

(async () => {
  try {
    await refreshServers();
    renderEmpty();
  } catch (e) {
    render(h('div', { class: 'error' }, msg(e)));
  }
})();
