/* Independent vanilla interaction adapter for the Shadcn Admin customization.
 * No business records, credentials, IPC, browser navigation or network calls.
 * List state stays in memory and is cleared by reset() on member/scope changes.
 */
(() => {
  'use strict';
  const doc = document;
  const sizes = [10, 20, 50, 100];
  const collator = new Intl.Collator('zh-CN', { numeric: true, sensitivity: 'base' });
  const views = new Map(), tableViews = new Map(), tables = new Map(), guards = new Map();
  let config = null, generation = 0, command = null, confirmation = null, serial = 0;
  const array = (selector, root = doc) => Array.from(root.querySelectorAll(selector));
  const keyFor = ({ scopeKey = '', route = '' } = {}) => JSON.stringify([String(scopeKey), String(route)]);
  const node = (tag, className, text) => { const el = doc.createElement(tag); if (className) el.className = className; if (text !== undefined) el.textContent = text; return el; };
  const button = (text, label) => { const el = node('button', 'small', text); el.type = 'button'; if (label) el.setAttribute('aria-label', label); return el; };
  const activeElement = () => doc.activeElement instanceof HTMLElement ? doc.activeElement : null;
  const isComposing = event => event.isComposing || event.keyCode === 229;
  function remember(map, key, value) {
    map.delete(key); map.set(key, value);
    // Bound retained view preferences, never retain prior business DOM here.
    if (map.size > 160) map.delete(map.keys().next().value);
  }
  function getView(scope = config || {}) { return { ...(views.get(keyFor(scope)) || {}) }; }
  function saveView(scope, value) {
    const clean = {};
    for (const name of ['search', 'filter', 'tab']) if (typeof value?.[name] === 'string') clean[name] = value[name].slice(0, 2000);
    remember(views, keyFor(scope), clean); return { ...clean };
  }
  function focusBack(target) {
    if (target?.isConnected && !target.closest('[inert]') && !target.matches(':disabled') && !doc.querySelector('dialog[open]')) target.focus({ preventScroll: true });
  }
  function recordChecks(row) { return array('input[type="checkbox"][data-product-check],input[type="checkbox"][data-check]', row); }
  function checkId(box) { return box.dataset.productCheck ?? box.dataset.check; }
  function emitSelection() {
    if (!config) return;
    const ids = [...new Set(array('tbody input[type="checkbox"][data-product-check]:checked,tbody input[type="checkbox"][data-check]:checked', config.root).map(checkId).filter(Boolean))];
    config.onSelectionChange?.(ids);
  }
  function cellValue(row, index, head) {
    const cell = row.cells[index];
    const value = String(cell?.dataset.sortValue ?? cell?.querySelector('[data-sort-value]')?.dataset.sortValue ?? cell?.textContent ?? '').trim();
    if (head.dataset.sortType === 'number' || /^[¥￥$]?\s*[+-]?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?%?$/.test(value)) {
      const number = Number(value.replace(/[¥￥$,%\s,]/g, ''));
      // Very long order identifiers must never be converted to imprecise Number.
      if (Number.isFinite(number) && Math.abs(number) <= Number.MAX_SAFE_INTEGER) return number;
    }
    if (head.dataset.sortType === 'date') { const stamp = Date.parse(value); if (Number.isFinite(stamp)) return stamp; }
    return value;
  }
  function destroyTable(control) {
    control.table.removeEventListener('change', control.change, true);
    control.tools.remove();
    for (const item of control.sortButtons) { item.button.remove(); item.head.removeAttribute('aria-sort'); item.head.append(...item.original); }
    if (control.table.isConnected) control.body.replaceChildren(...control.rows);
    tables.delete(control.table);
  }
  function enhanceTable(table, index) {
    if (tables.has(table) || table.dataset.uxTable === 'off' || table.closest('#ux-command,#ux-discard-confirm')) return;
    const headRow = table.tHead?.rows[0], body = table.tBodies[0];
    if (!headRow || !body || table.tBodies.length !== 1) return;
    const heads = Array.from(headRow.cells);
    const rows = Array.from(body.rows).filter(row => !(row.cells.length === 1 && row.cells[0].colSpan > 1 && heads.length > 1));
    const dialog = table.closest('dialog');
    const identity = table.dataset.tableKey || `${dialog ? `${dialog.id}:${dialog.querySelector('h2,h3')?.textContent || ''}` : 'page'}:${index}:${heads.map(h => h.textContent.trim()).join('|')}`;
    const stateKey = JSON.stringify([keyFor(config), identity]);
    const saved = tableViews.get(stateKey) || {};
    const state = { page: Math.max(1, Number(saved.page) || 1), size: sizes.includes(saved.size) ? saved.size : 20, sort: Number.isInteger(saved.sort) ? saved.sort : -1, direction: saved.direction === 'desc' ? 'desc' : 'asc' };
    const tools = node('div', 'ux-table-tools'); tools.dataset.uxOwned = 'table-tools';
    const summary = node('span', 'ux-table-summary'); summary.setAttribute('role', 'status'); summary.setAttribute('aria-live', 'polite');
    const pageSize = node('label', 'ux-page-size', '每页 '), select = node('select'); select.setAttribute('aria-label', '每页记录数');
    for (const size of sizes) { const option = node('option', '', String(size)); option.value = String(size); option.selected = size === state.size; select.append(option); }
    pageSize.append(select);
    const pagination = node('nav', 'ux-pagination'); pagination.setAttribute('aria-label', '本机结果分页');
    const first = button('首页', '第一页'), previous = button('上一页'), pageLabel = node('span', 'ux-page-position'), next = button('下一页'), last = button('末页', '最后一页');
    pagination.append(first, previous, pageLabel, next, last);
    const note = node('small', 'ux-table-scope', '仅排序和分页当前已载入的本机结果');
    tools.append(summary, pageSize, pagination, note);
    const wrapper = table.closest('.table-wrap'); (wrapper || table).insertAdjacentElement('afterend', tools);
    const control = { table, body, rows, tools, state, sortButtons: [], change: null }; tables.set(table, control);
    function syncHeader() {
      const checks = array('tbody input[type="checkbox"][data-product-check],tbody input[type="checkbox"][data-check]', table).filter(box => !box.disabled);
      for (const all of array('thead input[data-check-all]', table)) {
        const selected = checks.filter(box => box.checked).length;
        all.checked = checks.length > 0 && selected === checks.length; all.indeterminate = selected > 0 && selected < checks.length;
        all.disabled = checks.length === 0; all.setAttribute('aria-label', `选择本页 ${checks.length} 条记录`);
      }
    }
    function render({ clear = false, focus = null } = {}) {
      if (!config || !table.isConnected) return;
      const pages = Math.max(1, Math.ceil(rows.length / state.size)); state.page = Math.min(pages, Math.max(1, state.page));
      const sorted = rows.map((row, position) => ({ row, position }));
      if (state.sort >= 0 && state.sort < heads.length) sorted.sort((a, b) => {
        const av = cellValue(a.row, state.sort, heads[state.sort]), bv = cellValue(b.row, state.sort, heads[state.sort]);
        const comparison = typeof av === 'number' && typeof bv === 'number' ? av - bv : collator.compare(String(av), String(bv));
        return (state.direction === 'desc' ? -comparison : comparison) || a.position - b.position;
      });
      const start = (state.page - 1) * state.size, visible = sorted.slice(start, start + state.size).map(item => item.row), visibleSet = new Set(visible);
      for (const row of rows) for (const box of recordChecks(row)) if (clear || !visibleSet.has(row)) box.checked = false;
      body.replaceChildren(...visible);
      if (!visible.length) { const row = node('tr'), cell = node('td', 'muted', '当前没有本机结果'); cell.colSpan = heads.length; row.append(cell); body.append(row); }
      summary.textContent = `本机结果 ${rows.length ? start + 1 : 0}–${Math.min(start + state.size, rows.length)} / 共 ${rows.length} 条`;
      pageLabel.textContent = `第 ${state.page} / ${pages} 页`; first.disabled = previous.disabled = state.page <= 1; next.disabled = last.disabled = state.page >= pages;
      for (const item of control.sortButtons) {
        const active = item.index === state.sort;
        item.head.setAttribute('aria-sort', active ? (state.direction === 'asc' ? 'ascending' : 'descending') : 'none');
        item.indicator.textContent = active ? (state.direction === 'asc' ? ' ↑' : ' ↓') : ' ↕';
        item.button.setAttribute('aria-label', `${item.label}，${active ? (state.direction === 'asc' ? '当前升序，改为降序' : '当前降序，改为升序') : '按此列升序排列'}`);
      }
      syncHeader(); remember(tableViews, stateKey, { ...state }); emitSelection();
      if (focus && focus.isConnected && !focus.disabled) focus.focus({ preventScroll: true });
    }
    heads.forEach((head, column) => {
      if (head.colSpan !== 1 || head.dataset.sortable === 'false' || head.querySelector('input,select,button') || /^(操作|选择)$/.test(head.textContent.trim())) return;
      const label = head.textContent.trim(); if (!label) return;
      const original = Array.from(head.childNodes), sort = button('', `${label}，按此列排序`); sort.className = 'ux-sort-button';
      const text = node('span', '', label), indicator = node('span', '', ' ↕'); indicator.setAttribute('aria-hidden', 'true'); sort.append(text, indicator); head.replaceChildren(sort);
      sort.addEventListener('click', () => { state.direction = state.sort === column && state.direction === 'asc' ? 'desc' : 'asc'; state.sort = column; state.page = 1; render({ clear: true, focus: sort }); });
      control.sortButtons.push({ head, original, button: sort, indicator, index: column, label });
    });
    select.addEventListener('change', () => { state.size = Number(select.value); state.page = 1; render({ clear: true, focus: select }); });
    for (const [el, value] of [[first, () => 1], [previous, () => state.page - 1], [next, () => state.page + 1], [last, () => Math.max(1, Math.ceil(rows.length / state.size))]]) el.addEventListener('click', () => { state.page = value(); render({ clear: true, focus: el }); });
    control.change = event => {
      const box = event.target;
      if (box.matches('input[data-check-all]')) {
        event.stopImmediatePropagation();
        const selected = box.checked;
        for (const check of array('tbody input[type="checkbox"][data-product-check],tbody input[type="checkbox"][data-check]', table)) if (!check.disabled) { check.checked = selected; check.dispatchEvent(new Event('change', { bubbles: true })); }
        syncHeader(); emitSelection();
      } else if (box.matches('input[data-product-check],input[data-check]')) { syncHeader(); emitSelection(); }
    };
    table.addEventListener('change', control.change, true); render();
  }
  // A fingerprint prevents the state cache from retaining copies of form secrets.
  function fingerprint(root) {
    let a = 2166136261, b = 5381;
    const fields = array('input,select,textarea,[contenteditable="true"]', root).filter(el => !el.closest('[data-ux-ignore-dirty],[data-ux-owned]') && !el.matches('[data-search],[data-filter],[type="button"],[type="submit"],[type="reset"]'));
    const text = JSON.stringify(fields.map((el, i) => [i, el.name || '', el.type || '', el.matches('[type="checkbox"],[type="radio"]') ? el.checked : el.multiple ? Array.from(el.selectedOptions).map(o => o.value) : el.isContentEditable ? el.textContent : el.value, el.type === 'file' ? Array.from(el.files || []).map(f => [f.name, f.size, f.lastModified]) : null]));
    for (let i = 0; i < text.length; i++) { const code = text.charCodeAt(i); a = Math.imul(a ^ code, 16777619); b = Math.imul(b, 33) ^ code; }
    return `${fields.length}:${text.length}:${a >>> 0}:${b >>> 0}`;
  }
  function formsIn(root) { return root?.matches?.('form') ? [root] : array('form:not([data-ux-ignore-dirty])', root || doc).filter(form => !form.closest('[data-ux-owned]')); }
  function markClean(root = doc.querySelector('#main')) {
    if (!root) return;
    const targets = root.matches?.('dialog') ? [root] : formsIn(root);
    for (const target of targets) { const guard = guards.get(target) || {}; guard.baseline = fingerprint(target); guard.forcedDirty = false; guards.set(target, guard); }
  }
  function markDirty(root) {
    if (!root) return;
    const targets = root.matches?.('dialog') ? [root] : formsIn(root);
    for (const target of targets) { const guard = guards.get(target) || { baseline: fingerprint(target) }; guard.forcedDirty = true; guards.set(target, guard); }
  }
  function isDirty(root) {
    if (!root) return false;
    if (root.matches?.('dialog')) { const guard = guards.get(root); return Boolean(guard && (guard.forcedDirty || guard.baseline !== fingerprint(root))); }
    return formsIn(root).some(form => { const guard = guards.get(form); return Boolean(guard && (guard.forcedDirty || guard.baseline !== fingerprint(form))); });
  }
  function askDiscard(target) {
    if (!config) return Promise.resolve(false);
    if (confirmation) return confirmation.target === target ? confirmation.promise : Promise.resolve(false);
    const epoch = generation, returnFocus = activeElement(), dialog = node('dialog', 'ux-dialog ux-discard-confirm'); dialog.id = 'ux-discard-confirm'; dialog.dataset.uxOwned = 'confirmation';
    const titleId = `ux-discard-title-${++serial}`, title = node('h2', '', '放弃未保存的修改？'); title.id = titleId; dialog.setAttribute('aria-labelledby', titleId);
    const body = node('div', 'dialog-body'), text = node('p', '', '离开后，本次尚未保存的内容会丢失。已保存的业务记录不受影响。'), actions = node('div', 'ux-confirm-actions');
    const stay = button('继续编辑'), discard = button('放弃修改'); discard.classList.add('danger'); actions.append(stay, discard); body.append(text, actions);
    const header = node('header', 'dialog-head'); header.append(title); dialog.append(header, body);
    let resolve; const promise = new Promise(done => { resolve = done; });
    const settle = allowed => {
      if (confirmation?.dialog !== dialog) return;
      confirmation = null; if (dialog.open) dialog.close(); dialog.remove();
      if (!allowed && epoch === generation && returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
      resolve(Boolean(allowed && epoch === generation && config));
    };
    confirmation = { dialog, promise, settle, target };
    stay.addEventListener('click', () => settle(false)); discard.addEventListener('click', () => settle(true));
    dialog.addEventListener('cancel', event => { event.preventDefault(); settle(false); });
    dialog.addEventListener('keydown', event => { if (isComposing(event) && ['Enter', 'Escape'].includes(event.key)) { event.preventDefault(); event.stopImmediatePropagation(); } });
    doc.body.append(dialog); dialog.showModal(); stay.focus(); return promise;
  }
  async function requestLeave(root = doc.querySelector('#main')) {
    const epoch = generation; if (!config) return false;
    const result = !isDirty(root) || await askDiscard(root); return Boolean(result && config && epoch === generation && root?.isConnected);
  }
  function dialogOpened(dialog, { returnFocus } = {}) {
    if (!dialog) return;
    const previous = guards.get(dialog);
    if (previous?.cancel) { dialog.removeEventListener('cancel', previous.cancel); dialog.removeEventListener('close', previous.close); }
    const guard = { baseline: fingerprint(dialog), returnFocus: returnFocus?.isConnected ? returnFocus : previous?.returnFocus || null, epoch: generation };
    guard.cancel = event => { event.preventDefault(); if (!isComposing(event)) void requestClose(dialog); };
    guard.close = () => {
      if (dialog.open) return;
      const target = guard.returnFocus;
      guards.delete(dialog); dialog.removeEventListener('cancel', guard.cancel); dialog.removeEventListener('close', guard.close);
      for (const control of [...tables.values()]) if (!control.table.isConnected || dialog.contains(control.table)) destroyTable(control);
      for (const [form] of guards) if (!form.isConnected) guards.delete(form);
      queueMicrotask(() => { if (guard.epoch === generation) focusBack(target); });
    };
    guards.set(dialog, guard); dialog.addEventListener('cancel', guard.cancel); dialog.addEventListener('close', guard.close);
    if (config) array('table', dialog).forEach(enhanceTable);
  }
  function closeDialog(dialog, { force = false } = {}) {
    if (!force) return requestClose(dialog);
    if (confirmation?.target === dialog) confirmation.settle(false);
    if (dialog?.open) dialog.close(); return true;
  }
  async function requestClose(dialog) {
    if (!dialog?.open) return true;
    const epoch = generation, guard = guards.get(dialog), allowed = !isDirty(dialog) || await askDiscard(dialog);
    if (!allowed || epoch !== generation || !config || !dialog.isConnected || guards.get(dialog) !== guard) return false;
    if (dialog.open) dialog.close(); return true;
  }
  function routeItems() {
    const supplied = config?.routes;
    const source = Array.isArray(supplied) ? supplied : array('[data-action="navigate"][data-route]', config?.root || doc).map(el => ({ id: el.dataset.route, label: el.querySelector('.nav-label')?.textContent || el.textContent }));
    const seen = new Set(); return source.filter(item => item && item.id && !item.disabled && !seen.has(String(item.id)) && seen.add(String(item.id))).map(item => ({ id: String(item.id), label: String(item.label || item.name || item.id), keywords: String(item.keywords || '') }));
  }
  function closeCommand({ restore = true } = {}) {
    if (!command) return;
    const old = command; command = null; if (old.dialog.open) old.dialog.close(); old.dialog.remove(); if (restore) focusBack(old.returnFocus);
  }
  function openCommand() {
    if (!config || doc.querySelector('dialog[open]')) return false;
    const epoch = generation, items = routeItems(); if (!items.length) return false;
    const dialog = node('dialog', 'ux-dialog ux-command'); dialog.id = 'ux-command'; dialog.dataset.uxOwned = 'command'; dialog.setAttribute('aria-label', '查找业务工作区');
    const input = node('input', 'ux-command-search'); input.type = 'search'; input.placeholder = '搜索工作区名称'; input.setAttribute('aria-label', '搜索业务导航'); input.setAttribute('role', 'combobox'); input.setAttribute('aria-expanded', 'true'); input.setAttribute('aria-autocomplete', 'list'); input.autocomplete = 'off';
    const list = node('div', 'ux-command-list'); list.id = `ux-command-list-${++serial}`; list.setAttribute('role', 'listbox'); list.setAttribute('aria-label', '可用工作区'); input.setAttribute('aria-controls', list.id);
    const footer = node('div', 'ux-command-footer', '↑ ↓ 选择 · Enter 打开 · Esc 关闭');
    dialog.append(input, list, footer); command = { dialog, returnFocus: activeElement(), index: 0, filtered: items, epoch };
    async function choose(index) {
      if (!command || epoch !== generation) return;
      const item = command.filtered[index]; if (!item) return;
      closeCommand();
      // The controller owns dirty-navigation confirmation, actor scope and actions.
      if (config && epoch === generation) await config.onNavigate?.(item.id);
    }
    function highlight() {
      if (!command) return;
      array('[role="option"]', list).forEach((el, index) => el.setAttribute('aria-selected', String(index === command.index)));
      const selected = list.children[command.index]; if (selected?.getAttribute('role') === 'option') { input.setAttribute('aria-activedescendant', selected.id); selected.scrollIntoView({ block: 'nearest' }); } else input.removeAttribute('aria-activedescendant');
    }
    function filter() {
      if (!command) return;
      const query = input.value.trim().toLocaleLowerCase('zh-CN'); command.filtered = items.filter(item => `${item.label} ${item.id} ${item.keywords}`.toLocaleLowerCase('zh-CN').includes(query)); command.index = 0; list.replaceChildren();
      command.filtered.forEach((item, index) => { const option = node('div', 'ux-command-item', item.label); option.id = `${list.id}-${index}`; option.setAttribute('role', 'option'); option.setAttribute('aria-selected', String(index === 0)); option.addEventListener('click', () => { void choose(index); }); list.append(option); });
      if (!command.filtered.length) list.append(node('p', 'ux-command-empty', '没有匹配的工作区。试试“订单”“库存”或“设置”。'));
      highlight();
    }
    input.addEventListener('input', event => { if (!isComposing(event)) filter(); }); input.addEventListener('compositionend', filter);
    input.addEventListener('keydown', event => {
      if (isComposing(event) || !command) return;
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); const length = command.filtered.length; if (length) command.index = (command.index + (event.key === 'ArrowDown' ? 1 : length - 1)) % length; highlight(); }
      else if (event.key === 'Enter') { event.preventDefault(); void choose(command.index); }
      else if (event.key === 'Escape') { event.preventDefault(); closeCommand(); }
    });
    dialog.addEventListener('cancel', event => { event.preventDefault(); closeCommand(); });
    doc.body.append(dialog); dialog.showModal(); filter(); input.focus(); return true;
  }
  function mount(options = {}) {
    const root = options.root || doc;
    if (!root.querySelectorAll || !options.scopeKey || !options.route) throw new TypeError('LianpuUX.mount requires root, member/space/account scopeKey and route.');
    const oldScope = config?.scopeKey, oldRoute = config?.route;
    config = { ...options, root };
    if (oldScope && oldScope !== config.scopeKey) closeCommand();
    if (oldScope && (oldScope !== config.scopeKey || oldRoute !== config.route)) {
      for (const control of [...tables.values()]) { for (const row of control.rows) for (const check of recordChecks(row)) check.checked = false; destroyTable(control); }
    }
    for (const [table, control] of tables) if (!table.isConnected) destroyTable(control);
    for (const [target] of guards) if (!target.isConnected) guards.delete(target);
    array('table', root).forEach(enhanceTable);
    for (const form of formsIn(root)) if (!guards.has(form)) markClean(form);
    return { tables: tables.size, view: getView(config) };
  }
  function reset() {
    generation++; config = null;
    if (confirmation) confirmation.settle(false);
    closeCommand({ restore: false });
    for (const [target, guard] of guards) if (target.matches?.('dialog')) { target.removeEventListener('cancel', guard.cancel); target.removeEventListener('close', guard.close); if (target.open) target.close(); target.replaceChildren(); }
    for (const control of [...tables.values()]) destroyTable(control);
    guards.clear(); views.clear(); tableViews.clear();
  }
  doc.addEventListener('keydown', event => {
    if (!config || isComposing(event) || event.repeat || event.altKey) return;
    if (event.target?.closest?.('input,textarea,select,[contenteditable]:not([contenteditable="false"])')) return;
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); if (command) closeCommand(); else openCommand(); }
  });
  window.LianpuUX = Object.freeze({ mount, reset, getView, saveView, markClean, markDirty, isDirty, requestLeave, dialogOpened, requestClose, closeDialog, openCommand, closeCommand });
})();
