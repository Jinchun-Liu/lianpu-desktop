/*
 * 联铺 UI primitives and desktop shell, vanilla adaptation.
 * Selective semantic/structural adaptation from satnaing/shadcn-admin
 * commit e16c87f213a5ba5e45964e9b67c792105ec74d26 (v2.2.1), MIT,
 * Copyright (c) 2024 Sat Naing. Full notices ship with the application.
 * Sources: components/ui/button.tsx, badge.tsx; components/layout/
 * authenticated-layout.tsx, app-sidebar.tsx, header.tsx, main.tsx,
 * nav-group.tsx, nav-user.tsx; components/search.tsx.
 * React/Radix/Tailwind, template routes, cookies, demo identity and data are
 * not copied. Empty state, heading, breadcrumb and local SVG paths are new.
 * Business values are escaped. attrs/actions/content/icon are trusted project
 * markup, never remote HTML; this module has no IPC or persistence capability.
 */
(() => {
  'use strict';
  const escape = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
  const attributes = value => typeof value === 'string' ? value : Object.entries(value || {}).filter(([, item]) => item !== false && item != null).map(([key, item]) => /^[a-z][a-z0-9-]*$/i.test(key) && !/^on/i.test(key) ? `${key}${item === true ? '' : `="${escape(item)}"`}` : '').join(' ');
  function button(label, action, attrs = '', variant = 'outline') {
    const aliases = { default: 'primary', destructive: 'danger', ghost: 'quiet', sm: 'small' };
    const classes = String(variant || 'outline').split(/\s+/).filter(Boolean).map(item => aliases[item] || item);
    const tone = classes.includes('primary') ? 'primary' : classes.includes('danger') ? 'destructive' : classes.includes('link') ? 'link' : classes.includes('quiet') ? 'ghost' : classes.includes('secondary') ? 'secondary' : 'outline';
    return `<button type="button" data-slot="button" data-action="${escape(action)}" data-variant="${tone}" class="ui-button ${escape(classes.join(' '))}" ${attributes(attrs)}>${escape(label)}</button>`;
  }
  function badge(value, label = value, tone = 'neutral') {
    const aliases = { good: 'success', bad: 'danger', warn: 'warning', destructive: 'danger' };
    const selected = aliases[tone] || tone;
    const safeTone = ['success', 'danger', 'warning', 'info', 'neutral'].includes(selected) ? selected : 'neutral';
    return `<span data-slot="badge" data-status="${escape(value)}" data-tone="${safeTone}" class="badge badge-${safeTone}">${escape(label ?? '未设置')}</span>`;
  }
  const paths = {
    overview: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
    sidebar: 'M3 4h18v16H3zM9 4v16M5.5 8h1M5.5 12h1',
    search: 'M10.5 3a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15ZM16 16l5 5',
    bell: 'M5 17h14l-2-3V9a5 5 0 0 0-10 0v5l-2 3ZM10 21h4',
    memberMenu: 'M5 12h1M11.5 12h1M18 12h1',
    moon: 'M20 14.5A8.5 8.5 0 0 1 9.5 4 8.5 8.5 0 1 0 20 14.5Z',
    sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M5 19l1.5-1.5M17.5 6.5 19 5',
    refresh: 'M20 7v5h-5M4 17v-5h5M5.5 7a7 7 0 0 1 12-2L20 8M4 16l2.5 3a7 7 0 0 0 12-2',
    empty: 'M4 6h6l2 3h8v11H4zM4 6V4h6l2 2M8 14h8',
    chevron: 'm9 5 7 7-7 7',
  };
  const glyph = key => `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="${paths[key] || paths.overview}"></path></svg>`;
  function empty(title, description, actions = '') {
    return `<section class="empty" data-slot="empty"><div class="empty-symbol" aria-hidden="true">${glyph('empty')}</div><div class="empty-header"><h2>${escape(title)}</h2><p>${escape(description)}</p></div>${actions ? `<div class="actions">${actions}</div>` : ''}</section>`;
  }
  function heading(title, description, actions = '') {
    return `<header class="page-heading" data-slot="page-header"><div class="page-heading-copy"><h1>${escape(title)}</h1>${description ? `<p>${escape(description)}</p>` : ''}</div>${actions ? `<div class="actions page-actions">${actions}</div>` : ''}</header>`;
  }
  const routeLabels = { overview: '工作台', orders: '订单与交付', products: '商品档案', assets: '资料库', inventory: '唯一库存', messages: '买家消息', rules: '自动处理', operations: '商品运营', customers: '客户备注', afterSales: '售后与扩展', statistics: '经营统计', accounts: '经营账号', team: '成员与权限', data: '数据与备份', settings: '设置', requirements: '验收记录' };
  const groups = [
    { title: '工作台', routes: ['overview'] },
    { title: '日常经营', routes: ['orders', 'products', 'assets', 'inventory', 'messages'] },
    { title: '经营管理', routes: ['rules', 'operations', 'customers', 'afterSales', 'statistics'] },
    { title: '工作区', routes: ['accounts', 'team', 'data', 'settings', 'requirements'] },
  ];
  const roles = { owner: '管理员', operator: '经营人员', support: '客服', viewer: '只读成员' };
  const localTime = value => value && Number.isFinite(Date.parse(value)) ? new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(value)) : '';
  function shell({ state, labels = {}, icon, content = '', notificationCount = 0 }) {
    const names = { ...routeLabels, ...labels }, route = state.route || 'overview';
    const collapsed = typeof state.sidebarCollapsed === 'boolean' ? state.sidebarCollapsed : window.innerWidth < 1100;
    const dark = state.theme === 'dark', user = state.auth?.user || {};
    const name = user.name || '本机成员', role = roles[user.role] || '本机成员';
    const sessionLabel = state.auth?.rememberedSession?.saved===true?'持续登录':state.auth?.rememberedSession?.saved===false?'登录未保留':'已登录';
    const accounts = (Array.isArray(state.data?.accounts) ? state.data.accounts : []).filter(account => !account.space || account.space === state.space);
    const options = accounts.map(account => `<option value="${escape(account.id)}"${account.id === state.accountId ? ' selected' : ''}>${escape(account.name || account.id)}</option>`).join('');
    const selectedGroup = groups.find(group => group.routes.includes(route));
    const sync = state.backgroundChanged ? '已有新的状态或记录，请刷新核对' : state.lastSync ? `本机列表更新于 ${localTime(state.lastSync)}` : '尚未读取本机列表';
    const count = Number.isSafeInteger(notificationCount) && notificationCount > 0 ? notificationCount : 0;
    const routeIcon = key => key === 'overview' || typeof icon !== 'function' ? glyph('overview') : icon(key);
    const navigation = groups.map(group => `<section class="nav-section" data-slot="sidebar-group"><h2 class="nav-group">${escape(group.title)}</h2><div class="nav-menu" data-slot="sidebar-menu">${group.routes.map(key => `<button type="button" class="nav-item" data-slot="sidebar-menu-button" data-action="navigate" data-route="${key}" aria-label="${escape(names[key])}"${route === key ? ' aria-current="page" data-active="true"' : ''} title="${escape(names[key])}">${routeIcon(key)}<span class="nav-label">${escape(names[key])}</span></button>`).join('')}</div></section>`).join('');
    return `<div class="shell" data-slot="authenticated-layout" data-sidebar="${collapsed ? 'collapsed' : 'expanded'}">
      <aside id="app-sidebar" class="sidebar" data-slot="sidebar" aria-label="联铺导航">
        <div class="sidebar-header" data-slot="sidebar-header"><button type="button" class="brand" data-action="navigate" data-route="overview" aria-label="联铺工作台"><span class="brand-symbol" aria-hidden="true">联</span><span class="brand-name">联铺<small>数字资料经营工作区</small></span></button></div>
        <nav aria-label="主要功能" data-slot="sidebar-content">${navigation}</nav>
        <footer class="sidebar-footer" data-slot="sidebar-footer"><div class="person"><span class="user-avatar" aria-hidden="true">${escape(Array.from(name)[0] || '联')}</span><div class="person-info"><span class="person-name" title="${escape(name)}">${escape(name)}</span><small data-session-label>${escape(role)} · ${sessionLabel}</small></div><button type="button" class="ui-button quiet icon-button" data-action="member-menu" aria-label="本机成员与托管菜单" title="本机成员与托管菜单" aria-haspopup="dialog">${glyph('memberMenu')}<span class="visually-hidden">本机成员菜单</span></button></div><small class="app-version">版本 ${escape(state.auth?.version || '开发构建')}</small></footer>
      </aside>
      <section class="workspace" data-slot="sidebar-inset">
        <header class="app-header" data-slot="header"><div class="header-context"><button type="button" class="ui-button quiet icon-button" data-action="sidebar-toggle" aria-label="${collapsed ? '展开' : '收起'}导航侧栏" aria-controls="app-sidebar" aria-expanded="${!collapsed}" title="${collapsed ? '展开' : '收起'}导航侧栏">${glyph('sidebar')}</button><span class="header-divider" aria-hidden="true"></span><nav class="breadcrumb" aria-label="当前位置">${route === 'overview' ? '<span aria-current="page">工作台</span>' : `<button type="button" class="breadcrumb-home" data-action="navigate" data-route="overview">工作台</button>${glyph('chevron')}<span class="breadcrumb-group">${escape(selectedGroup?.title || '工作区')}</span>${glyph('chevron')}<span aria-current="page">${escape(names[route] || route)}</span>`}</nav></div>
        <div class="header-tools"><button type="button" class="ui-button outline command-trigger" data-action="command-open" aria-label="快速查找功能，Ctrl+K" aria-keyshortcuts="Control+K" aria-haspopup="dialog">${glyph('search')}<span>快速查找功能</span><kbd>Ctrl K</kbd></button><button type="button" class="ui-button quiet icon-button" data-action="theme-toggle" aria-label="切换为${dark ? '浅色' : '深色'}外观" title="切换为${dark ? '浅色' : '深色'}外观">${glyph(dark ? 'sun' : 'moon')}</button><button type="button" class="ui-button quiet notification-trigger" data-action="notifications" aria-label="经营提醒${count ? `，${count} 项待查看` : ''}">${glyph('bell')}<span>经营提醒</span>${count ? `<span class="notification-count">${count > 99 ? '99+' : count}</span>` : ''}</button></div></header>
        <div class="topbar" data-slot="scope-toolbar"><div class="scope-fields"><label>工作区<select id="space-select" aria-label="切换工作区"><option value="live"${state.space === 'live' ? ' selected' : ''}>真实经营</option><option value="test"${state.space === 'test' ? ' selected' : ''}>隔离测试</option></select></label><label>经营账号<select id="account-select" aria-label="筛选经营账号"><option value=""${!state.accountId ? ' selected' : ''}>全部账号</option>${options}</select></label></div><div class="scope-status"><span class="sync${state.backgroundChanged ? ' has-changes' : ''}" aria-live="polite">${escape(sync)}</span><button type="button" class="ui-button outline small" data-action="reload">${glyph('refresh')}<span>刷新</span></button></div></div>
        ${state.space === 'test' ? `<div class="test-banner" role="note"><div><strong>隔离测试工作区</strong><span>仅用于试运行，商品、买家与回执不计入真实经营。</span></div>${button('载入测试资料', 'seed', '', 'small outline')}</div>` : ''}
        <main id="main" tabindex="-1" data-route="${escape(route)}" data-layout="auto"><div id="page-error" role="alert"></div>${content}</main>
      </section>
    </div>`;
  }
  window.LianpuUI = Object.freeze({ escape, button, badge, empty, heading, shell });
})();
