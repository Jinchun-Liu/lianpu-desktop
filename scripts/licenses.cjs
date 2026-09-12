'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'compliance');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const json = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const relative = file => path.relative(ROOT, file).replaceAll('\\', '/');
function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(item => {
    const target = path.join(dir, item.name);
    return item.isDirectory() ? walk(target) : item.isFile() ? [target] : [];
  });
}
function copyEvidence(source, prefix) {
  const bytes = fs.readFileSync(source);
  const hash = sha(bytes);
  const destination = path.join(OUT, 'license-evidence', `${prefix.replace(/[^a-zA-Z0-9.-]/g, '_')}-${hash.slice(0, 12)}-${path.basename(source)}`);
  fs.copyFileSync(source, destination);
  return { path: relative(destination), originalPath: relative(source), sha256: hash, bytes: bytes.length };
}
function obligations(label) {
  if (/Apache-2\.0/.test(label)) return '保留许可证、版权和适用 NOTICE；标记修改；遵守专利及商标限制。';
  if (/MIT|ISC|BSD/.test(label)) return '保留版权、许可条件及免责声明；有署名/非背书条件时一并保留。';
  if (/Zlib/.test(label)) return '不冒认来源；修改版本需标记；源代码分发保留声明。';
  return '需依据证据原文逐项审查；不能仅凭标签确认分发义务。';
}
function collectUiReuse() {
  const manifestFile = path.join(OUT, 'ui-reuse', 'manifest.json');
  if (!fs.existsSync(manifestFile)) return null;
  const declared = json(manifestFile), origin = json(path.join(OUT, 'ui-reuse', 'origin.json'));
  if (declared.schemaVersion !== 1 || declared.upstream.commit !== origin.commit) throw new Error('UI 复用记录与固定来源提交不一致');
  const licenseEvidence = declared.licenseEvidence.map(entry => {
    const file = path.resolve(ROOT, entry.path), base = path.join(OUT, 'ui-reuse', 'licenses') + path.sep;
    if (!file.startsWith(base) || !fs.statSync(file).isFile() || fs.lstatSync(file).isSymbolicLink()) throw new Error('UI 许可原文必须在固定随包证据目录');
    const bytes = fs.readFileSync(file);
    if (sha(bytes) !== entry.sha256 || bytes.length !== entry.bytes) throw new Error('UI 许可原文字节与来源记录不一致');
    return { ...entry, actualSha256: sha(bytes), includedWithProduct: true };
  });
  const categories = new Set(['pending', 'layout-reference', 'code-adaptation', 'verbatim-copy', 'original']);
  const modules = declared.modules.map(module => {
    if (!categories.has(module.category)) throw new Error('UI 复用类别无效');
    const upstreamFiles = module.upstreamPaths.map(name => {
      const source = origin.selectedCandidateFiles.find(file => file.path === name);
      if (!source) throw new Error('UI 复用模块未登记精确上游文件: ' + name);
      return source;
    });
    const localFiles = module.localFiles.map(name => {
      const file = path.resolve(ROOT, name), base = path.join(ROOT, 'src', 'renderer') + path.sep;
      if (!file.startsWith(base)) throw new Error('UI 适配目的路径必须在渲染层');
      if (!fs.existsSync(file)) return { path: name, exists: false, sha256: null };
      if (!fs.statSync(file).isFile() || fs.lstatSync(file).isSymbolicLink()) throw new Error('UI 适配文件必须为普通文件');
      const bytes = fs.readFileSync(file); return { path: name, exists: true, sha256: sha(bytes), bytes: bytes.length };
    });
    const mappingComplete = module.category !== 'pending' && module.reviewStatus === 'recorded' && localFiles.length > 0 && localFiles.every(file => file.exists) && (module.category === 'original' || upstreamFiles.length > 0);
    return { ...module, upstreamFiles, localFiles, mappingComplete, adaptedCodeBundled: mappingComplete && ['code-adaptation', 'verbatim-copy'].includes(module.category) };
  });
  return { ...declared, manifestPath: relative(manifestFile), manifestSha256: sha(fs.readFileSync(manifestFile)), originPath: 'compliance/ui-reuse/origin.json', licenseEvidence, modules,
    adaptedCodeBundled: modules.some(module => module.adaptedCodeBundled), templateRuntimeBundled: false,
    moduleMappingComplete: modules.length > 0 && modules.every(module => module.mappingComplete),
    reviewStatus: modules.length > 0 && modules.every(module => module.mappingComplete) ? 'source-and-license-recorded-not-commercial-approval' : 'incomplete-actual-module-mapping',
    note: '只有逐模块源码转写/复制列为随包改编代码；布局参考不会被统计成 React 依赖或原样模板运行。源码出处记录不等于商业分发全部义务完成。' };
}
function uiReuseNotices(uiReuse) {
  if (!uiReuse) return '';
  let text = '\n## 开源 UI 参考与适配\n\n';
  text += `界面使用 Shadcn Admin ${uiReuse.upstream.version}（提交 ${uiReuse.upstream.commit}）的限定组件参考或适配；具体是否转写源码见 [逐模块记录](${uiReuse.manifestPath})。产品保留原生 DOM/CSS 渲染层和既有桌面桥，不装入 React 模板运行环境，不引入模板认证或演示业务数据。\n\n`;
  text += `逐模块登记状态：${uiReuse.reviewStatus}。shadcn/ui 补充原文只证明该许可文件的来源，不把其许可文件提交冒充模板基础组件的原始代码提交。\n\n`;
  for (const evidence of uiReuse.licenseEvidence) text += `### ${evidence.name}\n\n来源：[固定许可原文](${evidence.source})；随包文件：[${path.basename(evidence.path)}](${evidence.path})；SHA-256：${evidence.sha256}。\n\n\`\`\`text\n${fs.readFileSync(path.join(ROOT, evidence.path), 'utf8').trimEnd()}\n\`\`\`\n\n`;
  return text;
}
function generate({ installerFormat = 'msi' } = {}) {
  fs.mkdirSync(path.join(OUT, 'license-evidence'), { recursive: true });
  const lock = json(path.join(ROOT, 'package-lock.json'));
  const manifest = json(path.join(ROOT, 'package.json'));
  const uiReuse = collectUiReuse();
  const components = [];
  for (const [installPath, entry] of Object.entries(lock.packages || {})) {
    if (!installPath) continue;
    const dir = path.join(ROOT, installPath);
    const pkg = fs.existsSync(path.join(dir, 'package.json')) ? json(path.join(dir, 'package.json')) : {};
    const name = pkg.name || installPath.split('node_modules/').at(-1);
    const evidence = fs.existsSync(dir) ? fs.readdirSync(dir).filter(f => /^(licen[cs]e|copying|notice)([._-]|$)/i.test(f) && fs.statSync(path.join(dir, f)).isFile()).map(f => copyEvidence(path.join(dir, f), `${name}-${entry.version}`)) : [];
    const license = typeof pkg.license === 'string' ? pkg.license : entry.license || 'NOASSERTION';
    const declaredVersionMatches = pkg.version === entry.version;
    components.push({ name, version: entry.version, installPath, direct: Object.hasOwn(manifest.devDependencies || {}, name) || Object.hasOwn(manifest.dependencies || {}, name),
      source: entry.resolved || null, integrity: entry.integrity || null, repository: pkg.repository || null,
      license, modified: false, bundled: false, distribution: name === 'electron' ? 'npm 安装器不随包；其下载的 Electron 运行时单列' : '仅开发或测试；不复制 node_modules 到产品',
      evidence, obligations: obligations(license), versionMatchesLock: declaredVersionMatches,
      reviewStatus: evidence.length && declaredVersionMatches ? 'evidence-collected-review-required' : 'incomplete',
      reviewNote: '精确版本与许可原文已采集不等于人工审查通过。' });
  }
  const runtime = path.join(ROOT, 'node_modules', 'electron', 'dist');
  const runtimeFiles = fs.existsSync(runtime) ? walk(runtime).filter(file => !/\.log$/i.test(file)).map(file => {
    const bytes = fs.readFileSync(file); let architecture = null;
    if (bytes.length > 64 && bytes.readUInt16LE(0) === 0x5a4d) {
      const pe = bytes.readUInt32LE(60);
      if (pe + 6 < bytes.length && bytes.readUInt32LE(pe) === 0x4550) architecture = ({ 0x8664: 'x64', 0xaa64: 'arm64', 0x14c: 'x86' })[bytes.readUInt16LE(pe + 4)] || 'unknown';
    }
    return { path: path.relative(runtime, file).replaceAll('\\', '/'), size: bytes.length, sha256: sha(bytes), architecture, bundled: !file.endsWith('default_app.asar'),
      ...(architecture ? { licenseReviewStatus: 'incomplete-exact-binary-license-mapping', obligations: '将此精确二进制哈希与其上游构建、版权许可、再分发范围和任何对应源码义务逐一关联。' } : {}) };
  }) : [];
  const runtimeEvidence = fs.existsSync(runtime) ? fs.readdirSync(runtime).filter(f => /license|notice|copying/i.test(f)).map(f => copyEvidence(path.join(runtime, f), 'electron-runtime')) : [];
  let versions = null;
  const executable = path.join(runtime, process.platform === 'win32' ? 'electron.exe' : 'electron');
  if (fs.existsSync(executable)) {
    const probe = spawnSync(executable, ['-p', 'JSON.stringify(process.versions)'], { encoding: 'utf8', env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, windowsHide: true });
    if (probe.status === 0) { try { versions = JSON.parse(probe.stdout.trim()); } catch {} }
  }
  const abiKeys = new Set(['modules', 'napi', 'cldr', 'unicode', 'tz']);
  const runtimeComponents = versions ? Object.entries(versions).filter(([name, version]) => version && !abiKeys.has(name)).map(([name, version]) => ({ name, version, versionReliable: version !== '0.0.0', bundled: true, source: 'https://github.com/electron/electron/releases/tag/v' + versions.electron, evidence: runtimeEvidence,
    reviewStatus: 'aggregate-notice-collected-component-mapping-required' })) : [];
  const checksumFile=path.join(ROOT,'node_modules','electron','checksums.json');
  const archiveName=`electron-v${manifest.devDependencies.electron}-win32-x64.zip`;
  const runtimeArchive={declaredUpstreamUrl:`https://github.com/electron/electron/releases/download/v${manifest.devDependencies.electron}/${archiveName}`,expectedSha256:fs.existsSync(checksumFile)?json(checksumFile)[archiveName]||null:null,checksumMetadata:fs.existsSync(checksumFile)?{path:relative(checksumFile),sha256:sha(fs.readFileSync(checksumFile))}:null,archiveRehashedDuringThisAudit:false,note:'上游预期归档哈希来自锁定 npm 包内 checksums.json；本脚本另行校验每个解压后的实际运行文件，不把预期值冒充重新下载归档实测。'};
  const chromiumNotice = path.join(runtime, 'LICENSES.chromium.html');
  const noticeHeadings = fs.existsSync(chromiumNotice) ? [...fs.readFileSync(chromiumNotice, 'utf8').matchAll(/<span class="title">([^<]+)<\/span>/g)].map(m => m[1]) : [];
  const decode = value => value.replace(/&#(x[0-9a-f]+|[0-9]+);/gi, (_all, n) => String.fromCodePoint(n[0].toLowerCase() === 'x' ? parseInt(n.slice(1), 16) : parseInt(n, 10))).replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&quot;', '"').replaceAll('&#39;', "'").replaceAll('&amp;', '&');
  const chromiumComponents = fs.existsSync(chromiumNotice) ? [...fs.readFileSync(chromiumNotice, 'utf8').matchAll(/<div class="product">\s*<span class="title">([^<]+)<\/span>([\s\S]*?)<pre>([\s\S]*?)<\/pre>/g)].map((match, i) => {
    const text = decode(match[3]);
    const indicators = [['LGPL', /GNU LESSER GENERAL PUBLIC LICENSE|GNU LIBRARY GENERAL PUBLIC LICENSE/i], ['GPL', /GNU GENERAL PUBLIC LICENSE/i], ['MPL', /Mozilla Public License/i], ['Apache-2.0', /Apache License[\s\S]{0,90}Version 2\.0/], ['BSD', /Redistribution and use in source and binary forms/], ['MIT', /Permission is hereby granted, free of charge/], ['Zlib', /The origin of this software must not be misrepresented/]].filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
    const name = decode(match[1]); const hash = sha(Buffer.from(text));
    const evidenceName = `chromium-${String(i + 1).padStart(4, '0')}-${hash.slice(0, 12)}.txt`;
    fs.writeFileSync(path.join(OUT, 'license-evidence', evidenceName), text);
    return { name, bundled: 'unverified-listed-in-upstream-notice', modified: 'upstream-build-configuration-not-yet-mapped', version: null, versionStatus: 'individual revision not specified in aggregate notice; map exact Electron/Chromium build source',
      source: decode(match[2].match(/<a href="([^"]+)"/)?.[1] || ''), parentRuntime: `Electron ${versions?.electron || manifest.devDependencies.electron} / Chromium ${versions?.chrome || 'unknown'}`,
      evidence: { path: relative(path.join(OUT, 'license-evidence', evidenceName)), sha256: hash, aggregatePath: relative(chromiumNotice) }, possibleLicenseIndicators: indicators,
      obligations: indicators.some(x => ['LGPL', 'GPL', 'MPL'].includes(x)) ? '逐项核验适用版本、链接方式、修改、对应源码或重新链接材料及分发义务；不得仅保留标签。' : '核验完整版权、许可和 NOTICE 是否保留、构建实际使用范围及条款；不能仅凭关键词判定许可。',
      reviewStatus: 'incomplete-version-and-obligation-review' };
  }) : [];
  fs.writeFileSync(path.join(OUT, 'chromium-components.json'), JSON.stringify(chromiumComponents, null, 2));
  const nsisCopying = path.join(ROOT, 'work', 'tools', 'nsis-3.12', 'COPYING');
  const nsis = fs.existsSync(nsisCopying) ? { name: 'NSIS', version: '3.12', source: 'https://sourceforge.net/projects/nsis/files/NSIS%203/3.12/', modified: false,
    license: 'Zlib', bundled: installerFormat === 'nsis' ? 'zlib installer stub and standard NSIS UI components only; build compiler excluded' : false, distribution: installerFormat === 'nsis' ? 'selected installer format' : '仅保留历史失败诊断工具与许可证据；MSI 产品不含 NSIS', evidence: [copyEvidence(nsisCopying, 'nsis-3.12')],
    obligations: '保留 NSIS 原始归属与许可；仅选择 zlib 压缩模块，不将 NSIS LZMA/BZip2 模块加入安装产物。', reviewStatus: 'evidence-collected-review-required' } : null;
  const assets = [
    { name: '界面字体', version: 'host-system', bundled: false, source: '操作系统字体回退，无字体文件复制', license: 'not-redistributed', reviewStatus: 'file-list-check-required' },
    { name: '项目自绘图形与图标', version: manifest.version, bundled: true, source: '本项目绘制的图形独立登记；UI 模板参考/适配的第三方归属另见 uiReuse，不将模板组件宣称为原创', license: 'proprietary-undetermined-by-owner', reviewStatus: 'authorship-file-list-check-required' }
  ];
  const hostSpecs = [['makecab.exe',['developer-build']],['msiexec.exe',['developer-verification','installed-app-update-installation']],['msi.dll',['developer-build','developer-verification','installed-app-update-inspection']],['WindowsPowerShell/v1.0/powershell.exe',['developer-build','developer-verification','installed-app-update-inspection']]];
  const windowsTools = process.platform === 'win32' ? hostSpecs.map(([name,roles]) => { const file = path.join(process.env.SystemRoot,'System32',name); return { name, roles, source: '本机 Windows 系统组件', version: 'host-provided; varies across supported Windows installations', observedBuildHostSha256: fs.existsSync(file) ? sha(fs.readFileSync(file)) : null, bundled: false, modified: false, license: 'host-Windows-license-not-redistributed', obligations: '不复制 Windows 组件到产品；安装与更新身份核验使用用户系统已有的 Windows Installer/PowerShell；不可用或被策略限制时停止，不调整保护配置。', reviewStatus: 'not-redistributed' }; }) : [];
  const payload = { generatedAt: new Date().toISOString(), packageLockSha256: sha(fs.readFileSync(path.join(ROOT, 'package-lock.json'))), components, runtime: { version: versions, archive:runtimeArchive, evidence: runtimeEvidence, files: runtimeFiles, components: runtimeComponents, noticeHeadings, chromiumComponentsFile: 'compliance/chromium-components.json', chromiumComponentCount: chromiumComponents.length }, installer: installerFormat === 'msi' ? { format:'msi', engine:'Windows Installer', hostComponents:windowsTools, bundledExecutableStub:false, buildCode:'scripts/release-msi.cjs 独立编写' } : nsis, historicalDevelopmentTool: nsis, assets,
    uiReuse, commercialDistributionApproved: false,
    unresolved: ['Chromium 聚合许可中的每个原生/静态组件尚需与精确构建版本、适用许可和源码提供义务对应审查。', '特别核验 FFmpeg、编解码器和任何具有源码提供要求的构建组件；聚合许可证存在不等于义务全部完成。', '正式发行主体、产品许可、商标及代码签名未确定。'] };
  fs.writeFileSync(path.join(OUT, 'inventory.json'), JSON.stringify(payload, null, 2));
  fs.writeFileSync(path.join(OUT, 'runtime-files.json'), JSON.stringify(runtimeFiles, null, 2));
  const bom = { bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:' + crypto.randomUUID(), version: 1,
    metadata: { timestamp: payload.generatedAt, component: { type: 'application', name: manifest.name, version: manifest.version } },
    components: [...components.map(c => ({ type: 'library', name: c.name, version: c.version, purl: `pkg:npm/${c.name.replace('@', '%40')}@${c.version}`, scope: 'excluded',
      ...(c.license !== 'NOASSERTION' ? { licenses: [{ expression: c.license }] } : {}), externalReferences: c.source ? [{ type: 'distribution', url: c.source }] : [],
      properties: [{ name: 'lianpu:review', value: c.reviewStatus }, { name: 'lianpu:modified', value: 'false' }] })),
      ...runtimeComponents.map(c => ({ type: 'library', name: c.name, version: c.version, scope: 'required', properties: [{ name: 'lianpu:review', value: c.reviewStatus }] })),
      ...chromiumComponents.map(c => ({ type: 'library', name: c.name, properties: [{ name: 'lianpu:review', value: c.reviewStatus }, { name: 'lianpu:runtime-inclusion', value: c.bundled }, { name: 'lianpu:license-text-sha256', value: c.evidence.sha256 }, { name: 'lianpu:upstream-reference', value: c.source }] })),
      ...windowsTools.map(c => ({type:'application',name:'Windows host: '+c.name,version:'host-provided',scope:c.roles.some(role=>role.startsWith('installed-app-'))?'optional':'excluded',properties:[{name:'lianpu:bundled',value:'false'},{name:'lianpu:roles',value:c.roles.join(',')},{name:'lianpu:observed-build-host-sha256',value:c.observedBuildHostSha256||'unavailable'},{name:'lianpu:version-scope',value:'Host OS component; exact build-host bytes only, not the consumer OS version.'}]})),
      ...(uiReuse ? [{type:'framework',name:'Shadcn Admin UI reference/adaptation',version:uiReuse.upstream.version+'+git.'+uiReuse.upstream.commit,scope:uiReuse.adaptedCodeBundled?'required':'excluded',licenses:[{license:{id:'MIT'}}],externalReferences:[{type:'vcs',url:uiReuse.upstream.repository+'/tree/'+uiReuse.upstream.commit}],properties:[{name:'lianpu:review',value:uiReuse.reviewStatus},{name:'lianpu:template-runtime-bundled',value:'false'},{name:'lianpu:adapted-code-bundled',value:String(uiReuse.adaptedCodeBundled)},{name:'lianpu:module-record',value:uiReuse.manifestPath},{name:'lianpu:license-evidence',value:uiReuse.licenseEvidence.map(e=>e.path+'#sha256='+e.sha256).join(';')}]}] : []),
      ...(nsis ? [{ type: 'framework', name: installerFormat === 'nsis' ? 'NSIS installer stub' : 'NSIS historical development tool', version: nsis.version, scope: installerFormat === 'nsis' ? 'required' : 'excluded', licenses: [{ license: { id: 'Zlib' } }] }] : [])] };
  fs.writeFileSync(path.join(ROOT, 'SBOM.cdx.json'), JSON.stringify(bom, null, 2));
  let notices = '# 第三方声明\n\n联铺原创业务代码的发行许可由权利人决定。本文件不授予原创代码开源许可。\n\n';
  notices += `Electron ${versions?.electron || manifest.devDependencies.electron} 及内置 Node.js、Chromium、V8 与原生组件按各自许可提供。完整原文保存在随包的 compliance/license-evidence 内，Electron 运行时原始 LICENSE 和 LICENSES.chromium.html 亦保留。不得将第三方组件宣称为本项目原创。\n\n`;
  if (installerFormat === 'msi') notices += '安装包为独立编写的 MSI 数据库及 CAB 载荷，使用本机 Windows Installer。Windows makecab、msiexec、msi.dll 和 PowerShell 不随包复制；makecab 用于开发打包，更新身份核验及启动安装使用系统已有的 PowerShell/Windows Installer。系统组件受限时停止更新，不改变执行策略或保护配置。NSIS 仅用于历史安装诊断；其许可文本保留作为开发证据，MSI 不包含 NSIS 安装运行代码。\n\n';
  else if (nsis) notices += '安装器使用 NSIS 3.12 标准组件及 zlib 压缩，编译工具不随产品安装。其 COPYING 原文保存在随包许可证据目录。\n\n';
  notices += '## 精确开发依赖（不随运行包复制）\n\n| 名称 | 版本 | 声明许可 | 原文证据 |\n| --- | --- | --- | --- |\n';
  for (const c of components) notices += `| ${c.name} | ${c.version} | ${c.license} | ${c.evidence.map(e => `[${path.basename(e.path)}](${e.path})`).join(', ') || '缺失，未完成'} |\n`;
  notices += uiReuseNotices(uiReuse);
  notices += '\n## 审查状态\n\n此清单是可复核的证据集合。尚未完成的原生组件版本映射、义务检查与源码材料不得标为通过，详见 compliance/inventory.json。安装器当前用于开发验证，不能将本次清单当作正式商业发行许可审查已完成的证明。\n';
  fs.writeFileSync(path.join(ROOT, 'THIRD_PARTY_NOTICES.md'), notices);
  process.stdout.write(JSON.stringify({ packages: components.length, missingLicenseEvidence: components.filter(c => !c.evidence.length).map(c => c.name), runtimeFiles: runtimeFiles.length, chromiumComponents: chromiumComponents.length, runtimeVersions: versions, commercialDistributionApproved: false }) + '\n');
  return payload;
}
if (require.main === module) generate();
module.exports = { generate, walk, sha, collectUiReuse, uiReuseNotices };
