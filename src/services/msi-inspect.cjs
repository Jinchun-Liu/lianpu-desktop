'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const run = promisify(execFile);
const PRODUCT = Object.freeze({ name: '联铺', manufacturer: 'Lianpu Development', upgradeCode: '{9B0F315E-5660-4A1A-81E9-47E22F57C2B1}', architecture: 'x64', allUsers: '2', msiInstallPerUser: '1' });
class MsiInspectionError extends Error {
  constructor(code, message) { super(message); this.name = 'MsiInspectionError'; this.code = code; }
}
function fail(code, message) { throw new MsiInspectionError(code, message); }
// Only the main-process updater supplies this already prepared local path.
// It is never an IPC handler and does not accept an installer path from renderer input.
async function inspectMsi(file, { expectedVersion } = {}) {
  if (process.platform !== 'win32' || process.arch !== PRODUCT.architecture) fail('MSI_INSPECTION_UNAVAILABLE', '当前系统不支持此 Windows x64 安装包核验。');
  if (typeof file !== 'string' || !path.isAbsolute(file) || path.extname(file).toLowerCase() !== '.msi' || file.includes('\0')) fail('MSI_PATH_INVALID', '安装包准备路径无效。');
  if (typeof expectedVersion !== 'string' || !/^\d{1,3}\.\d{1,3}\.\d{1,5}$/.test(expectedVersion)) fail('MSI_EXPECTATION_INVALID', '安装包预期版本无效。');
  let stat;
  try { stat = await fs.lstat(file); } catch { fail('MSI_FILE_UNAVAILABLE', '无法读取已准备的安装包。'); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 512 || stat.size > 1024 * 1024 * 1024) fail('MSI_FILE_INVALID', '已准备的安装包文件无效。');
  const windows = process.env.SystemRoot || process.env.WINDIR;
  if (!windows || !path.isAbsolute(windows)) fail('MSI_INSPECTION_UNAVAILABLE', '无法定位系统安装包核验组件。');
  const executable = path.join(windows, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const helper = path.join(__dirname, 'msi-inspect.ps1');
  let raw;
  try {
    const result = await run(executable, ['-NoProfile', '-NonInteractive', '-File', helper, '-MsiPath', file], { encoding: 'utf8', windowsHide: true, timeout: 15000, maxBuffer: 32768 });
    raw = JSON.parse(result.stdout.replace(/^\uFEFF/, '').trim());
  } catch {
    // Do not include arbitrary PowerShell output, filesystem paths or MSI strings.
    fail('MSI_INSPECTION_FAILED', '系统无法核验安装包身份，已停止更新。');
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('MSI_METADATA_INVALID', '安装包身份信息无效。');
  const keys = ['productName', 'productVersion', 'upgradeCode', 'productCode', 'manufacturer', 'allUsers', 'msiInstallPerUser', 'template'];
  if (keys.some(key => typeof raw[key] !== 'string' || raw[key].length > 255)) fail('MSI_METADATA_INVALID', '安装包身份信息不完整。');
  const architecture = raw.template.split(';')[0];
  if (raw.productName !== PRODUCT.name || raw.manufacturer !== PRODUCT.manufacturer || raw.upgradeCode.toUpperCase() !== PRODUCT.upgradeCode ||
      raw.productVersion !== expectedVersion || raw.allUsers !== PRODUCT.allUsers || raw.msiInstallPerUser !== PRODUCT.msiInstallPerUser || architecture !== PRODUCT.architecture ||
      !/^\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}$/i.test(raw.productCode) ||
      !Number.isInteger(raw.wordCount) || (raw.wordCount & 10) !== 10) fail('MSI_IDENTITY_MISMATCH', '安装包的产品、版本、架构或安装范围与本产品不符。');
  return { verified: true, inspectedAt: new Date().toISOString(), productName: PRODUCT.name, productVersion: raw.productVersion, upgradeCode: PRODUCT.upgradeCode, productCode: raw.productCode.toUpperCase(), manufacturer: PRODUCT.manufacturer, allUsers: raw.allUsers, msiInstallPerUser: raw.msiInstallPerUser, architecture, template: raw.template, wordCount: raw.wordCount, windowsCodeSignatureVerified: false };
}
module.exports = { inspectMsi, MsiInspectionError, PRODUCT };
