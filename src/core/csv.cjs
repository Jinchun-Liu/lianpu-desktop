'use strict';

function parseCsv(text) {
  if (typeof text !== 'string' || text.length > 10 * 1024 * 1024) throw new Error('CSV 必须是小于 10 MB 的文本。');
  text = text.replace(/^\uFEFF/, '');
  const rows = []; let row = []; let field = ''; let quoted = false; let closed = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') { quoted = false; closed = true; }
      else field += c;
    } else if (c === '"' && field === '' && !closed) quoted = true;
    else if (c === ',' || c === '\r' || c === '\n') {
      row.push(field); field = ''; closed = false;
      if (c !== ',') { rows.push(row); row = []; if (c === '\r' && text[i + 1] === '\n') i++; }
    } else {
      if (closed || c === '"') throw new Error(`CSV 第 ${rows.length + 1} 行引号格式无效。`);
      field += c;
    }
  }
  if (quoted) throw new Error('CSV 含有未关闭的引号。');
  if (field || row.length || closed) { row.push(field); rows.push(row); }
  return rows;
}

// Prefix dangerous spreadsheet expressions. An accompanying metadata column makes reversal explicit.
function protect(value) {
  const text = value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  return /^[\s]*[=+\-@\t\r]/.test(text) || /^'/.test(text) || /^\d{15,}$/.test(text) || /^0\d+$/.test(text) ? `'${text}` : text;
}
function quote(value) { return `"${String(value).replaceAll('"', '""')}"`; }
function exportCsv(rows, columns) {
  const header = [...columns, '_format'];
  return '\uFEFF' + [header.map(quote).join(','), ...rows.map(row => [...columns.map(key => protect(row[key])), 'lianpu-csv-v1'].map(quote).join(','))].join('\r\n');
}
function unprotect(value, trustedFormat) { return trustedFormat && value.startsWith("'") ? value.slice(1) : value; }
module.exports = { parseCsv, exportCsv, unprotect };
