// Independent support protocol. Never accepted as a licensing proof.
export const VERSION = 1;
export const LIMITS = Object.freeze({ text:16384, image:262144, images:2, steps:30 });
const encoder=new TextEncoder();
export const bytes=value=>encoder.encode(typeof value==='string'?value:JSON.stringify(value));
export function requireValue(ok,code='REPORT_INVALID'){if(!ok){const e=new Error(code);e.code=code;throw e;}}
export const b64=value=>{let s='';for(const b of new Uint8Array(value))s+=String.fromCharCode(b);return btoa(s).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');};
export const un64=value=>{requireValue(typeof value==='string'&&/^[\w-]+$/.test(value));return Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')),x=>x.charCodeAt(0));};
export const digest=async value=>b64(await crypto.subtle.digest('SHA-256',typeof value==='string'?bytes(value):value));
export const uuid=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export const tag=(value,fallback='unknown')=>typeof value==='string'&&/^[a-zA-Z0-9_.:-]{1,100}$/.test(value)?value:fallback;
export function cleanText(value,max=2000){return String(value||'').slice(0,max).replace(/(?:https?:\/\/|file:\/\/)[^\s<>"']+/gi,'[地址已隐藏]').replace(/(?:[A-Z]:[\\/]|\\\\)[^\s<>"']+/gi,'[路径已隐藏]').replace(/\b(?:cookie|authorization|password|token|secret|api[_-]?key|提取码|兑换码|激活码)\s*[:=：]\s*[^\s,;，；]+/gi,'[凭据已隐藏]').replace(/\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|eyJ[A-Za-z0-9_.-]{20,})\b/g,'[凭据已隐藏]').replace(/LP1-[WMYP]-[A-F0-9]{40}/gi,'[兑换码已隐藏]').replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u206F]/g,'');}
export function frameList(stack){return String(stack||'').split('\n').slice(0,30).flatMap(line=>{const m=line.match(/(?:[\\/])(src|shared)[\\/]([A-Za-z0-9_./\\-]+\.(?:cjs|mjs|js)):(\d+):(\d+)/);return m&&!m[2].includes('..')?[`${m[1]}/${m[2].replaceAll('\\','/')}:${m[3]}:${m[4]}`]:[];}).slice(0,12);}
export function context(value={}){const out={};for(const k of ['space','source','role','connection','login','stage','result'])if(value[k]!=null)out[k]=tag(value[k]);for(const k of ['bound','stockAvailable','hosting'])if(typeof value[k]==='boolean')out[k]=value[k];for(const k of ['items','durationMs'])if(Number.isFinite(value[k]))out[k]=Math.max(0,Math.min(1e9,Math.round(value[k])));return out;}
export function normalizeReport(input){
 requireValue(input&&uuid(input.id)&&['automatic','manual'].includes(input.kind));
 const r={v:1,id:input.id,kind:input.kind,version:tag(input.version),build:tag(input.build),platform:tag(input.platform),feature:tag(input.feature),code:tag(input.code),at:input.at,firstAt:input.firstAt||input.at,count:Math.max(1,Math.min(1e6,Number(input.count)||1)),context:context(input.context),frames:frameList((input.frames||[]).map(x=>'/'+x).join('\n')),steps:[],attachments:[]};
 requireValue(Number.isSafeInteger(r.at)&&r.at>0&&Number.isSafeInteger(r.firstAt)&&r.firstAt>0);
 for(const s of (Array.isArray(input.steps)?input.steps:[]).slice(-30))r.steps.push({feature:tag(s.feature),at:Number.isSafeInteger(s.at)?s.at:r.at,...context(s)});
 if(r.kind==='manual'){r.description=cleanText(input.description);r.reproduce=cleanText(input.reproduce);r.expected=cleanText(input.expected,1000);r.actual=cleanText(input.actual,1000);r.contact=cleanText(input.contact,200);requireValue(r.description.trim().length>0);}
 for(const a of (Array.isArray(input.attachments)?input.attachments:[])){requireValue(uuid(a.id)&&typeof a.digest==='string'&&/^[\w-]{43}$/.test(a.digest)&&Number.isSafeInteger(a.size)&&a.size>0&&a.size<=LIMITS.image&&['image/png','image/jpeg'].includes(a.mime));r.attachments.push({id:a.id,digest:a.digest,size:a.size,mime:a.mime});}
 requireValue(r.attachments.length<=2&&(r.kind==='manual'||r.attachments.length===0));requireValue(bytes(r).length<=LIMITS.text,'REPORT_TOO_LARGE');return r;
}
export const proofBytes=(purpose,value)=>bytes('LIANPU-REPORT/v1/'+purpose+'\0'+JSON.stringify(value));
