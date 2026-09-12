'use strict';
const { contextBridge, ipcRenderer } = require('electron');
let pageGeneration = 0;
ipcRenderer.on('desk:event', (_event, value) => { if (['member-changed','access-revoked','workspace-closed'].includes(value?.type)) pageGeneration++; });
contextBridge.exposeInMainWorld('desk', Object.freeze({
  call: async (action, payload = {}) => {
    const epoch=pageGeneration,result=await ipcRenderer.invoke('desk:call', action, payload);
    if(epoch!==pageGeneration&&!String(action).startsWith('auth.'))return {ok:false,error:{code:'SESSION_CHANGED',message:'当前成员已变更，旧请求结果已清除。'}};
    return result;
  },
  onEvent: (callback) => {
    if (typeof callback !== 'function') return () => {};
    const listener = (_event, value) => callback(value);
    ipcRenderer.on('desk:event', listener);
    return () => ipcRenderer.removeListener('desk:event', listener);
  }
}));
