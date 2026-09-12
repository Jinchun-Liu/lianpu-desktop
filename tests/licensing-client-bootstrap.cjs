'use strict';
// Test-only entrypoint. It explicitly supplies isolated software signing keys and
// transport to the normal constructor; no customer code reads a bypass flag.
const {fixture}=require('./licensing-client-fixture.cjs');
const callbacks=[],prepared=(async()=>{const f=await fixture({after:fn=>callbacks.push(fn)});await f.activate();globalThis.__licenseFixture=f;return f;})();
const {app}=require('electron');app.once('will-quit',()=>{for(const callback of callbacks)callback();});
const clientModule=require('../src/licensing/client.cjs');
clientModule.createLicenseClient=async options=>{const f=await prepared;f.client.onChange=options.onChange;f.client.lastPublished='';return f.client;};
require('../src/main.cjs');
