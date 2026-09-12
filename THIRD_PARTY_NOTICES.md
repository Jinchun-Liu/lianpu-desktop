# 第三方声明

联铺原创业务代码的发行许可由权利人决定。本文件不授予原创代码开源许可。

Electron 44.3.0 及内置 Node.js、Chromium、V8 与原生组件按各自许可提供。完整原文保存在随包的 compliance/license-evidence 内，Electron 运行时原始 LICENSE 和 LICENSES.chromium.html 亦保留。不得将第三方组件宣称为本项目原创。

安装包为独立编写的 MSI 数据库及 CAB 载荷，使用本机 Windows Installer。Windows makecab、msiexec、msi.dll 和 PowerShell 不随包复制；makecab 用于开发打包，更新身份核验及启动安装使用系统已有的 PowerShell/Windows Installer。系统组件受限时停止更新，不改变执行策略或保护配置。NSIS 仅用于历史安装诊断；其许可文本保留作为开发证据，MSI 不包含 NSIS 安装运行代码。

## 精确开发依赖（不随运行包复制）

| 名称 | 版本 | 声明许可 | 原文证据 |
| --- | --- | --- | --- |
| @electron-internal/extract-zip | 1.0.5 | BSD-2-Clause | 缺失，未完成 |
| @electron/asar | 4.3.0 | MIT | [_electron_asar-4.3.0-d5af8fc171f6-LICENSE.md](compliance/license-evidence/_electron_asar-4.3.0-d5af8fc171f6-LICENSE.md) |
| @electron/fuses | 2.1.3 | MIT | [_electron_fuses-2.1.3-24e49a190cf9-LICENSE](compliance/license-evidence/_electron_fuses-2.1.3-24e49a190cf9-LICENSE) |
| @electron/get | 5.1.0 | MIT | [_electron_get-5.1.0-edab8abb78d9-LICENSE](compliance/license-evidence/_electron_get-5.1.0-edab8abb78d9-LICENSE) |
| @types/node | 24.13.4 | MIT | [_types_node-24.13.4-c2cfccb812fe-LICENSE](compliance/license-evidence/_types_node-24.13.4-c2cfccb812fe-LICENSE) |
| balanced-match | 4.0.4 | MIT | [balanced-match-4.0.4-d408f38ffa33-LICENSE.md](compliance/license-evidence/balanced-match-4.0.4-d408f38ffa33-LICENSE.md) |
| brace-expansion | 5.0.9 | MIT | [brace-expansion-5.0.9-9c63a23124d6-LICENSE](compliance/license-evidence/brace-expansion-5.0.9-9c63a23124d6-LICENSE) |
| debug | 4.4.3 | MIT | [debug-4.4.3-3a61c6c96caf-LICENSE](compliance/license-evidence/debug-4.4.3-3a61c6c96caf-LICENSE) |
| electron | 44.3.0 | MIT | [electron-44.3.0-5154e165bd6c-LICENSE](compliance/license-evidence/electron-44.3.0-5154e165bd6c-LICENSE) |
| env-paths | 3.0.0 | MIT | [env-paths-3.0.0-5c932d88256b-license](compliance/license-evidence/env-paths-3.0.0-5c932d88256b-license) |
| glob | 13.0.6 | BlueOak-1.0.0 | [glob-13.0.6-a49c9ba46479-LICENSE.md](compliance/license-evidence/glob-13.0.6-a49c9ba46479-LICENSE.md) |
| graceful-fs | 4.2.11 | ISC | [graceful-fs-4.2.11-f65c5d9f22a3-LICENSE](compliance/license-evidence/graceful-fs-4.2.11-f65c5d9f22a3-LICENSE) |
| lru-cache | 11.5.2 | BlueOak-1.0.0 | [lru-cache-11.5.2-8a1af140fdfb-LICENSE.md](compliance/license-evidence/lru-cache-11.5.2-8a1af140fdfb-LICENSE.md) |
| minimatch | 10.2.6 | BlueOak-1.0.0 | [minimatch-10.2.6-2c7c5d22ed5a-LICENSE.md](compliance/license-evidence/minimatch-10.2.6-2c7c5d22ed5a-LICENSE.md) |
| minipass | 7.1.3 | BlueOak-1.0.0 | [minipass-7.1.3-8a1af140fdfb-LICENSE.md](compliance/license-evidence/minipass-7.1.3-8a1af140fdfb-LICENSE.md) |
| ms | 2.1.3 | MIT | [ms-2.1.3-1662fae9b531-license.md](compliance/license-evidence/ms-2.1.3-1662fae9b531-license.md) |
| path-scurry | 2.0.2 | BlueOak-1.0.0 | [path-scurry-2.0.2-8a1af140fdfb-LICENSE.md](compliance/license-evidence/path-scurry-2.0.2-8a1af140fdfb-LICENSE.md) |
| playwright-core | 1.63.0 | Apache-2.0 | [playwright-core-1.63.0-45873d00a0dd-LICENSE](compliance/license-evidence/playwright-core-1.63.0-45873d00a0dd-LICENSE), [playwright-core-1.63.0-6d602191187b-NOTICE](compliance/license-evidence/playwright-core-1.63.0-6d602191187b-NOTICE) |
| progress | 2.0.3 | MIT | [progress-2.0.3-d7d2a7786de7-LICENSE](compliance/license-evidence/progress-2.0.3-d7d2a7786de7-LICENSE) |
| semver | 7.8.5 | ISC | [semver-7.8.5-4ec3d4c66cd8-LICENSE](compliance/license-evidence/semver-7.8.5-4ec3d4c66cd8-LICENSE) |
| sumchecker | 3.0.1 | Apache-2.0 | [sumchecker-3.0.1-cfc7749b96f6-LICENSE](compliance/license-evidence/sumchecker-3.0.1-cfc7749b96f6-LICENSE) |
| undici | 7.29.1 | MIT | [undici-7.29.1-a6db8096b270-LICENSE](compliance/license-evidence/undici-7.29.1-a6db8096b270-LICENSE) |
| undici-types | 7.18.2 | MIT | [undici-types-7.18.2-a6db8096b270-LICENSE](compliance/license-evidence/undici-types-7.18.2-a6db8096b270-LICENSE) |

## 开源 UI 参考与适配

界面使用 Shadcn Admin 2.2.1（提交 e16c87f213a5ba5e45964e9b67c792105ec74d26）的限定组件参考或适配；具体是否转写源码见 [逐模块记录](compliance/ui-reuse/manifest.json)。产品保留原生 DOM/CSS 渲染层和既有桌面桥，不装入 React 模板运行环境，不引入模板认证或演示业务数据。

逐模块登记状态：source-and-license-recorded-not-commercial-approval。shadcn/ui 补充原文只证明该许可文件的来源，不把其许可文件提交冒充模板基础组件的原始代码提交。

### Shadcn Admin

来源：[固定许可原文](https://github.com/satnaing/shadcn-admin/blob/e16c87f213a5ba5e45964e9b67c792105ec74d26/LICENSE)；随包文件：[LICENSE-shadcn-admin.txt](compliance/ui-reuse/licenses/LICENSE-shadcn-admin.txt)；SHA-256：d28c723c33a18dfed6af67b1a0ac368724f79bcb80750d3e080dbcf8dedb9e4b。

```text
MIT License

Copyright (c) 2024 Sat Naing

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### shadcn/ui upstream license notice

来源：[固定许可原文](https://raw.githubusercontent.com/shadcn-ui/ui/6ea6856f5a1082d4d9c231559b6bc3ee73827493/LICENSE.md)；随包文件：[LICENSE-shadcn-ui.txt](compliance/ui-reuse/licenses/LICENSE-shadcn-ui.txt)；SHA-256：1564074e13439397221ffd522e2e504d56561994a23d371aa5e3ad43e4f5423f。

```text
MIT License

Copyright (c) 2023 shadcn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```


## 审查状态

此清单是可复核的证据集合。尚未完成的原生组件版本映射、义务检查与源码材料不得标为通过，详见 compliance/inventory.json。安装器当前用于开发验证，不能将本次清单当作正式商业发行许可审查已完成的证明。

本产品将 Electron 主程序命名为 Lianpu.exe，修改 Win32 品牌资源、加入 ASAR 完整性资源，并设置官方 Electron 运行开关。上游与发行摘要及修改说明见 compliance/distribution-provenance.json。@electron/asar 与 @electron/fuses 仅用于构建，MIT 许可原文随附。
