'use strict';
const path=require('node:path');
function inside(parent,target) { const resolved=path.resolve(target),relative=path.relative(path.resolve(parent),resolved);if(!relative||relative.startsWith('..')||path.isAbsolute(relative))throw new Error('拒绝对工作范围外路径执行文件操作');return resolved; }
module.exports={inside};
