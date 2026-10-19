// GESP local compile server (no deps, Node 18+)
// Listens on 127.0.0.1:8377 only.
//   GET  /ping           -> { ok, ver, stds }
//   POST /run            -> body { code, input, std } -> compile & run with local g++
// Started by "start-local-compile-server.bat" and "deploy" bat.
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { spawn } = require('child_process');

// 云端模式（Docker 部署到 Koyeb/Render 等）：用 Linux g++，监听环境变量 $PORT，只暴露 /ping /run 接口。
// 本地模式（默认）：Windows g++，监听 80，并托管整个网站（同源直连用，方便家里平板）。
// 保险：即使云端忘设 CLOUD 环境变量，只要跑在 Linux 上（Docker 里必然是）也自动进入云端模式。
const IS_CLOUD = process.env.CLOUD === '1' || process.env.CLOUD === 'true' || process.platform === 'linux';
const PORT = parseInt(process.env.PORT, 10) || (IS_CLOUD ? 3000 : 80);
const GCC_CANDIDATES = IS_CLOUD
  ? ['/usr/bin/g++', '/usr/bin/g++-12', '/usr/bin/g++-11', 'g++']   // Linux（Docker 里 apt 装 g++）
  : ['E:\\mingw64\\bin\\g++.exe',                                  // nuwen GCC 15.2
     'E:\\LXY\\C++\\DEVC++\\Dev-Cpp\\MinGW64\\bin\\g++.exe'];        // Dev-C++ TDM-GCC fallback
function findGcc() {
  for (const p of GCC_CANDIDATES) { try { if (fs.existsSync(p)) return p; } catch (e) {} }
  return null;
}
const GCC = findGcc();
const STDS = ['c++11', 'c++14', 'c++17'];

// ---- 编译缓存：同一份 代码+标准 只编译一次，之后「仅运行/评测」直接跑缓存的 exe ----
const crypto = require('crypto');
const EXE_CACHE = path.join(os.tmpdir(), 'gesp-exe-cache');
try { fs.mkdirSync(EXE_CACHE, { recursive: true }); } catch (e) {}
const EXE_EXT = IS_CLOUD ? '' : '.exe';
function exeCachePath(code, std) {
  const key = crypto.createHash('sha1').update(std + '\u0000' + code).digest('hex');
  return path.join(EXE_CACHE, key + EXE_EXT);
}

// ---- 网站访问口令（自定义登录页，替代浏览器原生 Basic Auth 弹窗）----
// 公网来源必须登录；局域网/本机（192.168.x / 127.0.0.1 等）免登录，方便家里调试。
// 两种公网穿透都靠"本机转发"，需在转发流量里识别真实访客 IP：
//   1) Cloudflare Tunnel：cloudflared 从 127.0.0.1 转发，真实访客 IP 在 CF-Connecting-IP 头。
//   2) Tailscale Funnel：tailscaled 从 127.0.0.1 转发，真实访客 IP 在 X-Forwarded-For 头。
// 两者都据此判定"公网访客"要求登录；纯本机访问（127.0.0.1 且无转发头）仍免登录方便本地调试。
// 改成你自己的账号/口令（compile-server.js 顶部 SITE_USER / SITE_PASS）。
const SITE_USER = 'LXY';
const SITE_PASS = 'GESP@CCF';
// 远程编译直通项：公网链接上的网页用 X-Gesp-Key 头带上此口令即可跳过登录墙调用 /run /ping，
// 避免把本机 g++ 暴露给全网任意编译（仅知道隧道网址 + 此口令者可调用）。
const REMOTE_KEY = SITE_PASS;
// 登录态用一个签名 cookie 保存（会话级：关浏览器即失效，下次打开需重登）。
// token 只是 账号:口令 的哈希，不泄露口令本身。
const AUTH_TOKEN = crypto.createHash('sha256').update(SITE_USER + ':' + SITE_PASS + ':gesp-site-salt-2026').digest('hex');
function clientIp(req) {
  let ip = (req.socket.remoteAddress || '').trim();
  if (ip.indexOf('::ffff:') === 0) ip = ip.slice(7);
  return ip;
}
function needAuth(req) {
  const ip = clientIp(req);
  // 1) Cloudflare Tunnel：真实访客 IP 在 CF-Connecting-IP
  if (req.headers['cf-connecting-ip']) return true;
  // 2) Tailscale Funnel：tailscaled 从本机(127.0.0.1) 转发，真实访客 IP 在 X-Forwarded-For
  //    只有"本机转发 + 带真实访客 IP"才视为公网；纯本机访问(无 XFF)仍免口令方便本地调试。
  const xff = (req.headers['x-forwarded-for'] || '').trim();
  if ((ip === '127.0.0.1' || ip === '::1') && xff) return true;
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') return false;
  if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('169.254.') || ip.startsWith('fe80')) return false;
  return true;
}
function parseCookies(req) {
  const h = req.headers.cookie || '';
  const o = {};
  h.split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return o;
}
function validCookie(req) {
  return parseCookies(req).gesp_auth === AUTH_TOKEN;
}

function runProc(cmd, args, opts, timeoutMs, inputStr) {
  return new Promise(resolve => {
    let done = false, stdout = '', stderr = '';
    let p;
    try { p = spawn(cmd, args, opts); } catch (e) { return resolve({ code: -1, stdout: '', stderr: String(e) }); }
    const to = setTimeout(() => {
      if (done) return;
      done = true;
      try { p.kill(); } catch (e) {}
      resolve({ code: -1, stdout, stderr: stderr + '\n[超时被终止]', timedOut: true });
    }, timeoutMs);
    p.stdout.on('data', d => { if (stdout.length < 200000) stdout += d; });
    p.stderr.on('data', d => { if (stderr.length < 100000) stderr += d; });
    if (inputStr) { try { p.stdin.write(inputStr); } catch (e) {} }
    try { p.stdin.end(); } catch (e) {}
    p.on('error', e => { if (done) return; done = true; clearTimeout(to); resolve({ code: -1, stdout, stderr: String(e) }); });
    p.on('close', c => { if (done) return; done = true; clearTimeout(to); resolve({ code: c, stdout, stderr }); });
  });
}

// 云端模式：用 ulimit 给 g++/运行进程加内存(384MB)与 CPU(30s) 上限，防容器被滥用或 OOM。
// 注：SnapDeploy 免费容器总内存 512MB（node 本身占 ~70MB），子进程上限压到 384MB 更稳。
function wrapCmd(cmd, args) {
  if (!IS_CLOUD) return { cmd: cmd, args: args };
  return { cmd: 'bash', args: ['-c', 'ulimit -v 393216 -t 30 2>/dev/null; exec "$0" "$@"', cmd].concat(args) };
}

async function gccVersion() {
  const w = wrapCmd(GCC, ['--version']);
  const r = await runProc(w.cmd, w.args, {}, 5000);
  return (r.stdout.split('\n')[0] || '').trim();
}

// 同源直连方案：把整个网站也挂在 8377 上（读 dist 目录）。
// 背景：华为 ArkWeb 等浏览器可能限制"页面里跨端口 fetch"（80 页面请求 8377 接口失败），
// 但直接访问 8377 的导航不受影响。平板改用 http://电脑IP:8377 打开本站后，
// 页面与 /ping /run 同源，彻底绕开跨端口/CORS 问题。
const WWW_ROOT = path.join(__dirname, 'dist');
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp',
  '.gif': 'image/gif', '.svg': 'image/svg+xml', '.pdf': 'application/pdf',
  '.txt': 'text/plain; charset=utf-8'
};
let mainHtmlCache = null;
function mainHtmlName() {
  if (mainHtmlCache) return mainHtmlCache;
  try {
    const files = fs.readdirSync(WWW_ROOT)
      .filter(f => f.toLowerCase().endsWith('.html') && f.indexOf('jscpp_selftest') !== 0)
      .sort();
    mainHtmlCache = files[0] || 'index.html';
  } catch (e) { mainHtmlCache = 'index.html'; }
  return mainHtmlCache;
}
function serveStatic(res, urlPath, req) {
  let p;
  try { p = decodeURIComponent(urlPath.split('?')[0]); } catch (e) { res.writeHead(400); res.end(); return; }
  if (p === '/' || p === '\\') p = '/index.html';
  if (p === '/index.html') p = '/' + mainHtmlName();
  const full = path.normalize(path.join(WWW_ROOT, p));
  if (!full.startsWith(WWW_ROOT)) { res.writeHead(403); res.end('forbidden'); return; }
  fs.stat(full, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('404 not found: ' + p); return; }
    // ETag（弱）：按 文件大小+修改时间 生成，重建后自动变化 → 浏览器重新拉取
    const etag = 'W/"' + st.size.toString(36) + '-' + Math.floor(st.mtimeMs).toString(36) + '"';
    const inm = req && req.headers['if-none-match'];
    if (inm === etag) { res.writeHead(304); res.end(); return; }
    const ext = path.extname(full).toLowerCase();
    const type = MIME[ext] || 'application/octet-stream';
    const headers = {
      'Content-Type': type,
      'ETag': etag,
      // 同源直连 + 公网 Funnel 都走这里；静态资源给 5 分钟缓存（重建后 ETag 变会自动更新）
      'Cache-Control': 'public, max-age=300'
    };
    // 预压缩（build_single.js 构建时已生成 .br / .gz 配套文件）：
    //   优先 Brotli（比 gzip 再小约 1/3），其次 gzip，最后原始；服务端零运行时压缩开销。
    const accept = (req && req.headers['accept-encoding'] || '').toLowerCase();
    let encFile = null, encoding = null;
    if (/\bbr\b/.test(accept) && fs.existsSync(full + '.br')) { encFile = full + '.br'; encoding = 'br'; }
    else if (/\bgzip\b/.test(accept) && fs.existsSync(full + '.gz')) { encFile = full + '.gz'; encoding = 'gzip'; }
    const send = (buf) => {
      if (encoding) headers['Content-Encoding'] = encoding;
      headers['Content-Length'] = buf.length;
      res.writeHead(200, headers);
      res.end(buf);
    };
    if (encFile) {
      fs.readFile(encFile, (rerr, buf) => {
        if (rerr) { // 预压文件意外缺失 → 退回原始文件
          fs.readFile(full, (e2, b2) => { if (e2) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('404'); } else send(b2); });
        } else send(buf);
      });
    } else {
      fs.readFile(full, (rerr, buf) => {
        if (rerr) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('404 not found: ' + p); return; }
        send(buf);
      });
    }
  });
}

// 自定义登录页：未登录时返回它；输错账号/密码时在网址带 ?err=1 后重绘错误提示。
function serveLogin(res, showErr) {
  const errLine = showErr ? '<div class="err">⚠️ 账号或密码错误，请重试</div>' : '';
  const html = '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>GESP C++ 训练营 · 登录</title><style>'
    + '*{box-sizing:border-box}'
    + 'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f172a;'
    + 'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Microsoft YaHei",sans-serif;color:#e2e8f0}'
    + '.card{width:min(360px,90vw);background:#1e293b;border:1px solid #334155;border-radius:14px;padding:28px 24px;box-shadow:0 10px 30px rgba(0,0,0,.4)}'
    + 'h1{font-size:20px;margin:0 0 6px;text-align:center}'
    + '.sub{text-align:center;color:#94a3b8;font-size:13px;margin:0 0 20px}'
    + 'label{display:block;font-size:13px;color:#cbd5e1;margin:12px 0 6px}'
    + 'input{width:100%;padding:11px 12px;border-radius:9px;border:1px solid #475569;background:#0f172a;color:#e2e8f0;font-size:15px;outline:none}'
    + 'input:focus{border-color:#38bdf8}'
    + '.pw{position:relative}'
    + '#pass{padding-right:46px}'
    + '.eye{position:absolute;top:50%;right:8px;transform:translateY(-50%);border:0;background:transparent;color:#94a3b8;font-size:18px;line-height:1;cursor:pointer;width:auto;margin:0;padding:6px}'
    + '.eye:hover{background:transparent;color:#e2e8f0}'
    + '.err{margin:14px 0 0;padding:10px 12px;border-radius:9px;background:rgba(248,113,113,.12);color:#fca5a5;font-size:13px;border:1px solid rgba(248,113,113,.3)}'
    + 'button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:9px;background:#38bdf8;color:#0b1220;font-size:15px;font-weight:600;cursor:pointer}'
    + 'button:hover{background:#7dd3fc}'
    + '</style></head><body>'
    + '<form class="card" id="lf"><h1>🔐 GESP C++ 训练营</h1>'
    + '<p class="sub">请输入访问账号与密码</p>'
    + '<label for="user">账号</label>'
    + '<input id="user" type="text" autocomplete="off" autocapitalize="off" spellcheck="false">'
    + '<label for="pass">密码</label>'
    + '<div class="pw"><input id="pass" type="password" autocomplete="off">'
    + '<button type="button" class="eye" id="eye" aria-label="显示密码">👁️</button></div>' + errLine
    + '<button type="submit">登 录</button></form>'
    + '<script>document.getElementById("lf").addEventListener("submit",async function(ev){'
    + 'ev.preventDefault();'
    + 'var r=await fetch("/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({user:user.value,pass:pass.value})});'
    + 'var j=await r.json().catch(function(){return{ok:false};});'
    + 'if(j.ok){location.href="/";}else{location.href="/?err=1";}'
    + '});'
    + 'var eye=document.getElementById("eye");'
    + 'if(eye){eye.addEventListener("click",function(){var p=document.getElementById("pass");if(p.type==="password"){p.type="text";this.textContent="🙈";}else{p.type="password";this.textContent="👁️";}});}'
    + '<\/script></body></html>';
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(html);
}

const requestHandler = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Gesp-Key');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ---- 公开「唤醒/状态页」/wake（云端模式下根路径 / 也走这里）----
  // 背景：免费容器睡着时，只有"对它的一次真实请求/导航"才会触发平台唤醒。训练营站点用
  //   隐藏 iframe / 新标签页打开 /wake 来唤醒容器；但浏览器导航没法带上 X-Gesp-Key 头，
  //   于是被登录墙按匿名 GET 挡下、返回裸 404 "not found"，用户误以为连不上。
  // 这里单独放行一个免登录的静态页：① 页面友好，明确告诉用户"容器已醒，回站点即可"；
  //   ② 依然是一次真实的 GET 请求，照常触发容器唤醒。
  // 安全：此页不暴露账号/口令/编译能力，仅确认容器在跑。
  // 注意：本机模式(IS_CLOUD=false)下根路径 / 要继续托管整个网站，所以只对 /wake 放行。
  const WAKE_PATH = req.url.split('?')[0];
  if (req.method === 'GET' && (WAKE_PATH === '/wake' || (IS_CLOUD && WAKE_PATH === '/'))) {
    const html = '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
      + '<meta name="viewport" content="width=device-width,initial-scale=1">'
      + '<title>云端 GCC 已就绪</title><style>'
      + 'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;'
      + 'background:#0f172a;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",'
      + 'Roboto,"Microsoft YaHei",sans-serif;text-align:center}'
      + '.c{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:28px 26px;'
      + 'box-shadow:0 10px 30px rgba(0,0,0,.4);width:min(430px,90vw)}'
      + '.ic{font-size:44px;line-height:1.2}'
      + 'h1{font-size:19px;margin:6px 0 10px}'
      + 'p{margin:7px 0;color:#94a3b8;font-size:13.5px;line-height:1.7}'
      + 'b{color:#e2e8f0}'
      + '</style></head><body><div class="c">'
      + '<div class="ic">✅</div><h1>云端 GCC 容器已就绪</h1>'
      + '<p>这个地址是<b>编译引擎</b>的接口，不是网站首页，<br>所以浏览器里只会显示这一页。</p>'
      + '<p>直接关掉这个标签页，回到<br><b>GESP C++ 训练营</b>就能写代码运行了。</p>'
      + '<p style="border-top:1px dashed #334155;padding-top:12px;margin-top:14px">'
      + '如果训练营里还显示「未连接」，去 <b>⚙️ 引擎</b> 页再点一次 <b>🔄 测试/唤醒连接</b>。</p>'
      + '</div></body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(html);
    return;
  }

  // 远程编译直通：公网链接上的网页带上正确 X-Gesp-Key（= 登录口令）即可跳过登录墙直接调用 /ping /run；
  // 否则公网来源仍必须登录（避免把本机 g++ 暴露给全网任意编译）。
  const reqKey = (req.headers['x-gesp-key'] || '').toString().trim();
  const apiOk = reqKey === REMOTE_KEY || (req.url.indexOf('key=' + encodeURIComponent(REMOTE_KEY)) >= 0);

  // ---- 登录校验（公网来源需登录；局域网/本机免登录；带正确密钥的 API 请求免登录）----
  if (!apiOk && needAuth(req) && !validCookie(req)) {
    // 登录接口：校验账号密码，正确则下发会话 cookie
    if (req.method === 'POST' && req.url === '/login') {
      let body = '';
      req.on('data', d => { body += d; if (body.length > 10000) req.destroy(); });
      req.on('end', () => {
        let u = '', p = '';
        try { const j = JSON.parse(body); u = String(j.user || ''); p = String(j.pass || ''); } catch (e) {}
        if (u === SITE_USER && p === SITE_PASS) {
          res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'Set-Cookie': 'gesp_auth=' + AUTH_TOKEN + '; Path=/; HttpOnly; SameSite=Lax'
          });
          res.end(JSON.stringify({ ok: true }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ ok: false }));
        }
      });
      return;
    }
    // 未登录：/run 等接口返回未登录；其余 GET 一律返回登录页（带 ?err=1 时显示错误）
    if (req.url === '/run') {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: '未登录' }));
      return;
    }
    if (IS_CLOUD) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('not found'); return; }
    serveLogin(res, /[?&]err=1\b/.test(req.url || ''));
    return;
  }

  if (req.method === 'GET' && req.url === '/ping') {
    const ver = GCC ? await gccVersion() : null;
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: !!GCC, ver, stds: STDS }));
    return;
  }

  if (req.method === 'POST' && req.url === '/run') {
    if (!GCC) {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ compileErr: '本机未找到 g++（已尝试 ' + GCC_CANDIDATES.join(' ; ') + '）' }));
      return;
    }
    let body = '';
    let tooBig = false;
    req.on('data', d => { body += d; if (body.length > 1048576) { tooBig = true; req.destroy(); } });
    req.on('end', async () => {
      if (tooBig) return;
      let j;
      try { j = JSON.parse(body); } catch (e) { res.writeHead(400); res.end('bad json'); return; }
      const code = String(j.code || '').slice(0, 200000);
      const input = String(j.input || '').slice(0, 200000);
      let std = String(j.std || 'c++11');
      if (STDS.indexOf(std) < 0) std = 'c++11';
      const exe = exeCachePath(code, std);
      const reuse = !!j.reuse;   // reuse=1：只运行不编译（命中缓存才免编译，否则自动编译兜底）
      let dir = null;
      try {
        const t0 = Date.now();
        let cached = false;
        if (reuse && fs.existsSync(exe)) {
          cached = true;           // 缓存命中：跳过编译
        } else {
          dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gespcc-'));
          const cpp = path.join(dir, 'main.cpp');
          fs.writeFileSync(cpp, code);
          const w = wrapCmd(GCC, ['-std=' + std, '-pipe', '-o', exe, cpp]);
          const c = await runProc(w.cmd, w.args, { cwd: dir }, 15000);
          if (c.code !== 0) {
            try { fs.rmSync(exe, { force: true }); } catch (e) {}
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ compileErr: c.stderr || 'compilation failed' }));
            return;
          }
        }
        const w = wrapCmd(exe, []);
        const r = await runProc(w.cmd, w.args, { cwd: dir || EXE_CACHE }, 6000, input);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
          out: r.stdout, err: r.stderr, code: r.code,
          timedOut: !!r.timedOut, std: std, ms: Date.now() - t0, cached: cached
        }));
      } catch (e) {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ compileErr: String(e) }));
      } finally {
        if (dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {} }
      }
    });
    return;
  }

  // 其余 GET：云端模式只暴露 API，不托管网站，一律 404；本机模式把网站也挂在上面（同源直连）
  if (req.method === 'GET') {
    if (IS_CLOUD) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('not found'); return; }
    serveStatic(res, req.url, req); return;
  }
  res.writeHead(404); res.end();
};

const server = http.createServer(requestHandler);
server.on('error', e => {
  // 单端口监听：80 端口（平板已知能连通）。
  // 若 80 已被占用（多半是上一次没退干净的 node），直接退出，让已有实例继续服务，
  // 避免「每次双击 bat 都堆一个空转僵尸进程」把内存吃光、又把端口占死。
  if (e && e.code === 'EADDRINUSE') {
    console.log('[GESP] port 80 already in use by another process — exit (let existing instance serve).');
    process.exit(0);
  }
  console.log('[GESP] server error: ' + (e && e.code) + ' ' + (e && e.message));
});
server.listen(PORT, '0.0.0.0', () => {
  console.log('[GESP] compile server listening on :' + PORT + '  cloud=' + IS_CLOUD + '  gcc=' + GCC);
});
