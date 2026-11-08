#!/usr/bin/env node
// VNPTNAN_GATE - cài đặt và tự cập nhật qua npm (mặc định npmjs.com; đổi kho bằng npm config @vnptnan:registry hoặc --registry).
//   npx @vnptnan/gate                 cài hoặc cài lại (xin quyền admin qua UAC), đăng ký tự cập nhật hằng ngày
//   npx @vnptnan/gate --audit|--enforce   cài và cố định chế độ trên máy này (mặc định: theo policy.json của gói)
//   npx @vnptnan/gate status          phiên bản đang cài, bản mới nhất trên kho, chế độ, lịch cập nhật
//   npx @vnptnan/gate update [--check]    cập nhật ngay (lịch tự chạy lệnh này bằng tài khoản SYSTEM)
//   npx @vnptnan/gate uninstall       gỡ cổng và lịch cập nhật
// Linux/WSL/macOS: cài cho tài khoản hiện tại, không cần sudo: ~/.local/share/vnptnan-gate, lệnh ~/.local/bin/vnptnan-gate,
// tự cập nhật bằng systemd --user (hoặc cron; dự phòng: kiểm tra mỗi ngày khi gọi vnptnan-gate). Hook: Git >= 2.54 đăng ký
// bằng git config --global hook.*; Git cũ hơn thì từng repo chạy vnptnan-gate install-hooks, hoặc cài với --hooks-path
// (core.hooksPath toàn cục, vẫn gọi hook riêng của repo trước).
// Tuỳ chọn: --registry URL, --ca FILE (CA khi dùng kho nội bộ tự ký), --token T (khi kho cần đăng nhập),
// --proxy URL (mặc định lấy HTTPS_PROXY hoặc npm config https-proxy lúc cài, lưu lại cho lịch cập nhật chạy bằng SYSTEM).
// Không phụ thuộc gói ngoài. Cổng chạy bằng bash như trước; Node chỉ dùng để tải, kiểm tra và cài.
'use strict';
const fs = require('fs'), path = require('path'), cp = require('child_process'), zlib = require('zlib');
const crypto = require('crypto'), tls = require('tls'), https = require('https'), http = require('http'), os = require('os');

const ROOT = path.resolve(__dirname, '..');
const PKG = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const IS_WIN = process.platform === 'win32';
const HOME = IS_WIN ? path.join(process.env.ProgramData || 'C:\\ProgramData', 'VNPTNAN_GATE')
  : path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'vnptnan-gate');
const BIN_DIR = path.join(os.homedir(), '.local', 'bin');                 // Linux: nơi đặt lệnh vnptnan-gate
const UNIT_DIR = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'systemd', 'user');
const UNIT = 'vnptnan-gate-update';
const CFG = path.join(HOME, 'update.json');
const LOG = path.join(HOME, 'logs', 'update.log');
const TASK = 'VNPTNAN_GATE Update';

// ------------------------------------------------------------------ tham số
const argv = process.argv.slice(2);
const cmd = argv[0] && !argv[0].startsWith('-') ? argv.shift() : 'setup';
const opt = {};
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--audit' || a === '--enforce') opt.mode = a.slice(2);
  else if (a === '--check' || a === '--quiet' || a === '--elevated') opt[a.slice(2)] = true;
  else if (a === '--hooks-path') opt.hooksPath = true;
  else if (['--registry', '--ca', '--token', '--proxy', '--stage-only'].includes(a)) opt[a.slice(2).replace('-o', 'O')] = argv[++i];
  else die(`Tham số không hiểu: ${a}`);
}

function say(s) { if (!opt.quiet) console.log(s); log(s); }
function log(s) { try { fs.mkdirSync(path.dirname(LOG), { recursive: true }); if (IS_WIN && !fs.existsSync(LOG)) fs.writeFileSync(LOG, '\ufeff'); fs.appendFileSync(LOG, `${new Date().toISOString()}\t${s}\n`); } catch (_) { /* chưa có quyền ghi */ } }
function die(s, code = 1) { console.error(`[VNPTNAN_GATE] ${s}`); log(`LOI\t${s}`); process.exit(code); }
function readJson(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (_) { return null; } }
const cmpVer = (a, b) => { const x = a.split(/[.-]/).map(Number), y = b.split(/[.-]/).map(Number); for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0); return 0; };

// ------------------------------------------------------------------ cấu hình kho gói
function npmConfig(key) { try { return cp.execSync(`npm config get ${key}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch (_) { return ''; } }
function settings() {
  const saved = readJson(CFG) || {};
  const scope = PKG.name.split('/')[0];
  let registry = opt.registry || saved.registry || npmConfig(`${scope}:registry`);
  if (!registry || registry === 'undefined') registry = PKG.publishConfig && PKG.publishConfig.registry;
  if (!registry) die('Chưa biết địa chỉ kho gói. Chạy lại với --registry <URL Package Registry của GitLab>.');
  const ca = opt.ca || saved.ca || process.env.NODE_EXTRA_CA_CERTS || '';
  // Proxy: tham số > đã lưu lúc cài (lịch SYSTEM không có biến môi trường của dev) > biến môi trường > cấu hình npm
  const env = process.env;
  const proxy = [opt.proxy, saved.proxy, env.HTTPS_PROXY, env.https_proxy, env.HTTP_PROXY, env.http_proxy, npmConfig('https-proxy'), npmConfig('proxy')]
    .find((x) => x && !['null', 'undefined', 'false'].includes(x)) || '';
  return { name: PKG.name, registry: registry.replace(/\/?$/, '/'), ca, token: opt.token || saved.token || '', mode: opt.mode || saved.mode || '', proxy };
}

// ------------------------------------------------------------------ HTTP (có CA nội bộ, theo redirect)
function noProxy(host) {
  const list = (process.env.NO_PROXY || process.env.no_proxy || '').split(',').map((x) => x.trim().replace(/^\*?\./, '')).filter(Boolean);
  return list.some((d) => d === '*' || host === d || host.endsWith(`.${d}`));
}
// Đi qua proxy HTTP: đích https dùng CONNECT rồi bắt tay TLS với máy đích (chứng chỉ vẫn được kiểm như đi thẳng)
function proxied(u, s, o) {
  const p = new URL(/^[a-z]+:\/\//i.test(s.proxy) ? s.proxy : `http://${s.proxy}`);
  const plib = p.protocol === 'https:' ? https : http, pport = p.port || (p.protocol === 'https:' ? 443 : 80);
  const auth = p.username ? { 'Proxy-Authorization': `Basic ${Buffer.from(`${decodeURIComponent(p.username)}:${decodeURIComponent(p.password)}`).toString('base64')}` } : {};
  if (u.protocol === 'http:') return [http, { ...o, host: p.hostname, port: pport, path: u.href, headers: { ...o.headers, ...auth, Host: u.host } }];
  const target = `${u.hostname}:${u.port || 443}`;
  return [https, { ...o, host: u.hostname, port: u.port || 443, path: u.pathname + u.search, createConnection: (_, cb) => {
    const r = plib.request({ host: p.hostname, port: pport, method: 'CONNECT', path: target, headers: { Host: target, ...auth } });
    r.on('connect', (res, sock) => {
      if (res.statusCode !== 200) { sock.destroy(); return cb(new Error(`Proxy ${p.host} từ chối kết nối tới ${target} (HTTP ${res.statusCode})`)); }
      cb(null, tls.connect({ socket: sock, servername: u.hostname, ca: o.ca }));
    });
    r.on('error', (e) => cb(new Error(`Không kết nối được proxy ${p.host}: ${e.message}`))); r.end();
  } }];
}
function get(url, s, asJson, hops = 0) {
  return new Promise((resolve, reject) => {
    const u = new URL(url), lib = u.protocol === 'http:' ? http : https;
    const o = { headers: { 'User-Agent': `vnptnan-gate/${PKG.version}`, Accept: asJson ? 'application/json' : '*/*' }, timeout: 30000 };
    if (s.ca && fs.existsSync(s.ca)) o.ca = [...tls.rootCertificates, fs.readFileSync(s.ca, 'utf8')];
    if (s.token && u.host === new URL(s.registry).host) o.headers.Authorization = `Bearer ${s.token}`;
    let call = (cbk) => lib.get(u, o, cbk);
    if (s.proxy && !noProxy(u.hostname)) { const [plib, po] = proxied(u, s, o); call = (cbk) => plib.get(po, cbk); }
    const req = call((res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && hops < 5) {
        res.resume(); return resolve(get(new URL(res.headers.location, u).href, s, asJson, hops + 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode} ${u.href}`)); }
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => { const b = Buffer.concat(chunks); try { resolve(asJson ? JSON.parse(b.toString('utf8')) : b); } catch (e) { reject(e); } });
    });
    req.on('timeout', () => req.destroy(new Error(`Hết thời gian chờ ${u.host}`))); req.on('error', reject);
  });
}
async function latest(s) {
  const meta = await get(s.registry + s.name.replace('/', '%2f'), s, true);
  const ver = meta['dist-tags'] && meta['dist-tags'].latest;
  if (!ver || !meta.versions || !meta.versions[ver]) throw new Error('Kho gói không có bản latest');
  return { ver, dist: meta.versions[ver].dist };
}

// ------------------------------------------------------------------ tải, kiểm tra toàn vẹn, giải nén
function untar(buf, dest) {
  let o = 0, n = 0, longName = null, paxPath = null;
  while (o + 512 <= buf.length) {
    const h = buf.subarray(o, o + 512);
    if (h.every((b) => b === 0)) break;
    const str = (a, b) => h.subarray(a, b).toString('utf8').replace(/\0[\s\S]*$/, '');
    const size = parseInt(str(124, 136).trim() || '0', 8), type = String.fromCharCode(h[156] || 48);
    let name = str(345, 500) ? `${str(345, 500)}/${str(0, 100)}` : str(0, 100);
    const data = buf.subarray(o + 512, o + 512 + size); o += 512 + Math.ceil(size / 512) * 512;
    if (type === 'x') { const m = /\d+ path=([^\n]*)\n/.exec(data.toString('utf8')); if (m) paxPath = m[1]; continue; }
    if (type === 'g') continue;
    if (type === 'L') { longName = data.toString('utf8').replace(/\0[\s\S]*$/, ''); continue; }
    if (paxPath) { name = paxPath; paxPath = null; } if (longName) { name = longName; longName = null; }
    name = name.replace(/^package\//, '');
    if (!name || path.isAbsolute(name) || name.split(/[\\/]/).includes('..')) continue;   // chặn ghi ra ngoài thư mục
    const p = path.join(dest, name);
    if (type === '5') { fs.mkdirSync(p, { recursive: true }); continue; }
    if (type !== '0' && type !== '7') continue;                                              // bỏ link, thiết bị
    fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, data); n++;
  }
  return n;
}
async function fetchTo(s, dist, dest) {
  const tgz = await get(dist.tarball, s, false);
  if (dist.integrity) {
    const [alg, want] = dist.integrity.split(/-(.+)/);
    const got = crypto.createHash(alg).update(tgz).digest('base64');
    if (got !== want) throw new Error(`Sai mã toàn vẹn (${alg}): gói tải về khác gói trên kho, không cài`);
  } else if (dist.shasum) {
    if (crypto.createHash('sha1').update(tgz).digest('hex') !== dist.shasum) throw new Error('Sai shasum, không cài');
  } else throw new Error('Kho gói không cung cấp mã toàn vẹn, không cài');
  fs.rmSync(dest, { recursive: true, force: true }); fs.mkdirSync(dest, { recursive: true });
  const n = untar(zlib.gunzipSync(tgz), dest);
  for (const f of ['VERSION', 'installer/install.ps1', 'engine/gate-lib.sh', 'bin/cli.js']) {
    if (!fs.existsSync(path.join(dest, f))) throw new Error(`Gói thiếu ${f}`);
  }
  return n;
}

// ------------------------------------------------------------------ Windows: quyền admin, cài, lịch
function isAdmin() { try { cp.execSync('net session', { stdio: 'ignore' }); return true; } catch (_) { return false; } }
// Windows PowerShell 5.1 gọi từ PowerShell 7 (pwsh) kế thừa PSModulePath của bản 7 và nạp nhầm module
// (Get-Acl, Start-Process lỗi "module could not be loaded"). Bỏ biến này để 5.1 tự dựng lại đường dẫn mặc định.
const PS_ENV = Object.fromEntries(Object.entries(process.env).filter(([k]) => k.toLowerCase() !== 'psmodulepath'));
function ps(args) { return cp.spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', ...args], { stdio: opt.quiet ? 'ignore' : 'inherit', env: PS_ENV }).status; }
function elevate(extra) {
  if (opt.elevated) die('Đã chạy với quyền nâng nhưng vẫn không có quyền admin (net session lỗi). Mở terminal "Run as administrator" rồi chạy lại.');
  const q = (x) => `'${String(x).replace(/'/g, "''")}'`;
  const args = [__filename, cmd, ...extra, '--elevated'].map((x) => `'"${String(x).replace(/'/g, "''")}"'`).join(',');
  say('Đang xin quyền quản trị (UAC)...');
  const st = cp.spawnSync('powershell.exe', ['-NoProfile', '-Command',
    `$p = Start-Process -FilePath ${q(process.execPath)} -ArgumentList @(${args}) -Verb RunAs -Wait -PassThru; exit $p.ExitCode`], { stdio: 'inherit', env: PS_ENV }).status;
  try { const tail = fs.readFileSync(LOG, 'utf8').trim().split('\n').slice(-6).map((l) => l.split('\t').slice(1).join(' ')); console.log(tail.join('\n')); } catch (_) { /* không có log */ }
  process.exit(st || 0);
}
function passArgs(s) {
  const a = ['--registry', s.registry];
  if (s.proxy) a.push('--proxy', s.proxy);
  if (s.ca) a.push('--ca', path.resolve(s.ca));
  if (s.token) a.push('--token', s.token);
  if (opt.mode) a.push(`--${opt.mode}`);
  return a;
}
function installFrom(dir, mode) {
  const st = ps(['-File', path.join(dir, 'installer', 'install.ps1'), '-Mode', mode]);
  if (st !== 0) throw new Error(`install.ps1 lỗi (mã ${st})`);
}
function modeFor(s, dir) {
  if (s.mode) return s.mode;                                         // cố định trên máy này (--audit / --enforce)
  const pol = readJson(path.join(dir, 'policy.json'));              // theo chính sách phát hành cùng gói
  return pol && /^(audit|enforce)$/.test(pol.mode) ? pol.mode : 'enforce';
}
function saveConfig(s) {
  let ca = '';
  if (s.ca) { ca = path.join(HOME, 'gitlab-ca.crt'); if (path.resolve(s.ca) !== ca) fs.copyFileSync(s.ca, ca); }
  const prev = readJson(CFG) || {};
  fs.mkdirSync(HOME, { recursive: true });
  fs.writeFileSync(CFG, JSON.stringify({ registry: s.registry, ca, token: s.token, mode: s.mode, proxy: s.proxy,
    auto: s.auto || prev.auto, hooks: s.hooks || prev.hooks }, null, 2), { mode: 0o600 });
}
function schedule() {
  const tr = `"${process.execPath}" "${path.join(HOME, 'current', 'bin', 'cli.js')}" update --quiet`;
  for (const [suffix, sc] of [['', ['/SC', 'DAILY', '/ST', '10:17']], [' (khoi dong)', ['/SC', 'ONSTART', '/DELAY', '0010:00']]]) {
    const st = cp.spawnSync('schtasks.exe', ['/Create', '/F', '/TN', TASK + suffix, '/RU', 'SYSTEM', '/RL', 'HIGHEST', '/TR', tr, ...sc], { stdio: 'ignore' }).status;
    if (st !== 0) say(`Cảnh báo: không tạo được lịch "${TASK + suffix}" (mã ${st})`);
  }
}
function installedVersion() { try { return fs.readFileSync(path.join(HOME, 'current', 'VERSION'), 'utf8').trim(); } catch (_) { return ''; } }


// ------------------------------------------------------------------ Linux / WSL / macOS: cài cho tài khoản hiện tại
const HOOKS = [['vnptnan-gate-commit', 'pre-commit'], ['vnptnan-gate-push', 'pre-push'], ['vnptnan-gate-msg', 'commit-msg']];
const sq = (x) => `'${String(x).replace(/'/g, `'\\''`)}'`;                 // trích dẫn cho sh
function which(c) { return cp.spawnSync('sh', ['-c', `command -v ${c}`], { stdio: 'ignore' }).status === 0; }
function sh(c, args, input) { return cp.spawnSync(c, args, { encoding: 'utf8', input, stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] }); }
function gitVersion() { const m = /(\d+)\.(\d+)\.(\d+)/.exec(sh('git', ['--version']).stdout || ''); return m ? m.slice(1).join('.') : '0.0.0'; }
function gitGlobal(...a) { return sh('git', ['config', '--global', ...a]); }

function installNix(src, mode, s) {
  const cur = path.join(HOME, 'current'), nw = `${cur}.new`, old = `${cur}.old`;
  fs.mkdirSync(HOME, { recursive: true });
  fs.rmSync(nw, { recursive: true, force: true }); fs.rmSync(old, { recursive: true, force: true });
  fs.cpSync(src, nw, { recursive: true, filter: (p) => !path.relative(src, p).split(/[\\/]/).includes('node_modules') });
  const conf = path.join(nw, 'gate.conf');
  fs.writeFileSync(conf, fs.readFileSync(conf, 'utf8').replace(/^MODE=.*$/m, `MODE=${mode}`));
  for (const d of ['cli', 'hooks', 'engine', 'bin', 'server', 'tools']) {
    const dd = path.join(nw, d); if (!fs.existsSync(dd)) continue;
    for (const f of fs.readdirSync(dd)) { const p = path.join(dd, f); if (fs.statSync(p).isFile() && !/\.(cmd|ps1|md|rules|jsonl|pldata)$/.test(f)) fs.chmodSync(p, 0o755); }
  }
  // Thay thư mục current một lần (đổi tên), hook và lệnh đang trỏ vào đường dẫn current không bị gãy giữa chừng
  if (fs.existsSync(cur)) fs.renameSync(cur, old);
  fs.renameSync(nw, cur);
  fs.rmSync(old, { recursive: true, force: true });
  writeWrapper(s);
  return cur;
}

function writeWrapper(s) {
  const cur = path.join(HOME, 'current'), auto = (s && s.auto) || (readJson(CFG) || {}).auto || '';
  const cli = path.join(cur, 'bin', 'cli.js');
  // Dự phòng khi không có systemd/cron chạy: kiểm tra cập nhật nền, mỗi ngày một lần, lúc dùng lệnh
  const fallback = auto === 'systemd' ? '' : [
    `stamp=${sq(path.join(HOME, '.last-update-check'))}`,
    'if [ -z "$(find "$stamp" -mmin -1440 2>/dev/null)" ]; then',
    `  touch "$stamp" 2>/dev/null; ( ${sq(process.execPath)} ${sq(cli)} update --quiet >/dev/null 2>&1 & ) 2>/dev/null`,
    'fi'].join('\n');
  fs.mkdirSync(BIN_DIR, { recursive: true });
  const w = path.join(BIN_DIR, 'vnptnan-gate');
  fs.writeFileSync(w, ['#!/usr/bin/env bash', '# vnptnan-gate (cài bằng npx @vnptnan/gate; gỡ: npx @vnptnan/gate uninstall)', fallback,
    `exec bash ${sq(path.join(cur, 'cli', 'vnptnan-gate'))} "$@"`, ''].filter((x) => x !== '').join('\n') + '\n', { mode: 0o755 });
}

function hooksPathDir() { return path.join(HOME, 'githooks'); }
function registerHooksNix() {
  const cur = path.join(HOME, 'current');
  if (cmpVer(gitVersion(), '2.54.0') >= 0) {
    // Cùng cơ chế với bản Windows (hook theo config, không chiếm .git/hooks), ở cấp người dùng thay vì cấp máy
    for (const [name, ev] of HOOKS) {
      gitGlobal('--replace-all', `hook.${name}.event`, ev);
      gitGlobal('--replace-all', `hook.${name}.command`, `sh ${sq(path.join(cur, 'hooks', ev))}`);
    }
    return 'config';
  }
  if (!opt.hooksPath) return 'repo';
  const dir = hooksPathDir(), existing = (gitGlobal('--get', 'core.hooksPath').stdout || '').trim();
  if (existing && path.resolve(existing.replace(/^~/, os.homedir())) !== dir) {
    say(`Cảnh báo: core.hooksPath toàn cục đang là ${existing} (công cụ khác đặt), không ghi đè. Trong từng repo chạy: vnptnan-gate install-hooks`);
    return 'repo';
  }
  fs.mkdirSync(dir, { recursive: true });
  for (const [, ev] of HOOKS) {
    // Gọi hook riêng của repo (.git/hooks/<ev>) trước, rồi tới cổng. pre-push đọc stdin nên giữ lại để đưa cho cả hai.
    const keep = ev === 'pre-push';
    fs.writeFileSync(path.join(dir, ev), [
      '#!/bin/sh', `# VNPTNAN_GATE qua core.hooksPath (npx @vnptnan/gate --hooks-path). Hook riêng của repo vẫn chạy trước.`,
      keep ? 'in=$(cat)' : '',
      'gd=$(git rev-parse --git-dir 2>/dev/null)',
      `if [ -n "$gd" ] && [ -x "$gd/hooks/${ev}" ] && ! grep -q vnptnan-gate "$gd/hooks/${ev}" 2>/dev/null; then`,
      keep ? `  printf '%s\\n' "$in" | "$gd/hooks/${ev}" "$@" || exit $?` : `  "$gd/hooks/${ev}" "$@" || exit $?`,
      'fi',
      keep ? `printf '%s\\n' "$in" | exec sh ${sq(path.join(cur, 'hooks', ev))} "$@"` : `exec sh ${sq(path.join(cur, 'hooks', ev))} "$@"`,
      ''].filter((x) => x !== '').join('\n') + '\n', { mode: 0o755 });
  }
  gitGlobal('core.hooksPath', dir);
  return 'hooksPath';
}

function scheduleNix() {
  const cli = path.join(HOME, 'current', 'bin', 'cli.js');
  const st = sh('systemctl', ['--user', 'is-system-running']);
  if (which('systemctl') && /^(running|degraded|starting)/.test((st.stdout || '').trim())) {
    fs.mkdirSync(UNIT_DIR, { recursive: true });
    fs.writeFileSync(path.join(UNIT_DIR, `${UNIT}.service`), `[Unit]\nDescription=VNPTNAN_GATE: cập nhật từ kho gói\n\n[Service]\nType=oneshot\nExecStart="${process.execPath}" "${cli}" update --quiet\n`);
    fs.writeFileSync(path.join(UNIT_DIR, `${UNIT}.timer`), `[Unit]\nDescription=VNPTNAN_GATE: cập nhật hằng ngày\n\n[Timer]\nOnCalendar=*-*-* 10:17\nOnBootSec=10min\nRandomizedDelaySec=20min\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n`);
    sh('systemctl', ['--user', 'daemon-reload']);
    if (sh('systemctl', ['--user', 'enable', '--now', `${UNIT}.timer`]).status === 0) return 'systemd';
  }
  if (which('crontab')) {
    const cur = (sh('crontab', ['-l']).stdout || '').split('\n').filter((l) => l && !l.includes('# vnptnan-gate'));
    cur.push(`17 10 * * * ${sq(process.execPath)} ${sq(cli)} update --quiet # vnptnan-gate`);
    if (sh('crontab', ['-'], `${cur.join('\n')}\n`).status === 0) return 'cron';
  }
  return 'wrapper';
}

function unscheduleNix() {
  if (which('systemctl')) { sh('systemctl', ['--user', 'disable', '--now', `${UNIT}.timer`]); }
  for (const f of [`${UNIT}.service`, `${UNIT}.timer`]) fs.rmSync(path.join(UNIT_DIR, f), { force: true });
  if (which('systemctl')) sh('systemctl', ['--user', 'daemon-reload']);
  if (which('crontab')) {
    const r = sh('crontab', ['-l']);
    if (r.status === 0 && r.stdout.includes('# vnptnan-gate')) sh('crontab', ['-'], `${r.stdout.split('\n').filter((l) => l && !l.includes('# vnptnan-gate')).join('\n')}\n`);
  }
}

function withLock(fn) {
  // Hai lần cập nhật chạy cùng lúc (lịch + lệnh) không được thay current chồng lên nhau
  const lock = path.join(HOME, '.update.lock');
  fs.mkdirSync(HOME, { recursive: true });
  try { fs.mkdirSync(lock); } catch (_) {
    const age = Date.now() - (fs.statSync(lock).mtimeMs || 0);
    if (age < 10 * 60 * 1000) { say('Đang có lần cập nhật khác chạy, bỏ qua.'); return Promise.resolve(); }
    fs.rmSync(lock, { recursive: true, force: true }); fs.mkdirSync(lock);
  }
  return Promise.resolve().then(fn).finally(() => fs.rmSync(lock, { recursive: true, force: true }));
}

async function setupNix() {
  if (process.getuid && process.getuid() === 0 && !process.env.VNPTNAN_GATE_ALLOW_ROOT) {
    die('Không chạy bằng sudo: cổng cài cho tài khoản đang dùng (~/.local), không cần quyền root.');
  }
  for (const t of ['bash', 'git']) if (!which(t)) die(`Thiếu ${t}. Cài: sudo apt install -y ${t}`);
  if (!which('perl')) say('Cảnh báo: không có perl, cổng dùng lõi bash dự phòng (chậm hơn nhiều). Cài: sudo apt install -y perl');
  const s = settings();
  const stage = path.join(HOME, 'staging', PKG.version);
  fs.rmSync(stage, { recursive: true, force: true }); fs.mkdirSync(stage, { recursive: true });
  fs.cpSync(ROOT, stage, { recursive: true, filter: (p) => !path.relative(ROOT, p).split(/[\\/]/).includes('node_modules') });
  const mode = modeFor(s, stage);
  s.auto = scheduleNix();
  installNix(stage, mode, s);
  fs.rmSync(stage, { recursive: true, force: true });
  s.hooks = registerHooksNix();
  saveConfig(s);
  say(`Đã cài VNPTNAN_GATE ${PKG.version} (MODE=${mode}) tại ${path.join(HOME, 'current')}`);
  say(`Lệnh: ${path.join(BIN_DIR, 'vnptnan-gate')}${(process.env.PATH || '').split(':').includes(BIN_DIR) ? '' : `  (chưa có trong PATH: thêm export PATH="$HOME/.local/bin:$PATH" vào ~/.bashrc, rồi mở terminal mới)`}`);
  say({ systemd: 'Tự cập nhật: systemd --user, hằng ngày 10:17.', cron: 'Tự cập nhật: cron 10:17 hằng ngày (WSL: cron cần đang chạy; dự phòng: kiểm tra mỗi ngày khi gọi vnptnan-gate).',
    wrapper: 'Tự cập nhật: kiểm tra mỗi ngày một lần khi gọi vnptnan-gate (máy không có systemd/cron).' }[s.auto]);
  say({ config: `Hook: đăng ký cấp người dùng (git config --global hook.vnptnan-gate-*), áp cho mọi repo${opt.hooksPath ? '; Git >= 2.54 nên không cần --hooks-path' : ''}.`,
    hooksPath: `Hook: core.hooksPath toàn cục -> ${hooksPathDir()} (hook riêng của repo vẫn chạy trước).`,
    repo: `Hook: Git ${gitVersion()} chưa hỗ trợ hook theo config (cần >= 2.54). Trong từng repo chạy: vnptnan-gate install-hooks\n      (hoặc cài lại với --hooks-path để áp cho mọi repo qua core.hooksPath)` }[s.hooks]);
  say('Kiểm tra: vnptnan-gate doctor');
}

async function updateNix(s, cur, ver, dist) {
  if (cur && cmpVer(ver, cur) <= 0) {
    const conf = (() => { try { return fs.readFileSync(path.join(HOME, 'current', 'gate.conf'), 'utf8'); } catch (_) { return ''; } })();
    const want = modeFor(s, path.join(HOME, 'current')), now = (/^MODE=(\w+)/m.exec(conf) || [])[1];
    if (now && want !== now) { fs.writeFileSync(path.join(HOME, 'current', 'gate.conf'), conf.replace(/^MODE=.*$/m, `MODE=${want}`)); say(`Đổi chế độ ${now} -> ${want}`); }
    else say(`Đã là bản mới nhất ${cur}`);
    return;
  }
  const stage = path.join(HOME, 'staging', ver);
  const n = await fetchTo(s, dist, stage);
  const mode = modeFor(s, stage);
  installNix(stage, mode, readJson(CFG) || {});
  fs.rmSync(stage, { recursive: true, force: true });
  const saved = readJson(CFG) || {};
  if (saved.hooks === 'config' || saved.hooks === 'hooksPath') { opt.hooksPath = saved.hooks === 'hooksPath'; registerHooksNix(); }
  say(`Đã cập nhật ${cur || '(chưa cài)'} -> ${ver} (${n} file, MODE=${mode})`);
}

async function uninstallNix() {
  unscheduleNix();
  for (const [name] of HOOKS) { gitGlobal('--unset-all', `hook.${name}.event`); gitGlobal('--unset-all', `hook.${name}.command`); }
  const hp = (gitGlobal('--get', 'core.hooksPath').stdout || '').trim();
  if (hp && path.resolve(hp.replace(/^~/, os.homedir())) === hooksPathDir()) gitGlobal('--unset', 'core.hooksPath');
  const w = path.join(BIN_DIR, 'vnptnan-gate');
  if (fs.existsSync(w) && fs.readFileSync(w, 'utf8').includes('npx @vnptnan/gate')) fs.rmSync(w, { force: true });
  fs.rmSync(HOME, { recursive: true, force: true });
  console.log('Đã gỡ VNPTNAN_GATE, lịch tự cập nhật và hook cấp người dùng.');
  console.log('Repo đã chạy "vnptnan-gate install-hooks": xoá .git/hooks/{pre-commit,pre-push,commit-msg} (hook cũ, nếu có, nằm ở *.local).');
}

// ------------------------------------------------------------------ lệnh
async function setup() {
  if (!IS_WIN) return setupNix();
  const s = settings();
  if (!isAdmin()) return elevate(passArgs(s));
  const stage = path.join(HOME, 'staging', PKG.version);
  fs.rmSync(stage, { recursive: true, force: true }); fs.mkdirSync(stage, { recursive: true });
  // Lọc theo đường dẫn TƯƠNG ĐỐI: chạy qua npx thì chính ROOT nằm trong ...\npm-cache\_npx\...\node_modules\@vnptnan\gate
  fs.cpSync(ROOT, stage, { recursive: true, filter: (p) => !path.relative(ROOT, p).split(/[\\/]/).includes('node_modules') });
  if (!fs.existsSync(path.join(stage, 'installer', 'install.ps1'))) throw new Error(`Chép bộ cài vào ${stage} không đủ file`);
  const mode = modeFor(s, stage);
  installFrom(stage, mode);
  fs.rmSync(stage, { recursive: true, force: true });
  saveConfig(s); schedule();
  say(`Đã cài VNPTNAN_GATE ${PKG.version} (MODE=${mode}); tự cập nhật hằng ngày từ ${s.registry}`);
  say('Mở terminal mới và chạy: vnptnan-gate doctor');
}

async function update() {
  const s = settings();
  const cur = installedVersion();
  const { ver, dist } = await latest(s);
  if (opt.check) { console.log(`Đang cài: ${cur || '(chưa cài)'} · Trên kho: ${ver}${cur && cmpVer(ver, cur) > 0 ? ' · có bản mới' : ''}`); return; }
  if (opt.stageOnly) { const n = await fetchTo(s, dist, path.resolve(opt.stageOnly)); console.log(`Đã tải ${ver}, kiểm tra toàn vẹn đạt, giải nén ${n} file vào ${opt.stageOnly}`); return; }
  if (!IS_WIN) return withLock(() => updateNix(s, cur, ver, dist));
  if (!isAdmin()) return elevate(passArgs(s));
  if (cur && cmpVer(ver, cur) <= 0) {
    // Cùng phiên bản: chỉ đổi chế độ nếu chính sách gói khác chế độ đang chạy
    const conf = (() => { try { return fs.readFileSync(path.join(HOME, 'current', 'gate.conf'), 'utf8'); } catch (_) { return ''; } })();
    const want = modeFor(s, path.join(HOME, 'current')), now = (/^MODE=(\w+)/m.exec(conf) || [])[1];
    if (now && want !== now) { installFrom(path.join(HOME, 'current'), want); say(`Đổi chế độ ${now} -> ${want}`); }
    else say(`Đã là bản mới nhất ${cur}`);
    return;
  }
  const stage = path.join(HOME, 'staging', ver);
  const n = await fetchTo(s, dist, stage);
  const mode = modeFor(s, stage);
  installFrom(stage, mode);
  fs.rmSync(stage, { recursive: true, force: true });
  // Bản mới có thể sửa chính trình cập nhật: đăng ký lại lịch trỏ vào bản vừa cài
  schedule();
  say(`Đã cập nhật ${cur || '(chưa cài)'} -> ${ver} (${n} file, MODE=${mode})`);
}

async function status() {
  const s = settings(), saved = readJson(CFG) || {};
  console.log(`Đang cài   : ${installedVersion() || '(chưa cài)'} tại ${path.join(HOME, 'current')}`);
  console.log(`Kho gói    : ${s.registry}${s.ca ? ` (CA: ${s.ca})` : ''}`);
  console.log(`Proxy      : ${s.proxy ? s.proxy.replace(/\/\/[^@/]*@/, '//***@') : '(đi thẳng)'}`);
  console.log(`Chế độ     : ${saved.mode ? `${saved.mode} (cố định trên máy này)` : 'theo policy.json của gói'}`);
  try { const { ver } = await latest(s); console.log(`Bản mới nhất: ${ver}`); } catch (e) { console.log(`Bản mới nhất: không đọc được (${e.message})`); }
  if (IS_WIN) console.log(`Lịch cập nhật: ${cp.spawnSync('schtasks.exe', ['/Query', '/TN', TASK], { stdio: 'ignore' }).status === 0 ? 'có' : 'CHƯA CÓ'}`);
  else {
    const auto = saved.auto || '', active = auto === 'systemd' ? sh('systemctl', ['--user', 'is-active', `${UNIT}.timer`]).stdout.trim() === 'active'
      : auto === 'cron' ? (sh('crontab', ['-l']).stdout || '').includes('# vnptnan-gate') : auto === 'wrapper';
    console.log(`Tự cập nhật: ${{ systemd: 'systemd --user', cron: 'cron', wrapper: 'kiểm tra khi gọi vnptnan-gate' }[auto] || 'CHƯA CÓ'}${auto && !active ? ' (KHÔNG hoạt động)' : ''}`);
    console.log(`Hook       : ${{ config: 'git config --global hook.*', hooksPath: `core.hooksPath -> ${hooksPathDir()}`, repo: 'từng repo (vnptnan-gate install-hooks)' }[saved.hooks] || '(chưa cài)'}`);
    console.log(`Lệnh       : ${path.join(BIN_DIR, 'vnptnan-gate')}${fs.existsSync(path.join(BIN_DIR, 'vnptnan-gate')) ? '' : ' (CHƯA CÓ)'}`);
  }
}

async function uninstall() {
  if (!IS_WIN) return uninstallNix();
  if (!isAdmin()) return elevate([]);
  for (const t of [TASK, `${TASK} (khoi dong)`]) cp.spawnSync('schtasks.exe', ['/Delete', '/F', '/TN', t], { stdio: 'ignore' });
  const un = path.join(HOME, 'current', 'installer', 'uninstall.ps1');
  if (fs.existsSync(un)) { const tmp = path.join(require('os').tmpdir(), `vnptnan-gate-uninstall-${process.pid}.ps1`); fs.copyFileSync(un, tmp); ps(['-File', tmp]); fs.rmSync(tmp, { force: true }); }
  fs.rmSync(CFG, { force: true });
  say('Đã gỡ VNPTNAN_GATE và lịch tự cập nhật.');
}

const cmds = { setup, update, status, uninstall, version: async () => console.log(PKG.version) };
if (!cmds[cmd]) die(`Lệnh không có: ${cmd}. Dùng: setup | update [--check] | status | uninstall`);
cmds[cmd]().catch((e) => die(e.message));
