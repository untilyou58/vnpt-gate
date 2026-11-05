#!/usr/bin/env node
// VNPTNAN_GATE - cài đặt và tự cập nhật qua npm (mặc định npmjs.com; đổi kho bằng npm config @vnptnan:registry hoặc --registry).
//   npx @vnptnan/gate                 cài hoặc cài lại (xin quyền admin qua UAC), đăng ký tự cập nhật hằng ngày
//   npx @vnptnan/gate --audit|--enforce   cài và cố định chế độ trên máy này (mặc định: theo policy.json của gói)
//   npx @vnptnan/gate status          phiên bản đang cài, bản mới nhất trên kho, chế độ, lịch cập nhật
//   npx @vnptnan/gate update [--check]    cập nhật ngay (lịch tự chạy lệnh này bằng tài khoản SYSTEM)
//   npx @vnptnan/gate uninstall       gỡ cổng và lịch cập nhật
// Tuỳ chọn: --registry URL, --ca FILE (CA khi dùng kho nội bộ tự ký), --token T (khi kho cần đăng nhập).
// Không phụ thuộc gói ngoài. Cổng chạy bằng bash như trước; Node chỉ dùng để tải, kiểm tra và cài.
'use strict';
const fs = require('fs'), path = require('path'), cp = require('child_process'), zlib = require('zlib');
const crypto = require('crypto'), tls = require('tls'), https = require('https'), http = require('http');

const ROOT = path.resolve(__dirname, '..');
const PKG = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const IS_WIN = process.platform === 'win32';
const HOME = path.join(process.env.ProgramData || 'C:\\ProgramData', 'VNPTNAN_GATE');
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
  else if (['--registry', '--ca', '--token', '--stage-only'].includes(a)) opt[a.slice(2).replace('-o', 'O')] = argv[++i];
  else die(`Tham số không hiểu: ${a}`);
}

function say(s) { if (!opt.quiet) console.log(s); log(s); }
function log(s) { try { fs.mkdirSync(path.dirname(LOG), { recursive: true }); fs.appendFileSync(LOG, `${new Date().toISOString()}\t${s}\n`); } catch (_) { /* chưa có quyền ghi */ } }
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
  return { name: PKG.name, registry: registry.replace(/\/?$/, '/'), ca, token: opt.token || saved.token || '', mode: opt.mode || saved.mode || '' };
}

// ------------------------------------------------------------------ HTTP (có CA nội bộ, theo redirect)
function get(url, s, asJson, hops = 0) {
  return new Promise((resolve, reject) => {
    const u = new URL(url), lib = u.protocol === 'http:' ? http : https;
    const o = { headers: { 'User-Agent': `vnptnan-gate/${PKG.version}`, Accept: asJson ? 'application/json' : '*/*' }, timeout: 30000 };
    if (s.ca && fs.existsSync(s.ca)) o.ca = [...tls.rootCertificates, fs.readFileSync(s.ca, 'utf8')];
    if (s.token && u.host === new URL(s.registry).host) o.headers.Authorization = `Bearer ${s.token}`;
    const req = lib.get(u, o, (res) => {
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
function ps(args) { return cp.spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', ...args], { stdio: opt.quiet ? 'ignore' : 'inherit' }).status; }
function elevate(extra) {
  if (opt.elevated) die('Đã chạy với quyền nâng nhưng vẫn không có quyền admin (net session lỗi). Mở terminal "Run as administrator" rồi chạy lại.');
  const q = (x) => `'${String(x).replace(/'/g, "''")}'`;
  const args = [__filename, cmd, ...extra, '--elevated'].map((x) => `'"${String(x).replace(/'/g, "''")}"'`).join(',');
  say('Đang xin quyền quản trị (UAC)...');
  const st = cp.spawnSync('powershell.exe', ['-NoProfile', '-Command',
    `$p = Start-Process -FilePath ${q(process.execPath)} -ArgumentList @(${args}) -Verb RunAs -Wait -PassThru; exit $p.ExitCode`], { stdio: 'inherit' }).status;
  try { const tail = fs.readFileSync(LOG, 'utf8').trim().split('\n').slice(-6).map((l) => l.split('\t').slice(1).join(' ')); console.log(tail.join('\n')); } catch (_) { /* không có log */ }
  process.exit(st || 0);
}
function passArgs(s) {
  const a = ['--registry', s.registry];
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
  fs.writeFileSync(CFG, JSON.stringify({ registry: s.registry, ca, token: s.token, mode: s.mode }, null, 2));
}
function schedule() {
  const tr = `"${process.execPath}" "${path.join(HOME, 'current', 'bin', 'cli.js')}" update --quiet`;
  for (const [suffix, sc] of [['', ['/SC', 'DAILY', '/ST', '10:17']], [' (khoi dong)', ['/SC', 'ONSTART', '/DELAY', '0010:00']]]) {
    const st = cp.spawnSync('schtasks.exe', ['/Create', '/F', '/TN', TASK + suffix, '/RU', 'SYSTEM', '/RL', 'HIGHEST', '/TR', tr, ...sc], { stdio: 'ignore' }).status;
    if (st !== 0) say(`Cảnh báo: không tạo được lịch "${TASK + suffix}" (mã ${st})`);
  }
}
function installedVersion() { try { return fs.readFileSync(path.join(HOME, 'current', 'VERSION'), 'utf8').trim(); } catch (_) { return ''; } }

// ------------------------------------------------------------------ lệnh
async function setup() {
  if (!IS_WIN) die('Lệnh cài này dành cho máy dev Windows. Máy chủ GitLab dùng installer/install-server.sh.');
  const s = settings();
  if (!isAdmin()) return elevate(passArgs(s));
  const stage = path.join(HOME, 'staging', PKG.version);
  fs.rmSync(stage, { recursive: true, force: true }); fs.mkdirSync(stage, { recursive: true });
  fs.cpSync(ROOT, stage, { recursive: true, filter: (p) => !/[\\/]node_modules([\\/]|$)/.test(p) });
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
  if (!IS_WIN) die('Cập nhật chỉ chạy trên máy dev Windows.');
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
  console.log(`Đang cài   : ${installedVersion() || '(chưa cài)'}${IS_WIN ? ` tại ${path.join(HOME, 'current')}` : ''}`);
  console.log(`Kho gói    : ${s.registry}${s.ca ? ` (CA: ${s.ca})` : ''}`);
  console.log(`Chế độ     : ${saved.mode ? `${saved.mode} (cố định trên máy này)` : 'theo policy.json của gói'}`);
  try { const { ver } = await latest(s); console.log(`Bản mới nhất: ${ver}`); } catch (e) { console.log(`Bản mới nhất: không đọc được (${e.message})`); }
  if (IS_WIN) console.log(`Lịch cập nhật: ${cp.spawnSync('schtasks.exe', ['/Query', '/TN', TASK], { stdio: 'ignore' }).status === 0 ? 'có' : 'CHƯA CÓ'}`);
}

async function uninstall() {
  if (!IS_WIN) die('Chỉ dùng trên máy dev Windows.');
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
