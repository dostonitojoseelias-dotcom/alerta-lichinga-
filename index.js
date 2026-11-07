'use strict';
const { Pool, types } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

types.setTypeParser(1082, v => v); // DATE como texto AAAA-MM-DD

const CATS = ['Lixo', 'Buraco', 'Iluminação', 'Ruído', 'Árvore', 'Grafitis', 'Água', 'Outro'];
const EQP = { 'Lixo': 'Limpeza', 'Buraco': 'Estradas', 'Iluminação': 'Eletricidade', 'Água': 'Água', 'Árvore': 'Ambiente', 'Ruído': 'Ambiente', 'Grafitis': 'Limpeza', 'Outro': 'Ambiente' };
const EQUIPAS = ['Limpeza', 'Estradas', 'Água', 'Eletricidade', 'Ambiente'];
const URG = ['Baixa', 'Média', 'Alta - Perigo'];
const SEGUE = { 'Recebida': ['Em análise', 'Rejeitada'], 'Em análise': ['Aprovada', 'Rejeitada'], 'Aprovada': ['Resolvida', 'Rejeitada'], 'Resolvida': [], 'Rejeitada': [] };
const PUBLICO = ['Aprovada', 'Resolvida'];

class Erro extends Error { constructor(m, code = 400) { super(m); this.code = code; } }

const pool = global._alertaPool || (global._alertaPool = new Pool({ connectionString: process.env.DATABASE_URL || process.env.POSTGRES_URL, max: 1 }));
const q = async (t, p = []) => (await pool.query(t, p)).rows;

// ---------- Base de dados e administrador (corre 1x por arranque) ----------
let pronto = null;
function preparar() {
  if (!pronto) pronto = (async () => {
    await pool.query(`
CREATE TABLE IF NOT EXISTS utilizadores(id SERIAL PRIMARY KEY,nome VARCHAR(120) NOT NULL,tel VARCHAR(120) NOT NULL UNIQUE,passe_hash VARCHAR(255) NOT NULL,papel VARCHAR(10) NOT NULL DEFAULT 'cidadao',criado TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS denuncias(id VARCHAR(20) PRIMARY KEY,utilizador_id INT NOT NULL REFERENCES utilizadores(id) ON DELETE CASCADE,categoria VARCHAR(30) NOT NULL,bairro VARCHAR(80) NOT NULL,urgencia VARCHAR(20) NOT NULL,descricao TEXT NOT NULL,lat DOUBLE PRECISION,lng DOUBLE PRECISION,anonimo BOOLEAN NOT NULL DEFAULT false,estado VARCHAR(20) NOT NULL DEFAULT 'Recebida',resposta TEXT,equipa VARCHAR(30) NOT NULL,prazo DATE,criado TIMESTAMPTZ NOT NULL DEFAULT now(),atualizado TIMESTAMPTZ,resolvido_em TIMESTAMPTZ);
CREATE INDEX IF NOT EXISTS ix_den_estado ON denuncias(estado);
CREATE INDEX IF NOT EXISTS ix_den_user ON denuncias(utilizador_id);
CREATE TABLE IF NOT EXISTS fotos(id SERIAL PRIMARY KEY,denuncia_id VARCHAR(20) NOT NULL REFERENCES denuncias(id) ON DELETE CASCADE,tipo VARCHAR(10) NOT NULL,dados TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_fotos_den ON fotos(denuncia_id);
CREATE TABLE IF NOT EXISTS apoios(denuncia_id VARCHAR(20) NOT NULL REFERENCES denuncias(id) ON DELETE CASCADE,utilizador_id INT NOT NULL REFERENCES utilizadores(id) ON DELETE CASCADE,PRIMARY KEY(denuncia_id,utilizador_id));
CREATE TABLE IF NOT EXISTS tentativas(id SERIAL PRIMARY KEY,chave VARCHAR(160) NOT NULL,quando TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS ix_tent ON tentativas(chave,quando);`);
    // Administrador: definido pelas variáveis ADMIN_TEL e ADMIN_PASS (nunca no código)
    if (process.env.ADMIN_TEL && process.env.ADMIN_PASS) {
      const tel = ident(process.env.ADMIN_TEL), pass = process.env.ADMIN_PASS;
      const a = (await q("SELECT id,passe_hash FROM utilizadores WHERE tel=$1", [tel]))[0];
      if (!a) await q("INSERT INTO utilizadores(nome,tel,passe_hash,papel) VALUES('Administrador',$1,$2,'admin')", [tel, await bcrypt.hash(pass, 10)]);
      else {
        if (!(await bcrypt.compare(pass, a.passe_hash))) await q('UPDATE utilizadores SET passe_hash=$1 WHERE id=$2', [await bcrypt.hash(pass, 10), a.id]);
        await q("UPDATE utilizadores SET papel='admin' WHERE id=$1", [a.id]);
      }
    }
  })().catch(e => { pronto = null; throw e; });
  return pronto;
}

// ---------- Utilitários ----------
function ident(t) {
  t = String(t ?? '').trim();
  if (t.includes('@')) {
    t = t.toLowerCase();
    if (t.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(t)) throw new Erro('E-mail inválido');
    return t;
  }
  t = t.replace(/\s+/g, '').replace(/^\+?258/, '');
  if (!/^8[2-7]\d{7}$/.test(t)) throw new Erro('Número inválido. Ex: 841234567, ou use o seu e-mail');
  return t;
}
function txt(v, max, min = 0, campo = 'Texto') {
  v = String(v ?? '').trim().replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
  if ([...v].length < min || [...v].length > max) throw new Erro(campo + ' inválido');
  return v;
}
function jpeg(d) {
  const pre = 'data:image/jpeg;base64,';
  if (typeof d !== 'string' || !d.startsWith(pre) || d.length > 2200000) throw new Erro('Foto inválida ou muito grande');
  const b = d.slice(pre.length);
  if (!/^[A-Za-z0-9+/]+=*$/.test(b)) throw new Erro('Foto inválida');
  const bin = Buffer.from(b, 'base64');
  if (bin.length > 1500000 || bin.length < 100 || bin[0] !== 0xFF || bin[1] !== 0xD8 || bin[2] !== 0xFF) throw new Erro('Foto inválida');
  return bin.toString('base64');
}
const fmtData = d => new Date(d).toLocaleDateString('pt-PT', { timeZone: 'Africa/Maputo', day: '2-digit', month: '2-digit', year: 'numeric' });
const ipDe = req => String((req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '0').split(',')[0]).trim().slice(0, 45);
async function limite(chave, max) {
  const n = +(await q("SELECT COUNT(*) AS n FROM tentativas WHERE chave=$1 AND quando>now()-interval '15 minutes'", [chave]))[0].n;
  if (n >= max) throw new Erro('Demasiadas tentativas. Espere 15 minutos.', 429);
}
async function falha(chave) {
  await q("DELETE FROM tentativas WHERE quando<now()-interval '1 day'");
  await q('INSERT INTO tentativas(chave) VALUES($1)', [chave]);
}

// ---------- Sessão (cookie assinado) e CSRF ----------
const SECRET = () => { if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 16) throw new Error('Falta SESSION_SECRET'); return process.env.SESSION_SECRET; };
const hmac = (s, pre = '') => crypto.createHmac('sha256', SECRET()).update(pre + s).digest('base64url');
const igual = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
function lerSessao(req) {
  const c = (req.headers.cookie || '').split(/;\s*/).find(x => x.startsWith('als='));
  if (c) {
    const [p, m] = c.slice(4).split('.');
    if (p && m && igual(hmac(p), m)) {
      try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); if (o.exp > Date.now() && o.sid) return o; } catch { /* nova sessão */ }
    }
  }
  return { sid: crypto.randomBytes(18).toString('hex'), uid: 0 };
}
function gravarSessao(res, o) {
  o.exp = Date.now() + 30 * 864e5;
  const p = Buffer.from(JSON.stringify(o)).toString('base64url');
  res.setHeader('Set-Cookie', `als=${p}.${hmac(p)}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`);
}
const csrfDe = o => hmac(o.sid, 'csrf:');
async function utilizador(s) {
  if (!s.uid) return null;
  return (await q('SELECT id,nome,tel,papel FROM utilizadores WHERE id=$1', [s.uid]))[0] || null;
}
const pubUser = u => ({ uid: String(u.id), nome: u.nome, tel: u.tel, admin: u.papel === 'admin' });

// ---------- Contas ----------
async function register(d, s, req) {
  const nome = txt(d.nome, 120, 3, 'Nome'), tel = ident(d.tel), p = String(d.pass ?? '');
  if (p.length < 6 || p.length > 72) throw new Erro('A palavra-passe deve ter entre 6 e 72 caracteres');
  const ip = ipDe(req); await limite('r:' + ip, 20); await falha('r:' + ip);
  if ((await q('SELECT 1 FROM utilizadores WHERE tel=$1', [tel])).length) throw new Erro('Esta conta já existe. Toque em "Já tenho conta".');
  const id = (await q("INSERT INTO utilizadores(nome,tel,passe_hash,papel) VALUES($1,$2,$3,'cidadao') RETURNING id", [nome, tel, await bcrypt.hash(p, 10)]))[0].id;
  s.uid = id; s.sid = crypto.randomBytes(18).toString('hex');
  return { user: pubUser({ id, nome, tel, papel: 'cidadao' }) };
}
async function login(d, s, req) {
  const tel = ident(d.tel), p = String(d.pass ?? ''), ip = ipDe(req);
  await limite('l:' + tel, 8); await limite('i:' + ip, 40);
  const u = (await q('SELECT * FROM utilizadores WHERE tel=$1', [tel]))[0];
  const ok = await bcrypt.compare(p, u ? u.passe_hash : '$2a$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234');
  if (!u || !ok) { await falha('l:' + tel); await falha('i:' + ip); throw new Erro('Número/e-mail ou palavra-passe incorretos'); }
  await q('DELETE FROM tentativas WHERE chave=$1', ['l:' + tel]);
  s.uid = u.id; s.sid = crypto.randomBytes(18).toString('hex');
  return { user: pubUser(u) };
}

// ---------- Denúncias ----------
const BASE = 'SELECT d.*,u.nome AS u_nome,u.tel AS u_tel FROM denuncias d JOIN utilizadores u ON u.id=d.utilizador_id ';
async function mapa(rows, verTel, admin) {
  const ids = rows.map(r => r.id), fo = {}, ap = {};
  if (ids.length) {
    for (const f of await q('SELECT id,denuncia_id,tipo FROM fotos WHERE denuncia_id=ANY($1) ORDER BY id', [ids])) ((fo[f.denuncia_id] ??= {})[f.tipo] ??= []).push('/api?foto=' + f.id);
    for (const a of await q('SELECT denuncia_id,utilizador_id FROM apoios WHERE denuncia_id=ANY($1)', [ids])) (ap[a.denuncia_id] ??= []).push(String(a.utilizador_id));
  }
  return rows.map(r => {
    const an = r.anonimo, dp = fo[r.id]?.depois || [];
    return {
      id: r.id, criado: new Date(r.criado).getTime(), equipa: r.equipa, fotos: fo[r.id]?.antes || [], depois: dp.length ? dp[dp.length - 1] : '',
      data: fmtData(r.criado), cat: r.categoria, bairro: r.bairro, urg: r.urgencia, desc: r.descricao,
      lat: r.lat == null ? '' : r.lat.toFixed(5), lng: r.lng == null ? '' : r.lng.toFixed(5),
      anonimo: an ? 'Sim' : 'Não', nome: an ? '' : r.u_nome, telefone: an ? '' : r.u_tel,
      dono: (!admin && r.u_tel === verTel) ? verTel : '', estado: r.estado, resposta: r.resposta || '', prazo: r.prazo || '',
      resolvidoEm: r.resolvido_em ? new Date(r.resolvido_em).getTime() : 0, atualizado: r.atualizado ? fmtData(r.atualizado) : '', apoios: ap[r.id] || []
    };
  });
}
async function lista(u) {
  const admin = u.papel === 'admin';
  const rows = admin ? await q(BASE + 'ORDER BY d.criado DESC LIMIT 1000') : await q(BASE + 'WHERE d.utilizador_id=$1 ORDER BY d.criado DESC LIMIT 200', [u.id]);
  const pub = await q(BASE + "WHERE d.estado IN ('Aprovada','Resolvida') ORDER BY d.criado DESC LIMIT 300");
  const publicas = (await mapa(pub, '', false)).map(x => ({ id: x.id, cat: x.cat, bairro: x.bairro, desc: x.desc, fotos: x.fotos, estado: x.estado, data: x.data, depois: x.depois, resposta: x.resposta, apoios: x.apoios }));
  return { denuncias: await mapa(rows, u.tel, admin), publicas };
}
async function criar(u, d) {
  if (u.papel === 'admin') throw new Erro('O administrador não envia denúncias.');
  const cat = d.cat; if (!CATS.includes(cat)) throw new Erro('Categoria inválida');
  const urg = d.urg; if (!URG.includes(urg)) throw new Erro('Urgência inválida');
  const bairro = txt(d.bairro, 80, 2, 'Bairro'), desc = txt(d.desc, 2000, 0, 'Descrição');
  let lat = null, lng = null;
  if (d.lat != null && d.lng != null && isFinite(d.lat) && isFinite(d.lng) && Math.abs(+d.lat) <= 90 && Math.abs(+d.lng) <= 180) { lat = +d.lat; lng = +d.lng; }
  const bins = (Array.isArray(d.fotos) ? d.fotos.slice(0, 3) : []).map(jpeg);
  const n = +(await q("SELECT COUNT(*) AS n FROM denuncias WHERE utilizador_id=$1 AND criado>now()-interval '24 hours'", [u.id]))[0].n;
  if (n >= 20) throw new Erro('Limite de 20 denúncias por dia atingido.', 429);
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', c = await pool.connect();
  try {
    await c.query('BEGIN');
    let id = null;
    for (let t = 0; t < 5 && !id; t++) {
      let x = new Date().getFullYear() + '-LI-'; for (let k = 0; k < 6; k++) x += A[crypto.randomInt(A.length)];
      if (!(await c.query('SELECT 1 FROM denuncias WHERE id=$1', [x])).rows.length) id = x;
    }
    if (!id) throw new Erro('Tente novamente.');
    await c.query('INSERT INTO denuncias(id,utilizador_id,categoria,bairro,urgencia,descricao,lat,lng,anonimo,equipa) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', [id, u.id, cat, bairro, urg, desc, lat, lng, !!d.anonimo, EQP[cat]]);
    for (const b of bins) await c.query("INSERT INTO fotos(denuncia_id,tipo,dados) VALUES($1,'antes',$2)", [id, b]);
    await c.query('COMMIT');
    return { id };
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; } finally { c.release(); }
}
async function atualizar(d) {
  const id = String(d.id ?? ''), c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = (await c.query('SELECT estado FROM denuncias WHERE id=$1 FOR UPDATE', [id])).rows[0];
    if (!r) throw new Erro('Denúncia não encontrada', 404);
    const set = ['atualizado=now()'], par = [], add = (col, v) => { par.push(v); set.push(col + '=$' + par.length); };
    const novo = d.estado ?? r.estado;
    if (novo !== r.estado) {
      if (!SEGUE[r.estado].includes(novo)) throw new Erro('Mudança de estado não permitida');
      add('estado', novo); if (novo === 'Resolvida') set.push('resolvido_em=now()');
    }
    if (d.resposta != null && String(d.resposta).trim() !== '') add('resposta', txt(d.resposta, 1000, 0, 'Resposta'));
    if ('equipa' in d) { if (!EQUIPAS.includes(d.equipa)) throw new Erro('Equipa inválida'); add('equipa', d.equipa); }
    if ('prazo' in d) {
      const p = String(d.prazo ?? '');
      if (p !== '' && (!/^\d{4}-\d{2}-\d{2}$/.test(p) || isNaN(Date.parse(p)))) throw new Erro('Data inválida');
      add('prazo', p === '' ? null : p);
    }
    if (d.depois) {
      const b = jpeg(d.depois);
      await c.query("DELETE FROM fotos WHERE denuncia_id=$1 AND tipo='depois'", [id]);
      await c.query("INSERT INTO fotos(denuncia_id,tipo,dados) VALUES($1,'depois',$2)", [id, b]);
    }
    par.push(id); await c.query(`UPDATE denuncias SET ${set.join(',')} WHERE id=$${par.length}`, par);
    await c.query('COMMIT');
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; } finally { c.release(); }
}
async function apoiar(u, d) {
  const id = String(d.id ?? '');
  const r = (await q('SELECT estado FROM denuncias WHERE id=$1', [id]))[0];
  if (!r || !PUBLICO.includes(r.estado)) throw new Erro('Denúncia não encontrada', 404);
  const del = await pool.query('DELETE FROM apoios WHERE denuncia_id=$1 AND utilizador_id=$2', [id, u.id]);
  if (!del.rowCount) await q('INSERT INTO apoios(denuncia_id,utilizador_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [id, u.id]);
}
async function consultar(d, req) {
  const ip = ipDe(req); await limite('c:' + ip, 30); await falha('c:' + ip);
  const r = (await q('SELECT id,estado,categoria,bairro,resposta FROM denuncias WHERE id=$1', [String(d.id ?? '').trim().toUpperCase()]))[0];
  if (!r) throw new Erro('Código não encontrado.', 404);
  return { d: { id: r.id, estado: r.estado, cat: r.categoria, bairro: r.bairro, resposta: r.resposta || '' } };
}

// ---------- Ponto de entrada ----------
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
  const json = (code, o) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(o)); };
  try {
    await preparar();
    const s = lerSessao(req);
    // Fotos: só quem pode ver
    if (req.method === 'GET' && req.query && req.query.foto) {
      const f = (await q('SELECT f.dados,d.estado,d.utilizador_id FROM fotos f JOIN denuncias d ON d.id=f.denuncia_id WHERE f.id=$1', [parseInt(req.query.foto, 10) || 0]))[0];
      const u = await utilizador(s);
      if (!f || !(PUBLICO.includes(f.estado) || (u && (u.papel === 'admin' || u.id === f.utilizador_id)))) { res.statusCode = 404; return res.end(); }
      res.statusCode = 200; res.setHeader('Content-Type', 'image/jpeg'); res.setHeader('Cache-Control', 'private, max-age=86400');
      return res.end(Buffer.from(f.dados, 'base64'));
    }
    if (req.method !== 'POST') throw new Erro('Método inválido', 405);
    let d = req.body; if (typeof d === 'string') { try { d = JSON.parse(d); } catch { d = null; } }
    if (!d || typeof d !== 'object') throw new Erro('Pedido inválido');
    const acao = String(d.action ?? '');
    if (acao !== 'me' && !igual(req.headers['x-csrf'] || '', csrfDe(s))) throw new Erro('Sessão expirada. Recarregue a página.', 403);
    let res2 = {};
    switch (acao) {
      case 'me': { const u = await utilizador(s); res2 = { user: u ? pubUser(u) : null }; break; }
      case 'register': res2 = await register(d, s, req); break;
      case 'login': res2 = await login(d, s, req); break;
      case 'logout': s.uid = 0; s.sid = crypto.randomBytes(18).toString('hex'); break;
      case 'list': { const u = await utilizador(s); if (!u) return json(200, { ok: false, sessao: false, erro: 'Sessão terminada.' }); res2 = await lista(u); break; }
      case 'create': { const u = await utilizador(s); if (!u) throw new Erro('Faça login primeiro.', 401); res2 = await criar(u, d); break; }
      case 'update': { const u = await utilizador(s); if (!u || u.papel !== 'admin') throw new Erro('Acesso reservado ao administrador.', 403); await atualizar(d); break; }
      case 'support': { const u = await utilizador(s); if (!u) throw new Erro('Faça login primeiro.', 401); await apoiar(u, d); break; }
      case 'lookup': res2 = await consultar(d, req); break;
      default: throw new Erro('Ação desconhecida');
    }
    gravarSessao(res, s);
    json(200, { ok: true, csrf: csrfDe(s), ...res2 });
  } catch (e) {
    if (e instanceof Erro) return json(e.code, { ok: false, erro: e.message });
    console.error(e);
    json(500, { ok: false, erro: 'Erro no servidor. Tente de novo.' });
  }
};
