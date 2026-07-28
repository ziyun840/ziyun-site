// Cloudflare Pages _worker.js — 单文件处理所有 API
// 部署位置: functions/_worker.js

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // 只处理 /api/* 路径
    if (!path.startsWith('/api/')) {
      return env.ASSETS.fetch(request);
    }

    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    if (method === 'OPTIONS') return new Response(null, { headers: cors });

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const device = request.headers.get('User-Agent') || 'unknown';

    // 解析 body
    let body = {};
    try {
      const ct = request.headers.get('Content-Type') || '';
      if (ct.includes('application/json')) body = await request.json();
    } catch(e) {}

    // 获取 token 用户
    async function getUser() {
      const auth = request.headers.get('Authorization');
      if (!auth || !auth.startsWith('Bearer ')) return null;
      const s = await env.DB.prepare('SELECT username FROM sessions WHERE token = ?').bind(auth.slice(7)).first();
      return s ? s.username : null;
    }

    async function isAdmin(u) {
      if (!u) return false;
      const r = await env.DB.prepare('SELECT role FROM users WHERE username = ?').bind(u).first();
      return r && r.role === 'admin';
    }

    async function log(u, a, d) {
      await env.DB.prepare('INSERT INTO audit_logs (username,action,detail,ip,device) VALUES (?,?,?,?,?)').bind(u, a, d||'', ip, device).run();
    }

    function json(data, status) {
      return new Response(JSON.stringify(data), {
        status: status || 200,
        headers: { 'Content-Type': 'application/json', ...cors }
      });
    }

    try {
      // === 注册 ===
      if (path === '/api/register' && method === 'POST') {
        const { username, password } = body;
        if (!username || !password || username.length < 3) return json({ error: '用户名至少3个字符' }, 400);
        const e = await env.DB.prepare('SELECT username FROM users WHERE username = ?').bind(username).first();
        if (e) return json({ error: '用户名已存在' }, 409);
        await env.DB.prepare('INSERT INTO users (username,password_hash,role) VALUES (?,?,\'user\')').bind(username, password).run();
        await log(username, 'register', '新用户注册');
        return json({ success: true, message: '注册成功' });
      }

      // === 登录 ===
      if (path === '/api/login' && method === 'POST') {
        const { username, password } = body;
        if (!username || !password) return json({ error: '请输入用户名和密码' }, 400);
        const u = await env.DB.prepare('SELECT username,password_hash,role FROM users WHERE username = ?').bind(username).first();
        if (!u || u.password_hash !== password) return json({ error: '用户名或密码错误' }, 401);
        const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        let token = '';
        for (let i = 0; i < 32; i++) token += chars.charAt(Math.floor(Math.random() * chars.length));
        await env.DB.prepare('INSERT INTO sessions (token,username) VALUES (?,?)').bind(token, username).run();
        await log(username, u.role === 'admin' ? 'admin' : 'login', u.role === 'admin' ? '管理员登录' : '用户登录');
        return json({ success: true, token, username: u.username, role: u.role });
      }

      // === 退出 ===
      if (path === '/api/logout' && method === 'POST') {
        const a = request.headers.get('Authorization');
        if (a && a.startsWith('Bearer ')) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(a.slice(7)).run();
        return json({ success: true });
      }

      // === 当前用户 ===
      if (path === '/api/me' && method === 'GET') {
        const u = await getUser();
        if (!u) return json({ user: null });
        const r = await env.DB.prepare('SELECT username,role FROM users WHERE username = ?').bind(u).first();
        return json({ user: r ? { username: r.username, role: r.role } : null });
      }

      // === 统计数据 ===
      if (path === '/api/admin/stats' && method === 'GET') {
        const u = await getUser();
        if (!u || !(await isAdmin(u))) return json({ error: '无权限' }, 403);
        const uc = (await env.DB.prepare('SELECT COUNT(*) as c FROM users').first()).c;
        const lc = (await env.DB.prepare("SELECT COUNT(*) as c FROM audit_logs WHERE created_at >= datetime('now','-1 day')").first()).c;
        const t = await env.DB.prepare("SELECT COALESCE(bytes,0) as b FROM traffic WHERE date = date('now')").first();
        return json({ totalUsers: uc, recentLogins: lc, trafficToday: (t && t.b) || 0 });
      }

      // === 用户列表 ===
      if (path === '/api/admin/users' && method === 'GET') {
        const u = await getUser();
        if (!u || !(await isAdmin(u))) return json({ error: '无权限' }, 403);
        const { results } = await env.DB.prepare('SELECT username,password_hash as password,role FROM users ORDER BY created_at DESC').all();
        return json({ users: results });
      }

      // === 更新用户 ===
      if (path.startsWith('/api/admin/users/') && method === 'PUT') {
        const u = await getUser();
        if (!u || !(await isAdmin(u))) return json({ error: '无权限' }, 403);
        const tu = decodeURIComponent(path.replace('/api/admin/users/', ''));
        const { newUser, password, role } = body;
        if (!newUser || newUser.length < 3) return json({ error: '用户名至少3个字符' }, 400);
        if (tu === 'admin' && role !== 'admin') return json({ error: '管理员角色不可变更' }, 400);
        if (newUser !== tu) {
          // 用户名变更
          await env.DB.prepare('DELETE FROM sessions WHERE username = ?').bind(tu).run();
          await env.DB.prepare('DELETE FROM users WHERE username = ?').bind(tu).run();
          await env.DB.prepare('INSERT INTO users (username,password_hash,role) VALUES (?,?,?)').bind(newUser, password, role).run();
          await log(u, 'update', '修改用户: ' + tu + ' → ' + newUser);
        } else {
          await env.DB.prepare('UPDATE users SET password_hash = ?, role = ? WHERE username = ?').bind(password, role, tu).run();
          await log(u, 'update', '修改用户: ' + tu);
        }
        return json({ success: true });
      }

      // === 删除用户 ===
      if (path.startsWith('/api/admin/users/') && method === 'DELETE') {
        const u = await getUser();
        if (!u || !(await isAdmin(u))) return json({ error: '无权限' }, 403);
        const tu = decodeURIComponent(path.replace('/api/admin/users/', ''));
        if (tu === 'admin') return json({ error: '不能删除管理员' }, 400);
        await env.DB.prepare('DELETE FROM users WHERE username = ?').bind(tu).run();
        await env.DB.prepare('DELETE FROM sessions WHERE username = ?').bind(tu).run();
        await log(u, 'delete', '删除用户: ' + tu);
        return json({ success: true });
      }

      // === 审计日志 ===
      if (path === '/api/admin/logs' && method === 'GET') {
        const u = await getUser();
        if (!u || !(await isAdmin(u))) return json({ error: '无权限' }, 403);
        const filter = url.searchParams.get('filter') || 'all';
        let q, p;
        if (filter === 'all') { q = 'SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200'; p = []; }
        else { q = 'SELECT * FROM audit_logs WHERE action = ? ORDER BY id DESC LIMIT 200'; p = [filter]; }
        const { results } = await env.DB.prepare(q).bind(...p).all();
        return json({ logs: results });
      }

      // === 清空日志 ===
      if (path === '/api/admin/logs' && method === 'DELETE') {
        const u = await getUser();
        if (!u || !(await isAdmin(u))) return json({ error: '无权限' }, 403);
        await env.DB.prepare('DELETE FROM audit_logs').run();
        return json({ success: true });
      }

      // === 记录流量 ===
      if (path === '/api/track' && method === 'POST') {
        if (body.bytes) {
          await env.DB.prepare("INSERT INTO traffic (date,bytes) VALUES (date('now'),?) ON CONFLICT(date) DO UPDATE SET bytes = bytes + ?").bind(body.bytes, body.bytes).run();
        }
        return json({ success: true });
      }

      // === 获取下载链接 ===
      if (path === '/api/downloads' && method === 'GET') {
        const { results } = await env.DB.prepare('SELECT id, name, url FROM downloads ORDER BY sort_order ASC, id ASC').all();
        return json({ downloads: results });
      }

      // === 管理员更新下载链接 ===
      if (path === '/api/admin/downloads' && method === 'PUT') {
        const u = await getUser();
        if (!u || !(await isAdmin(u))) return json({ error: '无权限' }, 403);
        const { items } = body;
        if (!items || !Array.isArray(items)) return json({ error: '参数错误' }, 400);
        await env.DB.prepare('DELETE FROM downloads').run();
        for (let i = 0; i < items.length; i++) {
          const item = items[i];
          await env.DB.prepare('INSERT INTO downloads (name, url, sort_order) VALUES (?,?,?)').bind(item.name || '未命名', item.url || '#', i).run();
        }
        await log(u, 'update', '更新下载链接');
        return json({ success: true });
      }

      return json({ error: 'Not found' }, 404);
    } catch (err) {
      console.error(err);
      return json({ error: '服务器内部错误: ' + err.message }, 500);
    }
  }
};
