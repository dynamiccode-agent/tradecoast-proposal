// Password gate for a private proposal (Vercel Edge Middleware, framework-agnostic).
// Password is read from the PROPOSAL_PASSWORD env var — it is NEVER stored in this repo.
export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };

const COOKIE = 'dc_proposal_auth';
function sign(s) { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0; return h.toString(16); }

export default function middleware(request) {
  const pw = process.env.PROPOSAL_PASSWORD;
  const cont = new Response(null, { headers: { 'x-middleware-next': '1' } });
  if (!pw) return cont; // fail open if misconfigured, to avoid locking everyone out

  const url = new URL(request.url);
  const token = sign(pw);
  const cookie = request.headers.get('cookie') || '';
  if (cookie.split(/;\s*/).includes(`${COOKIE}=${token}`)) return cont;

  const submitted = url.searchParams.get('pw');
  if (submitted !== null && submitted === pw) {
    const res = new Response(null, { status: 302, headers: { Location: url.pathname || '/' } });
    res.headers.append('Set-Cookie', `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`);
    return res;
  }
  return new Response(page(submitted !== null), {
    status: 401,
    headers: { 'content-type': 'text/html; charset=utf-8', 'x-robots-tag': 'noindex, nofollow', 'cache-control': 'no-store' },
  });
}

function page(err) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Private proposal · Dynamic Code</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0a0a;color:#ededed;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,sans-serif}.card{width:min(92vw,380px);padding:40px 32px;border:1px solid #1f1f1f;border-radius:16px;background:#111;text-align:center}.mark{font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#8a8a8a;margin-bottom:24px}h1{font-size:19px;font-weight:600;margin:0 0 8px}p{font-size:14px;color:#a3a3a3;line-height:1.5;margin:0 0 24px}input{width:100%;padding:13px 15px;border:1px solid #2a2a2a;border-radius:10px;background:#0a0a0a;color:#fff;font-size:15px;outline:none}input:focus{border-color:#555}button{width:100%;margin-top:12px;padding:13px;border:0;border-radius:10px;background:#fff;color:#000;font-size:15px;font-weight:600;cursor:pointer}button:hover{opacity:.9}.err{color:#f87171;font-size:13px;margin-top:14px;min-height:16px}</style></head><body><form class="card" method="GET"><div class="mark">Dynamic Code</div><h1>This proposal is private</h1><p>Enter the access password to view this proposal.</p><input type="password" name="pw" placeholder="Password" autofocus autocomplete="current-password" required><button type="submit">View proposal</button><div class="err">${err ? 'Incorrect password — please try again.' : ''}</div></form></body></html>`;
}
