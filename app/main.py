from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.routing.proxy import BrowserProxy
from app.routing.selector import AdaptiveRouteSelector
from app.routing.state import MetricsStore


STATE_PATH = os.getenv("NETBOOST_STATE_PATH", "data/route_state.json")
PROXY_HOST = os.getenv("NETBOOST_PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.getenv("NETBOOST_PROXY_PORT", "8888"))
DASHBOARD_HOST = os.getenv("NETBOOST_DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.getenv("NETBOOST_DASHBOARD_PORT", "8000"))

store = MetricsStore(STATE_PATH)
selector = AdaptiveRouteSelector(store)
proxy_controller = BrowserProxy(store, selector)
proxy_server: asyncio.AbstractServer | None = None
flush_task: asyncio.Task[None] | None = None
startup_error: str | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global proxy_server, flush_task, startup_error
    async def flush_metrics() -> None:
        while True:
            await asyncio.sleep(1)
            store.flush()
    flush_task = asyncio.create_task(flush_metrics())
    try:
        proxy_server = await asyncio.start_server(
            proxy_controller.handle, PROXY_HOST, PROXY_PORT, limit=65536
        )
        store.add_event("startup", f"Browser proxy listening on {PROXY_HOST}:{PROXY_PORT}.")
        startup_error = None
    except OSError as exc:
        startup_error = f"Could not start browser proxy on {PROXY_HOST}:{PROXY_PORT}: {exc}"
        store.add_event("startup_error", startup_error)
    yield
    if flush_task is not None:
        flush_task.cancel()
        try:
            await flush_task
        except asyncio.CancelledError:
            pass
        flush_task = None
    store.flush()
    if proxy_server is not None:
        proxy_server.close()
        await proxy_server.wait_closed()
        proxy_server = None


app = FastAPI(title="NetBoost Live Routing", version="0.1.0", lifespan=lifespan)


DASHBOARD_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetBoost · Live Routing</title>
<style>
:root{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#e9eef7;background:#10141d}body{margin:0}main{max-width:1120px;margin:0 auto;padding:28px 18px 60px}h1{font-size:27px;margin:0 0 6px}p.sub{margin:0;color:#aab6ca}.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:24px}.pill{border:1px solid #394358;border-radius:999px;padding:7px 12px;color:#dce5f4;font-size:13px}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:20px 0}.card,section{background:#191f2b;border:1px solid #2a3446;border-radius:13px;padding:16px}.label{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#9caac1}.value{font-size:22px;font-weight:650;margin:7px 0}.muted{font-size:13px;color:#9caac1;line-height:1.5}.warning{border-color:#a8793a;color:#ffd79b}.good{color:#a8e6be}.bad{color:#ffb6ae}.layout{display:grid;grid-template-columns:1.1fr .9fr;gap:12px;margin-top:12px}section{min-width:0}h2{font-size:16px;margin:0 0 14px}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:9px 6px;border-bottom:1px solid #2a3446;vertical-align:top}th{color:#9caac1;font-weight:550}td{overflow-wrap:anywhere}.events{display:flex;flex-direction:column;gap:8px;max-height:560px;overflow:auto}.event{border-left:2px solid #52627d;padding:4px 0 5px 10px;font-size:13px;line-height:1.45}.event .time{font-size:11px;color:#8795ad;margin-bottom:3px}.event.failure{border-color:#c16b65}.event.fallback{border-color:#d8a65f}.event.connected{border-color:#70c89a}.empty{color:#8997ad;font-size:13px}.foot{font-size:12px;color:#8795ad;margin-top:18px}code{color:#c4dcff;background:#222c3d;padding:2px 4px;border-radius:4px}@media(max-width:780px){.grid{grid-template-columns:1fr}.layout{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}}
</style></head><body><main>
<div class="top"><div><h1>NetBoost <span style="color:#8ebcff">Live Routing</span></h1><p class="sub">Observe real browser traffic. No route-cycling benchmark.</p></div><div class="pill" id="updated">Connecting…</div></div>
<div class="grid"><div class="card"><div class="label">Direct route</div><div class="value" id="directState">Checking…</div><div class="muted" id="directDetail"></div></div><div class="card"><div class="label">VPS route</div><div class="value" id="vpsState">Checking…</div><div class="muted" id="vpsDetail"></div></div><div class="card"><div class="label">Browser proxy</div><div class="value" id="proxyState">Checking…</div><div class="muted" id="proxyDetail"></div></div></div>
<div id="notice" class="card warning" style="display:none;margin-bottom:12px"></div>
<div class="layout"><section><h2>Recent live decisions</h2><div id="events" class="events"><div class="empty">Waiting for browser traffic…</div></div></section><section><h2>Recent website observations</h2><div style="overflow-x:auto"><table><thead><tr><th>Website</th><th>Direct</th><th>VPS</th></tr></thead><tbody id="domains"><tr><td colspan="3" class="empty">No observations yet.</td></tr></tbody></table></div><div class="foot">Scores use recent successful connections plus a failure penalty. Unknown sites start direct unless recent real traffic provides enough evidence for another choice.</div></section></div>
<div class="layout"><section><h2>Route observations · last 15 minutes</h2><div style="overflow-x:auto"><table><thead><tr><th>Route</th><th>Attempts</th><th>Success</th><th>Median setup + first response</th><th>Proxy bytes down</th></tr></thead><tbody id="routeStats"></tbody></table></div></section><section><h2>How to try it</h2><p class="muted">Open a separate Chrome profile configured to use <code>127.0.0.1:8888</code>, then browse normally. Keep the dashboard open here. Direct and VPS paths must be genuinely distinct; the dashboard warns if the system default is still routed through <code>wg0</code>.</p><p class="muted">A successful CONNECT measures the route's TCP setup and the first server data after TLS begins. This proxy cannot inspect encrypted page contents, so it does not claim to know exact browser paint time. Byte counts are proxied stream bytes, not carrier-billed usage or tunnel overhead.</p></section></div>
</main><script>
const esc=(s)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ms=v=>v==null?'—':`${Math.round(v)} ms`;
const bytes=v=>{v=Number(v||0);if(v<1024)return `${v} B`;if(v<1048576)return `${(v/1024).toFixed(1)} KB`;return `${(v/1048576).toFixed(2)} MB`};
const score=(o)=>!o||!o.observations?'—':`${o.successes}/${o.observations}${o.median_response_ms==null?'':` · ${ms(o.median_response_ms)}`}`;
async function refresh(){try{const [s,e,d]=await Promise.all([fetch('/api/status').then(r=>r.json()),fetch('/api/events').then(r=>r.json()),fetch('/api/domains').then(r=>r.json())]);document.getElementById('updated').textContent='Updated '+new Date().toLocaleTimeString();document.getElementById('directState').textContent=s.paths.direct_route_ready?'Available':'Not independent';document.getElementById('directState').className='value '+(s.paths.direct_route_ready?'good':'bad');document.getElementById('directDetail').textContent='System route device: '+(s.paths.direct_device||'unknown');document.getElementById('vpsState').textContent=s.paths.vps_proxy_ready?'Connected':(s.paths.wireguard_route_ready?'Proxy unavailable':'Tunnel unavailable');document.getElementById('vpsState').className='value '+(s.paths.vps_proxy_ready?'good':'bad');document.getElementById('vpsDetail').textContent='10.8.0.1:'+s.vps_port+' via '+(s.paths.tunnel_device||'unknown');document.getElementById('proxyState').textContent=s.proxy_listening?'Listening':'Not listening';document.getElementById('proxyState').className='value '+(s.proxy_listening?'good':'bad');document.getElementById('proxyDetail').textContent=s.proxy_host+':'+s.proxy_port+(s.startup_error?' · '+s.startup_error:'');const n=document.getElementById('notice');if(s.paths.note){n.style.display='block';n.textContent=s.paths.note}else{n.style.display='none'}document.getElementById('events').innerHTML=e.events.length?e.events.map(x=>`<div class="event ${x.kind==='route_failure'||x.kind==='proxy_error'?'failure':''} ${x.kind==='fallback'?'fallback':''} ${x.kind==='connected'?'connected':''}"><div class="time">${esc(new Date(x.at).toLocaleTimeString())} · ${esc(x.kind)}${x.route?' · '+esc(x.route):''}</div>${esc(x.message)}${x.host?`<div class="muted">${esc(x.host)}</div>`:''}</div>`).join(''):'<div class="empty">Waiting for browser traffic…</div>';document.getElementById('domains').innerHTML=d.domains.length?d.domains.slice(0,30).map(x=>`<tr><td>${esc(x.host)}</td><td>${esc(score(x.direct))}</td><td>${esc(score(x.vps))}</td></tr>`).join(''):'<tr><td colspan="3" class="empty">No observations yet.</td></tr>';document.getElementById('routeStats').innerHTML=s.route_stats.map(x=>`<tr><td>${esc(x.route)}</td><td>${x.observations}</td><td>${x.observations?Math.round(100*x.successes/x.observations)+'%':'—'}</td><td>${ms(x.median_response_ms)}</td><td>${bytes(x.bytes_down)}</td></tr>`).join('')}catch(err){document.getElementById('updated').textContent='Dashboard API unavailable'}}refresh();setInterval(refresh,2000);
</script></body></html>'''


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return DASHBOARD_HTML


@app.get("/api/status")
async def api_status() -> dict[str, Any]:
    paths = await proxy_controller.path_status()
    return {
        "proxy_listening": proxy_server is not None,
        "proxy_host": PROXY_HOST,
        "proxy_port": PROXY_PORT,
        "dashboard_host": DASHBOARD_HOST,
        "dashboard_port": DASHBOARD_PORT,
        "vps_host": proxy_controller.vps_host,
        "vps_port": proxy_controller.vps_port,
        "paths": paths,
        "route_stats": [store.route_summary("direct"), store.route_summary("vps")],
        "startup_error": startup_error,
    }


@app.get("/api/events")
async def api_events(limit: int = 40) -> dict[str, Any]:
    return {"events": store.recent_events(max(1, min(limit, 100)))}


@app.get("/api/domains")
async def api_domains() -> dict[str, Any]:
    return {"domains": store.all_domain_summaries()}


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "proxy_listening": proxy_server is not None}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=DASHBOARD_HOST, port=DASHBOARD_PORT, reload=False)
