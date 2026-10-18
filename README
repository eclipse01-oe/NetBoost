# NetBoost v0.1 — live adaptive browser routing

This is the first working product slice for the existing NetBoost project. It adds:

- A localhost HTTP proxy for browser HTTP requests and HTTPS `CONNECT` tunnels.
- Two real paths: `direct` (the laptop's normal network route) and `vps` (through the existing WireGuard tunnel to the Oracle VPS).
- A route selector that remembers recent live observations per hostname and across sites.
- Recovery attempts: connection setup failures try the alternative route; HTTPS tunnels can replay the initial TLS client data through the alternative if the selected route does not return its first server data within the configured timeout; safe bodyless HTTP `GET`/`HEAD`/`OPTIONS` requests may be retried before any response is shown.
- A local dashboard at `http://127.0.0.1:8000` showing route readiness, real decisions, failures, and recent observations.

The proxy is intentionally local-only (`127.0.0.1:8888`) and the VPS relay binds only to `10.8.0.1:8765`. Do not expose the relay on the VPS public address.

## Important architecture prerequisite: split-tunnel WireGuard

The existing client config used `AllowedIPs = 0.0.0.0/0`. While that is active, the laptop's default route uses WireGuard, so a proxy connection labelled `direct` would still be routed through the VPS. NetBoost explicitly refuses browser requests in that state rather than show misleading results.

We need WireGuard up for the VPS route, but the laptop's *default* internet route must remain on Wi-Fi/Ethernet. On the laptop, run:

```bash
cd ~/Desktop/NetBoost
sudo bash scripts/enable_split_tunnel.sh
```

This backs up `/etc/wireguard/wg0.conf` and changes the client peer's `AllowedIPs` to `10.8.0.0/24`. It does not change the VPS peer configuration and does not restart WireGuard for you. Then, on the **Ubuntu laptop only**, run:

```bash
sudo wg-quick down wg0
sudo wg-quick up wg0
ip -4 route get 1.1.1.1
ip -4 route get 10.8.0.1
```

Verify:

- `ip -4 route get 1.1.1.1` uses the physical network interface such as `wlo1`, not `wg0`.
- `ip -4 route get 10.8.0.1` uses `wg0`.

The client proxy resolves each hostname before route selection and uses that resolved IP for either route. This means VPS routing does not independently resolve the hostname and bypass AdGuard Home's DNS blocks. The existing PostUp DNS hook may continue sending DNS queries to AdGuard at `10.8.0.1`; this does not make the website's TCP connection use the VPS. If the tunnel does not come back up, restore the timestamped backup printed by the script and run `sudo wg-quick up wg0`.

**Never run the client split-tunnel script or the laptop `wg-quick down/up` commands on the VPS.**

## 1. Install the VPS relay

The relay is required for the `vps` route. It accepts requests only on the WireGuard address and allows only the WireGuard client source `10.8.0.2` through the firewall rule. The script uses the existing SSH key location and connects over WireGuard at `10.8.0.1`.

On the Ubuntu laptop, with WireGuard up, run:

```bash
cd ~/Desktop/NetBoost
bash scripts/deploy_vps_proxy.sh
```

If your key is somewhere else:

```bash
NETBOOST_SSH_KEY="$HOME/path/to/key" bash scripts/deploy_vps_proxy.sh
```

The script installs a systemd service called `netboost-vps-proxy` and uses port `8765` on `10.8.0.1` only. Check the service with:

```bash
ssh -i "$HOME/Downloads/netboost_vps_ssh.key" opc@10.8.0.1 'sudo systemctl --no-pager --full status netboost-vps-proxy'
```

If SSH is unavailable over the tunnel, do not disable firewall protections or expose port 8765 publicly. Resolve the WireGuard/SSH path first.

## 2. Put the files into the existing project

Extract/merge this package into `~/Desktop/NetBoost`, replacing only the matching scaffold files. It contains `app/main.py`, the new `app/routing/` package, `app/vps/main.py`, `requirements.txt`, and two scripts. It intentionally leaves `app/data_saver/main.py` and `app/wireguard/main.py` alone for the next milestones.

Install the existing app dependencies in the Python environment you use for NetBoost:

```bash
cd ~/Desktop/NetBoost
python -m pip install -r requirements.txt
```

Start NetBoost:

```bash
cd ~/Desktop/NetBoost
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open the dashboard at:

```text
http://127.0.0.1:8000
```

The dashboard must show **Direct route: Available** and **VPS route: Connected**. If Direct says `Not independent`, verify the split tunnel before browsing. If the VPS route is unavailable, verify that WireGuard is up and the server service is active.

## 3. Browse through the product

Use a separate Chrome profile so your ordinary browser session is untouched. This command picks an installed Chrome/Chromium executable and uses the NetBoost proxy:

```bash
BROWSER="$(command -v google-chrome || command -v google-chrome-stable || command -v chromium || command -v chromium-browser)"
if [ -z "$BROWSER" ]; then echo "Chrome/Chromium executable not found"; else "$BROWSER" --user-data-dir="$HOME/.config/netboost/chrome-profile" --proxy-server="http://127.0.0.1:8888" --no-first-run --new-window https://example.com; fi
```

Keep the dashboard open. Visit websites normally. The dashboard will show route choices and actual connection observations. Unknown sites start direct until enough live evidence exists; failed setup or first-response waits can trigger an alternative-route attempt. The selector uses a failure penalty and prefers direct when measurements are close to avoid the extra tunnel hop.

To stop the app, press `Ctrl+C` in the terminal running Uvicorn. Close the separate Chrome profile to stop its proxied traffic.

## Optional code tests

From the project directory, install the development-only test tools and run the local unit/integration tests:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

These local tests use simulated endpoints; they do not replace the live browsing test on your laptop and mobile network.

## What this version can and cannot do

- It routes **browser HTTP and HTTPS TCP traffic** for the browser profile configured to use the proxy. It does not control other applications, non-proxy browser traffic, or every UDP-based feature.
- It does not decrypt HTTPS or inspect page content. For HTTPS, it sees the destination hostname from `CONNECT`, tunnel setup latency, and the time from the browser's initial TLS data to the first server data. This is useful but is not exact page-load or first-paint time.
- A TLS connection that already exchanged server data cannot be transparently moved to another route. This version can try the alternate before TLS server data reaches the browser, or let the browser create a new connection later.
- Recovery does not manufacture bandwidth. E/EDGE may remain slow even when the chosen path is the most reliable available.
- Do not infer data savings or a speed improvement from the dashboard alone. This first milestone establishes routing and recovery behavior. The next milestone is to integrate the Data Saver module, then benchmark the whole system under ordinary and poor-network conditions.

## Safety/rollback

The dashboard and local proxy bind to loopback only. The relay is bound to `10.8.0.1`, with a firewall rule restricted to source `10.8.0.2`. Keep that restriction.

To stop the VPS relay:

```bash
ssh -i "$HOME/Downloads/netboost_vps_ssh.key" opc@10.8.0.1 'sudo systemctl disable --now netboost-vps-proxy'
```

To remove only the local browser proxy, stop Uvicorn and close the separate Chrome profile. The standard browser and existing AdGuard/WireGuard server configuration remain separate.
