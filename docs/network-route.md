# Network route (proxy and WireGuard)

## WireGuard for the whole app (recommended for Go Live in a restricted region)

Discord decides some features from the address of the gateway connection *and* the voice/video
media. A proxy only carries TCP, so voice and screen-share UDP would leave from your own address
while the session sits behind the proxy; that mismatch can make streams fail to load for viewers.
The WireGuard mode avoids it: Serein restarts inside a private network namespace whose only route
is your tunnel, so every connection (gateway, REST, voice, video) shares one address. The rest of the
computer keeps its normal connection.

In **Settings → Network → WireGuard**, choose the `.conf` from your VPN provider (Serein validates it
against an allow-list and keeps a private copy in `~/.config/serein/wireguard.conf`), then press
**Restart Serein**. The system asks for the administrator password (polkit) to create the namespace;
Serein itself never runs as root. Choose Direct (or another route) and restart to leave the tunnel.

It needs `wireguard-tools`, `iproute2`, `polkit` and the `serein-vpn` helper
(`packaging/linux/vpn`, installed to `/usr/local/libexec/serein-vpn`). The page offers to install
`wireguard-tools`. The namespace is `serein-vpn`; the interface is `wg-serein`.

Terminal and scripts (everything the page does is available here too):

```sh
serein-route vpn import wg.conf   # validate and keep the configuration (no root)
serein-route vpn start            # start Serein inside the tunnel (sudo, or SEREIN_VPN_PRIV=pkexec)
serein-route vpn host             # start Serein outside the tunnel
serein-route vpn status | stop    # tunnel state / remove the namespace
sudo /usr/local/libexec/serein-vpn run wg.conf -- curl -s https://ifconfig.me   # any command, as you
```

The proxy sections below still work for people without a WireGuard tunnel they can use this way.

## Proxy

**Settings → Network** configures this from the app: choose Direct, SOCKS5 or HTTP, enter the
address and port, optionally a login, then **Save** (and **Test connection**, which opens the Discord
gateway through the candidate route without signing in). The route is read when Serein starts, so the
page offers **Restart Serein** after a change. The login is kept in the OS credential store and only
used for the endpoint it was saved for; the file below never holds it (it carries a
`# credentials: keyring` marker instead). `SEREIN_PROXY`, when set, overrides the page, which then says so.

Serein can send its Discord traffic through a SOCKS5 or HTTP proxy. Set `SEREIN_PROXY` before
starting the app, or put the same URL on one line in `$XDG_CONFIG_HOME/serein/proxy`
(`~/.config/serein/proxy`). The environment variable wins over the file.

```sh
SEREIN_PROXY=socks5://127.0.0.1:1080 serein
SEREIN_PROXY=http://user:pass@proxy.example:8080 serein
SEREIN_PROXY=direct serein            # same as leaving it unset
```

| Scheme | Notes |
| --- | --- |
| `socks5://`, `socks5h://` | SOCKS5, no authentication or username/password. The proxy resolves names. |
| `http://` | HTTP `CONNECT` tunnel, optional Basic credentials. |

The host and port are required; a path, query or fragment is rejected. Credentials in the URL are
percent-decoded, bounded to 255 bytes, kept in zeroizing memory and never printed. A proxy file that
contains credentials must not be readable by group or others (`chmod 600`).

## What goes through the proxy

| Traffic | Routed |
| --- | --- |
| Gateway WebSocket (login session, presence, events) | Yes |
| REST API and attachment upload slots | Yes |
| Voice and screen-share signalling WebSockets | Yes |
| Avatar/CDN images and image-share downloads | Yes |
| Voice and stream media (UDP/RTP) | **No**, direct |
| Sign-in webview, system browser, notifications | **No** |
| External video and extension downloads | **No**: they pin DNS locally for private-network checks |

An extension that sets the REST-only `api_proxy` capability keeps priority for REST; the gateway,
CDN and voice still follow `SEREIN_PROXY`.

## Failure behaviour

The route is read once at startup. If the value cannot be parsed, every connection fails and a single
line is printed to stderr; there is never a fallback to a direct connection. If the proxy itself is
unreachable the usual reconnect/backoff applies. Remove the setting (or use `direct`) to go back.

## Checking a proxy without an account

```sh
SEREIN_PROXY=socks5://127.0.0.1:1080 \
  cargo run -p net-route --example probe -- 'wss://gateway.discord.gg/?v=10&encoding=json'
```

The probe opens the gateway WebSocket through the configured route and prints the opcode of the first
frame (`10`, Hello). It sends no credentials and signs in to nothing.

## Terms of service and account risk

Discord decides some features (for example regional restrictions) from the IP of the gateway
connection, so a proxy can change what a session is offered. Using a proxy or VPN to get around a
restriction can violate Discord's Terms of Service, and a login from an unexpected location can trigger
extra verification or account action. This feature only adds routing; it does not spoof, hide or alter
anything else about the client. Use it at your own risk.

## Example: a WireGuard tunnel for Serein only

`wireproxy` runs a WireGuard client in user space and exposes it as a local SOCKS5 proxy, so no root
or namespace is needed and the rest of the computer keeps its normal connection:

```ini
# ~/.config/serein/wireproxy.conf  (the [Interface]/[Peer] sections come from your provider's .conf)
[Interface]
PrivateKey = ...
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = ...
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0

[Socks5]
BindAddress = 127.0.0.1:1080
```

```sh
wireproxy -c ~/.config/serein/wireproxy.conf &
echo 'socks5://127.0.0.1:1080' > ~/.config/serein/proxy
serein
```

Voice media is not proxied, so calls keep the direct, low-latency path.
