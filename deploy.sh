#!/usr/bin/env bash
set -euo pipefail

: "${ROUTE_PORTAL_ADMIN_PASSWORD:?missing admin password}"

if ! id routeportal >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/route-portal --shell /usr/sbin/nologin routeportal
fi

install -d -o root -g root -m 0755 /opt/route-portal
install -d -o routeportal -g routeportal -m 0750 /var/lib/route-portal
install -d -o routeportal -g routeportal -m 0750 /var/lib/route-portal/public
install -o root -g root -m 0644 /tmp/app.py /opt/route-portal/app.py
if [ -f /tmp/logo.svg ]; then
    install -o root -g root -m 0644 /tmp/logo.svg /opt/route-portal/logo.svg
fi
install -o root -g root -m 0644 /tmp/route-portal.service /etc/systemd/system/route-portal.service
install -o root -g root -m 0644 /tmp/nginx.conf /etc/nginx/sites-available/route-portal
ln -sfn /etc/nginx/sites-available/route-portal /etc/nginx/sites-enabled/route-portal
rm -f /etc/nginx/sites-enabled/default

umask 077
printf '%s\n' \
    'ROUTE_PORTAL_DATA=/var/lib/route-portal' \
    'ROUTE_PORTAL_LISTEN=127.0.0.1' \
    'ROUTE_PORTAL_PORT=8080' \
    'ROUTE_PORTAL_ADMIN_USER=admin' \
    "ROUTE_PORTAL_ADMIN_PASSWORD=${ROUTE_PORTAL_ADMIN_PASSWORD}" \
    > /etc/route-portal.env

if [ -f /tmp/initial-routes.txt ]; then
python3 - <<'PY'
import ipaddress
from pathlib import Path

source = Path("/tmp/initial-routes.txt").read_text(encoding="utf-8-sig")
items = [item.strip() for item in source.replace(",", "\n").splitlines() if item.strip()]
networks = [ipaddress.ip_network(item, strict=False) for item in items]
output = "\n".join(str(item) for item in ipaddress.collapse_addresses(networks)) + "\n"
Path("/var/lib/route-portal/public/routes.txt").write_text(output, encoding="ascii")
PY
chown routeportal:routeportal /var/lib/route-portal/public/routes.txt
chmod 0640 /var/lib/route-portal/public/routes.txt
fi

nginx -t
systemctl daemon-reload
systemctl enable --now route-portal
systemctl reload nginx
rm -f /tmp/app.py /tmp/logo.svg /tmp/route-portal.service /tmp/nginx.conf \
    /tmp/initial-routes.txt /tmp/deploy.sh
