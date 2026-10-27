#!/usr/bin/env bash
# ==============================================================================
# Kovanica Testnet (Chain 4) — Ingress & Reverse Proxy Setup (Nginx + Certbot)
# Usage:
#   sudo bash setup-nginx.sh seed1 [email]
#   sudo bash setup-nginx.sh seed2 [email]
#   sudo bash setup-nginx.sh seed3 [email]
# ==============================================================================
set -euo pipefail

NODE_ID="${1:-}"
EMAIL="${2:-kovanicaprotokol@gmail.com}"

if [[ -z "$NODE_ID" || ! "$NODE_ID" =~ ^(seed1|seed2|seed3)$ ]]; then
    echo "Usage: sudo bash $0 <seed1|seed2|seed3> [certbot_email]"
    exit 1
fi

echo "==> [1/6] Preparing system dependencies on $NODE_ID..."
export DEBIAN_FRONTEND=noninteractive

# Stop and disable conflicting web servers if present
echo "Stopping any existing processes listening on ports 80 and 443..."
systemctl stop caddy apache2 || true
systemctl disable caddy apache2 || true
pkill -9 -f caddy || true
fuser -k 80/tcp || true
fuser -k 443/tcp || true

apt-get update -y
apt-get install -y nginx certbot python3-certbot-nginx curl ufw

echo "==> [2/6] Configuring firewall rules (80, 443, 8000, 8001)..."
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw allow 8000/tcp || true
ufw allow 8001/tcp || true
ufw status || true

echo "==> [3/6] Setting up webroot directory for Let's Encrypt ACME challenges..."
mkdir -p /var/www/html/.well-known/acme-challenge
chown -R www-data:www-data /var/www/html
mkdir -p /etc/nginx/snippets

# Copy CORS snippet
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/nginx/cors.conf" /etc/nginx/snippets/kovanica-cors.conf

echo "==> [4/6] Issuing SSL certificates via Certbot for $NODE_ID..."

DOMAINS=""
case "$NODE_ID" in
    seed1)
        DOMAINS="-d seed1.kovanica.online"
        ;;
    seed2)
        DOMAINS="-d seed2.kovanica.online"
        ;;
    seed3)
        DOMAINS="-d seed3.kovanica.online"
        ;;
esac

# Create minimal bootstrap HTTP config if certs don't exist yet
PRIMARY_DOMAIN="${NODE_ID}.kovanica.online"
if [ ! -d "/etc/letsencrypt/live/$PRIMARY_DOMAIN" ]; then
    echo "Configuring temporary HTTP server for ACME challenge..."
    cat > "/etc/nginx/sites-available/bootstrap-$NODE_ID.conf" <<EOF
server {
    listen 80 default_server;
    listen [::]:80;
    server_name _;
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    location / {
        return 200 "Kovanica ACME bootstrap\n";
    }
}
EOF
    rm -f /etc/nginx/sites-enabled/default
    ln -sf "/etc/nginx/sites-available/bootstrap-$NODE_ID.conf" /etc/nginx/sites-enabled/
    nginx -t
    systemctl reload nginx || systemctl restart nginx

    echo "Running certbot for $DOMAINS..."
    certbot certonly --webroot -w /var/www/html \
        $DOMAINS \
        --agree-tos \
        --non-interactive \
        --no-eff-email \
        -m "$EMAIL" || {
            echo "Certbot failed with webroot. Retrying in standalone mode..."
            systemctl stop nginx
            certbot certonly --standalone \
                $DOMAINS \
                --agree-tos \
                --non-interactive \
                --no-eff-email \
                -m "$EMAIL"
            systemctl start nginx
        }
    rm -f "/etc/nginx/sites-enabled/bootstrap-$NODE_ID.conf"
    rm -f "/etc/nginx/sites-available/bootstrap-$NODE_ID.conf"
fi

# Ensure options-ssl-nginx.conf and ssl-dhparams.pem exist
if [ ! -f /etc/letsencrypt/options-ssl-nginx.conf ]; then
    curl -sS https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf > /etc/letsencrypt/options-ssl-nginx.conf
fi
if [ ! -f /etc/letsencrypt/ssl-dhparams.pem ]; then
    curl -sS https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem > /etc/letsencrypt/ssl-dhparams.pem
fi

echo "==> [5/6] Deploying production Nginx configuration for $NODE_ID..."
cp "$SCRIPT_DIR/nginx/$NODE_ID.conf" "/etc/nginx/sites-available/$NODE_ID.conf"
ln -sf "/etc/nginx/sites-available/$NODE_ID.conf" "/etc/nginx/sites-enabled/$NODE_ID.conf"

nginx -t
systemctl reload nginx

echo "==> [6/6] Verifying local endpoints on $NODE_ID..."
echo -n "Checking local node RPC health: "
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8545/health || echo "FAILED"

if [ "$NODE_ID" == "seed3" ]; then
    echo -n "Checking local faucet health: "
    curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3000/health || echo "FAILED"
fi

echo "==> Ingress successfully configured for $NODE_ID!"
