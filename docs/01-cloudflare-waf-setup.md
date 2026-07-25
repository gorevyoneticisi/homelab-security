# Cloudflare WAF Setup Guide

Complete guide for setting up Cloudflare WAF rules to protect your homelab behind Cloudflare proxy.

## Prerequisites

- Cloudflare account (free tier works)
- Domain added to Cloudflare
- DNS proxied (orange cloud enabled)

## WAF Custom Rules

Go to **Security** → **WAF** → **Custom rules** → **Create rule**

### Rule 1: Block Environment File Probes

```
Rule name: Block .env probes
When: http.request.uri.path contains "/.env"
Action: Block
```

**Why:** Attackers scan for `.env`, `.env.local`, `.env.production`, `.env.bak` files to steal secrets, API keys, and database credentials.

### Rule 2: Block Git Directory Probes

```
Rule name: Block .git probes
When: http.request.uri.path contains "/.git"
Action: Block
```

**Why:** `.git/config` and `.git/HEAD` exposure reveals repository URLs, branch names, and sometimes credentials.

### Rule 3: Block All PHP Paths (Node.js Apps)

```
Rule name: Block PHP paths
When: http.request.uri.path contains ".php"
Action: Block
```

**Why:** If your app is Node.js/Python/Go, no PHP should ever be served. PHP paths indicate exploitation attempts.

### Rule 4: Block WordPress Paths (Non-WordPress Apps)

```
Rule name: Block WP paths
When: http.request.uri.path contains "/wp-" or http.request.uri.path contains "/wplogin" or http.request.uri.path contains "/xmlrpc"
Action: Block
```

**Why:** WordPress brute force, XML-RPC amplification attacks, and plugin exploitation probes.

### Rule 5: Block Exploit Scanner Paths

```
Rule name: Block exploit scanners
When: http.request.uri.path contains "/vendor/phpunit" or http.request.uri.path contains "/laravel" or http.request.uri.path contains "/yii" or http.request.uri.path contains "/alfacgiapi" or http.request.uri.path contains "/ALFA_DATA"
Action: Block
```

**Why:** Known PHP framework exploit paths used by automated scanners.

### Rule 6: Block GraphQL/API Probing

```
Rule name: Block GraphQL probes
When: http.request.uri.path contains "/graphql" or http.request.uri.path contains "/api/gql"
Action: Block
```

**Why:** GraphQL introspection attacks and API enumeration attempts.

### Rule 7: Block Sensitive File Probes

```
Rule name: Block sensitive files
When: http.request.uri.path contains "/.htaccess" or http.request.uri.path contains "/.htpasswd" or http.request.uri.path contains "/config.json" or http.request.uri.path contains "/phpinfo"
Action: Block
```

**Why:** Apache config files, configuration files, and PHP info disclosure.

## Cloudflare Bot Fight Mode

Go to **Security** → **Bots** → **Bot Fight Mode**

- Toggle **ON**
- Toggle **Definitely automated** → **Block**
- Toggle **Likely automated** → **Managed Challenge**

**Why:** Catches bots with spoofed User-Agent strings that WAF path rules miss.

## Testing

After creating rules, test with:

```bash
# Should return 200
curl -s -o /dev/null -w "%{http_code}" -A "Mozilla/5.0" https://yourdomain.com/

# Should return 403 (blocked by WAF)
curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/.env
curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/.git/config
curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/wp-login.php
curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/xmlrpc.php
curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/test.php
```

## Rate Limiting (Paid Feature)

If you have Cloudflare Pro or higher, add rate limiting rules:

```
Rule 1: Block .env scanners
When: http.request.uri.path contains "/.env"
Action: Block for 1 hour

Rule 2: Block PHP backdoor scanners
When: http.request.uri.path contains ".php"
Action: Block for 1 hour

Rule 3: Block xmlrpc/eval-stdin exploits
When: http.request.uri contains "xmlrpc" or http.request.uri contains "eval-stdin"
Action: Block for 24 hours
```

## Free Tier Limitations

- 5 WAF Custom Rules (free tier)
- No Rate Limiting Rules (paid feature)
- Bot Fight Mode available (basic)
- No Advanced Bot Management (enterprise)

Prioritize your 5 rules based on your attack surface.
