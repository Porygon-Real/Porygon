"""How each monitored image is started, health-checked, driven and administered.

Every value here is a start-up recipe, not a measurement. Credentials are
throwaway values for disposable, internet-less containers and are recorded in
the run record. Any image-specific fix applied during collection is appended to
that image's "fixes" list (with the source) so the recipe stays the record.
"""
from __future__ import annotations

from typing import Any

THROWAWAY_PASSWORD = "porygon-runtime-throwaway-pw"


def tcp_http_check(port: int, path: str = "/") -> str:
    """Healthcheck for images without curl/wget: a raw HTTP request through bash's /dev/tcp."""
    return (f"bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port} && printf \"GET {path} HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n\" >&3 "
            f"&& head -n 1 <&3 | grep -qE \" [234][0-9][0-9] \"'")


def curl_check(port: int, path: str = "/") -> str:
    return f"curl -fsS -o /dev/null http://127.0.0.1:{port}{path}"


def wget_check(port: int, path: str = "/") -> str:
    """Healthcheck for busybox/Alpine images, which ship wget but neither curl nor bash."""
    return f"wget -q -O /dev/null http://127.0.0.1:{port}{path}"


NODE_SERVER = "require('http').createServer((q,s)=>{s.end('ok '+Date.now()+'\\n')}).listen(3000,'0.0.0.0')"
RUBY_SERVER = ('srv=TCPServer.new("0.0.0.0",4567); loop { c=srv.accept; c.gets; '
               'c.print "HTTP/1.1 200 OK\\r\\nContent-Length: 3\\r\\nConnection: close\\r\\n\\r\\nok\\n"; c.close }')
PERL_SERVER = (
    "use IO::Socket::INET; $s=IO::Socket::INET->new(LocalAddr=>'0.0.0.0',LocalPort=>5000,Listen=>8,"
    "ReuseAddr=>1,Proto=>'tcp') or die $!; while(my $c=$s->accept()){ my $b=''; $c->recv($b,1024); "
    "print $c \"HTTP/1.1 200 OK\\r\\nContent-Length: 3\\r\\nConnection: close\\r\\n\\r\\nok\\n\"; close $c; }"
)
GO_SOURCE = '''package main

import (
\t"fmt"
\t"net/http"
\t"time"
)

func main() {
\thttp.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "ok %d\\n", time.Now().Unix()) })
\thttp.ListenAndServe("0.0.0.0:8080", nil)
}
'''

# key: tag, port, env, cmd, health, driver, admin (argv list, run without a shell),
# log (in-container command or "docker_logs"), user_service (True when the image
# drops root for its main process), paths (HTTP driver paths), sidecar (optional).
RECIPES: dict[str, dict[str, Any]] = {
    "redis": {"tag": "redis:latest", "port": 6379, "health": "redis-cli ping", "driver": "redis",
              "admin": ["redis-cli", "INFO", "server"], "log": "docker_logs"},
    "memcached": {"tag": "memcached:latest", "port": 11211, "driver": "memcached",
                  "health": "bash -c 'exec 3<>/dev/tcp/127.0.0.1/11211 && printf \"version\\r\\n\" >&3 && head -c 7 <&3 | grep -q VERSION'",
                  "admin": ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/11211; printf 'stats\\r\\nquit\\r\\n' >&3; cat <&3"],
                  "log": "docker_logs"},
    "httpd": {"tag": "httpd:latest", "port": 80, "driver": "http", "health": tcp_http_check(80),
              "admin": ["httpd", "-t"], "log": "docker_logs"},
    "traefik": {"tag": "traefik:latest", "port": 8080, "driver": "http", "paths": ["/ping", "/api/overview", "/api/rawdata"],
                "cmd": ["--api.insecure=true", "--ping=true", "--entrypoints.web.address=:80"],
                "health": "traefik healthcheck --ping", "admin": ["traefik", "version"], "log": "docker_logs"},
    "rabbitmq": {"tag": "rabbitmq:latest", "port": 5672, "driver": "amqp",
                 "health": "rabbitmq-diagnostics -q ping", "admin": ["rabbitmqctl", "status"],
                 "log": "docker_logs", "start_period": 90},
    "mariadb": {"tag": "mariadb:latest", "port": 3306, "driver": "mysql",
                "env": {"MARIADB_ROOT_PASSWORD": THROWAWAY_PASSWORD, "MARIADB_DATABASE": "porygon_rt"},
                "health": "healthcheck.sh --connect --innodb_initialized",
                "admin": ["mariadb-admin", "-uroot", f"-p{THROWAWAY_PASSWORD}", "status"],
                "log": "docker_logs", "start_period": 90},
    "mysql": {"tag": "mysql:8.4", "port": 3306, "driver": "mysql",
              "env": {"MYSQL_ROOT_PASSWORD": THROWAWAY_PASSWORD, "MYSQL_DATABASE": "porygon_rt"},
              "health": f"mysqladmin ping -h 127.0.0.1 -uroot -p{THROWAWAY_PASSWORD}",
              "admin": ["mysqladmin", "-uroot", f"-p{THROWAWAY_PASSWORD}", "status"],
              "log": "docker_logs", "start_period": 120},
    "mongo": {"tag": "mongo:latest", "port": 27017, "driver": "mongo",
              "health": "mongosh --quiet --eval 'db.runCommand({ping:1}).ok' | grep -q 1",
              "admin": ["mongosh", "--quiet", "--eval", "JSON.stringify(db.serverStatus().connections)"],
              "log": "docker_logs", "start_period": 60},
    "tomcat": {"tag": "tomcat:latest", "port": 8080, "driver": "http", "health": tcp_http_check(8080),
               "admin": ["catalina.sh", "version"], "log": "docker_logs", "start_period": 60},
    "php74": {"tag": "php:7.4-apache", "port": 80, "driver": "http", "paths": ["/", "/index.php"],
              "cmd": ["bash", "-c", "echo '<?php echo date(\"c\"), \"\\n\";' > /var/www/html/index.php && exec apache2-foreground"],
              "health": tcp_http_check(80, "/index.php"), "admin": ["apachectl", "-t"],
              "log": "docker_logs"},
    "wordpress": {"tag": "wordpress:latest", "port": 80, "driver": "http", "paths": ["/", "/wp-login.php"],
                  "env": {"WORDPRESS_DB_HOST": "db", "WORDPRESS_DB_USER": "root",
                          "WORDPRESS_DB_PASSWORD": THROWAWAY_PASSWORD, "WORDPRESS_DB_NAME": "wordpress"},
                  "sidecar": {"tag": "mariadb:latest", "alias": "db",
                              "env": {"MARIADB_ROOT_PASSWORD": THROWAWAY_PASSWORD, "MARIADB_DATABASE": "wordpress"},
                              "health": "healthcheck.sh --connect --innodb_initialized"},
                  "health": tcp_http_check(80, "/wp-login.php"), "admin": ["apachectl", "-t"],
                  "log": "docker_logs", "start_period": 90},
    "drupal": {"tag": "drupal:latest", "port": 80, "driver": "http", "paths": ["/", "/core/install.php"],
               "health": tcp_http_check(80, "/core/install.php"), "admin": ["apachectl", "-t"],
               "log": "docker_logs", "start_period": 60},
    "nextcloud": {"tag": "nextcloud:latest", "port": 80, "driver": "http", "paths": ["/status.php", "/login"],
                  "env": {"SQLITE_DATABASE": "nextcloud", "NEXTCLOUD_ADMIN_USER": "admin",
                          "NEXTCLOUD_ADMIN_PASSWORD": THROWAWAY_PASSWORD,
                          "NEXTCLOUD_TRUSTED_DOMAINS": "127.0.0.1 localhost"},
                  "health": tcp_http_check(80, "/status.php"), "admin": ["php", "/var/www/html/occ", "status"],
                  "admin_user": "www-data", "log": "docker_logs", "start_period": 240},
    "ghost": {"tag": "ghost:latest", "port": 2368, "driver": "http", "paths": ["/", "/ghost/api/admin/site/"],
              "env": {"NODE_ENV": "development", "url": "http://127.0.0.1:2368"},
              "health": "node -e \"require('http').get('http://127.0.0.1:2368/',r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1))\"",
              "admin": ["node", "--version"], "log": "docker_logs", "start_period": 120},
    "python-latest": {"tag": "python:latest", "port": 8000, "driver": "http", "cmd": ["python", "-m", "http.server", "8000"],
                      "health": curl_check(8000), "admin": ["python", "-m", "pip", "list"], "log": "docker_logs"},
    "python-3.8": {"tag": "python:3.8", "port": 8000, "driver": "http", "cmd": ["python", "-m", "http.server", "8000"],
                   "health": curl_check(8000), "admin": ["python", "-m", "pip", "list"], "log": "docker_logs"},
    "python-3.6": {"tag": "python:3.6", "port": 8000, "driver": "http", "cmd": ["python", "-m", "http.server", "8000"],
                   "health": curl_check(8000), "admin": ["python", "-m", "pip", "list"], "log": "docker_logs"},
    "node-22": {"tag": "node:22", "port": 3000, "driver": "http", "cmd": ["node", "-e", NODE_SERVER],
                "health": curl_check(3000), "admin": ["npm", "ls", "-g", "--depth=0"], "log": "docker_logs"},
    "node-16": {"tag": "node:16", "port": 3000, "driver": "http", "cmd": ["node", "-e", NODE_SERVER],
                "health": curl_check(3000), "admin": ["npm", "ls", "-g", "--depth=0"], "log": "docker_logs"},
    "temurin-21": {"tag": "eclipse-temurin:21", "port": 8000, "driver": "http",
                   "cmd": ["jwebserver", "-b", "0.0.0.0", "-p", "8000", "-d", "/opt"],
                   "health": tcp_http_check(8000), "admin": ["java", "-version"], "log": "docker_logs"},
    "golang": {"tag": "golang:latest", "port": 8080, "driver": "http", "cmd": ["go", "run", "/src/main.go"],
               "env": {"GOTOOLCHAIN": "local", "GOFLAGS": "-mod=mod"}, "mount_go_source": True,
               "health": curl_check(8080), "admin": ["go", "version"], "log": "docker_logs", "start_period": 120},
    "ruby": {"tag": "ruby:latest", "port": 4567, "driver": "http", "cmd": ["ruby", "-rsocket", "-e", RUBY_SERVER],
             "health": curl_check(4567), "admin": ["gem", "list", "--local"], "log": "docker_logs"},

    # ---------------------------------------------------------------- batch 2
    # A held-out set of 22 further images, run through the identical protocol.
    # Chosen to cover GNU coreutils-single images (mysql:9 and the three UBI 9
    # images), busybox/Alpine images, and service types batch 1 did not include.
    "nginx": {"tag": "nginx:1.27", "port": 80, "driver": "http", "health": curl_check(80),
              "admin": ["nginx", "-t"], "log": "docker_logs"},
    "caddy": {"tag": "caddy:2", "port": 80, "driver": "http", "health": curl_check(80),
              "admin": ["caddy", "version"], "log": "docker_logs"},
    "postgres-16": {"tag": "postgres:16", "port": 5432, "driver": "postgres",
                    "env": {"POSTGRES_USER": "postgres", "POSTGRES_PASSWORD": THROWAWAY_PASSWORD,
                            "POSTGRES_DB": "porygon_rt"},
                    "health": "pg_isready -U postgres -d porygon_rt",
                    "admin": ["psql", "-U", "postgres", "-d", "porygon_rt", "-tAc", "select version()"],
                    "log": "docker_logs", "start_period": 60},
    "valkey": {"tag": "valkey/valkey:8", "port": 6379, "driver": "redis", "health": "valkey-cli ping",
               "admin": ["valkey-cli", "INFO", "server"], "log": "docker_logs"},
    "influxdb": {"tag": "influxdb:2", "port": 8086, "driver": "http", "paths": ["/ping", "/health"],
                 "env": {"DOCKER_INFLUXDB_INIT_MODE": "setup", "DOCKER_INFLUXDB_INIT_USERNAME": "porygon",
                         "DOCKER_INFLUXDB_INIT_PASSWORD": THROWAWAY_PASSWORD,
                         "DOCKER_INFLUXDB_INIT_ORG": "porygon-rt", "DOCKER_INFLUXDB_INIT_BUCKET": "porygon_rt"},
                 "health": curl_check(8086, "/health"),
                 "admin": ["influx", "ping", "--host", "http://127.0.0.1:8086"],
                 "log": "docker_logs", "start_period": 60},
    "couchdb": {"tag": "couchdb:3", "port": 5984, "driver": "http", "paths": ["/", "/_up"],
                "env": {"COUCHDB_USER": "admin", "COUCHDB_PASSWORD": THROWAWAY_PASSWORD},
                "health": curl_check(5984, "/_up"),
                "admin": ["curl", "-fsS", "-u", f"admin:{THROWAWAY_PASSWORD}",
                          "http://127.0.0.1:5984/_node/_local/_system"],
                "fixes": ["admin command: /opt/couchdb/bin/weatherreport exits 127 because the image ships no "
                          "escript; replaced with the _node/_local/_system admin endpoint, CouchDB's documented "
                          "server-status call, through the curl the image ships"],
                "log": "docker_logs", "start_period": 60},
    "prometheus": {"tag": "prom/prometheus:latest", "port": 9090, "driver": "http",
                   "paths": ["/-/healthy", "/-/ready", "/api/v1/query?query=up"],
                   "health": wget_check(9090, "/-/healthy"),
                   "admin": ["promtool", "check", "config", "/etc/prometheus/prometheus.yml"],
                   "log": "docker_logs"},
    "grafana": {"tag": "grafana/grafana:latest", "port": 3000, "driver": "http",
                "paths": ["/api/health", "/login"], "health": wget_check(3000, "/api/health"),
                "admin": ["grafana", "cli", "plugins", "ls"], "log": "docker_logs", "start_period": 60},
    "consul": {"tag": "hashicorp/consul:latest", "port": 8500, "driver": "http",
               "cmd": ["agent", "-dev", "-client", "0.0.0.0"],
               "paths": ["/v1/status/leader", "/v1/agent/self", "/v1/catalog/services"],
               "health": "consul members", "admin": ["consul", "info"], "log": "docker_logs"},
    "mosquitto": {"tag": "eclipse-mosquitto:2", "port": 1883, "driver": "mqtt",
                  "cmd": ["mosquitto", "-c", "/mosquitto-no-auth.conf"],
                  "health": "mosquitto_pub -h 127.0.0.1 -t porygon/health -m ok",
                  "admin": ["mosquitto_sub", "-h", "127.0.0.1", "-t", "$SYS/broker/uptime", "-C", "1", "-W", "15"],
                  "log": "docker_logs"},
    "registry": {"tag": "registry:2", "port": 5000, "driver": "http", "paths": ["/v2/", "/v2/_catalog"],
                 "health": wget_check(5000, "/v2/"),
                 "admin": ["registry", "--version"],
                 "fixes": ["admin command: registry 2.8.3 offers only serve and garbage-collect, and "
                           "garbage-collect --dry-run exits 1 on an empty registry (\"Path not found: "
                           "/docker/registry/v2/repositories\"); replaced with the image's own registry CLI "
                           "version call, as for batch 1's runtime images"],
                 "log": "docker_logs"},
    "gitea": {"tag": "gitea/gitea:latest", "port": 3000, "driver": "http", "paths": ["/api/healthz", "/"],
              "env": {"USER_UID": "1000", "USER_GID": "1000", "GITEA__database__DB_TYPE": "sqlite3",
                      "GITEA__database__PATH": "/data/gitea/gitea.db",
                      "GITEA__security__INSTALL_LOCK": "true"},
              "health": wget_check(3000, "/api/healthz"), "admin": ["gitea", "--version"],
              "log": "docker_logs", "start_period": 90},
    "nats": {"tag": "nats:alpine", "port": 4222, "driver": "nats", "cmd": ["-m", "8222"],
             "health": wget_check(8222, "/healthz"),
             "admin": ["wget", "-q", "-O-", "http://127.0.0.1:8222/varz"], "log": "docker_logs"},
    "php83": {"tag": "php:8.3-apache", "port": 80, "driver": "http", "paths": ["/", "/index.php"],
              "cmd": ["bash", "-c", "echo '<?php echo date(\"c\"), \"\\n\";' > /var/www/html/index.php && exec apache2-foreground"],
              "health": tcp_http_check(80, "/index.php"), "admin": ["apachectl", "-t"], "log": "docker_logs"},
    "mysql-9": {"tag": "mysql:9", "port": 3306, "driver": "mysql",
                "env": {"MYSQL_ROOT_PASSWORD": THROWAWAY_PASSWORD, "MYSQL_DATABASE": "porygon_rt"},
                "health": f"mysqladmin ping -h 127.0.0.1 -uroot -p{THROWAWAY_PASSWORD}",
                "admin": ["mysqladmin", "-uroot", f"-p{THROWAWAY_PASSWORD}", "status"],
                "log": "docker_logs", "start_period": 120},
    "ubi9-httpd": {"tag": "registry.access.redhat.com/ubi9/httpd-24", "port": 8080, "driver": "http",
                   "cmd": ["bash", "-c", "printf 'ok\\n' > /var/www/html/index.html && exec /usr/bin/run-httpd"],
                   "health": curl_check(8080), "admin": ["httpd", "-t"], "log": "docker_logs",
                   "fixes": ["start command: the image's DocumentRoot /var/www/html ships empty, so httpd answered "
                             "403 (\"No matching DirectoryIndex\") and the container never became healthy; an "
                             "index.html is written before exec, the same pattern as batch 1's php:7.4-apache "
                             "recipe. /var/www/html is owned by the image's own uid 1001"],
                   "start_period": 60},
    "ubi9-nginx": {"tag": "registry.access.redhat.com/ubi9/nginx-124", "port": 8080, "driver": "http",
                   "cmd": ["bash", "-c", "printf 'ok\\n' > /opt/app-root/src/index.html && "
                                         "exec nginx -g 'daemon off;'"],
                   "health": curl_check(8080), "admin": ["nginx", "-t"], "log": "docker_logs",
                   "fixes": ["start command: the image's default CMD only prints the s2i usage text, and its "
                             "root /opt/app-root/src ships without an index, so Red Hat's documented "
                             "`nginx -g \"daemon off;\"` start is used with an index.html written first, as for "
                             "ubi9-httpd"],
                   "start_period": 60},
    "ubi9-python": {"tag": "registry.access.redhat.com/ubi9/python-312", "port": 8000, "driver": "http",
                    "cmd": ["python3", "-m", "http.server", "8000"], "health": curl_check(8000),
                    "admin": ["python3", "-m", "pip", "list"], "log": "docker_logs"},
    "node-20-alpine": {"tag": "node:20-alpine", "port": 3000, "driver": "http",
                       "cmd": ["node", "-e", NODE_SERVER], "health": wget_check(3000),
                       "admin": ["npm", "ls", "-g", "--depth=0"], "log": "docker_logs"},
    "python-3.12-alpine": {"tag": "python:3.12-alpine", "port": 8000, "driver": "http",
                           "cmd": ["python", "-m", "http.server", "8000"], "health": wget_check(8000),
                           "admin": ["python", "-m", "pip", "list"], "log": "docker_logs"},
    "ruby-3.3-alpine": {"tag": "ruby:3.3-alpine", "port": 4567, "driver": "http",
                        "cmd": ["ruby", "-rsocket", "-e", RUBY_SERVER], "health": wget_check(4567),
                        "admin": ["gem", "list", "--local"], "log": "docker_logs"},
    "perl": {"tag": "perl:5.40", "port": 5000, "driver": "http", "cmd": ["perl", "-e", PERL_SERVER],
             "health": tcp_http_check(5000), "admin": ["perl", "-v"], "log": "docker_logs"},

    # Batch 2 reserves, used in this order when a primary cannot be run.
    "varnish": {"tag": "varnish:7", "port": 80, "driver": "http",
                "env": {"VARNISH_BACKEND_HOST": "backend", "VARNISH_BACKEND_PORT": "80"},
                "sidecar": {"tag": "nginx:1.27", "alias": "backend", "health": curl_check(80)},
                "health": "varnishadm status", "admin": ["varnishadm", "status"], "log": "docker_logs",
                "start_period": 60},
    "memcached-alpine": {"tag": "memcached:1.6-alpine", "port": 11211, "driver": "memcached",
                         "health": "sh -c 'printf \"version\\r\\n\" | nc -w 2 127.0.0.1 11211 | grep -q VERSION'",
                         "admin": ["sh", "-c", "printf 'stats\\r\\nquit\\r\\n' | nc -w 2 127.0.0.1 11211"],
                         "log": "docker_logs"},
    "httpd-alpine": {"tag": "httpd:2.4-alpine", "port": 80, "driver": "http", "health": wget_check(80),
                     "admin": ["httpd", "-t"], "log": "docker_logs"},
    "redis-alpine": {"tag": "redis:7.4-alpine", "port": 6379, "driver": "redis", "health": "redis-cli ping",
                     "admin": ["redis-cli", "INFO", "server"], "log": "docker_logs"},
    "vault": {"tag": "hashicorp/vault:latest", "port": 8200, "driver": "http",
              "cmd": ["server", "-dev"],
              "env": {"SKIP_SETCAP": "1", "VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
                      "VAULT_ADDR": "http://127.0.0.1:8200"},
              "paths": ["/v1/sys/health", "/v1/sys/seal-status"],
              "health": wget_check(8200, "/v1/sys/health"), "admin": ["vault", "status"],
              "log": "docker_logs"},
    "rabbitmq-3-mgmt": {"tag": "rabbitmq:3-management-alpine", "port": 5672, "driver": "amqp",
                        "health": "rabbitmq-diagnostics -q ping", "admin": ["rabbitmqctl", "status"],
                        "log": "docker_logs", "start_period": 90},
    "adminer": {"tag": "adminer:latest", "port": 8080, "driver": "http", "health": wget_check(8080),
                "admin": ["php", "-v"], "log": "docker_logs"},
    "mariadb-11": {"tag": "mariadb:11", "port": 3306, "driver": "mysql",
                   "env": {"MARIADB_ROOT_PASSWORD": THROWAWAY_PASSWORD, "MARIADB_DATABASE": "porygon_rt"},
                   "health": "healthcheck.sh --connect --innodb_initialized",
                   "admin": ["mariadb-admin", "-uroot", f"-p{THROWAWAY_PASSWORD}", "status"],
                   "log": "docker_logs", "start_period": 90},

}

PILOT = "redis"
# Queue order for the batch (pilot excluded); runtimes interleaved with services.
BATCH_ORDER = [
    "memcached", "httpd", "traefik", "python-latest", "rabbitmq", "node-22", "php74", "ruby",
    "tomcat", "python-3.8", "mysql", "node-16", "ghost", "temurin-21", "drupal", "python-3.6",
    "mongo", "golang", "nextcloud", "mariadb", "wordpress",
]
# Images whose sidecar shares a monitored digest must never overlap with that image's run.
CONFLICTS = {"wordpress": {"mariadb"}, "mariadb": {"wordpress"}}

# Batch 2 queue order (held-out set): coreutils images and runtimes interleaved
# with the services, so a problem with one family cannot cluster at one end.
BATCH2_ORDER = [
    "nginx", "valkey", "prometheus", "mysql-9", "caddy", "postgres-16", "ubi9-httpd", "node-20-alpine",
    "influxdb", "consul", "ubi9-nginx", "python-3.12-alpine", "couchdb", "mosquitto", "ubi9-python",
    "ruby-3.3-alpine", "grafana", "registry", "php83", "perl", "gitea", "nats",
]
# Reserves, tried in this order when a primary cannot be run.
BATCH2_RESERVES = [
    "varnish", "memcached-alpine", "httpd-alpine", "redis-alpine", "vault", "rabbitmq-3-mgmt",
    "adminer", "mariadb-11",
]
# The four images built on a GNU coreutils multicall binary (batch 1's mysql finding).
BATCH2_COREUTILS = ["mysql-9", "ubi9-httpd", "ubi9-nginx", "ubi9-python"]
