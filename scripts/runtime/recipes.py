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
