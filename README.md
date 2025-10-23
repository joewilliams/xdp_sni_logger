## XDP SNI Logger

### Building and running
```
$ go generate && go build && sudo ./xdp_sni_logger lo
{"time":"2025-10-22T20:45:06.473415304-07:00","level":"INFO","msg":"looking for SNIs","iface":"lo"}
{"time":"2025-10-22T20:45:10.616986825-07:00","level":"INFO","msg":"got sni","sni":"joetest123.com"}
```

If you have a local nginx or similar webserver running you can test with `curl`.
```
$ curl -k --resolve joetest123.com:443:127.0.0.1 https://joetest123.com
```

Important bits of the nginx config:
```
listen 443 ssl default_server;
listen [::]:443 ssl default_server;

ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

server_name joetest123.com;
```

![](https://github.com/user-attachments/assets/7c775dbd-9af7-45fa-89e4-dd105245fc26)