
## Data Collection - WAF and Honeypots

```sh
# 8080:80 (WAF)
docker compose -f ./src/waf-honeypots/docker-compose.yml up -d
```

## Data ETL - Airflow (admin/admin)

```sh
# 8081
airflow webserver -p 8081 -D
airflow scheduler -D
```

## Data Visualisation - MISP (admin/@PxnhdAwiocQBXHS)

```sh
# 80:80, 443:443
docker compose -f ./src/misp/docker-compose.yaml up -d
```








```sh

# test
curl -I 'http://localhost/?param="><script>alert(1);</script>' --insecure
```
curl localhost?doc=/bin/ls
