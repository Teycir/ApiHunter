# Vulhub Lab Setup

This guide documents a reproducible Vulhub workflow for validating new CVE templates before committing real payload fixtures.

## Prerequisites

- Docker Engine + Docker Compose plugin
- `git`
- Local clone of Vulhub:
  - `git clone https://github.com/vulhub/vulhub.git`

## Standard Workflow

From the ApiHunter repo root:

```bash
# Start one scenario
docker compose -f vulhub/<product>/<cve>/docker-compose.yml up -d

# Check exposed ports/services
docker compose -f vulhub/<product>/<cve>/docker-compose.yml ps

# Stop and clean when done
docker compose -f vulhub/<product>/<cve>/docker-compose.yml down -v
```

Run one scenario at a time unless you intentionally remap ports.

## Priority CVE Labs (Ready In Upstream Vulhub)

The following are good next validation targets and are present in upstream `vulhub/vulhub` as of **March 19, 2026**.

```bash
# 1) Spring Security OAuth2 (CVE-2016-4977)
docker compose -f vulhub/spring/CVE-2016-4977/docker-compose.yml up -d
# -> http://127.0.0.1:8080

# 2) Spring Cloud Gateway (CVE-2022-22947)
docker compose -f vulhub/spring/CVE-2022-22947/docker-compose.yml up -d
# -> http://127.0.0.1:8080

# 3) Apache Airflow (CVE-2020-11978)
docker compose -f vulhub/airflow/CVE-2020-11978/docker-compose.yml up -d
# -> http://127.0.0.1:8080

# 4) Kibana (CVE-2018-17246)
docker compose -f vulhub/kibana/CVE-2018-17246/docker-compose.yml up -d
# -> http://127.0.0.1:5601

# 5) Metabase (CVE-2021-41277)
docker compose -f vulhub/metabase/CVE-2021-41277/docker-compose.yml up -d
# -> http://127.0.0.1:3000

# 6) Joomla (CVE-2023-23752)
docker compose -f vulhub/joomla/CVE-2023-23752/docker-compose.yml up -d
# -> http://127.0.0.1:8080

# 7) Superset (CVE-2023-27524)
docker compose -f vulhub/superset/CVE-2023-27524/docker-compose.yml up -d
# -> http://127.0.0.1:8088

# 8) TeamCity (CVE-2024-27198)
docker compose -f vulhub/teamcity/CVE-2024-27198/docker-compose.yml up -d
# -> http://127.0.0.1:8111

# 9) n8n (CVE-2025-68613)
docker compose -f vulhub/n8n/CVE-2025-68613/docker-compose.yml up -d
# -> http://127.0.0.1:5678

# 10) Nginx UI (CVE-2026-27944)
docker compose -f vulhub/nginx-ui/CVE-2026-27944/docker-compose.yml up -d
# -> http://127.0.0.1:9000
```

## Nacos Migration (From Custom Local Ports To Vulhub Compose)

Use Vulhub-native Nacos labs instead of custom local server references:

```bash
# CVE-2021-29441
docker compose -f vulhub/nacos/CVE-2021-29441/docker-compose.yml up -d
# target URL: http://127.0.0.1:8848/nacos

# CVE-2021-29442
docker compose -f vulhub/nacos/CVE-2021-29442/docker-compose.yml up -d
# target URL: http://127.0.0.1:8848/nacos
```

Both scenarios bind `8848`, so run them one at a time.

## Catalog Candidate Paths Not Found In Upstream Vulhub

The following paths were checked against `vulhub/vulhub` upstream on **March 19, 2026** and returned `404`:

- `minio/CVE-2021-41266/docker-compose.yml`
- `forgerock/CVE-2021-35464/docker-compose.yml`
- `sonarqube/CVE-2020-27986/docker-compose.yml`
- `gitlab/CVE-2021-22214/docker-compose.yml`

If you maintain an internal Vulhub fork that includes these scenarios, prefer your fork paths in local validation.

