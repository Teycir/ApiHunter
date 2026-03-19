# Real CVE Payload Fixtures

These fixtures combine live vulnerable lab captures and Exa-sourced upstream snapshots on **2026-03-19** for deterministic regression testing.

Capture sources (local lab endpoints):
- `http://127.0.0.1:18080/actuator/gateway/routes` -> `cve-2022-22947-body.json`
- `http://127.0.0.1:18848/nacos/v1/auth/users?pageNo=1&pageSize=1` -> `cve-2021-29442-body.json`
- `http://127.0.0.1:18851/nacos/v1/auth/users?pageNo=1&pageSize=1` -> `cve-2021-29441-baseline-body.json` (without spoofed UA)
- `http://127.0.0.1:18851/nacos/v1/auth/users?pageNo=1&pageSize=1` with `User-Agent: Nacos-Server` -> `cve-2021-29441-bypass-body.json`
- `http://127.0.0.1:19080/apisix/admin/routes` with `X-API-KEY: edd1c9f034335f136f87ad84b625c8f1` -> `cve-2020-13945-body.json`
- `http://127.0.0.1:19000/apisix/admin/migrate/export` -> `cve-2021-45232-body.json`
- `http://127.0.0.1:19000/actuator/gateway/routes` -> `nonmatch-apisix-dashboard-actuator-routes.html` (real non-match control)

Exa-sourced upstream snapshots (retrieved via curl) used as real-world fixture bodies:
- `https://raw.githubusercontent.com/apache/airflow/2.2.3/airflow/example_dags/example_passing_params_via_test_command.py` -> `cve-2022-24288-body.py` (vulnerable signal contains `{{ params.foo }}`)
- `https://raw.githubusercontent.com/apache/airflow/2.2.4/airflow/example_dags/example_passing_params_via_test_command.py` -> `nonmatch-cve-2022-24288-airflow-2.2.4-body.py` (patched control)

These fixtures are intentionally replayed through `wiremock` so tests stay stable and fast while still using real response data.
