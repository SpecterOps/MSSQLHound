# GitHub Actions CI: Integration Tests with Samba AD DC + SQL Server

## Context

MSSQLHound needs CI that validates all expected edges are created against a real AD environment. The integration test framework already handles AD object creation via LDAP, SQL setup/teardown, collector execution, and edge validation — we just need to provide the infrastructure.

**Architecture**: SQL Server installed on the runner host (via apt) + Samba AD DC in a Docker container. SQL Server is configured for AD auth via a keytab from `samba-tool`. The integration test framework (`TestIntegrationAll`) handles everything else.

## Network and domain config

| Setting | Value |
|---------|-------|
| Subnet | `10.2.0.0/20` |
| DC IP | `10.2.10.100` |
| SQL Server | On the runner host (localhost) |
| Domain FQDN | `MAYYHEM.COM` |
| NetBIOS | `MAYYHEM` |
| Admin account | `MAYYHEM\domainadmin` (sysadmin on SQL) |
| Password (all) | `password` |
| SQL auth mode | Mixed mode (Windows + SQL) |

## Files to create

- `.github/workflows/ci.yml` (new)

## Plan

### 1. Create `.github/workflows/ci.yml` with two jobs

**Job 1: `unit-tests`** — Fast validation of all edge creation logic
- `ubuntu-latest`, checkout, setup Go, `go test -v -count=1 ./...`

**Job 2: `integration-tests`** — Full pipeline against real AD + SQL Server on `ubuntu-22.04`

#### Step 1: Checkout + Setup Go

#### Step 2: Start Samba AD DC
```bash
docker network create --subnet=10.2.0.0/20 adnet

docker run -d --privileged \
  --name dc --hostname DC \
  --network adnet --ip 10.2.10.100 \
  -e REALM='MAYYHEM.COM' \
  -e DOMAIN='MAYYHEM' \
  -e ADMIN_PASS='password' \
  -e DNS_FORWARDER='8.8.8.8' \
  -p 389:389/tcp -p 389:389/udp \
  -p 636:636/tcp \
  -p 88:88/tcp -p 88:88/udp \
  -p 464:464/tcp -p 464:464/udp \
  diegogslomp/samba-ad-dc
```

#### Step 3: Wait for Samba DC readiness
Poll `samba-tool domain info` up to 60 attempts / 2s.

#### Step 4: Create domainadmin user + SQL Server service account + keytab
```bash
# Create domainadmin user
docker exec dc samba-tool user create domainadmin 'password' --use-username-as-cn
docker exec dc samba-tool group addmembers "Domain Admins" domainadmin

# Create SQL Server service account
docker exec dc samba-tool user create sqlsvc 'password' --use-username-as-cn
HOSTNAME=$(hostname)
docker exec dc samba-tool spn add MSSQLSvc/${HOSTNAME}.mayyhem.com sqlsvc
docker exec dc samba-tool spn add MSSQLSvc/${HOSTNAME}.mayyhem.com:1433 sqlsvc

# Export keytab
docker exec dc samba-tool domain exportkeytab /tmp/mssql.keytab --principal=sqlsvc
docker exec dc samba-tool domain exportkeytab /tmp/mssql.keytab \
  --principal=MSSQLSvc/${HOSTNAME}.mayyhem.com
docker exec dc samba-tool domain exportkeytab /tmp/mssql.keytab \
  --principal=MSSQLSvc/${HOSTNAME}.mayyhem.com:1433
docker cp dc:/tmp/mssql.keytab /tmp/mssql.keytab
```

#### Step 5: Configure host DNS + Kerberos
```bash
# DNS
echo "10.2.10.100 dc.mayyhem.com dc mayyhem.com" | sudo tee -a /etc/hosts
sudo sed -i '1i nameserver 10.2.10.100' /etc/resolv.conf

# Kerberos
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y krb5-user
cat <<'EOF' | sudo tee /etc/krb5.conf
[libdefaults]
    default_realm = MAYYHEM.COM
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    MAYYHEM.COM = {
        kdc = 10.2.10.100
        admin_server = 10.2.10.100
        default_domain = mayyhem.com
    }

[domain_realm]
    .mayyhem.com = MAYYHEM.COM
    mayyhem.com = MAYYHEM.COM
EOF
```

#### Step 6: Install SQL Server 2022
```bash
curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg
curl -fsSL https://packages.microsoft.com/config/ubuntu/22.04/mssql-server-2022.list | \
  sudo tee /etc/apt/sources.list.d/mssql-server-2022.list
sudo apt-get update
sudo apt-get install -y mssql-server
sudo MSSQL_SA_PASSWORD='password' MSSQL_PID='Developer' \
  /opt/mssql/bin/mssql-conf setup accept-eula
```

#### Step 7: Enable mixed mode auth
```bash
sudo /opt/mssql/bin/mssql-conf set sqlagent.enabled true
sudo /opt/mssql/bin/mssql-conf set network.kerberoskeytabfile /var/opt/mssql/secrets/mssql.keytab
sudo /opt/mssql/bin/mssql-conf set network.privilegedadaccount sqlsvc

# Enable mixed mode (SQL + Windows auth)
# SQL Server Linux uses the MSSQL_SA_PASSWORD being set during setup to enable mixed mode.
# To explicitly toggle it post-setup if needed:
sudo /opt/mssql/bin/mssql-conf set sqlagent.enabled true
```

Note: SQL Server on Linux enables mixed mode auth when SA password is set during setup. The `MSSQL_SA_PASSWORD` in step 6 handles this.

#### Step 8: Configure SQL Server keytab + restart
```bash
sudo mkdir -p /var/opt/mssql/secrets
sudo cp /tmp/mssql.keytab /var/opt/mssql/secrets/mssql.keytab
sudo chown mssql:mssql /var/opt/mssql/secrets/mssql.keytab
sudo chmod 400 /var/opt/mssql/secrets/mssql.keytab
sudo systemctl restart mssql-server
sleep 5
```

#### Step 9: Create domainadmin as SQL sysadmin
```bash
# Install sqlcmd
curl -fsSL https://packages.microsoft.com/config/ubuntu/22.04/prod.list | \
  sudo tee /etc/apt/sources.list.d/mssql-release.list
sudo apt-get update
sudo ACCEPT_EULA=Y apt-get install -y mssql-tools18

export PATH="$PATH:/opt/mssql-tools18/bin"
sqlcmd -S localhost -U sa -P 'password' -C -Q "
  CREATE LOGIN [MAYYHEM\domainadmin] FROM WINDOWS;
  ALTER SERVER ROLE [sysadmin] ADD MEMBER [MAYYHEM\domainadmin];
"
```

#### Step 10: Verify AD auth
```bash
echo 'password' | kinit Administrator@MAYYHEM.COM
klist
```

#### Step 11: Run integration tests
```bash
MSSQL_SERVER=localhost \
MSSQL_USER=sa \
MSSQL_PASSWORD='password' \
MSSQL_DOMAIN=mayyhem.com \
MSSQL_DC=10.2.10.100 \
LDAP_USER='Administrator@mayyhem.com' \
LDAP_PASSWORD='password' \
MSSQL_SKIP_DOMAIN=false \
MSSQL_ACTION=all \
MSSQL_SKIP_HTML=true \
go test -v -count=1 -tags integration -timeout 30m \
  -run TestIntegrationAll ./internal/collector/...
```

Since `MSSQL_DOMAIN=mayyhem.com` → `substituteDomain()` extracts `MAYYHEM` as NetBIOS, which matches the hardcoded `MAYYHEM\` references in the SQL scripts. No substitution gap.

## Critical files

| File | Role |
|------|------|
| [integration_setup_test.go](internal/collector/integration_setup_test.go) | Config loading, LDAP object creation, SQL setup orchestration |
| [integration_sql_test.go](internal/collector/integration_sql_test.go) | Embedded SQL scripts with `FROM WINDOWS` + `$Domain` references |
| [edge_integration_test.go](internal/collector/edge_integration_test.go) | `TestIntegrationAll` entry point, edge validation |
| [edge_test_data_test.go](internal/collector/edge_test_data_test.go) | 200+ edge test case definitions |

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Port 53 conflict on runner | Don't publish port 53; use `/etc/hosts` + `/etc/resolv.conf` |
| SQL Server 2022 not on Ubuntu 24.04 | Pin `ubuntu-22.04` |
| Samba DC slow to start | 120s timeout with polling |
| `FROM WINDOWS` fails if DNS broken | Verify `kinit` works before running tests |
| `diegogslomp/samba-ad-dc` unavailable | Fall back to `craftdock/samba-ad-dc` |
| Mixed mode not enabled | SA password set during setup enables it automatically |

## Verification

1. Unit tests locally: `go test -v ./...`
2. Push to branch and verify both jobs pass
3. Integration test output includes edge coverage report from `TestIntegrationAll`
