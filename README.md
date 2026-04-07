# ipa_certmonger

Ansible module for requesting and managing TLS certificates from FreeIPA CA via certmonger.

## Features

- **Automatic certificate requests** from FreeIPA CA via certmonger
- **Automatic renewal** handled by certmonger — no repeated Ansible runs needed
- **Idempotent** — skips if certificate is already tracked by certmonger
- **Drift detection** — detects changes in SANs or post_save configuration and automatically re-requests the certificate
- **VIP support** — manages certificates with shared VIP addresses for HAProxy/Keepalived setups, including managedBy associations in FreeIPA
- **Service principal management** — automatically creates IPA service principals when needed
- **SELinux aware** — sets `cert_t` context on certificate directories
- **Check mode and diff mode** support
- **Detailed error messages** with actionable hints for every failure scenario

## Requirements

- FreeIPA-enrolled host (`ipa-client-install`)
- certmonger installed and running
- Base64-encoded Kerberos keytab for the certificate admin principal
- For VIP support: VIP hosts and services pre-created by an IPA admin (see [VIP Setup](#vip-setup))

## Installation

Copy `library/ipa_certmonger.py` into the `library/` directory of your Ansible playbook or role:

```
your_playbook/
├── library/
│   └── ipa_certmonger.py
├── playbooks/
│   └── certificates.yml
└── site.yml
```

## Usage

### Basic certificate request

```yaml
- name: Request certificate from FreeIPA CA
  ipa_certmonger:
    service: HTTP
    cert_dir: /etc/pki/myservice
    owner: root
    keytab: "{{ vault_certadmin_keytab }}"
```

This will:
1. Create a service principal `HTTP/<fqdn>` if it doesn't exist
2. Request a certificate with the host FQDN as SAN
3. Wait for certmonger to receive the certificate
4. Set correct ownership and permissions

Certificate and key are stored as:
- `<cert_dir>/<fqdn>.crt`
- `<cert_dir>/<fqdn>.key`

### With extra SANs and post-save command

```yaml
- name: Request certificate with node IP and service restart
  ipa_certmonger:
    service: HTTP
    cert_dir: /etc/pki/elasticsearch
    owner: root
    shortname: false
    extra_sans:
      - "{{ ansible_facts['default_ipv4']['address'] }}"
    post_save: "systemctl restart elasticsearch"
    keytab: "{{ vault_certadmin_keytab }}"
```

### With VIP records (load balancer setup)

```yaml
# group_vars
freeipa_vip_records:
  - dns_names:
      - haproxy-vip.example.com
      - elastic-vip.example.com
      - logstash-vip.example.com
    ip: "10.0.0.100"
    include_ip_in_cert: true
    reverse_dns_name: haproxy-vip.example.com

# playbook
- name: Request certificate with VIP SANs
  ipa_certmonger:
    service: HTTP
    cert_dir: /etc/pki/elasticsearch
    owner: root
    shortname: false
    extra_sans:
      - "{{ ansible_facts['default_ipv4']['address'] }}"
    vip_records: "{{ freeipa_vip_records | default([]) }}"
    keytab: "{{ vault_certadmin_keytab }}"
```

The module will:
- Add all `dns_names` as DNS SANs
- Add the `ip` as an IP SAN (only when `include_ip_in_cert: true`)
- Create `managedBy` associations in FreeIPA for each VIP DNS name
- Validate the `vip_records` structure before making any changes

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `service` | yes | | Service principal type (e.g. `HTTP`, `ldap`) |
| `hostname` | no | system FQDN | FQDN of the host |
| `cert_dir` | yes | | Directory for certificate and key files |
| `owner` | yes | | Owner of the certificate and key files |
| `group` | no | same as owner | Group of the certificate directory and files |
| `cert_mode` | no | `0640` | Permissions for the certificate file (octal) |
| `key_mode` | no | `0640` | Permissions for the key file (octal) |
| `post_save` | no | | Command certmonger runs after each renewal |
| `extra_sans` | no | `[]` | Extra SANs besides FQDN and shortname (e.g. node IP) |
| `vip_records` | no | `[]` | VIP configuration (see [VIP Records Structure](#vip-records-structure)) |
| `shortname` | no | `true` | Add shortname (hostname without domain) as SAN |
| `wait` | no | `true` | Wait until the certificate is issued |
| `wait_timeout` | no | `150` | Maximum wait time in seconds |
| `keytab` | no | | Base64-encoded Kerberos keytab (required for new requests) |
| `keytab_principal` | no | `certadmin` | Kerberos principal for kinit |
| `profile` | no | | FreeIPA certificate profile |

## VIP Records Structure

The `vip_records` parameter accepts a list of dictionaries, each representing a VIP endpoint:

```yaml
vip_records:
  - dns_names:            # Required: list of DNS names for this VIP
      - haproxy-vip.example.com
      - elastic-vip.example.com
    ip: "10.0.0.100"      # Required: VIP IP address
    include_ip_in_cert: true   # Optional: add IP as SAN (default: false)
    reverse_dns_name: haproxy-vip.example.com  # Required when include_ip_in_cert is true
```

### Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `dns_names` | yes | | List of DNS names (become DNS SANs + managedBy associations) |
| `ip` | yes | | VIP IP address (used for A-records, optionally as IP SAN) |
| `include_ip_in_cert` | no | `false` | Whether to add the IP as an IP SAN in the certificate |
| `reverse_dns_name` | when `include_ip_in_cert` is true | | DNS name for the PTR record; must be present in `dns_names` |

### Validation rules

- `dns_names` must be a non-empty list of valid FQDNs (containing at least one dot)
- `ip` must be a valid IP address
- When `include_ip_in_cert` is true, `reverse_dns_name` is required and must be present in `dns_names`
- FreeIPA requires a PTR record for each IP SAN; only one PTR is possible per IP, hence the explicit `reverse_dns_name`

## VIP Setup

Before using `vip_records`, the following must be set up once per environment by an IPA admin:

```bash
# For each DNS name in vip_records:

# 1. DNS A-record
ipa dnsrecord-add example.com haproxy-vip --a-rec=10.0.0.100

# 2. DNS PTR-record (only for the reverse_dns_name, one per IP)
ipa dnsrecord-add <reverse-zone> <reverse-octets> --ptr-rec=haproxy-vip.example.com.

# 3. Dummy host (no enrollment needed)
ipa host-add haproxy-vip.example.com --force

# 4. Service principal
ipa service-add HTTP/haproxy-vip.example.com --force

# 5. Permission for the keytab principal to manage managedBy
ipa permission-add "Manage haproxy-vip managedBy" \
    --right=write --attrs=managedby \
    --subtree="krbprincipalname=HTTP/haproxy-vip.example.com@EXAMPLE.COM,cn=services,cn=accounts,dc=example,dc=com"

# 6. Privilege (once, reuse for all VIPs)
ipa privilege-add "Service Host Management" \
    --desc="Manage managedBy for VIP services"

# 7. Attach permission to privilege
ipa privilege-add-permission "Service Host Management" \
    --permissions="Manage haproxy-vip managedBy"

# 8. Attach privilege to the keytab principal's role (once)
ipa role-add-privilege "<CERTADMIN_ROLE>" \
    --privileges="Service Host Management"
```

Steps 6 and 8 are one-time only. For each additional VIP DNS name, repeat steps 1-5 and 7.

The module automatically handles per-host `managedBy` associations (`ipa service-add-host`) on each run.

## Drift Detection

When a certificate is already tracked by certmonger, the module checks for configuration drift:

- **post_save changes** — detects if the post-renewal command has changed
- **SAN changes** — detects missing DNS or IP SANs (e.g. when VIP records are added)

When drift is detected, the module automatically:
1. Warns about the specific drift
2. Stops tracking of the current certificate
3. Re-requests the certificate with the desired configuration

## Return Values

| Key | Type | Description |
|-----|------|-------------|
| `cert_file` | str | Path to the certificate file |
| `key_file` | str | Path to the key file |
| `fqdn` | str | FQDN used for the certificate |
| `sans` | list | List of all SANs (on change) |
| `actions` | list | List of actions performed (on change) |
| `msg` | str | Status message |
| `drift` | list | Configuration differences (when drift detected) |
| `diff` | dict | Before/after diff (with `--diff` flag) |

## Error Handling

The module provides detailed, actionable error messages for every failure:

- **VIP service not found**: shows the exact `ipa host-add` and `ipa service-add` commands needed
- **Insufficient access**: identifies which permission is missing and shows the `ipa permission-add` command
- **Certificate rejected**: extracts the CA error from certmonger and distinguishes permanent from temporary failures
- **Kinit failures**: shows the principal and original Kerberos error
- **Invalid configuration**: pinpoints the exact `vip_records` entry and field with the problem

## Testing

Run the unit tests:

```bash
pip install pytest ansible-core
pytest tests/test_ipa_certmonger.py -v
```

All IPA/certmonger/OS interactions are mocked — no FreeIPA or certmonger needed to run tests.

## How It Works

```
┌─────────────────────────────────────────────────┐
│                 ipa_certmonger                   │
├─────────────────────────────────────────────────┤
│  1. Validate parameters and vip_records         │
│  2. Check IPA enrollment and certmonger status  │
│  3. Check existing certmonger tracking          │
│     ├─ Already tracked, no drift → skip (ok)    │
│     ├─ Tracked with drift → stop + re-request   │
│     └─ Not tracked → new request                │
│  4. kinit with keytab                           │
│  5. Create service principal (if needed)        │
│  6. Create managedBy for VIP services           │
│  7. ipa-getcert request with all SANs           │
│  8. Wait for certificate (MONITORING status)    │
│  9. Set group ownership on cert/key files       │
│ 10. kdestroy + cleanup keytab                   │
└─────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────┐
│              certmonger (daemon)                 │
│  - Tracks the certificate                       │
│  - Handles automatic renewal                    │
│  - Runs post_save command after renewal          │
└─────────────────────────────────────────────────┘
```

## License

GNU General Public License v3.0+
