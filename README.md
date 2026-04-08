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
- For VIP support: [freeipa_vip_setup](https://github.com/Oddly/freeipa_vip_setup) role must have been run first

## Installation

Add to your `requirements.yml`:

```yaml
- src: https://github.com/Oddly/ipa_certmonger.git
  scm: git
  name: ipa_certmonger
  version: main
```

Then install:

```bash
ansible-galaxy install -r requirements.yml
```

Include the role in any play that uses the module:

```yaml
- name: My certificates play
  hosts: myservers
  roles:
    - ipa_certmonger
  tasks:
    - name: Request certificate
      ipa_certmonger:
        service: HTTP
        cert_dir: /etc/pki/myservice
        owner: root
        keytab: "{{ vault_certadmin_keytab }}"
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

### Remove certificate tracking and files

```yaml
- name: Remove certificate
  ipa_certmonger:
    service: HTTP
    cert_dir: /etc/pki/elasticsearch
    owner: root
    state: absent
```

When `state: absent`, the module:
- Stops certmonger tracking
- Removes the certificate and key files
- Removes managedBy associations (if `keytab` and `vip_records` are provided)
- Service principals are NOT removed (they may be used by other hosts)

### Force certificate re-request

```yaml
- name: Force re-request (e.g. after compromise)
  ipa_certmonger:
    service: HTTP
    cert_dir: /etc/pki/elasticsearch
    owner: root
    force: true
    keytab: "{{ vault_certadmin_keytab }}"
```

Use `force: true` when the certificate must be replaced even though no drift is detected (e.g. after a private key compromise).

### Without VIP (simple certificate)

```yaml
- name: Request certificate for Kibana
  ipa_certmonger:
    service: HTTP
    cert_dir: /etc/pki/kibana
    owner: root
    shortname: false
    keytab: "{{ vault_certadmin_keytab }}"
```

No `vip_records` needed — just a simple certificate with the host FQDN as SAN.

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
| `state` | no | `present` | `present` (request/track) or `absent` (stop tracking, remove files) |
| `force` | no | `false` | Force re-request even without drift (e.g. after key compromise) |

## VIP Records Structure

The `vip_records` parameter accepts a list of dictionaries, each representing a VIP endpoint. This is the same structure used by the [freeipa_vip_setup](https://github.com/Oddly/freeipa_vip_setup) role.

```yaml
vip_records:
  - dns_names:            # Required: list of DNS names for this VIP
      - haproxy-vip.example.com
      - elastic-vip.example.com
    ip: "10.0.0.100"      # Required: VIP IP address
    include_ip_in_cert: true   # Optional: add IP as SAN (default: false)
    reverse_dns_name: haproxy-vip.example.com  # Required when include_ip_in_cert is true
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `dns_names` | yes | | List of DNS names (become DNS SANs + managedBy associations) |
| `ip` | yes | | VIP IP address (optionally used as IP SAN) |
| `include_ip_in_cert` | no | `false` | Whether to add the IP as an IP SAN in the certificate |
| `reverse_dns_name` | when `include_ip_in_cert` is true | | DNS name for the PTR record; must be present in `dns_names` |

### Validation rules

- `dns_names` must be a non-empty list of valid FQDNs (containing at least one dot)
- `ip` must be a valid IP address
- When `include_ip_in_cert` is true, `reverse_dns_name` is required and must be present in `dns_names`
- FreeIPA requires a PTR record for each IP SAN; only one PTR is possible per IP, hence the explicit `reverse_dns_name`

## VIP Prerequisites

Before using `vip_records`, the required FreeIPA objects (DNS records, dummy hosts, service principals, permissions) must exist. Use the [freeipa_vip_setup](https://github.com/Oddly/freeipa_vip_setup) role to create them automatically.

The `freeipa_vip_setup` role can be run standalone or integrated into your playbook via `delegate_to`. See its README for details.

If the VIP prerequisites are missing, the module will fail with a clear error message showing exactly what needs to be created.

## Drift Detection

When a certificate is already tracked by certmonger, the module checks for configuration drift:

- **post_save changes** — detects if the post-renewal command has changed
- **Missing SANs** — detects DNS or IP SANs that should be in the cert but aren't (e.g. when VIP records are added)
- **Extra SANs** — detects DNS or IP SANs that are in the cert but shouldn't be (e.g. when VIP records are removed)
- **Profile changes** — detects if the certificate profile has changed

When drift is detected, the module automatically:
1. Warns about the specific drift
2. Stops tracking of the current certificate
3. Re-requests the certificate with the desired configuration

Use `force: true` to re-request even when no drift is detected.

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

- **VIP service not found**: shows the exact `ipa host-add` and `ipa service-add` commands needed, or suggests running `freeipa_vip_setup`
- **Insufficient access**: identifies which permission is missing and shows the `ipa permission-add` command
- **Certificate rejected**: extracts the CA error from certmonger and distinguishes permanent from temporary failures
- **Kinit failures**: shows the principal and original Kerberos error
- **Invalid configuration**: pinpoints the exact `vip_records` entry and field with the problem

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

## Relationship with freeipa_vip_setup

The [freeipa_vip_setup](https://github.com/Oddly/freeipa_vip_setup) role creates the FreeIPA prerequisites. This module then uses them:

```
freeipa_vip_setup (once, as IPA admin)         ipa_certmonger (each deploy, as certadmin)
──────────────────────────────────────         ──────────────────────────────────────────
DNS A-records                                  (reads dns_names as SANs)
DNS PTR-record                                 (enables IP SAN validation)
Dummy hosts                                    (required for service principals)
Service principals                             (required for managedBy)
managedBy permissions                      ->  service-add-host (per host)
Privilege + role for certadmin                 (enables service-add-host)
```

Both consume the same `freeipa_vip_records` variable structure.

## Directory Structure

```
ipa_certmonger/
├── library/
│   └── ipa_certmonger.py      # The Ansible module
├── meta/
│   └── main.yml               # Role metadata (for ansible-galaxy)
├── tasks/
│   └── main.yml               # Empty (module loaded from library/)
├── tests/
│   └── test_ipa_certmonger.py # Unit tests (47 tests, all mocked)
└── README.md
```

## Testing

```bash
pip install pytest ansible-core
pytest tests/test_ipa_certmonger.py -v
```

All IPA/certmonger/OS interactions are mocked — no FreeIPA or certmonger needed to run tests.

## License

GNU General Public License v3.0+
