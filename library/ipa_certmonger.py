#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, RINIS
# GNU General Public License v3.0+
# (see https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ipa_certmonger
short_description: Request TLS certificates from FreeIPA CA via certmonger
description:
  - Requests TLS certificates from the FreeIPA CA via certmonger.
  - Certmonger handles automatic renewal — no repeated runs needed.
  - Requires the node to be IPA-enrolled (ipa-client-install).
  - Requires certmonger to be installed and running.
  - Supports VIP addresses for load balancer setups via the vip_records parameter.
  - Detects configuration drift (SANs, post_save) and automatically re-requests
    certificates when the desired state differs from the current tracking.
version_added: "1.0.0"
author: RINIS
options:
  service:
    description: Service principal type (e.g. HTTP, ldap).
    required: true
    type: str
  hostname:
    description:
      - FQDN of the host.
      - Defaults to the system FQDN (hostname -f).
    required: false
    type: str
  cert_dir:
    description: Directory for certificate and key files.
    required: true
    type: path
  owner:
    description: Owner of the certificate and key files.
    required: true
    type: str
  group:
    description:
      - Group of the certificate directory and files.
      - Defaults to the same value as owner.
    required: false
    type: str
  cert_mode:
    description: Permissions for the certificate file (octal).
    required: false
    type: str
    default: '0640'
  key_mode:
    description: Permissions for the key file (octal).
    required: false
    type: str
    default: '0640'
  post_save:
    description: Command that certmonger executes after each renewal.
    required: false
    type: str
  extra_sans:
    description:
      - Extra Subject Alternative Names besides FQDN and shortname.
      - Use for host-specific SANs such as the node IP address.
      - IPs are validated against local interfaces (warning on mismatch).
    required: false
    type: list
    elements: str
    default: []
  vip_records:
    description:
      - VIP configuration for shared service addresses (e.g. HAProxy VIP).
      - Uses the same structure as the FreeIPA VIP setup role.
      - DNS names are added as SANs and get a managedBy association.
      - The IP is only added as a SAN when include_ip_in_cert is true.
    required: false
    type: list
    elements: dict
    default: []
    suboptions:
      dns_names:
        description: List of DNS names for this VIP (become DNS SANs).
        required: true
        type: list
        elements: str
      ip:
        description: IP address of the VIP.
        required: true
        type: str
      include_ip_in_cert:
        description: Add the IP address as an IP SAN in the certificate.
        required: false
        type: bool
        default: false
      reverse_dns_name:
        description:
          - DNS name for the PTR record of the IP.
          - Required when include_ip_in_cert is true.
          - Must be present in dns_names.
        required: false
        type: str
  shortname:
    description: Add the shortname (hostname without domain) as SAN and principal alias.
    required: false
    type: bool
    default: true
  wait:
    description: Wait until the certificate has been issued.
    required: false
    type: bool
    default: true
  wait_timeout:
    description: Maximum wait time in seconds.
    required: false
    type: int
    default: 150
  keytab:
    description:
      - Base64-encoded Kerberos keytab for FreeIPA authentication.
      - Required for ipa service-add and ipa-getcert request.
      - Not needed when the certificate is already tracked by certmonger.
    required: false
    type: str
  keytab_principal:
    description: Kerberos principal for kinit (from the keytab).
    required: false
    type: str
    default: certadmin
  profile:
    description:
      - FreeIPA certificate profile (ipa-getcert -T).
      - Use a profile with short validity for test/renewal verification.
    required: false
    type: str
'''

EXAMPLES = r'''
- name: Certificate for Elasticsearch with VIP
  ipa_certmonger:
    service: HTTP
    cert_dir: /etc/pki/elasticsearch
    owner: root
    shortname: false
    extra_sans:
      - "{{ ansible_facts['default_ipv4']['address'] }}"
    vip_records: "{{ freeipa_vip_records | default([]) }}"
    keytab: "{{ vault_certadmin_keytab }}"

- name: Certificate for Logstash with post-save restart
  ipa_certmonger:
    service: HTTP
    cert_dir: /etc/pki/logstash
    owner: root
    shortname: false
    extra_sans:
      - "{{ ansible_facts['default_ipv4']['address'] }}"
    vip_records: "{{ freeipa_vip_records | default([]) }}"
    post_save: "systemctl restart logstash"
    keytab: "{{ vault_certadmin_keytab }}"

- name: Certificate without VIP (e.g. Kibana)
  ipa_certmonger:
    service: HTTP
    cert_dir: /etc/pki/kibana
    owner: root
    shortname: false
    keytab: "{{ vault_certadmin_keytab }}"

- name: Certificate with inline VIP configuration
  ipa_certmonger:
    service: HTTP
    cert_dir: /etc/pki/elasticsearch
    owner: root
    extra_sans:
      - "{{ ansible_facts['default_ipv4']['address'] }}"
    vip_records:
      - dns_names:
          - haproxy-vip.example.com
          - elastic-vip.example.com
        ip: "10.0.0.100"
        include_ip_in_cert: true
        reverse_dns_name: haproxy-vip.example.com
    keytab: "{{ vault_certadmin_keytab }}"
'''

RETURN = r'''
cert_file:
  description: Path to the certificate file.
  type: str
  returned: always
  sample: /etc/pki/elasticsearch/host.example.com.crt
key_file:
  description: Path to the key file.
  type: str
  returned: always
  sample: /etc/pki/elasticsearch/host.example.com.key
fqdn:
  description: FQDN used for the certificate.
  type: str
  returned: always
  sample: host.example.com
sans:
  description: List of all SANs in the certificate.
  type: list
  returned: on change
  sample: ["host.example.com", "10.0.0.1", "haproxy-vip.example.com"]
actions:
  description: List of actions performed.
  type: list
  returned: on change
  sample: ["Service principal created: HTTP/host.example.com",
           "Certificate requested with SANs: host.example.com, 10.0.0.1"]
msg:
  description: Status message.
  type: str
  returned: always
  sample: Certificate successfully requested
drift:
  description: List of configuration differences compared to certmonger tracking.
  type: list
  returned: when drift detected
  sample: ["post_save: expected=systemctl restart logstash, current=<none>",
           "Missing DNS SANs in current cert: elastic-vip.example.com"]
diff:
  description: Before/after diff (only with --diff flag).
  type: dict
  returned: on change with --diff
'''

import base64
import grp as grp_mod
import ipaddress
import os
import pwd
import tempfile
import time

from ansible.module_utils.basic import AnsibleModule


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def is_ip(value):
    """Check whether a string is a valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_local_ips(module):
    """Collect all IP addresses from local interfaces via 'ip -j addr'."""
    local_ips = set()
    rc, stdout, stderr = module.run_command(['ip', '-j', 'addr', 'show'])
    if rc == 0:
        try:
            import json
            for iface in json.loads(stdout):
                for addr_info in iface.get('addr_info', []):
                    local_ips.add(addr_info.get('local', ''))
        except (ValueError, KeyError):
            pass
    return local_ips


def validate_ip_sans(module, extra_sans, result):
    """Check whether IP addresses in extra_sans exist on a local interface."""
    ip_sans = [san for san in extra_sans if is_ip(san)]
    if not ip_sans:
        return

    local_ips = get_local_ips(module)
    for ip in ip_sans:
        if ip not in local_ips:
            module.warn(
                "IP SAN '%s' from extra_sans was not found on a local "
                "interface. Available IPs: %s. If this is a VIP address, "
                "use vip_records instead of extra_sans."
                % (ip, ', '.join(sorted(local_ips)))
            )


def validate_fqdn(module, fqdn):
    """Check whether the FQDN is valid (contains at least one dot)."""
    if '.' not in fqdn:
        module.fail_json(
            msg="'%s' is not a valid FQDN (does not contain a domain). "
                "Check 'hostname -f' or the hostname parameter." % fqdn
        )


def validate_vip_records(module, vip_records, result):
    """Validate the structure of vip_records with clear error messages."""
    for i, record in enumerate(vip_records):
        prefix = "vip_records[%d]" % i

        # dns_names is required and must be a non-empty list
        dns_names = record.get('dns_names')
        if not dns_names or not isinstance(dns_names, list):
            module.fail_json(
                msg="%s: 'dns_names' is required and must be a non-empty "
                    "list of DNS names. Received: %s"
                    % (prefix, dns_names),
                **result
            )

        # ip is required and must be a valid IP
        ip = record.get('ip')
        if not ip:
            module.fail_json(
                msg="%s: 'ip' is required. Provide the VIP IP address."
                    % prefix,
                **result
            )
        if not is_ip(ip):
            module.fail_json(
                msg="%s: 'ip' value '%s' is not a valid IP address."
                    % (prefix, ip),
                **result
            )

        # Validate dns_names entries
        for dns_name in dns_names:
            if not isinstance(dns_name, str) or '.' not in dns_name:
                module.fail_json(
                    msg="%s: DNS name '%s' is not a valid FQDN "
                        "(must contain at least one dot)."
                        % (prefix, dns_name),
                    **result
                )

        # If include_ip_in_cert, then reverse_dns_name is required
        include_ip = record.get('include_ip_in_cert', False)
        if include_ip:
            reverse_name = record.get('reverse_dns_name')
            if not reverse_name:
                module.fail_json(
                    msg="%s: 'reverse_dns_name' is required when "
                        "'include_ip_in_cert' is true. FreeIPA requires a "
                        "PTR record for IP SANs. Provide the DNS name that "
                        "should serve as the PTR for %s." % (prefix, ip),
                    **result
                )
            if reverse_name not in dns_names:
                module.fail_json(
                    msg="%s: 'reverse_dns_name' value '%s' is not present "
                        "in 'dns_names' %s. The PTR name must be one of the "
                        "defined DNS names."
                        % (prefix, reverse_name, dns_names),
                    **result
                )


# ---------------------------------------------------------------------------
# FQDN helpers
# ---------------------------------------------------------------------------

def get_fqdn(module):
    """Determine the system FQDN."""
    rc, stdout, stderr = module.run_command(['hostname', '-f'])
    if rc != 0:
        module.fail_json(
            msg='Cannot determine FQDN via "hostname -f". '
                'stderr: %s. Check the hostname configuration or '
                'provide the hostname parameter explicitly.' % stderr.strip()
        )
    fqdn = stdout.strip()
    if not fqdn:
        module.fail_json(
            msg='FQDN is empty (hostname -f returned no output). '
                'Check /etc/hostname and DNS, or provide the hostname '
                'parameter explicitly.'
        )
    validate_fqdn(module, fqdn)
    return fqdn


# ---------------------------------------------------------------------------
# Certmonger helpers
# ---------------------------------------------------------------------------

def get_cert_status(module, getcert_bin, cert_file):
    """Get certmonger tracking status. Returns (tracked, stdout)."""
    rc, stdout, stderr = module.run_command(
        [getcert_bin, 'list', '-f', cert_file]
    )
    return rc == 0, stdout


def parse_tracking_info(status_output):
    """Parse certmonger status output into a dict with relevant fields."""
    info = {'dns_sans': [], 'ip_sans': []}
    for line in status_output.splitlines():
        line = line.strip()
        if line.startswith('post-save command:'):
            info['post_save'] = line.split(':', 1)[1].strip()
        elif line.startswith('dns:'):
            info['dns_sans'].append(line.split(':', 1)[1].strip())
        elif line.startswith('ip-address:'):
            info['ip_sans'].append(line.split(':', 1)[1].strip())
    return info


def wait_for_certificate(module, getcert_bin, cert_file, timeout, result):
    """Wait until certmonger has received the certificate."""
    deadline = time.time() + timeout
    status_output = ''
    last_status = ''

    while time.time() < deadline:
        rc, stdout, stderr = module.run_command(
            [getcert_bin, 'list', '-f', cert_file]
        )
        status_output = stdout

        if 'MONITORING' in stdout:
            return True

        if 'CA_REJECTED' in stdout:
            ca_error = ''
            for line in stdout.splitlines():
                if 'ca-error:' in line:
                    ca_error = line.split('ca-error:', 1)[1].strip()
                    break
            module.fail_json(
                msg='Certificate rejected by FreeIPA CA. '
                    'CA error: %s. '
                    'Full certmonger status:\n%s'
                    % (ca_error or 'unknown', stdout),
                **result
            )

        if 'CA_UNREACHABLE' in stdout:
            ca_error = ''
            for line in stdout.splitlines():
                if 'ca-error:' in line:
                    ca_error = line.split('ca-error:', 1)[1].strip()
                    break
            permanent_errors = [
                'does not exist',
                'not found',
                'denied',
                'not allowed',
            ]
            if any(err in ca_error.lower() for err in permanent_errors):
                module.fail_json(
                    msg='FreeIPA CA is unreachable or denied the request. '
                        'CA error: %s. '
                        'This appears to be a permanent issue (no retry). '
                        'Check that all VIP service principals exist '
                        'and that DNS records are correct. '
                        'Full certmonger status:\n%s'
                        % (ca_error, stdout),
                    **result
                )
            last_status = ca_error

        time.sleep(5)

    module.fail_json(
        msg='Timeout after %d seconds waiting for certificate. '
            'Last status: %s. '
            'Check that the FreeIPA CA is reachable and '
            'that certmonger is configured correctly. '
            'Use "ipa-getcert list -f %s" on the host for details. '
            'Full certmonger status:\n%s'
            % (timeout, last_status or 'unknown', cert_file, status_output),
        **result
    )


# ---------------------------------------------------------------------------
# Directory and SELinux
# ---------------------------------------------------------------------------

def ensure_directory(module, path, group, result):
    """Ensure the certificate directory exists with correct permissions."""
    changed = False

    if not os.path.isdir(path):
        parent = os.path.dirname(path)
        if not os.path.isdir(parent):
            module.fail_json(
                msg="Parent directory '%s' does not exist. "
                    "Install the service or create the directory "
                    "before requesting certificates." % parent,
                **result
            )
        try:
            os.makedirs(path, mode=0o750)
        except OSError as e:
            module.fail_json(
                msg="Cannot create directory '%s': %s" % (path, e),
                **result
            )
        changed = True

    try:
        uid = pwd.getpwnam('root').pw_uid
        gid = grp_mod.getgrnam(group).gr_gid
    except KeyError as e:
        module.fail_json(
            msg="User or group not found: %s. "
                "Check that the 'owner'/'group' parameter is correct "
                "and that the user/group exists on the system." % e,
            **result
        )

    stat = os.stat(path)
    if stat.st_uid != uid or stat.st_gid != gid:
        os.chown(path, uid, gid)
        changed = True

    current_mode = stat.st_mode & 0o7777
    if current_mode != 0o750:
        os.chmod(path, 0o750)
        changed = True

    ensure_selinux_context(module, path, result)
    return changed


def ensure_selinux_context(module, path, result):
    """Ensure the directory has cert_t SELinux context."""
    semanage = module.get_bin_path('semanage')
    restorecon = module.get_bin_path('restorecon')

    if not semanage or not restorecon:
        return

    rc, stdout, stderr = module.run_command(
        ['stat', '-c', '%C', path]
    )
    if rc == 0 and 'cert_t' in stdout:
        return

    pattern = '%s(/.*)?' % path
    module.run_command([
        'semanage', 'fcontext', '-a', '-t', 'cert_t', pattern
    ])
    module.run_command([
        'semanage', 'fcontext', '-m', '-t', 'cert_t', pattern
    ])

    rc, stdout, stderr = module.run_command(
        ['restorecon', '-Rv', path]
    )
    if rc != 0:
        module.warn(
            "Could not set SELinux context on '%s': %s" % (path, stderr)
        )


# ---------------------------------------------------------------------------
# Kerberos authentication
# ---------------------------------------------------------------------------

def kinit_from_keytab(module, keytab_b64, principal, result):
    """Decode keytab and obtain Kerberos ticket. Returns keytab path."""
    try:
        keytab_data = base64.b64decode(keytab_b64)
    except Exception as e:
        module.fail_json(
            msg='Cannot decode keytab (invalid base64): %s. '
                'Check that the keytab is correctly stored '
                'in Ansible vault.' % e,
            **result
        )

    if len(keytab_data) < 10:
        module.fail_json(
            msg='Keytab data is too small (%d bytes). '
                'Check that the keytab is correctly stored '
                'in Ansible vault.' % len(keytab_data),
            **result
        )

    fd, keytab_path = tempfile.mkstemp(prefix='ipa_certmonger_', suffix='.keytab')
    try:
        os.write(fd, keytab_data)
        os.close(fd)
        os.chmod(keytab_path, 0o600)
    except Exception as e:
        os.close(fd)
        os.unlink(keytab_path)
        module.fail_json(
            msg='Cannot write keytab to %s: %s' % (keytab_path, e),
            **result
        )

    rc, stdout, stderr = module.run_command(
        ['kinit', '-p', principal, '-t', keytab_path]
    )
    if rc != 0:
        os.unlink(keytab_path)
        module.fail_json(
            msg="kinit failed for principal '%s'. "
                "Check that the keytab is valid and that the principal "
                "exists in FreeIPA. stderr: %s, stdout: %s"
                % (principal, stderr.strip(), stdout.strip()),
            **result
        )

    return keytab_path


def kerberos_cleanup(module, keytab_path):
    """Destroy Kerberos ticket and remove keytab file."""
    module.run_command(['kdestroy'])
    if keytab_path and os.path.exists(keytab_path):
        os.unlink(keytab_path)


# ---------------------------------------------------------------------------
# FreeIPA service principal and managedBy
# ---------------------------------------------------------------------------

def ensure_service_principal(module, service, fqdn, result):
    """Create the IPA service principal for the host FQDN if it does not exist.

    Returns True if the principal was created, False if it already existed.
    """
    principal = '%s/%s' % (service, fqdn)

    rc, stdout, stderr = module.run_command(
        ['ipa', 'service-show', principal]
    )
    if rc == 0:
        return False

    rc, stdout, stderr = module.run_command(
        ['ipa', 'service-add', principal, '--force']
    )
    if rc != 0:
        module.fail_json(
            msg="Cannot create service principal '%s' in FreeIPA. "
                "Check that '%s' (keytab_principal) has permission for "
                "service-add. IPA error: %s"
                % (principal, module.params['keytab_principal'],
                   stderr.strip()),
            **result
        )
    return True


# ---------------------------------------------------------------------------
# VIP records processing
# ---------------------------------------------------------------------------

def extract_vip_sans(vip_records):
    """Extract SANs from the vip_records structure.

    Returns a list of DNS names and (optionally) IP addresses
    that should be included as SANs in the certificate.
    """
    sans = []
    for record in vip_records:
        for dns_name in record.get('dns_names', []):
            if dns_name not in sans:
                sans.append(dns_name)
        if record.get('include_ip_in_cert', False):
            ip = record.get('ip', '')
            if ip and ip not in sans:
                sans.append(ip)
    return sans


def ensure_vip_managed_by(module, service, fqdn, vip_records, result):
    """Add managedBy associations for all DNS names in vip_records.

    For each DNS name in vip_records, checks that the corresponding
    service principal exists in FreeIPA (created by the FreeIPA admin role).
    Then adds the current host as a managed-by host so that this host
    is permitted to request a certificate with the VIP as SAN.
    """
    for record in vip_records:
        ip = record.get('ip', '')
        for dns_name in record.get('dns_names', []):
            principal = '%s/%s' % (service, dns_name)

            # Check that the VIP service exists (created by IPA admin)
            rc, stdout, stderr = module.run_command(
                ['ipa', 'service-show', principal]
            )
            if rc != 0:
                module.fail_json(
                    msg="VIP service principal '%s' does not exist in FreeIPA. "
                        "This must be created once by an IPA admin. "
                        "Required steps:\n"
                        "  1. ipa host-add %s --force\n"
                        "  2. ipa service-add %s --force\n"
                        "  3. Configure managedBy permission for the keytab principal\n"
                        "See the README for the full setup procedure."
                        % (principal, dns_name, principal),
                    **result
                )

            # Check if managedBy is already set
            # Use word boundary check to avoid substring matches
            # (e.g. 'host.example.com' matching 'other-host.example.com')
            managed_hosts = [
                h.strip() for line in stdout.splitlines()
                for h in line.split(':')[1:] if line.strip().startswith('Managed by')
            ]
            if fqdn in managed_hosts:
                continue

            # Add managedBy
            rc, stdout, stderr = module.run_command(
                ['ipa', 'service-add-host',
                 '--hosts=%s' % fqdn, principal]
            )
            if rc != 0:
                ipa_error = stderr.strip()
                if 'Insufficient access' in ipa_error:
                    hint = (
                        "The '%s' principal does not have write permission "
                        "on the managedBy attribute of service '%s'. "
                        "An IPA admin must create a permission:\n"
                        "  ipa permission-add 'Manage %s managedBy' "
                        "--right=write --attrs=managedby "
                        "--subtree=\"krbprincipalname=%s@<REALM>,"
                        "cn=services,cn=accounts,dc=...\""
                        % (module.params['keytab_principal'],
                           principal, dns_name, principal)
                    )
                elif 'not found' in ipa_error.lower():
                    hint = (
                        "Host '%s' was not found in FreeIPA. "
                        "Check that the host is IPA-enrolled."
                        % fqdn
                    )
                else:
                    hint = "Unexpected error during service-add-host."

                module.fail_json(
                    msg="Cannot add host '%s' as managed-by for "
                        "VIP service '%s' (ip: %s). %s IPA error: %s"
                        % (fqdn, principal, ip, hint, ipa_error),
                    **result
                )


# ---------------------------------------------------------------------------
# Certificate request
# ---------------------------------------------------------------------------

def request_certificate(module, getcert_bin, params, result):
    """Request the certificate via ipa-getcert."""
    cmd = [
        getcert_bin, 'request',
        '-K', '%s/%s' % (params['service'], params['fqdn']),
        '-f', params['cert_file'],
        '-k', params['key_file'],
        '-N', 'CN=%s' % params['fqdn'],
    ]

    for san in params['sans']:
        if is_ip(san):
            cmd.extend(['-A', san])
        else:
            cmd.extend(['-D', san])

    cmd.extend([
        '-o', params['owner'],
        '-O', params['owner'],
        '-m', params['cert_mode'],
        '-M', params['key_mode'],
    ])

    if params.get('post_save'):
        cmd.extend(['-C', params['post_save']])

    if params.get('profile'):
        cmd.extend(['-T', params['profile']])

    rc, stdout, stderr = module.run_command(cmd)
    if rc != 0:
        dns_sans = [s for s in params['sans'] if not is_ip(s)]
        ip_sans = [s for s in params['sans'] if is_ip(s)]
        module.fail_json(
            msg="ipa-getcert request failed. "
                "Command: %s. "
                "DNS SANs: %s. IP SANs: %s. "
                "stderr: %s. stdout: %s"
                % (' '.join(cmd), dns_sans, ip_sans,
                   stderr.strip(), stdout.strip()),
            **result
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    module = AnsibleModule(
        argument_spec=dict(
            service=dict(type='str', required=True),
            hostname=dict(type='str', required=False, default=None),
            cert_dir=dict(type='path', required=True),
            owner=dict(type='str', required=True),
            group=dict(type='str', required=False, default=None),
            cert_mode=dict(type='str', required=False, default='0640'),
            key_mode=dict(type='str', required=False, default='0640'),
            post_save=dict(type='str', required=False, default=None),
            extra_sans=dict(
                type='list', elements='str', required=False, default=[]
            ),
            vip_records=dict(
                type='list', elements='dict', required=False, default=[]
            ),
            shortname=dict(type='bool', required=False, default=True),
            wait=dict(type='bool', required=False, default=True),
            wait_timeout=dict(type='int', required=False, default=150),
            keytab=dict(type='str', required=False, default=None, no_log=True),
            keytab_principal=dict(
                type='str', required=False, default='certadmin'
            ),
            profile=dict(type='str', required=False, default=None),
        ),
        supports_check_mode=True,
    )

    service = module.params['service']
    fqdn = module.params['hostname'] or get_fqdn(module)
    if module.params['hostname']:
        validate_fqdn(module, fqdn)
    cert_dir = module.params['cert_dir']
    owner = module.params['owner']
    group = module.params['group'] or owner
    cert_mode = module.params['cert_mode']
    key_mode = module.params['key_mode']
    post_save = module.params['post_save']
    extra_sans = module.params['extra_sans']
    vip_records = module.params['vip_records']
    include_shortname = module.params['shortname']
    wait = module.params['wait']
    wait_timeout = module.params['wait_timeout']

    short = fqdn.split('.')[0]
    cert_file = os.path.join(cert_dir, '%s.crt' % fqdn)
    key_file = os.path.join(cert_dir, '%s.key' % fqdn)

    result = dict(
        changed=False,
        cert_file=cert_file,
        key_file=key_file,
        fqdn=fqdn,
    )

    # --- Validation ---

    if vip_records:
        validate_vip_records(module, vip_records, result)

    if not os.path.exists('/etc/ipa/default.conf'):
        module.fail_json(
            msg="Node is not IPA-enrolled (/etc/ipa/default.conf is missing). "
                "Run 'ipa-client-install' on this host first.",
            **result
        )

    getcert_bin = module.get_bin_path('ipa-getcert', required=True)

    rc, stdout, stderr = module.run_command(
        ['systemctl', 'is-active', 'certmonger']
    )
    if rc != 0:
        module.fail_json(
            msg="Certmonger service is not running (status: %s). "
                "Start certmonger first: systemctl start certmonger"
                % stdout.strip(),
            **result
        )

    # --- Check existing tracking ---

    tracked, status_output = get_cert_status(module, getcert_bin, cert_file)
    if tracked:
        if not os.path.isfile(cert_file) or not os.path.isfile(key_file):
            module.warn(
                "Certmonger tracking found but files are missing "
                "(%s, %s). Tracking will be stopped and cert re-requested."
                % (cert_file, key_file)
            )
            module.run_command(
                [getcert_bin, 'stop-tracking', '-f', cert_file]
            )
            tracked = False
        else:
            tracking = parse_tracking_info(status_output)
            drift = []

            # post_save drift
            current_post_save = tracking.get('post_save', '') or ''
            if post_save and current_post_save != post_save:
                drift.append(
                    'post_save: expected=%s, current=%s' % (
                        post_save, current_post_save or '<none>'
                    )
                )
            elif not post_save and current_post_save:
                drift.append(
                    'post_save: expected=<none>, current=%s'
                    % current_post_save
                )

            # SAN drift
            desired_sans = [fqdn]
            if include_shortname:
                desired_sans.append(short)
            desired_sans.extend(extra_sans)
            desired_sans.extend(extract_vip_sans(vip_records))

            desired_dns = sorted(set(
                s for s in desired_sans if not is_ip(s)
            ))
            desired_ips = sorted(set(
                s for s in desired_sans if is_ip(s)
            ))
            current_dns = sorted(set(tracking.get('dns_sans', [])))
            current_ips = sorted(set(tracking.get('ip_sans', [])))

            missing_dns = set(desired_dns) - set(current_dns)
            missing_ips = set(desired_ips) - set(current_ips)
            if missing_dns:
                drift.append(
                    'Missing DNS SANs in current cert: %s'
                    % ', '.join(sorted(missing_dns))
                )
            if missing_ips:
                drift.append(
                    'Missing IP SANs in current cert: %s'
                    % ', '.join(sorted(missing_ips))
                )

            if drift:
                result['drift'] = drift
                module.warn(
                    'Certificate drift detected: %s. '
                    'Tracking will be stopped and cert re-requested.'
                    % '; '.join(drift)
                )
                module.run_command(
                    [getcert_bin, 'stop-tracking', '-f', cert_file]
                )
                tracked = False
                # Fall through to the request flow below

            if tracked:
                result['msg'] = (
                    'Certificate is already tracked by certmonger'
                )
                module.exit_json(**result)

    # --- Validate extra_sans IPs ---

    validate_ip_sans(module, extra_sans, result)

    # --- Changes ---

    result['changed'] = True

    # Build SAN list (also for check_mode output)
    sans = [fqdn]
    if include_shortname:
        sans.append(short)
    sans.extend(extra_sans)
    vip_sans = extract_vip_sans(vip_records)
    sans.extend(vip_sans)
    result['sans'] = sans

    if module.check_mode:
        result['msg'] = (
            'Certificate would be requested (check mode). '
            'SANs: %s' % sans
        )
        module.exit_json(**result)

    # Keytab is required for new requests
    keytab = module.params['keytab']
    keytab_principal = module.params['keytab_principal']
    if not keytab:
        module.fail_json(
            msg="Keytab is required for requesting new certificates. "
                "Provide the 'keytab' parameter "
                "(base64-encoded keytab from Ansible vault).",
            **result
        )

    # Create directory / fix permissions
    ensure_directory(module, cert_dir, group, result)

    # Track actions performed (for diff output)
    actions = []

    # Kerberos authentication — all IPA operations within try/finally
    keytab_path = kinit_from_keytab(
        module, keytab, keytab_principal, result
    )
    try:
        # Create service principal for the host FQDN
        if ensure_service_principal(module, service, fqdn, result):
            actions.append(
                'Service principal created: %s/%s' % (service, fqdn)
            )

        # ManagedBy associations for VIP services
        if vip_records:
            ensure_vip_managed_by(module, service, fqdn, vip_records, result)

        # Request certificate
        actions.append(
            'Certificate requested with SANs: %s' % ', '.join(sans)
        )
        request_certificate(module, getcert_bin, dict(
            service=service,
            fqdn=fqdn,
            cert_file=cert_file,
            key_file=key_file,
            owner=owner,
            cert_mode=cert_mode,
            key_mode=key_mode,
            post_save=post_save,
            profile=module.params['profile'],
            sans=sans,
        ), result)

        # Wait for certificate
        if wait:
            wait_for_certificate(module, getcert_bin, cert_file, wait_timeout,
                                 result)

        # Set group on cert and key files
        # (ipa-getcert has no flag for group ownership)
        try:
            gid = grp_mod.getgrnam(group).gr_gid
            for path in (cert_file, key_file):
                if os.path.exists(path):
                    os.chown(path, -1, gid)
        except (KeyError, OSError) as e:
            module.warn(
                "Could not set group '%s' on files: %s" % (group, e)
            )
    finally:
        kerberos_cleanup(module, keytab_path)

    result['msg'] = 'Certificate successfully requested'
    result['actions'] = actions

    # Diff output
    if module._diff:
        result['diff'] = {
            'before': 'No certificate for %s\n' % fqdn,
            'after': 'Certificate requested:\n  cert: %s\n  key: %s\n'
                     '  SANs: %s\n  post_save: %s\n'
                     % (cert_file, key_file, ', '.join(sans),
                        post_save or '<none>'),
        }

    module.exit_json(**result)


if __name__ == '__main__':
    main()
