"""Unit tests for the ipa_certmonger module.

All IPA/certmonger/OS interactions are mocked so the tests
run locally without FreeIPA or certmonger.
"""

import json
import os
import sys
import pytest
from unittest.mock import MagicMock

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), '..', 'library')
)

from ansible.module_utils.basic import AnsibleModule

import ipa_certmonger as mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_module_args(**kwargs):
    """Build a default set of module arguments, override with kwargs."""
    args = dict(
        service='HTTP',
        hostname='host.example.com',
        cert_dir='/etc/pki/test',
        owner='root',
        group=None,
        cert_mode='0640',
        key_mode='0640',
        post_save=None,
        extra_sans=[],
        vip_records=[],
        shortname=False,
        wait=True,
        wait_timeout=10,
        keytab=None,
        keytab_principal='certadmin',
        profile=None,
    )
    args.update(kwargs)
    return args


def make_module(args, check_mode=False):
    """Create a mocked AnsibleModule."""
    module = MagicMock(spec=AnsibleModule)
    module.params = args
    module.check_mode = check_mode
    module._diff = False
    module.get_bin_path = MagicMock(return_value='/usr/bin/ipa-getcert')
    module.run_command = MagicMock(return_value=(0, '', ''))
    module.fail_json = MagicMock(side_effect=SystemExit(1))
    module.exit_json = MagicMock(side_effect=SystemExit(0))
    module.warn = MagicMock()
    return module


# ---------------------------------------------------------------------------
# Tests: is_ip helper
# ---------------------------------------------------------------------------

class TestIsIp:
    def test_ipv4(self):
        assert mod.is_ip('10.0.0.1') is True

    def test_ipv6(self):
        assert mod.is_ip('::1') is True

    def test_fqdn(self):
        assert mod.is_ip('host.example.com') is False

    def test_empty(self):
        assert mod.is_ip('') is False

    def test_garbage(self):
        assert mod.is_ip('not-an-ip') is False


# ---------------------------------------------------------------------------
# Tests: validate_vip_records
# ---------------------------------------------------------------------------

class TestValidateVipRecords:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')

    def test_valid_dns_only(self):
        """Valid vip_records without include_ip_in_cert."""
        module = make_module(build_module_args())
        records = [dict(
            dns_names=['vip.example.com'],
            ip='10.0.0.100',
        )]
        mod.validate_vip_records(module, records, self.result)
        module.fail_json.assert_not_called()

    def test_valid_with_ip_san(self):
        """Valid vip_records with include_ip_in_cert and reverse_dns_name."""
        module = make_module(build_module_args())
        records = [dict(
            dns_names=['haproxy-vip.example.com', 'elastic-vip.example.com'],
            ip='10.0.0.100',
            include_ip_in_cert=True,
            reverse_dns_name='haproxy-vip.example.com',
        )]
        mod.validate_vip_records(module, records, self.result)
        module.fail_json.assert_not_called()

    def test_missing_dns_names(self):
        """Fails when dns_names is missing, reports what is expected."""
        module = make_module(build_module_args())
        records = [dict(ip='10.0.0.100')]
        with pytest.raises(SystemExit):
            mod.validate_vip_records(module, records, self.result)
        msg = module.fail_json.call_args[1]['msg']
        assert 'dns_names' in msg
        assert 'non-empty list' in msg
        assert 'vip_records[0]' in msg

    def test_empty_dns_names(self):
        """Fails when dns_names is empty, reports what is expected."""
        module = make_module(build_module_args())
        records = [dict(dns_names=[], ip='10.0.0.100')]
        with pytest.raises(SystemExit):
            mod.validate_vip_records(module, records, self.result)
        msg = module.fail_json.call_args[1]['msg']
        assert 'dns_names' in msg
        assert 'non-empty list' in msg

    def test_missing_ip(self):
        """Fails when ip is missing, reports that ip is required."""
        module = make_module(build_module_args())
        records = [dict(dns_names=['vip.example.com'])]
        with pytest.raises(SystemExit):
            mod.validate_vip_records(module, records, self.result)
        msg = module.fail_json.call_args[1]['msg']
        assert 'ip' in msg
        assert 'required' in msg.lower()

    def test_invalid_ip(self):
        """Fails when ip is invalid, shows the invalid value."""
        module = make_module(build_module_args())
        records = [dict(dns_names=['vip.example.com'], ip='not-an-ip')]
        with pytest.raises(SystemExit):
            mod.validate_vip_records(module, records, self.result)
        msg = module.fail_json.call_args[1]['msg']
        assert 'not-an-ip' in msg
        assert 'not a valid IP' in msg

    def test_invalid_dns_name(self):
        """Fails when a dns_name is not a FQDN, shows the invalid name."""
        module = make_module(build_module_args())
        records = [dict(dns_names=['no-dot'], ip='10.0.0.100')]
        with pytest.raises(SystemExit):
            mod.validate_vip_records(module, records, self.result)
        msg = module.fail_json.call_args[1]['msg']
        assert 'no-dot' in msg
        assert 'not a valid FQDN' in msg

    def test_include_ip_without_reverse_dns(self):
        """Fails with PTR explanation when reverse_dns_name is missing."""
        module = make_module(build_module_args())
        records = [dict(
            dns_names=['vip.example.com'],
            ip='10.0.0.100',
            include_ip_in_cert=True,
        )]
        with pytest.raises(SystemExit):
            mod.validate_vip_records(module, records, self.result)
        msg = module.fail_json.call_args[1]['msg']
        assert 'reverse_dns_name' in msg
        assert 'PTR' in msg
        assert '10.0.0.100' in msg

    def test_reverse_dns_not_in_dns_names(self):
        """Fails when reverse_dns_name is not in dns_names, shows both."""
        module = make_module(build_module_args())
        records = [dict(
            dns_names=['elastic-vip.example.com'],
            ip='10.0.0.100',
            include_ip_in_cert=True,
            reverse_dns_name='haproxy-vip.example.com',
        )]
        with pytest.raises(SystemExit):
            mod.validate_vip_records(module, records, self.result)
        msg = module.fail_json.call_args[1]['msg']
        assert 'haproxy-vip.example.com' in msg
        assert 'elastic-vip.example.com' in msg
        assert 'not present in' in msg

    def test_index_in_error_message(self):
        """Error message contains the index of the bad entry."""
        module = make_module(build_module_args())
        records = [
            dict(dns_names=['ok.example.com'], ip='10.0.0.100'),
            dict(dns_names=['no-dot'], ip='10.0.0.101'),
        ]
        with pytest.raises(SystemExit):
            mod.validate_vip_records(module, records, self.result)
        assert 'vip_records[1]' in module.fail_json.call_args[1]['msg']


# ---------------------------------------------------------------------------
# Tests: extract_vip_sans
# ---------------------------------------------------------------------------

class TestExtractVipSans:
    def test_dns_only(self):
        """Extracts only DNS names when include_ip_in_cert is false."""
        records = [dict(
            dns_names=['elastic-vip.example.com', 'logstash-vip.example.com'],
            ip='10.0.0.100',
        )]
        sans = mod.extract_vip_sans(records)
        assert sans == ['elastic-vip.example.com', 'logstash-vip.example.com']
        assert '10.0.0.100' not in sans

    def test_with_ip_san(self):
        """Extracts DNS names and IP when include_ip_in_cert is true."""
        records = [dict(
            dns_names=['elastic-vip.example.com'],
            ip='10.0.0.100',
            include_ip_in_cert=True,
        )]
        sans = mod.extract_vip_sans(records)
        assert 'elastic-vip.example.com' in sans
        assert '10.0.0.100' in sans

    def test_no_duplicates(self):
        """No duplicate entries when multiple records share the same IP."""
        records = [
            dict(dns_names=['elastic-vip.example.com'], ip='10.0.0.100',
                 include_ip_in_cert=True),
            dict(dns_names=['logstash-vip.example.com'], ip='10.0.0.100',
                 include_ip_in_cert=True),
        ]
        sans = mod.extract_vip_sans(records)
        assert sans.count('10.0.0.100') == 1

    def test_empty_records(self):
        """Empty vip_records returns empty list."""
        assert mod.extract_vip_sans([]) == []

    def test_multiple_records_different_ips(self):
        """Multiple records with different IPs."""
        records = [
            dict(dns_names=['elastic-vip.example.com'], ip='10.0.0.100',
                 include_ip_in_cert=True),
            dict(dns_names=['monitoring-vip.example.com'], ip='10.0.0.101',
                 include_ip_in_cert=True),
        ]
        sans = mod.extract_vip_sans(records)
        assert '10.0.0.100' in sans
        assert '10.0.0.101' in sans


# ---------------------------------------------------------------------------
# Tests: validate_ip_sans
# ---------------------------------------------------------------------------

class TestValidateIpSans:
    def test_local_ip_no_warning(self):
        """No warning when IP is on a local interface."""
        module = make_module(build_module_args())
        module.run_command.return_value = (
            0,
            json.dumps([{'addr_info': [{'local': '10.0.0.1'}]}]),
            ''
        )
        result = dict(changed=False, cert_file='', key_file='', fqdn='')
        mod.validate_ip_sans(module, ['10.0.0.1'], result)
        module.warn.assert_not_called()

    def test_non_local_ip_warning(self):
        """Warning when IP is not on a local interface."""
        module = make_module(build_module_args())
        module.run_command.return_value = (
            0,
            json.dumps([{'addr_info': [{'local': '10.0.0.1'}]}]),
            ''
        )
        result = dict(changed=False, cert_file='', key_file='', fqdn='')
        mod.validate_ip_sans(module, ['10.0.0.100'], result)
        module.warn.assert_called_once()
        assert '10.0.0.100' in module.warn.call_args[0][0]

    def test_dns_names_skipped(self):
        """DNS names are ignored (no IP validation)."""
        module = make_module(build_module_args())
        result = dict(changed=False, cert_file='', key_file='', fqdn='')
        mod.validate_ip_sans(module, ['vip.example.com'], result)
        module.run_command.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: ensure_service_principal
# ---------------------------------------------------------------------------

class TestEnsureServicePrincipal:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')

    def test_already_exists(self):
        """Returns False when the principal already exists."""
        module = make_module(build_module_args())
        module.run_command.return_value = (0, 'Principal: HTTP/host.example.com', '')
        created = mod.ensure_service_principal(
            module, 'HTTP', 'host.example.com', self.result
        )
        assert created is False
        assert module.run_command.call_count == 1

    def test_creates_new(self):
        """Creates the principal when it does not exist."""
        module = make_module(build_module_args())
        module.run_command.side_effect = [
            (1, '', 'not found'),
            (0, 'Added service', ''),
        ]
        created = mod.ensure_service_principal(
            module, 'HTTP', 'host.example.com', self.result
        )
        assert created is True
        assert module.run_command.call_count == 2

    def test_create_fails(self):
        """Fails with IPA error, principal name, and keytab_principal in the message."""
        module = make_module(build_module_args())
        module.run_command.side_effect = [
            (1, '', 'not found'),
            (1, '', 'Insufficient access: write'),
        ]
        with pytest.raises(SystemExit):
            mod.ensure_service_principal(
                module, 'HTTP', 'host.example.com', self.result
            )
        msg = module.fail_json.call_args[1]['msg']
        assert 'HTTP/host.example.com' in msg
        assert 'certadmin' in msg
        assert 'Insufficient access' in msg


# ---------------------------------------------------------------------------
# Tests: ensure_vip_managed_by
# ---------------------------------------------------------------------------

class TestEnsureVipManagedBy:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')
        self.fqdn = 'host.example.com'
        self.records = [dict(
            dns_names=['elastic-vip.example.com'],
            ip='10.0.0.100',
        )]

    def test_service_not_found(self):
        """Fails with step-by-step instructions when VIP service does not exist."""
        module = make_module(build_module_args())
        module.run_command.return_value = (1, '', 'service not found')
        with pytest.raises(SystemExit):
            mod.ensure_vip_managed_by(
                module, 'HTTP', self.fqdn, self.records, self.result
            )
        msg = module.fail_json.call_args[1]['msg']
        assert 'does not exist' in msg
        assert 'ipa host-add elastic-vip.example.com --force' in msg
        assert 'ipa service-add HTTP/elastic-vip.example.com --force' in msg
        assert 'README' in msg

    def test_already_managed(self):
        """Skips when managedBy is already set."""
        module = make_module(build_module_args())
        module.run_command.return_value = (
            0,
            'Managed by: host.example.com',
            ''
        )
        mod.ensure_vip_managed_by(
            module, 'HTTP', self.fqdn, self.records, self.result
        )
        assert module.run_command.call_count == 1

    def test_adds_managed_by(self):
        """Adds managedBy when it is missing."""
        module = make_module(build_module_args())
        module.run_command.side_effect = [
            (0, 'Managed by: elastic-vip.example.com', ''),
            (0, 'Added host', ''),
        ]
        mod.ensure_vip_managed_by(
            module, 'HTTP', self.fqdn, self.records, self.result
        )
        assert module.run_command.call_count == 2
        add_call = module.run_command.call_args_list[1]
        assert 'service-add-host' in add_call[0][0]

    def test_insufficient_access(self):
        """Gives targeted error with permission instructions on Insufficient access."""
        module = make_module(build_module_args())
        module.run_command.side_effect = [
            (0, 'Managed by: other-host.example.com', ''),
            (1, '', "ipa: ERROR: Insufficient access: Insufficient 'write' privilege"),
        ]
        with pytest.raises(SystemExit):
            mod.ensure_vip_managed_by(
                module, 'HTTP', self.fqdn, self.records, self.result
            )
        msg = module.fail_json.call_args[1]['msg']
        assert self.fqdn in msg
        assert 'HTTP/elastic-vip.example.com' in msg
        assert 'write permission' in msg
        assert 'managedBy' in msg
        assert 'ipa permission-add' in msg

    def test_host_not_found(self):
        """Gives targeted error when host is not found in IPA."""
        module = make_module(build_module_args())
        module.run_command.side_effect = [
            (0, 'Managed by: elastic-vip.example.com', ''),
            (1, '', "ipa: ERROR: host not found"),
        ]
        with pytest.raises(SystemExit):
            mod.ensure_vip_managed_by(
                module, 'HTTP', self.fqdn, self.records, self.result
            )
        msg = module.fail_json.call_args[1]['msg']
        assert self.fqdn in msg
        assert 'not found' in msg
        assert 'IPA-enrolled' in msg

    def test_multiple_dns_names(self):
        """Checks all DNS names in a record."""
        module = make_module(build_module_args())
        records = [dict(
            dns_names=['elastic-vip.example.com', 'logstash-vip.example.com'],
            ip='10.0.0.100',
        )]
        module.run_command.return_value = (
            0,
            'Managed by: host.example.com',
            ''
        )
        mod.ensure_vip_managed_by(
            module, 'HTTP', self.fqdn, records, self.result
        )
        assert module.run_command.call_count == 2


# ---------------------------------------------------------------------------
# Tests: request_certificate
# ---------------------------------------------------------------------------

class TestRequestCertificate:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')

    def test_success(self):
        """Successful cert request with correct flags."""
        module = make_module(build_module_args())
        module.run_command.return_value = (0, 'New request added', '')
        params = dict(
            service='HTTP', fqdn='host.example.com',
            cert_file='/etc/pki/test/host.crt',
            key_file='/etc/pki/test/host.key',
            owner='root', cert_mode='0640', key_mode='0640',
            post_save=None, profile=None,
            sans=['host.example.com', '10.0.0.1'],
        )
        mod.request_certificate(module, '/usr/bin/ipa-getcert', params, self.result)
        cmd = module.run_command.call_args[0][0]
        assert '-D' in cmd
        assert '-A' in cmd
        assert 'host.example.com' in cmd
        assert '10.0.0.1' in cmd

    def test_with_post_save(self):
        """post_save is passed as -C flag."""
        module = make_module(build_module_args())
        module.run_command.return_value = (0, '', '')
        params = dict(
            service='HTTP', fqdn='host.example.com',
            cert_file='/tmp/h.crt', key_file='/tmp/h.key',
            owner='root', cert_mode='0640', key_mode='0640',
            post_save='systemctl restart logstash', profile=None,
            sans=['host.example.com'],
        )
        mod.request_certificate(module, '/usr/bin/ipa-getcert', params, self.result)
        cmd = module.run_command.call_args[0][0]
        assert '-C' in cmd
        assert 'systemctl restart logstash' in cmd

    def test_failure_shows_sans(self):
        """On failure, DNS and IP SANs are shown separately."""
        module = make_module(build_module_args())
        module.run_command.return_value = (1, '', 'request failed')
        params = dict(
            service='HTTP', fqdn='host.example.com',
            cert_file='/tmp/h.crt', key_file='/tmp/h.key',
            owner='root', cert_mode='0640', key_mode='0640',
            post_save=None, profile=None,
            sans=['host.example.com', 'vip.example.com', '10.0.0.100'],
        )
        with pytest.raises(SystemExit):
            mod.request_certificate(
                module, '/usr/bin/ipa-getcert', params, self.result
            )
        msg = module.fail_json.call_args[1]['msg']
        assert 'DNS SANs' in msg
        assert 'IP SANs' in msg
        assert 'request failed' in msg


# ---------------------------------------------------------------------------
# Tests: wait_for_certificate
# ---------------------------------------------------------------------------

class TestWaitForCertificate:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')

    def test_monitoring_success(self):
        """Returns True when status is MONITORING."""
        module = make_module(build_module_args())
        module.run_command.return_value = (0, 'status: MONITORING', '')
        result = mod.wait_for_certificate(
            module, '/usr/bin/ipa-getcert', '/tmp/test.crt', 10, self.result
        )
        assert result is True

    def test_ca_rejected(self):
        """Fails with extracted CA error on CA_REJECTED."""
        module = make_module(build_module_args())
        module.run_command.return_value = (
            0,
            'status: CA_REJECTED\n\tca-error: IP address does not have PTR',
            ''
        )
        with pytest.raises(SystemExit):
            mod.wait_for_certificate(
                module, '/usr/bin/ipa-getcert', '/tmp/test.crt', 10,
                self.result
            )
        msg = module.fail_json.call_args[1]['msg']
        assert 'rejected' in msg.lower()
        assert 'PTR' in msg

    def test_ca_unreachable_permanent(self):
        """Fails immediately on permanent CA_UNREACHABLE issue."""
        module = make_module(build_module_args())
        module.run_command.return_value = (
            0,
            'status: CA_UNREACHABLE\n\tca-error: principal does not exist',
            ''
        )
        with pytest.raises(SystemExit):
            mod.wait_for_certificate(
                module, '/usr/bin/ipa-getcert', '/tmp/test.crt', 10,
                self.result
            )
        msg = module.fail_json.call_args[1]['msg']
        assert 'does not exist' in msg


# ---------------------------------------------------------------------------
# Tests: parse_tracking_info
# ---------------------------------------------------------------------------

class TestParseTrackingInfo:
    def test_post_save(self):
        info = mod.parse_tracking_info(
            '\tpost-save command: systemctl restart logstash'
        )
        assert info['post_save'] == 'systemctl restart logstash'

    def test_dns_sans(self):
        info = mod.parse_tracking_info(
            '\tdns: host.example.com\n'
            '\tdns: vip.example.com'
        )
        assert 'host.example.com' in info['dns_sans']
        assert 'vip.example.com' in info['dns_sans']

    def test_ip_sans(self):
        info = mod.parse_tracking_info(
            '\tip-address: 10.0.0.1\n'
            '\tip-address: 10.0.0.100'
        )
        assert '10.0.0.1' in info['ip_sans']
        assert '10.0.0.100' in info['ip_sans']

    def test_empty(self):
        info = mod.parse_tracking_info('')
        assert info['dns_sans'] == []
        assert info['ip_sans'] == []


# ---------------------------------------------------------------------------
# Tests: validate_fqdn
# ---------------------------------------------------------------------------

class TestValidateFqdn:
    def test_valid(self):
        module = make_module(build_module_args())
        mod.validate_fqdn(module, 'host.example.com')
        module.fail_json.assert_not_called()

    def test_no_dot(self):
        module = make_module(build_module_args())
        with pytest.raises(SystemExit):
            mod.validate_fqdn(module, 'host-no-domain')
        assert 'not a valid FQDN' in module.fail_json.call_args[1]['msg']


# ---------------------------------------------------------------------------
# Tests: kinit_from_keytab
# ---------------------------------------------------------------------------

class TestKinitFromKeytab:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')

    def test_invalid_base64(self):
        """Fails on invalid base64, refers to vault."""
        module = make_module(build_module_args())
        with pytest.raises(SystemExit):
            mod.kinit_from_keytab(module, '!!!invalid!!!', 'certadmin', self.result)
        msg = module.fail_json.call_args[1]['msg']
        assert 'base64' in msg
        assert 'vault' in msg.lower()

    def test_too_small(self):
        """Fails when keytab is too small, shows size and refers to vault."""
        module = make_module(build_module_args())
        import base64
        tiny = base64.b64encode(b'tiny').decode()
        with pytest.raises(SystemExit):
            mod.kinit_from_keytab(module, tiny, 'certadmin', self.result)
        msg = module.fail_json.call_args[1]['msg']
        assert 'too small' in msg
        assert '4 bytes' in msg
        assert 'vault' in msg.lower()

    def test_kinit_fails(self):
        """Fails with principal, stderr, and hint about keytab validity."""
        module = make_module(build_module_args())
        import base64
        valid_keytab = base64.b64encode(b'x' * 100).decode()
        module.run_command.return_value = (
            1, '', 'kinit: Client not found in Kerberos database'
        )
        with pytest.raises(SystemExit):
            mod.kinit_from_keytab(module, valid_keytab, 'certadmin', self.result)
        msg = module.fail_json.call_args[1]['msg']
        assert 'certadmin' in msg
        assert 'Client not found' in msg
        assert 'keytab' in msg.lower()
