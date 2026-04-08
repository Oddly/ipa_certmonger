"""Integration-level tests for ipa_certmonger module.

These tests exercise the main() function and the flows that connect
individual helpers: drift detection, check mode, directory management,
SELinux, kerberos cleanup, and error paths that only trigger during
full orchestration.

All OS/IPA/certmonger interactions are mocked.
"""

import base64
import json
import os
import sys
import pytest
from unittest.mock import MagicMock, patch, call

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), '..', 'library')
)

from ansible.module_utils.basic import AnsibleModule

import ipa_certmonger as mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_module_args(**kwargs):
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
        state='present',
        force=False,
    )
    args.update(kwargs)
    return args


def make_module(args, check_mode=False):
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


VALID_KEYTAB = base64.b64encode(b'x' * 100).decode()


# ---------------------------------------------------------------------------
# Tests: get_fqdn
# ---------------------------------------------------------------------------

class TestGetFqdn:
    def test_success(self):
        module = make_module(build_module_args())
        module.run_command.return_value = (0, 'host.example.com\n', '')
        assert mod.get_fqdn(module) == 'host.example.com'

    def test_hostname_fails(self):
        module = make_module(build_module_args())
        module.run_command.return_value = (1, '', 'hostname: Unknown host')
        with pytest.raises(SystemExit):
            mod.get_fqdn(module)
        assert 'hostname -f' in module.fail_json.call_args[1]['msg']

    def test_empty_hostname(self):
        module = make_module(build_module_args())
        module.run_command.return_value = (0, '\n', '')
        with pytest.raises(SystemExit):
            mod.get_fqdn(module)
        assert 'empty' in module.fail_json.call_args[1]['msg'].lower()

    def test_non_fqdn(self):
        module = make_module(build_module_args())
        module.run_command.return_value = (0, 'nodotshere\n', '')
        with pytest.raises(SystemExit):
            mod.get_fqdn(module)
        assert 'not a valid FQDN' in module.fail_json.call_args[1]['msg']


# ---------------------------------------------------------------------------
# Tests: get_cert_status
# ---------------------------------------------------------------------------

class TestGetCertStatus:
    def test_tracked(self):
        module = make_module(build_module_args())
        module.run_command.return_value = (0, 'status: MONITORING', '')
        tracked, output = mod.get_cert_status(
            module, '/usr/bin/ipa-getcert', '/tmp/test.crt'
        )
        assert tracked is True
        assert 'MONITORING' in output

    def test_not_tracked(self):
        module = make_module(build_module_args())
        module.run_command.return_value = (1, '', 'not tracking')
        tracked, output = mod.get_cert_status(
            module, '/usr/bin/ipa-getcert', '/tmp/test.crt'
        )
        assert tracked is False


# ---------------------------------------------------------------------------
# Tests: get_local_ips
# ---------------------------------------------------------------------------

class TestGetLocalIps:
    def test_parses_interfaces(self):
        module = make_module(build_module_args())
        module.run_command.return_value = (
            0,
            json.dumps([
                {'addr_info': [{'local': '10.0.0.1'}, {'local': '127.0.0.1'}]},
                {'addr_info': [{'local': '192.168.1.5'}]},
            ]),
            ''
        )
        ips = mod.get_local_ips(module)
        assert '10.0.0.1' in ips
        assert '127.0.0.1' in ips
        assert '192.168.1.5' in ips

    def test_command_fails(self):
        module = make_module(build_module_args())
        module.run_command.return_value = (1, '', 'error')
        ips = mod.get_local_ips(module)
        assert ips == set()

    def test_invalid_json(self):
        module = make_module(build_module_args())
        module.run_command.return_value = (0, 'not json', '')
        ips = mod.get_local_ips(module)
        assert ips == set()


# ---------------------------------------------------------------------------
# Tests: ensure_directory
# ---------------------------------------------------------------------------

class TestEnsureDirectory:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')

    @patch('os.path.isdir')
    @patch('os.stat')
    @patch('pwd.getpwnam')
    @patch('grp.getgrnam')
    def test_exists_correct_perms(self, mock_grp, mock_pwd, mock_stat,
                                  mock_isdir):
        module = make_module(build_module_args())
        mock_isdir.return_value = True
        mock_pwd.return_value = MagicMock(pw_uid=0)
        mock_grp.return_value = MagicMock(gr_gid=0)
        stat_result = MagicMock()
        stat_result.st_uid = 0
        stat_result.st_gid = 0
        stat_result.st_mode = 0o40750
        mock_stat.return_value = stat_result
        changed = mod.ensure_directory(
            module, '/etc/pki/test', 'root', 'root', self.result
        )
        assert changed is False

    @patch('os.chmod')
    @patch('os.chown')
    @patch('os.stat')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('pwd.getpwnam')
    @patch('grp.getgrnam')
    def test_creates_missing_dir(self, mock_grp, mock_pwd, mock_isdir,
                                 mock_makedirs, mock_stat, mock_chown,
                                 mock_chmod):
        module = make_module(build_module_args())
        # First call: target dir missing; second call: parent exists
        mock_isdir.side_effect = [False, True]
        mock_pwd.return_value = MagicMock(pw_uid=0)
        mock_grp.return_value = MagicMock(gr_gid=0)
        stat_result = MagicMock()
        stat_result.st_uid = 0
        stat_result.st_gid = 0
        stat_result.st_mode = 0o40750
        mock_stat.return_value = stat_result
        changed = mod.ensure_directory(
            module, '/etc/pki/test', 'root', 'root', self.result
        )
        assert changed is True
        mock_makedirs.assert_called_once_with('/etc/pki/test', mode=0o750)

    @patch('os.path.isdir')
    def test_parent_missing_fails(self, mock_isdir):
        module = make_module(build_module_args())
        mock_isdir.side_effect = [False, False]  # target and parent both missing
        with pytest.raises(SystemExit):
            mod.ensure_directory(
                module, '/nonexistent/path/certs', 'root', 'root', self.result
            )
        assert 'Parent directory' in module.fail_json.call_args[1]['msg']

    @patch('os.chmod')
    @patch('os.chown')
    @patch('os.stat')
    @patch('os.path.isdir')
    @patch('pwd.getpwnam')
    @patch('grp.getgrnam')
    def test_fixes_wrong_ownership(self, mock_grp, mock_pwd, mock_isdir,
                                   mock_stat, mock_chown, mock_chmod):
        module = make_module(build_module_args())
        mock_isdir.return_value = True
        mock_pwd.return_value = MagicMock(pw_uid=0)
        mock_grp.return_value = MagicMock(gr_gid=100)
        stat_result = MagicMock()
        stat_result.st_uid = 0
        stat_result.st_gid = 99  # wrong group
        stat_result.st_mode = 0o40750
        mock_stat.return_value = stat_result
        changed = mod.ensure_directory(
            module, '/etc/pki/test', 'root', 'elasticsearch', self.result
        )
        assert changed is True
        mock_chown.assert_called_once_with('/etc/pki/test', 0, 100)

    @patch('os.chmod')
    @patch('os.chown')
    @patch('os.stat')
    @patch('os.path.isdir')
    @patch('pwd.getpwnam')
    @patch('grp.getgrnam')
    def test_non_root_owner(self, mock_grp, mock_pwd, mock_isdir,
                            mock_stat, mock_chown, mock_chmod):
        """Directory ownership uses the owner parameter, not hardcoded root."""
        module = make_module(build_module_args())
        mock_isdir.return_value = True
        mock_pwd.return_value = MagicMock(pw_uid=1000)  # elasticsearch uid
        mock_grp.return_value = MagicMock(gr_gid=1000)
        stat_result = MagicMock()
        stat_result.st_uid = 0  # currently root
        stat_result.st_gid = 0
        stat_result.st_mode = 0o40750
        mock_stat.return_value = stat_result
        changed = mod.ensure_directory(
            module, '/etc/pki/elasticsearch', 'elasticsearch',
            'elasticsearch', self.result
        )
        assert changed is True
        mock_pwd.assert_called_with('elasticsearch')
        mock_chown.assert_called_once_with(
            '/etc/pki/elasticsearch', 1000, 1000
        )

    @patch('os.path.isdir')
    @patch('pwd.getpwnam')
    @patch('grp.getgrnam')
    def test_unknown_group_fails(self, mock_grp, mock_pwd, mock_isdir):
        module = make_module(build_module_args())
        mock_isdir.return_value = True
        mock_grp.side_effect = KeyError("'nosuchgroup'")
        with pytest.raises(SystemExit):
            mod.ensure_directory(
                module, '/etc/pki/test', 'root', 'nosuchgroup', self.result
            )
        assert 'not found' in module.fail_json.call_args[1]['msg'].lower()


# ---------------------------------------------------------------------------
# Tests: ensure_selinux_context
# ---------------------------------------------------------------------------

class TestEnsureSelinuxContext:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')

    def test_no_semanage_skips(self):
        module = make_module(build_module_args())
        module.get_bin_path = MagicMock(return_value=None)
        mod.ensure_selinux_context(module, '/etc/pki/test', self.result)
        # No commands should be run
        module.run_command.assert_not_called()

    def test_already_cert_t(self):
        module = make_module(build_module_args())
        module.get_bin_path = MagicMock(side_effect=['/usr/sbin/semanage',
                                                      '/usr/sbin/restorecon'])
        module.run_command.return_value = (0, 'system_u:object_r:cert_t:s0', '')
        mod.ensure_selinux_context(module, '/etc/pki/test', self.result)
        # Only stat was called, no semanage
        assert module.run_command.call_count == 1

    def test_applies_context(self):
        module = make_module(build_module_args())
        module.get_bin_path = MagicMock(side_effect=['/usr/sbin/semanage',
                                                      '/usr/sbin/restorecon'])
        # stat shows wrong context, semanage+restorecon succeed
        module.run_command.side_effect = [
            (0, 'system_u:object_r:default_t:s0', ''),  # stat
            (0, '', ''),  # semanage fcontext -a
            (0, '', ''),  # semanage fcontext -m
            (0, '', ''),  # restorecon
        ]
        mod.ensure_selinux_context(module, '/etc/pki/test', self.result)
        assert module.run_command.call_count == 4


# ---------------------------------------------------------------------------
# Tests: kerberos_cleanup
# ---------------------------------------------------------------------------

class TestKerberosCleanup:
    def test_cleanup_with_file(self):
        module = make_module(build_module_args())
        with patch('os.path.exists', return_value=True), \
             patch('os.unlink') as mock_unlink:
            mod.kerberos_cleanup(module, '/tmp/test.keytab')
        module.run_command.assert_called_once_with(['kdestroy'])
        mock_unlink.assert_called_once_with('/tmp/test.keytab')

    def test_cleanup_no_file(self):
        module = make_module(build_module_args())
        with patch('os.path.exists', return_value=False), \
             patch('os.unlink') as mock_unlink:
            mod.kerberos_cleanup(module, '/tmp/gone.keytab')
        module.run_command.assert_called_once_with(['kdestroy'])
        mock_unlink.assert_not_called()

    def test_cleanup_none_path(self):
        module = make_module(build_module_args())
        mod.kerberos_cleanup(module, None)
        module.run_command.assert_called_once_with(['kdestroy'])


# ---------------------------------------------------------------------------
# Tests: drift detection (via parse_tracking_info integration)
# ---------------------------------------------------------------------------

class TestDriftDetection:
    """Test SAN and post_save drift detection logic from main()."""

    def test_post_save_added(self):
        """Detects post_save added where there was none."""
        tracking_output = (
            '\tdns: host.example.com\n'
            '\tstatus: MONITORING'
        )
        info = mod.parse_tracking_info(tracking_output)
        current_post_save = info.get('post_save', '') or ''
        desired = 'systemctl restart logstash'
        assert current_post_save != desired

    def test_post_save_changed(self):
        """Detects post_save changed."""
        tracking_output = (
            '\tpost-save command: systemctl restart elasticsearch\n'
            '\tdns: host.example.com'
        )
        info = mod.parse_tracking_info(tracking_output)
        assert info['post_save'] == 'systemctl restart elasticsearch'
        assert info['post_save'] != 'systemctl restart logstash'

    def test_post_save_removed(self):
        """Detects post_save removed (was set, now None)."""
        tracking_output = (
            '\tpost-save command: systemctl restart logstash\n'
            '\tdns: host.example.com'
        )
        info = mod.parse_tracking_info(tracking_output)
        current = info.get('post_save', '') or ''
        desired = None
        # Current has post_save, desired doesn't → drift
        assert current and not desired

    def test_san_added(self):
        """Detects new SAN added."""
        tracking_output = '\tdns: host.example.com'
        info = mod.parse_tracking_info(tracking_output)
        current_dns = set(info['dns_sans'])
        desired_dns = {'host.example.com', 'vip.example.com'}
        missing = desired_dns - current_dns
        assert 'vip.example.com' in missing

    def test_ip_san_added(self):
        """Detects IP SAN added."""
        tracking_output = '\tdns: host.example.com'
        info = mod.parse_tracking_info(tracking_output)
        current_ips = set(info['ip_sans'])
        desired_ips = {'10.0.0.100'}
        missing = desired_ips - current_ips
        assert '10.0.0.100' in missing

    def test_extra_dns_san_detected(self):
        """Detects extra DNS SAN that should be removed."""
        tracking_output = (
            '\tdns: host.example.com\n'
            '\tdns: old-vip.example.com'
        )
        info = mod.parse_tracking_info(tracking_output)
        current_dns = set(info['dns_sans'])
        desired_dns = {'host.example.com'}
        extra = current_dns - desired_dns
        assert 'old-vip.example.com' in extra

    def test_extra_ip_san_detected(self):
        """Detects extra IP SAN that should be removed."""
        tracking_output = (
            '\tdns: host.example.com\n'
            '\tip-address: 10.0.0.100\n'
            '\tip-address: 10.0.0.200'
        )
        info = mod.parse_tracking_info(tracking_output)
        current_ips = set(info['ip_sans'])
        desired_ips = {'10.0.0.100'}
        extra = current_ips - desired_ips
        assert '10.0.0.200' in extra

    def test_no_drift_exact_match(self):
        """No drift when tracking matches desired state."""
        tracking_output = (
            '\tpost-save command: systemctl restart logstash\n'
            '\tdns: host.example.com\n'
            '\tdns: vip.example.com\n'
            '\tip-address: 10.0.0.100'
        )
        info = mod.parse_tracking_info(tracking_output)
        current_dns = sorted(info['dns_sans'])
        current_ips = sorted(info['ip_sans'])
        desired_dns = sorted(['host.example.com', 'vip.example.com'])
        desired_ips = sorted(['10.0.0.100'])
        assert current_dns == desired_dns
        assert current_ips == desired_ips
        assert info['post_save'] == 'systemctl restart logstash'


# ---------------------------------------------------------------------------
# Tests: main() orchestration
# ---------------------------------------------------------------------------

class TestMainFlow:
    """Test the main() function through its major code paths."""

    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_not_ipa_enrolled(self, mock_ansible_mod, mock_exists):
        """Fails when /etc/ipa/default.conf is missing."""
        args = build_module_args(keytab=VALID_KEYTAB)
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = False

        with pytest.raises(SystemExit):
            mod.main()

        msg = module.fail_json.call_args[1]['msg']
        assert 'not IPA-enrolled' in msg
        assert 'ipa-client-install' in msg

    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_certmonger_not_running(self, mock_ansible_mod, mock_exists):
        """Fails when certmonger service is not active."""
        args = build_module_args(keytab=VALID_KEYTAB)
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True  # ipa enrolled

        # systemctl is-active certmonger → inactive
        module.run_command.return_value = (3, 'inactive', '')

        with pytest.raises(SystemExit):
            mod.main()

        msg = module.fail_json.call_args[1]['msg']
        assert 'not running' in msg.lower()
        assert 'certmonger' in msg.lower()

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_already_tracked_no_drift(self, mock_ansible_mod, mock_exists,
                                       mock_isfile):
        """Exits unchanged when cert is already tracked with correct config."""
        args = build_module_args(
            keytab=VALID_KEYTAB,
            post_save='systemctl restart logstash',
        )
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = True

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str and 'certmonger' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (0, (
                    '\tstatus: MONITORING\n'
                    '\tpost-save command: systemctl restart logstash\n'
                    '\tdns: host.example.com\n'
                ), '')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with pytest.raises(SystemExit) as exc_info:
            mod.main()

        # exit_json was called (not fail_json)
        module.exit_json.assert_called_once()
        result = module.exit_json.call_args[1]
        assert result['changed'] is False
        assert 'already tracked' in result['msg']

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_check_mode_no_keytab_ops(self, mock_ansible_mod, mock_exists,
                                       mock_isfile):
        """Check mode returns without requesting certificates."""
        args = build_module_args(keytab=VALID_KEYTAB)
        module = make_module(args, check_mode=True)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = False

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (1, '', 'not found')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with pytest.raises(SystemExit):
            mod.main()

        module.exit_json.assert_called_once()
        result = module.exit_json.call_args[1]
        assert result['changed'] is True
        assert 'check mode' in result['msg'].lower()
        assert 'host.example.com' in result['sans']

        # No kinit should have been called
        for c in module.run_command.call_args_list:
            cmd_str = c[0][0] if isinstance(c[0][0], str) else ' '.join(c[0][0])
            assert 'kinit' not in cmd_str

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_missing_keytab_on_new_request(self, mock_ansible_mod,
                                            mock_exists, mock_isfile):
        """Fails when keytab is not provided for a new cert request."""
        args = build_module_args(keytab=None)  # no keytab
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = False

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str:
                return (1, '', 'not found')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with pytest.raises(SystemExit):
            mod.main()

        msg = module.fail_json.call_args[1]['msg']
        assert 'keytab' in msg.lower()
        assert 'required' in msg.lower()

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_drift_stops_and_rerequests(self, mock_ansible_mod, mock_exists,
                                         mock_isfile):
        """When SAN drift is detected, stop tracking and fall through to re-request."""
        args = build_module_args(
            keytab=VALID_KEYTAB,
            extra_sans=['new-san.example.com'],
        )
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = True

        calls = []

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            calls.append(cmd_str)
            if 'systemctl' in cmd_str and 'certmonger' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                # Currently tracked but missing new-san
                return (0, (
                    '\tstatus: MONITORING\n'
                    '\tdns: host.example.com\n'
                ), '')
            if 'stop-tracking' in cmd_str:
                return (0, '', '')
            # After stop-tracking, the flow continues to request
            # (keytab → kinit → service-add → request → wait)
            if 'kinit' in cmd_str:
                return (0, '', '')
            if 'service-show' in cmd_str:
                return (0, 'Principal: HTTP/host.example.com', '')
            if 'ipa-getcert' in cmd_str and 'request' in cmd_str:
                return (0, 'New request added', '')
            if 'MONITORING' not in cmd_str and 'ipa-getcert' in cmd_str:
                return (0, 'status: MONITORING', '')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        # This will fail because we can't fully mock the filesystem ops
        # (ensure_directory, os.write, etc.), but we can verify drift was
        # detected by checking the warn call
        try:
            mod.main()
        except (SystemExit, Exception):
            pass

        # Verify drift was detected
        module.warn.assert_called()
        warn_msg = module.warn.call_args_list[0][0][0]
        assert 'drift' in warn_msg.lower()
        assert 'new-san.example.com' in warn_msg

        # Verify stop-tracking was called
        stop_calls = [c for c in calls if 'stop-tracking' in c]
        assert len(stop_calls) > 0

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_tracked_but_files_missing(self, mock_ansible_mod, mock_exists,
                                        mock_isfile):
        """Stop tracking and re-request when cert files are missing."""
        args = build_module_args(keytab=VALID_KEYTAB)
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = False  # cert files missing

        calls = []

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            calls.append(cmd_str)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (0, 'status: MONITORING', '')
            if 'stop-tracking' in cmd_str:
                return (0, '', '')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        try:
            mod.main()
        except (SystemExit, Exception):
            pass

        # Verify warning about missing files
        module.warn.assert_called()
        warn_msg = module.warn.call_args_list[0][0][0]
        assert 'missing' in warn_msg.lower()

        # Verify stop-tracking was called
        stop_calls = [c for c in calls if 'stop-tracking' in c]
        assert len(stop_calls) > 0

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_check_mode_with_vip_records(self, mock_ansible_mod, mock_exists,
                                          mock_isfile):
        """Check mode includes VIP SANs in the output."""
        args = build_module_args(
            keytab=VALID_KEYTAB,
            vip_records=[dict(
                dns_names=['vip.example.com'],
                ip='10.0.0.100',
                include_ip_in_cert=True,
                reverse_dns_name='vip.example.com',
            )],
        )
        module = make_module(args, check_mode=True)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = False

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str:
                return (1, '', 'not found')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with pytest.raises(SystemExit):
            mod.main()

        result = module.exit_json.call_args[1]
        assert 'vip.example.com' in result['sans']
        assert '10.0.0.100' in result['sans']

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_sans_deduplicated(self, mock_ansible_mod, mock_exists,
                                mock_isfile):
        """SANs are deduplicated when fqdn appears in extra_sans or vip."""
        args = build_module_args(
            keytab=VALID_KEYTAB,
            extra_sans=['host.example.com', 'other.example.com'],
            vip_records=[dict(
                dns_names=['other.example.com'],
                ip='10.0.0.100',
            )],
        )
        module = make_module(args, check_mode=True)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = False

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str:
                return (1, '', 'not found')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with pytest.raises(SystemExit):
            mod.main()

        result = module.exit_json.call_args[1]
        sans = result['sans']
        # Each entry should appear only once
        assert sans.count('host.example.com') == 1
        assert sans.count('other.example.com') == 1
        assert sans.count('10.0.0.100') == 0  # include_ip_in_cert not set

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_shortname_included_when_enabled(self, mock_ansible_mod,
                                              mock_exists, mock_isfile):
        """Shortname is added to SANs when shortname=true."""
        args = build_module_args(
            keytab=VALID_KEYTAB,
            shortname=True,
        )
        module = make_module(args, check_mode=True)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = False

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str:
                return (1, '', 'not found')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with pytest.raises(SystemExit):
            mod.main()

        result = module.exit_json.call_args[1]
        assert 'host' in result['sans']  # shortname of host.example.com


# ---------------------------------------------------------------------------
# Tests: request_certificate edge cases
# ---------------------------------------------------------------------------

class TestRequestCertificateEdgeCases:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')

    def test_profile_flag(self):
        """Profile is passed as -T flag."""
        module = make_module(build_module_args())
        module.run_command.return_value = (0, '', '')
        params = dict(
            service='HTTP', fqdn='host.example.com',
            cert_file='/tmp/h.crt', key_file='/tmp/h.key',
            owner='root', cert_mode='0640', key_mode='0640',
            post_save=None, profile='caIPAserviceCert_short',
            sans=['host.example.com'],
        )
        mod.request_certificate(module, '/usr/bin/ipa-getcert', params,
                                self.result)
        cmd = module.run_command.call_args[0][0]
        assert '-T' in cmd
        assert 'caIPAserviceCert_short' in cmd

    def test_mixed_dns_and_ip_sans(self):
        """DNS SANs use -D, IP SANs use -A."""
        module = make_module(build_module_args())
        module.run_command.return_value = (0, '', '')
        params = dict(
            service='HTTP', fqdn='host.example.com',
            cert_file='/tmp/h.crt', key_file='/tmp/h.key',
            owner='root', cert_mode='0640', key_mode='0640',
            post_save=None, profile=None,
            sans=['host.example.com', 'vip.example.com', '10.0.0.1', '10.0.0.2'],
        )
        mod.request_certificate(module, '/usr/bin/ipa-getcert', params,
                                self.result)
        cmd = module.run_command.call_args[0][0]
        # Count -D and -A flags
        d_count = sum(1 for i, c in enumerate(cmd) if c == '-D')
        a_count = sum(1 for i, c in enumerate(cmd) if c == '-A')
        assert d_count == 2  # host.example.com, vip.example.com
        assert a_count == 2  # 10.0.0.1, 10.0.0.2

    def test_no_post_save_no_flag(self):
        """No -C flag when post_save is None."""
        module = make_module(build_module_args())
        module.run_command.return_value = (0, '', '')
        params = dict(
            service='HTTP', fqdn='host.example.com',
            cert_file='/tmp/h.crt', key_file='/tmp/h.key',
            owner='root', cert_mode='0640', key_mode='0640',
            post_save=None, profile=None,
            sans=['host.example.com'],
        )
        mod.request_certificate(module, '/usr/bin/ipa-getcert', params,
                                self.result)
        cmd = module.run_command.call_args[0][0]
        assert '-C' not in cmd


# ---------------------------------------------------------------------------
# Tests: wait_for_certificate edge cases
# ---------------------------------------------------------------------------

class TestWaitEdgeCases:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')

    @patch('time.sleep')
    @patch('time.time')
    def test_timeout(self, mock_time, mock_sleep):
        """Fails with timeout message after deadline passes."""
        module = make_module(build_module_args())
        # Simulate time passing: first call before deadline, second after
        mock_time.side_effect = [0, 0, 100]
        module.run_command.return_value = (
            0, 'status: SUBMITTING_REQUEST', ''
        )

        with pytest.raises(SystemExit):
            mod.wait_for_certificate(
                module, '/usr/bin/ipa-getcert', '/tmp/test.crt', 10,
                self.result
            )
        msg = module.fail_json.call_args[1]['msg']
        assert 'timeout' in msg.lower()

    def test_ca_unreachable_transient(self):
        """CA_UNREACHABLE with transient error retries (doesn't fail immediately)."""
        module = make_module(build_module_args())

        call_count = [0]

        def side_effect(cmd, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return (0, 'status: CA_UNREACHABLE\n\tca-error: connection refused', '')
            return (0, 'status: MONITORING', '')

        module.run_command.side_effect = side_effect

        with patch('time.sleep'):
            result = mod.wait_for_certificate(
                module, '/usr/bin/ipa-getcert', '/tmp/test.crt', 300,
                self.result
            )
        assert result is True
        assert call_count[0] == 2


# ---------------------------------------------------------------------------
# Tests: kinit_from_keytab edge cases
# ---------------------------------------------------------------------------

class TestKinitEdgeCases:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')

    def test_successful_kinit(self):
        """Successful kinit returns keytab path and uses correct flags."""
        module = make_module(build_module_args())
        module.run_command.return_value = (0, '', '')

        with patch('tempfile.mkstemp', return_value=(99, '/tmp/test.keytab')), \
             patch('os.write'), \
             patch('os.close'), \
             patch('os.chmod'):
            path = mod.kinit_from_keytab(
                module, VALID_KEYTAB, 'certadmin', self.result
            )
        assert path == '/tmp/test.keytab'
        # Verify kinit uses -k -t (keytab mode), not -p
        cmd = module.run_command.call_args[0][0]
        assert cmd == ['kinit', '-k', '-t', '/tmp/test.keytab', 'certadmin']

    def test_boundary_keytab_size(self):
        """Keytab exactly 10 bytes passes size check."""
        module = make_module(build_module_args())
        module.run_command.return_value = (0, '', '')
        keytab_10 = base64.b64encode(b'x' * 10).decode()

        with patch('tempfile.mkstemp', return_value=(99, '/tmp/test.keytab')), \
             patch('os.write'), \
             patch('os.close'), \
             patch('os.chmod'):
            path = mod.kinit_from_keytab(
                module, keytab_10, 'certadmin', self.result
            )
        assert path == '/tmp/test.keytab'

    def test_keytab_exactly_9_bytes_fails(self):
        """Keytab of 9 bytes fails size check."""
        module = make_module(build_module_args())
        keytab_9 = base64.b64encode(b'x' * 9).decode()
        with pytest.raises(SystemExit):
            mod.kinit_from_keytab(
                module, keytab_9, 'certadmin', self.result
            )
        assert 'too small' in module.fail_json.call_args[1]['msg']


# ---------------------------------------------------------------------------
# Tests: state=absent
# ---------------------------------------------------------------------------

class TestStateAbsent:
    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_absent_stops_tracking_and_removes_files(self, mock_ansible_mod,
                                                      mock_exists,
                                                      mock_isfile):
        """Stops tracking and removes cert/key files."""
        args = build_module_args(state='absent')
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = True

        calls = []

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            calls.append(cmd_str)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (0, 'status: MONITORING', '')
            if 'stop-tracking' in cmd_str:
                return (0, '', '')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with patch('os.unlink') as mock_unlink:
            with pytest.raises(SystemExit):
                mod.main()

        module.exit_json.assert_called_once()
        result = module.exit_json.call_args[1]
        assert result['changed'] is True
        assert 'stopped' in result['msg'].lower() or 'removed' in result['msg'].lower()

        # Verify stop-tracking was called
        stop_calls = [c for c in calls if 'stop-tracking' in c]
        assert len(stop_calls) == 1

        # Verify files were unlinked
        assert mock_unlink.call_count == 2

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_absent_already_absent(self, mock_ansible_mod, mock_exists,
                                    mock_isfile):
        """No changes when already absent."""
        args = build_module_args(state='absent')
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = False  # no cert files

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (1, '', 'not tracking')  # not tracked
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with pytest.raises(SystemExit):
            mod.main()

        module.exit_json.assert_called_once()
        result = module.exit_json.call_args[1]
        assert result['changed'] is False
        assert 'not tracked' in result['msg'].lower()

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_absent_check_mode(self, mock_ansible_mod, mock_exists,
                                mock_isfile):
        """Check mode reports what would happen without acting."""
        args = build_module_args(state='absent')
        module = make_module(args, check_mode=True)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = True

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (0, 'status: MONITORING', '')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with pytest.raises(SystemExit):
            mod.main()

        module.exit_json.assert_called_once()
        result = module.exit_json.call_args[1]
        assert result['changed'] is True
        assert 'check mode' in result['msg'].lower()

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_absent_removes_managed_by(self, mock_ansible_mod, mock_exists,
                                        mock_isfile):
        """Removes managedBy when keytab and vip_records provided."""
        args = build_module_args(
            state='absent',
            keytab=VALID_KEYTAB,
            vip_records=[dict(
                dns_names=['vip.example.com'],
                ip='10.0.0.100',
            )],
        )
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = True

        calls = []

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            calls.append(cmd_str)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (0, 'status: MONITORING', '')
            if 'stop-tracking' in cmd_str:
                return (0, '', '')
            if 'kinit' in cmd_str:
                return (0, '', '')
            if 'kdestroy' in cmd_str:
                return (0, '', '')
            if 'service-show' in cmd_str:
                return (0, '  Managed by: host.example.com', '')
            if 'service-remove-host' in cmd_str:
                return (0, 'Removed host', '')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with patch('os.unlink'), \
             patch('os.path.exists', return_value=True), \
             patch('tempfile.mkstemp', return_value=(99, '/tmp/t.keytab')), \
             patch('os.write'), \
             patch('os.close'), \
             patch('os.chmod'):
            with pytest.raises(SystemExit):
                mod.main()

        module.exit_json.assert_called_once()
        result = module.exit_json.call_args[1]
        assert result['changed'] is True

        # Verify service-remove-host was called
        remove_calls = [c for c in calls if 'service-remove-host' in c]
        assert len(remove_calls) == 1
        assert 'host.example.com' in remove_calls[0]
        assert 'HTTP/vip.example.com' in remove_calls[0]

        # Verify action was recorded
        actions = result['actions']
        managed_actions = [a for a in actions if 'managedBy' in a]
        assert len(managed_actions) == 1

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_absent_no_managed_by_without_keytab(self, mock_ansible_mod,
                                                  mock_exists, mock_isfile):
        """Skips managedBy cleanup when no keytab provided."""
        args = build_module_args(
            state='absent',
            keytab=None,
            vip_records=[dict(
                dns_names=['vip.example.com'],
                ip='10.0.0.100',
            )],
        )
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = True

        calls = []

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            calls.append(cmd_str)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (0, 'status: MONITORING', '')
            if 'stop-tracking' in cmd_str:
                return (0, '', '')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with patch('os.unlink'):
            with pytest.raises(SystemExit):
                mod.main()

        module.exit_json.assert_called_once()

        # No kinit or service-remove-host calls
        kinit_calls = [c for c in calls if 'kinit' in c]
        assert len(kinit_calls) == 0
        remove_calls = [c for c in calls if 'service-remove-host' in c]
        assert len(remove_calls) == 0

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_absent_not_tracked_but_files_exist(self, mock_ansible_mod,
                                                 mock_exists, mock_isfile):
        """Removes orphan files even when not tracked."""
        args = build_module_args(state='absent')
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = True  # files exist

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (1, '', 'not tracking')  # not tracked
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with patch('os.unlink') as mock_unlink:
            with pytest.raises(SystemExit):
                mod.main()

        module.exit_json.assert_called_once()
        result = module.exit_json.call_args[1]
        assert result['changed'] is True
        assert mock_unlink.call_count == 2


# ---------------------------------------------------------------------------
# Tests: force parameter
# ---------------------------------------------------------------------------

class TestForceParameter:
    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_force_rerequests_without_drift(self, mock_ansible_mod,
                                             mock_exists, mock_isfile):
        """Force stops tracking and falls through to re-request."""
        args = build_module_args(
            keytab=VALID_KEYTAB,
            force=True,
        )
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = True

        calls = []

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            calls.append(cmd_str)
            if 'systemctl' in cmd_str and 'certmonger' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (0, (
                    '\tstatus: MONITORING\n'
                    '\tdns: host.example.com\n'
                ), '')
            if 'stop-tracking' in cmd_str:
                return (0, '', '')
            if 'kinit' in cmd_str:
                return (0, '', '')
            if 'service-show' in cmd_str:
                return (0, 'Principal: HTTP/host.example.com', '')
            if 'ipa-getcert' in cmd_str and 'request' in cmd_str:
                return (0, 'New request added', '')
            return (0, 'status: MONITORING', '')

        module.run_command.side_effect = run_cmd_side_effect

        try:
            mod.main()
        except (SystemExit, Exception):
            pass

        # Verify force warning
        warn_calls = [c[0][0] for c in module.warn.call_args_list]
        force_warns = [w for w in warn_calls if 'force' in w.lower()]
        assert len(force_warns) > 0

        # Verify stop-tracking was called (force triggers re-request)
        stop_calls = [c for c in calls if 'stop-tracking' in c]
        assert len(stop_calls) > 0

        # After stop-tracking, the flow falls through to the request path.
        # It will fail at ensure_directory (real filesystem), but that's OK —
        # the important thing is that force=true didn't exit early.

    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_force_false_exits_unchanged(self, mock_ansible_mod, mock_exists,
                                          mock_isfile):
        """Without force, tracked cert with no drift exits unchanged."""
        args = build_module_args(
            keytab=VALID_KEYTAB,
            force=False,
        )
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = True

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str and 'certmonger' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (0, (
                    '\tstatus: MONITORING\n'
                    '\tdns: host.example.com\n'
                ), '')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with pytest.raises(SystemExit):
            mod.main()

        module.exit_json.assert_called_once()
        result = module.exit_json.call_args[1]
        assert result['changed'] is False


# ---------------------------------------------------------------------------
# Tests: remove_vip_managed_by
# ---------------------------------------------------------------------------

class TestRemoveVipManagedBy:
    def setup_method(self):
        self.result = dict(changed=False, cert_file='', key_file='', fqdn='')

    def test_removes_managed_by(self):
        module = make_module(build_module_args())
        module.run_command.side_effect = [
            (0, '  Managed by: host.example.com', ''),  # service-show
            (0, 'Removed host', ''),  # service-remove-host
        ]
        removed = mod.remove_vip_managed_by(
            module, 'HTTP', 'host.example.com',
            [dict(dns_names=['vip.example.com'], ip='10.0.0.100')],
            self.result
        )
        assert removed == ['HTTP/vip.example.com']

    def test_skips_when_not_managed(self):
        module = make_module(build_module_args())
        module.run_command.return_value = (
            0, '  Managed by: other-host.example.com', ''
        )
        removed = mod.remove_vip_managed_by(
            module, 'HTTP', 'host.example.com',
            [dict(dns_names=['vip.example.com'], ip='10.0.0.100')],
            self.result
        )
        assert removed == []
        assert module.run_command.call_count == 1  # only service-show

    def test_skips_when_service_missing(self):
        module = make_module(build_module_args())
        module.run_command.return_value = (1, '', 'not found')
        removed = mod.remove_vip_managed_by(
            module, 'HTTP', 'host.example.com',
            [dict(dns_names=['vip.example.com'], ip='10.0.0.100')],
            self.result
        )
        assert removed == []

    def test_warns_on_remove_failure(self):
        module = make_module(build_module_args())
        module.run_command.side_effect = [
            (0, '  Managed by: host.example.com', ''),
            (1, '', 'unexpected error'),
        ]
        removed = mod.remove_vip_managed_by(
            module, 'HTTP', 'host.example.com',
            [dict(dns_names=['vip.example.com'], ip='10.0.0.100')],
            self.result
        )
        assert removed == []
        module.warn.assert_called_once()
        assert 'unexpected error' in module.warn.call_args[0][0]

    def test_multiple_vip_records(self):
        module = make_module(build_module_args())
        module.run_command.side_effect = [
            (0, '  Managed by: host.example.com', ''),  # show vip1
            (0, 'Removed', ''),  # remove vip1
            (0, '  Managed by: host.example.com', ''),  # show vip2
            (0, 'Removed', ''),  # remove vip2
        ]
        records = [
            dict(dns_names=['vip1.example.com'], ip='10.0.0.1'),
            dict(dns_names=['vip2.example.com'], ip='10.0.0.2'),
        ]
        removed = mod.remove_vip_managed_by(
            module, 'HTTP', 'host.example.com', records, self.result
        )
        assert len(removed) == 2


# ---------------------------------------------------------------------------
# Tests: validate_file_mode
# ---------------------------------------------------------------------------

class TestValidateFileMode:
    def test_valid_mode(self):
        module = make_module(build_module_args())
        mod.validate_file_mode(module, '0640', 'cert_mode')
        module.fail_json.assert_not_called()

    def test_valid_mode_0600(self):
        module = make_module(build_module_args())
        mod.validate_file_mode(module, '0600', 'key_mode')
        module.fail_json.assert_not_called()

    def test_invalid_octal(self):
        module = make_module(build_module_args())
        with pytest.raises(SystemExit):
            mod.validate_file_mode(module, '9999', 'cert_mode')
        msg = module.fail_json.call_args[1]['msg']
        assert 'not a valid octal' in msg
        assert '9999' in msg

    def test_non_numeric(self):
        module = make_module(build_module_args())
        with pytest.raises(SystemExit):
            mod.validate_file_mode(module, 'rwxr--r--', 'cert_mode')
        assert 'not a valid octal' in module.fail_json.call_args[1]['msg']


# ---------------------------------------------------------------------------
# Tests: parse_tracking_info — profile parsing
# ---------------------------------------------------------------------------

class TestParseTrackingInfoProfile:
    def test_profile_parsed(self):
        info = mod.parse_tracking_info(
            '\tprofile: caIPAserviceCert_short\n'
            '\tdns: host.example.com'
        )
        assert info['profile'] == 'caIPAserviceCert_short'

    def test_ca_name_parsed(self):
        info = mod.parse_tracking_info(
            '\tca-name: IPA\n'
            '\tdns: host.example.com'
        )
        assert info['ca_name'] == 'IPA'

    def test_no_profile(self):
        info = mod.parse_tracking_info('\tdns: host.example.com')
        assert 'profile' not in info


# ---------------------------------------------------------------------------
# Tests: drift detection — profile drift
# ---------------------------------------------------------------------------

class TestProfileDrift:
    def test_profile_changed(self):
        """Detects profile change."""
        tracking_output = (
            '\tprofile: caIPAserviceCert\n'
            '\tdns: host.example.com'
        )
        info = mod.parse_tracking_info(tracking_output)
        current = info.get('profile', '') or ''
        desired = 'caIPAserviceCert_short'
        assert current != desired

    def test_profile_added(self):
        """Detects profile added where there was none."""
        tracking_output = '\tdns: host.example.com'
        info = mod.parse_tracking_info(tracking_output)
        current = info.get('profile', '') or ''
        desired = 'caIPAserviceCert_short'
        assert current != desired

    def test_profile_removed(self):
        """Detects profile removed."""
        tracking_output = (
            '\tprofile: caIPAserviceCert_short\n'
            '\tdns: host.example.com'
        )
        info = mod.parse_tracking_info(tracking_output)
        current = info.get('profile', '') or ''
        desired = None
        assert current and not desired


# ---------------------------------------------------------------------------
# Tests: post_save command validation
# ---------------------------------------------------------------------------

class TestPostSaveValidation:
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_warns_on_missing_command(self, mock_ansible_mod, mock_exists):
        args = build_module_args(
            keytab=VALID_KEYTAB,
            post_save='/usr/local/bin/nonexistent restart',
        )
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True

        # get_bin_path returns None for missing command
        orig_get_bin_path = module.get_bin_path

        def get_bin_path_side_effect(name, **kwargs):
            if name == '/usr/local/bin/nonexistent':
                return None
            return orig_get_bin_path(name, **kwargs)

        module.get_bin_path = MagicMock(side_effect=get_bin_path_side_effect)

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str:
                return (1, '', 'not found')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        # Will eventually fail on missing keytab in check_mode=False,
        # but the warning should fire first
        try:
            mod.main()
        except (SystemExit, Exception):
            pass

        # Check that a warning was issued about the command
        warn_calls = [c[0][0] for c in module.warn.call_args_list]
        post_save_warns = [w for w in warn_calls if 'post_save' in w]
        assert len(post_save_warns) > 0
        assert 'nonexistent' in post_save_warns[0]


# ---------------------------------------------------------------------------
# Tests: already-tracked result includes tracking info
# ---------------------------------------------------------------------------

class TestTrackedResultInfo:
    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch.object(mod, 'AnsibleModule')
    def test_includes_sans_and_post_save(self, mock_ansible_mod, mock_exists,
                                          mock_isfile):
        args = build_module_args(
            keytab=VALID_KEYTAB,
            post_save='systemctl restart logstash',
            extra_sans=['10.0.0.1'],
            profile='caIPAserviceCert',
        )
        module = make_module(args)
        mock_ansible_mod.return_value = module
        mock_exists.return_value = True
        mock_isfile.return_value = True

        def run_cmd_side_effect(cmd, *a, **kw):
            cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
            if 'systemctl' in cmd_str and 'certmonger' in cmd_str:
                return (0, 'active', '')
            if 'ipa-getcert' in cmd_str and 'list' in cmd_str:
                return (0, (
                    '\tstatus: MONITORING\n'
                    '\tpost-save command: systemctl restart logstash\n'
                    '\tdns: host.example.com\n'
                    '\tip-address: 10.0.0.1\n'
                    '\tprofile: caIPAserviceCert\n'
                ), '')
            return (0, '', '')

        module.run_command.side_effect = run_cmd_side_effect

        with pytest.raises(SystemExit):
            mod.main()

        module.exit_json.assert_called_once()
        result = module.exit_json.call_args[1]
        assert result['changed'] is False
        assert 'host.example.com' in result['sans']
        assert '10.0.0.1' in result['sans']
        assert result['post_save'] == 'systemctl restart logstash'
        assert result['profile'] == 'caIPAserviceCert'
