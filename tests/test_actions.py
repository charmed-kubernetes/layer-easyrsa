# Copyright 2020 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
from datetime import datetime
from contextlib import contextmanager
from copy import copy

from unittest import TestCase
from unittest.mock import MagicMock, patch, call, mock_open

from actions import actions


def tls_certificate_relation(name, cert_type='client'):
    mock_ = MagicMock()
    mock_.common_name = name
    mock_.cert_type = cert_type
    return mock_


class _ActionTestCase(TestCase):

    NAME = ''

    def __init__(self, methodName='runTest'):
        super(_ActionTestCase, self).__init__(methodName)
        self._func_args = {}

    def function_get_side_effect(self, arg):
        """Simulate behavior of function_get.

        This method, that is patched as a "side effect" in setUp(), emulates
        behavior of function_get calls as if the action was invoked by using
        `juju run-action unit_name action_name param1=value1 param2=value2`
        """
        return self._func_args.get(arg)

    def setUp(self, to_mock=None):
        """
        Mock commonly used objects from actions.py module. Additional objects
        can be passed in for mocking in the form of a dict with format
        {module.object: ['method1', 'method2']}

        Example usage:
        ```python
            class MyTestCase(unittest.TestCase):
                def setUp(self, to_mock=None):
                    additional_mocks = {
                                        actions.os: ['remove', 'mkdir'],
                                        actions.shutil: ['rmtree'],
                                        }
                    super(MyTestcase, self).setUp(to_mock=additional_mocks)

        ```

        :param to_mock: Additional objects to mock
        :return: None
        """
        to_mock = to_mock or {}
        default_mock = {
            actions: {'function_get',
                      'function_set',
                      'function_fail',
                      'local_unit',
                      'leader_set',
                      'leader_get',
                      }
        }
        for key, value in to_mock.items():
            if key in default_mock:
                default_mock[key].update(value)
            else:
                default_mock[key] = value
        self.patch_all(default_mock)
        actions.function_get.side_effect = self.function_get_side_effect

    def patch_all(self, to_patch):
        for object_, methods in to_patch.items():
            for method in methods:
                mock_ = patch.object(object_, method, MagicMock())
                mock_.start()
                self.addCleanup(mock_.stop)

    def assert_function_fail_msg(self, msg):
        """Shortcut for asserting error with default structure"""
        actions.function_fail.assert_called_with("Action {} failed: "
                                                 "{}".format(self.NAME, msg))

    def call_action(self):
        """Shortcut to calling action based on the current TestCase"""
        actions.main([self.NAME])


class GeneralActionsTests(_ActionTestCase):

    def test_action_unknown(self):
        """Verify that attempt to perform unknown action fails"""
        bad_action = 'foo'
        actions.main([bad_action])
        actions.function_fail.assert_called_with("Action {} undefined"
                                                 "".format(bad_action))


class BackupActionsTests(_ActionTestCase):

    NAME = 'backup'

    def setUp(self, to_mock=None):
        additional_mocks = {
            actions.pwd: ['getpwnam'],
            actions.grp: ['getgrnam'],
            actions.os: ['chown', 'mkdir'],
            actions.os.path: ['isdir'],
            actions.tarfile: ['open'],
        }
        super(BackupActionsTests, self).setUp(to_mock=additional_mocks)

    def test_dont_fail_if_destination_dir_already_exists(self):
        """Don't fail if destination directory for backups already exists"""
        actions.os.mkdir.side_effect = FileExistsError()
        self.call_action()
        actions.os.mkdir.assert_called()
        actions.function_fail.assert_not_called()

    def test_destination_not_dir(self):
        """Fail if default backup destination exists but it's not a dir"""
        actions.os.path.isdir.return_value = False
        patch.object(actions.os, 'mkdir')
        patch.object(actions.os.path, 'isdir')
        self.call_action()
        self.assert_function_fail_msg('Backup destination is not a directory.')

    @patch.object(actions, 'datetime')
    def test_backup_filename_format(self, mock_datetime):
        """Test that backups are saved to the file with expected name"""
        freeze_time = datetime(2020, 1, 1)
        mock_datetime.now = MagicMock(return_value=freeze_time)
        timestamp = freeze_time.strftime('%Y-%m-%d_%H-%M-%S')
        expected_path = os.path.join(actions.PKI_BACKUP,
                                     'easyrsa-{}.tar.gz'.format(timestamp))
        expected_format = 'w:gz'

        self.call_action()
        actions.tarfile.open.assert_called_with(expected_path,
                                                mode=expected_format)
        actions.function_fail.assert_not_called()

    @patch.object(actions, 'datetime')
    def test_response(self, mock_datetime):
        """Test successful backup response"""
        freeze_time = datetime(2020, 1, 1)
        mock_datetime.now = MagicMock(return_value=freeze_time)
        timestamp = freeze_time.strftime('%Y-%m-%d_%H-%M-%S')
        expected_path = os.path.join(actions.PKI_BACKUP,
                                     'easyrsa-{}.tar.gz'.format(timestamp))
        local_unit = 'easyrsa/0'
        actions.local_unit.return_value = local_unit
        self.call_action()
        expected_arguments = {
            'command': 'juju scp {}:{} .'.format(local_unit, expected_path),
            'message': 'Backup archive created successfully. Use the juju scp'
                       ' command to copy it to your local machine.'
        }

        actions.function_set.assert_called_with(expected_arguments)
        actions.function_fail.assert_not_called()


class ListBackupTests(_ActionTestCase):

    NAME = 'list-backups'

    def setUp(self, to_mock=None):
        additional_mocks = {
            actions.os: ['listdir'],
        }
        super(ListBackupTests, self).setUp(to_mock=additional_mocks)

    def test_missing_backup_dir_ok(self):
        """Don't fail if backup directory does not exist"""
        actions.os.listdir.side_effect = FileNotFoundError()
        self.call_action()
        actions.function_fail.assert_not_called()

    def test_no_backups_response(self):
        """Test reposnse if there are no backups"""
        actions.os.listdir.return_value = []
        self.call_action()

        expected_response = {'message': 'There are no available backup files.'}
        actions.function_set.assert_called_with(expected_response)
        actions.function_fail.assert_not_called()

    def test_backup_list_response(self):
        """Test response containing list of available backups"""
        backups = ['backup1.tar.gz', 'backup2.tar.gz']
        actions.os.listdir.return_value = backups
        self.call_action()

        expected_text = "Available backup " \
                        "files:\n{}".format("\n".join(backups))

        actions.function_set({'message': expected_text})
        actions.function_fail.assert_not_called()


class DeleteBackupTests(_ActionTestCase):

    NAME = 'delete-backup'

    def __init__(self, methodName='runTest'):
        super(DeleteBackupTests, self).__init__(methodName)
        self._func_args = {'name': None, 'all': None}

    def setUp(self, to_mock=None):
        additional_mocks = {
            actions.os: ['remove', 'mkdir'],
            actions.shutil: ['rmtree'],
            actions.os.path: ['realpath'],
        }
        super(DeleteBackupTests, self).setUp(to_mock=additional_mocks)

        actions.os.path.realpath.return_value = os.path.join(
            '/home', 'ubuntu', 'easyrsa_backup', 'foo.tar.gz')

    @contextmanager
    def func_call_arguments(self, name=None, all_=None):
        """Set action parameters limited to the scope of this context.

        This context manager allows you to set paramters of 'delete-backup'
        action with the scope of the context and then resets them to the
        defaults.
        """
        default = copy(self._func_args)
        try:
            self._func_args = {'name': name, 'all': all_}
            yield
        finally:
            self._func_args = copy(default)

    def test_name_required(self):
        """Name is required if we are not deleting all the backups"""
        with self.func_call_arguments(name=None, all_=False):
            self.call_action()
            expected_err = "Parameter 'name' is required if parameter " \
                           "'all' is False."
            self.assert_function_fail_msg(expected_err)

    def test_single_file_delete(self):
        """Test single file deletion"""
        backup_name = 'foo.tar.gz'
        full_path = os.path.join(actions.PKI_BACKUP, backup_name)

        with self.func_call_arguments(name=backup_name):
            self.call_action()
            actions.os.remove.assert_called_with(full_path)
            actions.function_fail.assert_not_called()

    def test_file_delete_failed(self):
        """Test error if file deletion fails"""
        backup_name = 'bar.tar.gz'
        actions.os.remove.side_effect = FileNotFoundError()

        with self.func_call_arguments(name=backup_name):
            self.call_action()
            expected_err = "Backup file '{}' does not " \
                           "exist".format(backup_name)
            self.assert_function_fail_msg(expected_err)

    def test_delete_path_traversal(self):
        """Test that attempt at path traversal fails"""
        backup_name = '../../../bin/bash'
        resolved_path = '/bin/bash'
        expected_parent_dir = actions.PKI_BACKUP + '/'
        actions.os.path.realpath.return_value = resolved_path

        with self.func_call_arguments(name=backup_name):
            self.call_action()
            expected_err = "Path traversal detected. '{}' tries to travers" \
                           " out of {}".format(resolved_path,
                                               expected_parent_dir)
            self.assert_function_fail_msg(expected_err)

    def test_delete_all(self):
        """Test deletion of all backups at once"""
        with self.func_call_arguments(all_=True):
            self.call_action()

            actions.os.remove.assert_not_called()
            actions.shutil.rmtree.assert_called_with(actions.PKI_BACKUP)
            actions.function_fail.assert_not_called()


class RestoreActionTests(_ActionTestCase):

    NAME = 'restore'

    def __init__(self, methodName='runTest'):
        super(RestoreActionTests, self).__init__(methodName)
        self._func_args = {'name': None}
        self.tar_ctx = MagicMock()
        self.tar_obj = MagicMock()
        self.mock_file_content = 'content'

    def setUp(self, to_mock=None):
        additional_mocks = {
            actions: ['endpoint_from_name'],
            actions.os.path: ['isfile', 'realpath'],
            actions.tarfile.TarFile: ['getnames', 'extractall'],
            actions.tarfile: ['open'],
            actions.shutil: ['move', 'rmtree'],
        }
        super(RestoreActionTests, self).setUp(to_mock=additional_mocks)
        # Mock contextmanager 'with tarfile.open() as tar:'
        self.tar_obj.getnames.return_value = actions.TAR_STRUCTURE
        self.tar_ctx.__enter__.return_value = self.tar_obj
        actions.tarfile.open.return_value = self.tar_ctx

        actions.os.path.realpath.return_value = os.path.join(
            actions.easyrsa_directory, 'pki', 'foo')

    @contextmanager
    def func_call_arguments(self, name=None):
        """Set action parameters limited to the scope of this context.

        This context manager allows you to set paramters of 'restore'
        action with the scope of the context and then resets them to the
        defaults.
        """
        default = copy(self._func_args)
        try:
            self._func_args = {'name': name}
            yield
        finally:
            self._func_args = copy(default)

    def test_require_name(self):
        """Parameter 'name' is required by the 'restore' action"""
        with self.func_call_arguments(name=None):
            self.call_action()
            self.assert_function_fail_msg("Parameter 'name' is required.")

    def test_missing_backup_file(self):
        """Fail if backup archive specified by 'name' is not foud"""
        actions.os.path.isfile.return_value = False
        backup_name = 'foo.tar.gz'
        expected_error = "Backup with name '{}' does not exist. Use action " \
                         "'list-backups' to list all available " \
                         "backups".format(backup_name)
        with self.func_call_arguments(name='foo.tar.gz'):
            self.call_action()
            self.assert_function_fail_msg(expected_error)

    def test_bad_backup_structure(self):
        """Fail if the backup archive does not have the expected structure"""
        bad_tar_structure = {
            'foo',
            'bar',
            'bad/structure',
        }
        self.tar_obj.getnames.return_value = bad_tar_structure
        expected_error = "Backup has unexpected content. Corrupted file?"

        with self.func_call_arguments(name='backup.tar.gz'):
            self.call_action()
            self.assert_function_fail_msg(expected_error)

    def test_failed_extract_restore_original_pki(self):
        """Test that original pki is restored in case of failure"""
        pki_dst = os.path.join(actions.easyrsa_directory, 'pki')
        safety_backup = os.path.join(actions.easyrsa_directory, 'pki_backup')
        exception_message = 'Extraction failed'

        self.tar_obj.extractall.side_effect = Exception(exception_message)
        expected_error = 'Failed to extract backup bundle. ' \
                         'Error: {}'.format(exception_message)

        expected_move_calls = [
            call(pki_dst, safety_backup),  # Original pki set aside
            call(safety_backup, pki_dst)   # Original pki restored
        ]

        with self.func_call_arguments(name='backup.tar.gz'):
            self.call_action()
            actions.shutil.move.assert_has_calls(expected_move_calls)
            self.assert_function_fail_msg(expected_error)

    def test_path_traversal_in_backup_file(self):
        """Test that relative paths in tarball can't traverse outside
        expected parent dir"""
        malicious_tarball = copy(actions.TAR_STRUCTURE)
        malicious_tarball.add('../../../bin/bash')
        resolved_malicious_path = '/bin/bash'
        actions.os.path.realpath.return_value = resolved_malicious_path
        expected_error = "Path traversal detected. " \
                         "'{}' tries to travers out of charm_dir/" \
                         "EasyRSA/pki/".format(resolved_malicious_path)
        self.tar_obj.getnames.return_value = malicious_tarball

        with self.func_call_arguments(name='backup.tar.gz'):
            self.call_action()
            self.assert_function_fail_msg(expected_error)

    @patch("builtins.open", new_callable=mock_open, read_data="mock_data")
    def test_update_leader_values(self, mock_open_):
        """Test that _update_leadership_data sets all required fields

        Some of the pki information are stored in the database of the
        leadership unit. These needs to be updated when new pki is imported
        """
        mock_data = "mock_data"
        leader_set_calls = [
            call({'certificate_authority': mock_data}),
            call({'certificate_authority_key': mock_data}),
            call({'certificate_authority_serial': mock_data}),
            call({'client_certificate': mock_data}),
            call({'client_key': mock_data}),
        ]

        actions._update_leadership_data('foo', 'bar', 'baz')
        actions.leader_set.has_calls(leader_set_calls, any_order=True)

    def test_restore_action(self):
        """Test happy path of the 'restore' action

        This UT tests that all the critical functions are called during the
        successful execution of the 'restore' action. There are 2 happy path
        scenarios:

            * Certificate for the host is found in the backup and is
              pushed to the host.
            * Certificate for the host is NOT found in the backup and the
              newly imported CA will create new cert which is the pushed
              to the host
                * Based on the original request from the host, this
                  certificate can be either client or erver type.
        """
        mock_internal = {
            actions: ['_verify_backup',
                      '_replace_pki',
                      '_update_leadership_data',
                      'create_client_certificate',
                      'create_server_certificate',
                      ]
        }
        self.patch_all(mock_internal)

        tls_provider = MagicMock()
        tls_cert_relation = tls_certificate_relation('tls_client', 'client')
        tls_provider.all_requests = [tls_cert_relation]
        actions.endpoint_from_name.return_value = tls_provider

        # Update certificate from backup
        # builtin 'open()' function is mocked, which acts as if the file was
        # found in the backup
        with patch('builtins.open', new_callable=mock_open, read_data='data'):
            with self.func_call_arguments(name='backup.tar.gz'):
                self.call_action()

                actions._verify_backup.assert_called()
                actions._replace_pki.assert_called()
                actions._update_leadership_data.assert_called()
                tls_provider.set_ca.assert_called()
                tls_provider.set_client_cert.assert_called()
                tls_cert_relation.set_cert.assert_called()

        # Generate client certificate for host missing in backup
        # builtin 'open()' function will raise FileNotFoundError, which acts
        # as if the file was not found in the backup
        with patch('builtins.open', new_callable=mock_open, read_data='data') \
                as mock_file:
            mock_file.side_effect = FileNotFoundError()
            with self.func_call_arguments(name='backup.tar.gz'):
                self.call_action()

                actions._verify_backup.assert_called()
                actions._replace_pki.assert_called()
                actions._update_leadership_data.assert_called()
                tls_provider.set_ca.assert_called()
                tls_provider.set_client_cert.assert_called()
                actions.create_client_certificate.assert_called()
                tls_cert_relation.set_cert.assert_called()

        # Generate server certificate for host missing in backup
        tls_server_relation = tls_certificate_relation('tls_server',
                                                       'server')
        tls_provider.all_requests = [tls_server_relation]
        with patch('builtins.open', new_callable=mock_open, read_data='data') \
                as mock_file:
            mock_file.side_effect = FileNotFoundError()
            with self.func_call_arguments(name='backup.tar.gz'):
                self.call_action()

                actions._verify_backup.assert_called()
                actions._replace_pki.assert_called()
                actions._update_leadership_data.assert_called()
                tls_provider.set_ca.assert_called()
                tls_provider.set_client_cert.assert_called()
                actions.create_server_certificate.assert_called()
                tls_cert_relation.set_cert.assert_called()
