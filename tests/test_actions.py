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
from unittest.mock import MagicMock, patch

from actions import actions


class _ActionTestCase(TestCase):

    NAME = ''

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
        """Fail if default backup destination exists but it's not a directory"""
        actions.os.path.isdir.return_value = False
        patch.object(actions.os, 'mkdir')
        patch.object(actions.os.path, 'isdir')
        self.call_action()
        self.assert_function_fail_msg('Backup destination is not a directory.')

    @patch.object(actions, 'datetime')
    def test_backup_filename_format(self, mock_datetime):
        """Test that backups are saved to the file with expected time-stamped name"""
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
            actions.shutil: ['rmtree']
        }
        super(DeleteBackupTests, self).setUp(to_mock=additional_mocks)
        actions.function_get.side_effect = self.function_get_side_effect

    def function_get_side_effect(self, arg):
        """Simulate behavior of function_get.

        This method, that is patched as a "side effect" in setUp(), emulates
        behavior of function_get calls as if the action was invoked by using
        `juju run-action unit_name action_name param1=value1 param2=value2`
        """
        return self._func_args.get(arg)

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
            expected_err = 'Backup file "{}" does not ' \
                           'exist'.format(backup_name)
            self.assert_function_fail_msg(expected_err)

    def test_delete_all(self):
        """Test deletioon of all backups aat once"""
        with self.func_call_arguments(all_=True):
            self.call_action()

            actions.os.remove.assert_not_called()
            actions.shutil.rmtree.assert_called_with(actions.PKI_BACKUP)
            actions.function_fail.assert_not_called()
