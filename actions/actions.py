#!/usr/local/sbin/charm-env python3
import os
import pwd
import grp
import sys
import tarfile
import shutil

from datetime import datetime

from charms import layer
from charms.reactive.relations import endpoint_from_name
from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import (
    function_get,
    function_set,
    function_fail,
    local_unit,
    log,
    leader_set,
    leader_get,
)

from reactive.easyrsa import (
    easyrsa_directory,
    create_client_certificate,
    create_server_certificate,
)

# Import charm layers and start reactive
layer.import_layer_libs()
hookenv._run_atstart()

PKI_BACKUP = '/home/ubuntu/easyrsa_backup'
# Minimal required contents of the backup tarball
TAR_STRUCTURE = {'pki',
                 'pki/ca.crt',
                 'pki/issued',
                 'pki/issued/client.crt',
                 'pki/private',
                 'pki/private/ca.key',
                 'pki/private/client.key',
                 'pki/serial',
                 }


def _check_path_traversal(path_, parent_dir):
    """Check that 'path_' does not lie outside of the 'parent_dir'.

    This function takes into account possible '../' in 'path_' and also
    any symlinks that could point somewhere outside the expected 'parent_dir'

    NOTE(mkalcok): This implementation could be improved by using
                   'os.path.commonpath()'. However it's available only in
                    py35+.

    :param path_: Path to be tested
    :param parent_dir: Directory in which the 'path_' must lie
    :raises: RuntimeError if 'path_' is outside of the 'parent_dir'
    """
    full_path = os.path.realpath(path_)
    parent_dir = os.path.realpath(parent_dir)
    if not parent_dir.endswith('/'):
        parent_dir += '/'

    if os.path.commonprefix([parent_dir, full_path]) != parent_dir:
        err_msg = "Path traversal detected. '{}' tries to travers out " \
                  "of {}".format(full_path, parent_dir)
        log(err_msg, hookenv.ERROR)
        raise RuntimeError(err_msg)


def _ensure_backup_dir_exists():
    """Ensure that backup directory exists with proper ownership"""
    uid = pwd.getpwnam("ubuntu").pw_uid
    gid = grp.getgrnam("ubuntu").gr_gid
    try:
        os.mkdir(PKI_BACKUP, mode=0o700)
    except FileExistsError:
        pass
    os.chown(PKI_BACKUP, uid, gid)

    if not os.path.isdir(PKI_BACKUP):
        log("Backup destination '{}' is not a directory".format(PKI_BACKUP),
            hookenv.ERROR)
        raise RuntimeError('Backup destination is not a directory.')


def _verify_backup(pki_tar):
    """
    Verify that backup archive contains expected files

    :param pki_tar: Tarfile object containing easyrsa backup
    """
    log("Verifying backup", hookenv.DEBUG)
    members = set(pki_tar.getnames())

    # Check that backup contains all the expected/required files
    if not TAR_STRUCTURE.issubset(members):
        raise RuntimeError("Backup has unexpected content. Corrupted file?")
    log("Check expected files - OK", hookenv.DEBUG)

    # Check for path traversal attempts in tar file
    pki_dir = os.path.join(easyrsa_directory, 'pki')
    for path_ in members:
        destination = os.path.join(pki_dir, path_)
        _check_path_traversal(destination, pki_dir)


def _replace_pki(pki_tar, pki_dir):
    """
    Safely replace easyrsa pki directory.

    If there are any problems during the extraction of the backup, original
    pki directory will be brought back and error raised.

    :param pki_tar: Tarfile object containing easyrsa backup
    :param pki_dir: Destination for extraction of easyrsa backup
    :return: None
    """
    safety_backup = os.path.join(easyrsa_directory, 'pki_backup')
    shutil.move(pki_dir, safety_backup)
    try:
        log("Extracting pki from backup", hookenv.DEBUG)
        pki_tar.extractall(easyrsa_directory)
    except Exception as exc:
        log("pki extraction failed: {}".format(exc),
            hookenv.WARNING)
        log("Restoring original pki.", hookenv.INFO)
        shutil.move(safety_backup, pki_dir)
        raise RuntimeError('Failed to extract backup bundle. '
                           'Error: {}'.format(exc))
    else:
        shutil.rmtree(safety_backup)


def _update_leadership_data(pki_dir, cert_dir, key_dir):
    """
    Update certificates stored in the leaders database.

    :param pki_dir: location of easyrsa pki (usually <charm_dir>/EasyRSA/pki)
    :param cert_dir: location of issued certificates (usually <pki_dir>/issued)
    :param key_dir: location of private keys (usually <pki_dir>/private)
    :return: None
    """
    ca_cert = os.path.join(pki_dir, 'ca.crt')
    ca_key = os.path.join(key_dir, 'ca.key')
    serial_file = os.path.join(pki_dir, 'serial')
    global_client_cert = os.path.join(cert_dir, 'client.crt')
    global_client_key = os.path.join(key_dir, 'client.key')

    with open(ca_cert, 'r') as stream:
        data = stream.read()
        log("Updating CA certificate in leader's database",
            hookenv.INFO)
        log("CA certificate:\n{}".format(data), hookenv.DEBUG)
        leader_set({
            'certificate_authority': data})

    with open(ca_key, 'r') as stream:
        log("Updating CA key in leader's database",
            hookenv.INFO)
        leader_set({
            'certificate_authority_key': stream.read()})

    with open(serial_file, 'r') as stream:
        log("Updating CA serial in leader's database",
            hookenv.INFO)
        leader_set({
            'certificate_authority_serial': stream.read()})

    with open(global_client_cert) as stream:
        data = stream.read()
        log("Updating (legacy) global client certificate in leader's database",
            hookenv.INFO)
        log(data, hookenv.DEBUG)
        leader_set({'client_certificate': data})

    with open(global_client_key) as stream:
        log("Updating (legacy) global client key in leader's database",
            hookenv.INFO)
        leader_set({'client_key': stream.read()})


def backup():
    """
    Implementation of easyrsa 'backup' action.

    Currently deployed pki is packed into tarball and stored in the
    backups directory.
    """
    _ensure_backup_dir_exists()

    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    backup_name = 'easyrsa-{}.tar.gz'.format(timestamp)
    backup_path = os.path.join(PKI_BACKUP, backup_name)
    with tarfile.open(backup_path, mode='w:gz') as pki_tar:
        pki_tar.add(os.path.join(easyrsa_directory, 'pki'), 'pki')

    log("Backup created and saved to '{}'".format(backup_path), hookenv.DEBUG)
    function_set({
        'command': 'juju scp {}:{} .'.format(local_unit(), backup_path),
        'message': 'Backup archive created successfully. Use the juju scp '
                   'command to copy it to your local machine.'
    })


def restore():
    """
    Implementation of easyrsa 'restore' action

    Backup restoration process can be summarized as following:

        * Selected backup is scanned and verified
        * Contents of the backup are unpacked into <cahrm_dir>/EasyRSA/pki
        * Data that are stored in the local database are updated
        * All units that have relation with this easyrsa unit will be notified
          about the certificate changes.
    """
    pki_dir = os.path.join(easyrsa_directory, 'pki')
    backup_name = function_get('name')

    if backup_name is None:
        raise RuntimeError("Parameter 'name' is required.")

    log("Restoring pki from backup file {}".format(backup_name), hookenv.INFO)

    backup_path = os.path.join(PKI_BACKUP, backup_name)

    if not os.path.isfile(backup_path):
        log("Backup file '{}' does not exists.".format(backup_path),
            hookenv.ERROR)
        raise RuntimeError("Backup with name '{}' does not exist. Use action "
                           "'list-backups' to list all available "
                           "backups".format(backup_name))

    with tarfile.open(backup_path, 'r:gz') as pki_tar:
        _verify_backup(pki_tar)
        _replace_pki(pki_tar, pki_dir)

    cert_dir = os.path.join(pki_dir, 'issued')
    key_dir = os.path.join(pki_dir, 'private')

    # Update CA and global client data stored in the local leader's database
    # NOTE(mkalcok): Easyrsa does not really support HA mode, so it's usually
    #                run as a single unit/model
    _update_leadership_data(pki_dir, cert_dir, key_dir)

    ca_cert = leader_get('certificate_authority')
    tls = endpoint_from_name('client')
    log("Sending CA certificate to all related units", hookenv.INFO)
    tls.set_ca(ca_cert)
    log("Sending global client certificate and key to all related units",
        hookenv.INFO)
    tls.set_client_cert(leader_get('client_certificate'),
                        leader_get('client_key'))
    for client in tls.all_requests:
        try:
            cert_file = os.path.join(cert_dir,
                                     "{}.crt".format(client.common_name))
            key_file = os.path.join(key_dir,
                                    "{}.key".format(client.common_name))
            with open(cert_file, 'r') as file:
                cert = file.read()
            with open(key_file, 'r') as file:
                key = file.read()
            log("Sending certificate for '{}' to unit"
                "'{}'".format(client.common_name, client.unit_name),
                hookenv.INFO)
            log(cert, hookenv.DEBUG)
            client.set_cert(cert, key)

        except FileNotFoundError:
            log("Certificate for '{}' not found in backup. "
                "Generating new one.", hookenv.INFO)
            if client.cert_type == 'client':
                cert, key = create_client_certificate(client.common_name)
            elif client.cert_type == 'server':
                cert, key = create_server_certificate(client.common_name,
                                                      client.sans,
                                                      client.common_name)
            else:
                # This use case should not really happen as easyrsa charm
                # does not support Application type certificates
                raise RuntimeError('Unrecognized certificate request type '
                                   '"{}".'.format(client.cert_type))
            log("Sending certificate for '{}' to unit"
                "'{}'".format(client.common_name, client.unit_name),
                hookenv.INFO)
            log(cert, hookenv.DEBUG)
            client.set_cert(cert, key)

    hookenv._run_atexit()


def list_backups():
    """Implementation of  easyrsa 'list-backups' action."""
    file_list = []

    try:
        file_list = os.listdir(PKI_BACKUP)
    except FileNotFoundError:
        pass

    if file_list:
        message = 'Available backup files:'
        for file in file_list:
            message += '\n{}'.format(file)
    else:
        message = 'There are no available backup files.'

    function_set({'message': message})


def delete_backup():
    """Implementation of easyrsa 'delete-backup' action"""
    backup_name = function_get('name')
    delete_all = function_get('all')

    if not delete_all:
        if backup_name is None:
            raise RuntimeError("Parameter 'name' is required if parameter "
                               "'all' is False.")
        log("Removing backup '{}'".format(backup_name), hookenv.INFO)
        delete_file = os.path.join(PKI_BACKUP, backup_name)
        _check_path_traversal(delete_file, PKI_BACKUP)
        try:
            os.remove(delete_file)
        except FileNotFoundError:
            err_msg = "Backup file '{}' does not exist".format(backup_name)
            log(err_msg, hookenv.ERROR)
            raise RuntimeError(err_msg)
    else:
        log("Removing all backup files.", hookenv.INFO)
        shutil.rmtree(PKI_BACKUP)


ACTIONS = {'backup': backup,
           'restore': restore,
           'list-backups': list_backups,
           'delete-backup': delete_backup
           }


def main(args):
    action_name = os.path.basename(args.pop(0))
    try:
        action = ACTIONS[action_name]
    except KeyError:
        s = "Action {} undefined".format(action_name)
        function_fail(s)
        return
    else:
        try:
            log("Running action '{}'.".format(action_name))
            action()
        except Exception as e:
            function_fail("Action {} failed: {}".format(action_name, str(e)))


if __name__ == '__main__':
    main(sys.argv)
