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
        raise RuntimeError('Backup destination is not a directory.')


def _verify_backup(tarball):
    """
    Verify that backup archive contains expected files

    :param tarball: Tarfile object containing easyrsa backup
    :return: None
    """
    members = set(tarball.getnames())
    if members.issubset(TAR_STRUCTURE):
        raise RuntimeError("Backup has unexpected content. Corrupted file?")


def _replace_pki(pki_tar, pki_dir):
    """
    Safely replace easyrsa pki directory.

    If there are any problems during the extraction of the backup. Original
    pki directory will be brought back and error raised.

    :param pki_tar: Tarfile object containing easyrsa backup
    :param pki_dir: Destination for extraction of easyrsa backup
    :return: None
    """
    safety_backup = os.path.join(easyrsa_directory, 'pki_backup')
    shutil.move(pki_dir, safety_backup)
    try:
        pki_tar.extractall(easyrsa_directory)
    except Exception as exc:
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
        leader_set({
            'certificate_authority': stream.read()})

    with open(ca_key, 'r') as stream:
        leader_set({
            'certificate_authority_key': stream.read()})

    with open(serial_file, 'r') as stream:
        leader_set({
            'certificate_authority_serial': stream.read()})

    with open(global_client_cert) as stream:
        leader_set({'client_certificate': stream.read()})

    with open(global_client_key) as stream:
        leader_set({'client_key': stream.read()})


def backup():
    """
    Implementation of easyrsa 'backup' action.

    Currently deployed pki is packed into tarball and stored in the
    backups directory.
    :return:
    """
    _ensure_backup_dir_exists()

    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    backup_name = 'easyrsa-{}.tar.gz'.format(timestamp)
    backup_path = os.path.join(PKI_BACKUP, backup_name)
    with tarfile.open(backup_path, mode='w:gz') as tar:
        tar.add(os.path.join(easyrsa_directory, 'pki'), 'pki')

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
        * All units that have relation with this easyrsa unit will be notified
          about the certificate changes.
    """
    pki_dir = os.path.join(easyrsa_directory, 'pki')
    backup_name = function_get('name')

    if backup_name is None:
        raise RuntimeError("Parameter 'name' is required.")

    backup_path = os.path.join(PKI_BACKUP, backup_name)

    if not os.path.isfile(backup_path):
        raise RuntimeError("Backup with name '{}' does not exist. Use action "
                           "'list-backups' to list all available "
                           "backups".format(backup_name))

    with tarfile.open(backup_path, 'r:gz') as tar:
        _verify_backup(tar)
        _replace_pki(tar, pki_dir)

    cert_dir = os.path.join(pki_dir, 'issued')
    key_dir = os.path.join(pki_dir, 'private')

    _update_leadership_data(pki_dir, cert_dir, key_dir)

    ca_cert = leader_get('certificate_authority')
    tls = endpoint_from_name('client')
    tls.set_ca(ca_cert)
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
            client.set_cert(cert, key)

        except FileNotFoundError:
            if client.cert_type == 'client':
                cert, key = create_client_certificate(client.common_name)
                client.set_cert(cert, key)
            elif client.cert_type == 'server':
                cert, key = create_server_certificate(client.common_name,
                                                      client.sans,
                                                      client.common_name)
                client.set_cert(cert, key)
            else:
                # This use case should not really happen as easyrsa charm
                # does not support Application type certificates
                function_fail('Unrecognized certificate request type '
                              '"{}".'.format(client.cert_type))

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
        delete_file = os.path.join(PKI_BACKUP, backup_name)
        try:
            os.remove(delete_file)
        except FileNotFoundError:
            raise RuntimeError('Backup file "{}" does not '
                               'exist'.format(backup_name))
    else:
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
            action()
        except Exception as e:
            function_fail("Action {} failed: {}".format(action_name, str(e)))


if __name__ == '__main__':
    main(sys.argv)
