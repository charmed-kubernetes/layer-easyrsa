#!/usr/local/sbin/charm-env python3
import os
import pwd
import grp
import sys
import tarfile
import shutil

from datetime import datetime
from typing import List

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
)

# Import charm layers and start reactive
layer.import_layer_libs()
hookenv._run_atstart()

PKI_BACKUP = '/home/ubuntu/easyrsa_backup'


def backup() -> None:
    uid = pwd.getpwnam("ubuntu").pw_uid
    gid = grp.getgrnam("ubuntu").gr_gid
    try:
        os.mkdir(PKI_BACKUP, mode=0o700)
    except FileExistsError:
        pass

    os.chown(PKI_BACKUP, uid, gid)
    if not os.path.isdir(PKI_BACKUP):
        raise RuntimeError('Backup destination is not a directory.')

    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    backup_name = 'easy-rsa-{}.tar.gz'.format(timestamp)
    backup_path = os.path.join(PKI_BACKUP, backup_name)
    with tarfile.open(backup_path, mode='w:gz') as tar:
        tar.add(os.path.join(easyrsa_directory, 'pki'), 'pki')

    function_set({
        'command': 'juju scp {}:{} .'.format(local_unit(), backup_path),
        'message': 'Backup archive created successfully. Use the juju scp '
                   'command to copy it to your local machine.'
    })


def restore() -> None:
    pki_dir = os.path.join(easyrsa_directory, 'pki')
    backup_name: str = function_get('name')
    if backup_name is None:
        raise RuntimeError('Parameter \'name\' is required.')

    backup_path = os.path.join(PKI_BACKUP, backup_name)

    shutil.rmtree(pki_dir, ignore_errors=True)
    with tarfile.open(backup_path, 'r:gz') as tar:
        try:
            tar.extractall(easyrsa_directory)
        except KeyError:
            raise RuntimeError('Backup file "{}" does not contain expected '
                               'files'.format(backup_name))

    # Set these values on the leadership data.
    cert_dir = os.path.join(pki_dir, 'issued')
    key_dir = os.path.join(pki_dir, 'private')
    ca_cert = os.path.join(pki_dir, 'ca.crt')
    ca_key = os.path.join(key_dir, 'ca.key')
    serial_file = os.path.join(pki_dir, 'serial')

    with open(ca_cert, 'r') as stream:
        print("Writing ca")
        leader_set({
            'certificate_authority': stream.read()})

    with open(ca_key, 'r') as stream:
        print("Writing key")
        leader_set({
            'certificate_authority_key': stream.read()})

    with open(serial_file, 'r') as stream:
        print("Writing serial")
        leader_set({
            'certificate_authority_serial': stream.read()})

    ca_cert = leader_get('certificate_authority')
    print(ca_cert)
    tls = endpoint_from_name('client')
    tls.set_ca(ca_cert)
    for client in tls.all_requests:
        try:
            cert_file = os.path.join(cert_dir,
                                     "{}.crt".format(client.common_name))
            key_file = os.path.join(key_dir,
                                    "{}.key".format(client.common_name))
            with open(cert_file, 'r') as file:
                cert = file.read()
                print('writing cert to '
                      '{}:\n{}'.format(client.common_name, cert))
            with open(key_file, 'r') as file:
                key = file.read()
            client.set_cert(cert, key)

        except FileNotFoundError:
            print("Cert not found for {}".format(client.common_name))


def list_backups() -> None:
    file_list: List[str] = []

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


def delete_backup() -> None:
    backup_name: str = function_get('name')
    delete_all: bool = function_get('all')

    if not delete_all:
        if backup_name is None:
            raise RuntimeError('Parameter \'name\' is required if parameter '
                               '\'all\' is False.')
        delete_file = os.path.join(PKI_BACKUP, backup_name)
        try:
            os.remove(delete_file)
        except FileNotFoundError:
            raise RuntimeError('Backup file "{}" does not '
                               'exist'.format(backup_name))
    else:
        shutil.rmtree(PKI_BACKUP)
        os.mkdir(PKI_BACKUP)


ACTIONS = {'backup': backup,
           'restore': restore,
           'list-backups': list_backups,
           'delete-backup': delete_backup
           }


def main(args: List) -> None:
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
