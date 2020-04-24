import os
import shutil

from shlex import split
from subprocess import check_call
from subprocess import check_output

from charms.reactive import hook
from charms.reactive import when
from charms.reactive import when_not
from charms.reactive.helpers import data_changed
from charms.reactive.relations import endpoint_from_flag
from charms.reactive.flags import is_flag_set
from charms.reactive.flags import clear_flag
from charms.reactive.flags import set_flag

from charmhelpers.core import hookenv
from charmhelpers.core import unitdata
from charmhelpers.core.host import chdir
from charmhelpers.core.hookenv import resource_get

from charms.leadership import leader_set
from charms.leadership import leader_get

from charms.layer import status


charm_directory = hookenv.charm_dir()
easyrsa_directory = os.path.join(charm_directory, 'EasyRSA')


@when_not('easyrsa.installed')
def install():
    '''Install the easy-rsa software that is used by this layer.'''
    easyrsa_resource = None
    try:
        # Try to get the resource from Juju.
        easyrsa_resource = resource_get('easyrsa')
    except Exception as e:
        message = 'An error occurred fetching the easyrsa resource.'
        hookenv.log(message)
        hookenv.log(e)
        hookenv.status.blocked(message)
        return

    if not easyrsa_resource:
        hookenv.status.blocked('The easyrsa resource is missing.')
        return

    # Get the filesize in bytes.
    filesize = os.stat(easyrsa_resource).st_size
    # When the filesize is less than 10 KB we do not have a real file.
    if filesize < 10240:
        hookenv.status.blocked('The easyrsa resource is not complete.')
        return

    # Expand the archive in the charm directory creating an EasyRSA directory.
    untar = 'tar -xvzf {0} -C {1}'.format(easyrsa_resource, charm_directory)
    check_call(split(untar))

    version = get_version(easyrsa_resource)
    # Save the version in the key/value store of the charm.
    unitdata.kv().set('easyrsa-version', version)

    if os.path.islink(easyrsa_directory):
        check_call(split('rm -v {0}'.format(easyrsa_directory)))

    # Link the EasyRSA version directory to a common name.
    link = 'ln -v -s {0}/EasyRSA-{1} {2}'.format(charm_directory,
                                                 version,
                                                 easyrsa_directory)
    check_call(split(link))
    # The charm pki directory contains backup of pki for upgrades.
    charm_pki_directory = os.path.join(charm_directory, 'pki')
    if os.path.isdir(charm_pki_directory):
        new_pki_directory = os.path.join(easyrsa_directory, 'pki')
        # Only copy the directory if the new_pki_directory does not exist.
        if not os.path.isdir(new_pki_directory):
            # Copy the pki to this new directory.
            shutil.copytree(charm_pki_directory, new_pki_directory,
                            symlinks=True)
        # We are done with the old charm pki directory, so delete contents.
        shutil.rmtree(charm_pki_directory)
    else:
        # Create new pki.
        with chdir(easyrsa_directory):
            check_call(split('./easyrsa --batch init-pki 2>&1'))
    set_flag('easyrsa.installed')


@when('easyrsa.installed')
def set_easyrsa_version():
    '''Find the version of easyrsa and set that on the charm.'''
    version = unitdata.kv().get('easyrsa-version')
    hookenv.application_version_set(version)


@when('easyrsa.installed')
@when_not('easyrsa.configured')
def configure_easyrsa():
    '''A transitional state to allow modifications to configuration before
    generating the certificates and working with PKI.'''
    hookenv.log('Configuring OpenSSL to copy extensions.')
    configure_copy_extensions()
    hookenv.log('Configuring X509 server extensions with clientAuth.')
    configure_client_authorization()
    set_flag('easyrsa.configured')


def configure_copy_extensions():
    '''Update the EasyRSA configuration with the capacity to copy the exensions
    through to the resulting certificates. '''
    # Create an absolute path to the file which will not be impacted by cwd.
    openssl_file = os.path.join(easyrsa_directory, 'openssl-1.0.cnf')
    # Update EasyRSA configuration with the capacity to copy CSR Requested
    # Extensions through to the resulting certificate. This can be tricky,
    # and the implications are not fully clear on this.
    with open(openssl_file, 'r') as f:
        conf = f.readlines()
    # When the copy_extensions key is not in the configuration.
    if 'copy_extensions = copy\n' not in conf:
        for idx, line in enumerate(conf):
            if '[ CA_default ]' in line:
                # Insert a new line with the copy_extensions key set to copy.
                conf.insert(idx + 1, "copy_extensions = copy\n")
        with open(openssl_file, 'w+') as f:
            f.writelines(conf)


def configure_client_authorization():
    '''easyrsa has a default OpenSSL configuration that does not support
    client authentication. Append "clientAuth" to the server ssl certificate
    configuration. This is not default, to enable this in your charm set the
    reactive state 'tls.client.authorization.required'.
    '''
    # Use an absolute path so current directory does not affect the result.
    openssl_config = os.path.join(easyrsa_directory, 'x509-types/server')
    hookenv.log('Updating {0}'.format(openssl_config))

    # Read the X509 server extension file in.
    with open(openssl_config, 'r') as f:
        server_extensions = f.readlines()

    client_server = []
    for line in server_extensions:
        # Replace the extendedKeyUsage with clientAuth and serverAuth.
        if 'extendedKeyUsage' in line:
            line = line.replace('extendedKeyUsage = serverAuth',
                                'extendedKeyUsage = clientAuth, serverAuth')
        client_server.append(line)
    # Write the configuration file back out.
    with open(openssl_config, 'w+') as f:
        f.writelines(client_server)


@when('easyrsa.configured')
@when('leadership.is_leader')
@when_not('easyrsa.certificate.authority.available')
@when_not('upgrade.series.in-progress')
def create_certificate_authority():
    '''Return the CA and server certificates for this system. If the CA is
    empty, generate a self signged certificate authority.'''
    ca_file = 'pki/ca.crt'
    key_file = 'pki/private/ca.key'
    serial_file = 'pki/serial'

    with chdir(easyrsa_directory):
        if leader_get('certificate_authority') and \
                leader_get('certificate_authority_key'):
            hookenv.log('Recovering CA from controller')
            certificate_authority = \
                leader_get('certificate_authority')
            certificate_authority_key = \
                leader_get('certificate_authority_key')
            certificate_authority_serial = \
                leader_get('certificate_authority_serial')

            # Write the CA from existing relation.
            with open(ca_file, 'w') as f_out:
                f_out.write(certificate_authority)

            # Write the private key from existing relation.
            with open(key_file, 'w') as f_out:
                f_out.write(certificate_authority_key)

            # Write the serial from existing relation.
            with open(serial_file, 'w') as f_out:
                f_out.write(certificate_authority_serial)

            # Bluff required files and folders.
            with open('pki/index.txt', 'w') as f_out:
                pass
            os.makedirs('pki/issued')
            os.makedirs('pki/certs_by_serial')

        else:
            hookenv.log('Creating new CA')
            # The Common Name (CN) for a certificate
            # must be an IP or hostname.
            cn = hookenv.unit_public_ip()
            # Create a self signed CA with the CN, stored pki/ca.crt
            build_ca = \
                './easyrsa --batch "--req-cn={0}" build-ca nopass 2>&1'
            # Build a self signed Certificate Authority.
            check_call(split(build_ca.format(cn)))

            # Read the CA so it can be returned in leader data.
            with open(ca_file, 'r') as stream:
                certificate_authority = stream.read()

            # Read the private key so it can be set in leader data.
            with open(key_file, 'r') as stream:
                certificate_authority_key = stream.read()

            with open(serial_file, 'r') as stream:
                certificate_authority_serial = stream.read()

    # Set these values on the leadership data.
    leader_set({
        'certificate_authority': certificate_authority})
    leader_set({
        'certificate_authority_key': certificate_authority_key})
    leader_set({
        'certificate_authority_serial': certificate_authority_serial})

    # Install the CA on this system as a trusted CA.
    install_ca(certificate_authority)
    status.active('Certificiate Authority available')

    set_flag('easyrsa.certificate.authority.available')


@when('easyrsa.certificate.authority.available')
@when_not('upgrade.series.in-progress')
def message():
    '''Set a message to notify the user that this charm is ready.'''
    if is_flag_set('client.available'):
        status.active('Certificate Authority connected.')
    else:
        status.active('Certificate Authority ready.')


@when('client.available', 'easyrsa.certificate.authority.available')
@when('leadership.is_leader')
def send_ca():
    '''The client relationship has been established, read the CA and client
    certificate from leadership data to set them on the relationship object.'''
    tls = endpoint_from_flag('client.available')
    certificate_authority = leader_get('certificate_authority')
    tls.set_ca(certificate_authority)


@when('leadership.is_leader',
      'easyrsa.certificate.authority.available',
      'client.available')
@when_not('easyrsa.global-client-cert.created')
def create_global_client_cert():
    """
    This is for backwards compatibility with older tls-certificate clients
    only.  Obviously, it's not good security / design to have clients sharing
    a certificate, but it seems that there are clients that depend on this
    (though some, like etcd, only block on the flag that it triggers but don't
    actually use the cert), so we have to set it for now.
    """
    client_cert = leader_get('client_certificate')
    client_key = leader_get('client_key')
    if not client_cert or not client_key:
        hookenv.log("Unable to find global client cert on "
                    "leadership data, generating...")
        client_cert, client_key = create_client_certificate()
        # Set the client certificate and key on leadership data.
        leader_set({'client_certificate': client_cert})
        leader_set({'client_key': client_key})
    else:
        hookenv.log("found global client cert on leadership "
                    "data, not generating...")
    set_flag('easyrsa.global-client-cert.created')


@when('leadership.is_leader',
      'easyrsa.global-client-cert.created',
      'client.available')
def publish_global_client_cert():
    # global client cert needs to always be re-published to account for new
    # clients joining
    tls = endpoint_from_flag('client.available')
    tls.set_client_cert(leader_get('client_certificate'),
                        leader_get('client_key'))


@when('client.server.certs.requested', 'easyrsa.configured')
def create_server_cert():
    '''Create server certificates with the request information from the
    relation object.'''

    tls = endpoint_from_flag('client.server.certs.requested')

    # Iterate over all new requests
    for request in tls.new_server_requests:
        cn = request.common_name
        sans = request.sans
        name = request.common_name
        # Create the server certificate based on the information in request.
        server_cert, server_key = create_server_certificate(cn, sans, name)
        # Set the certificate and key for the unit on the relationship object.
        request.set_cert(server_cert, server_key)


@when('client.client.certs.requested', 'easyrsa.configured')
def create_client_cert():
    '''Create client certificates with the request information from the
    relation object.'''

    tls = endpoint_from_flag('client.client.certs.requested')

    # Iterate over all new requests
    for request in tls.new_client_requests:
        # Create a client certificate for this request.
        name = request.common_name
        client_cert, client_key = create_client_certificate(name)
        # Set the client certificate and key on the relationship object.
        request.set_cert(client_cert, client_key)


@hook('upgrade-charm')
def upgrade():
    '''An upgrade has been triggered.'''
    pki_directory = os.path.join(easyrsa_directory, 'pki')
    if os.path.isdir(pki_directory):
        charm_pki_directory = os.path.join(charm_directory, 'pki')
        # When the charm pki directory exists, it is stale, remove it.
        if os.path.isdir(charm_pki_directory):
            shutil.rmtree(charm_pki_directory)
        # Copy the EasyRSA/pki to the charm pki directory.
        shutil.copytree(pki_directory, charm_pki_directory, symlinks=True)
    clear_flag('easyrsa.installed')
    clear_flag('easyrsa.configured')


@hook('pre-series-upgrade')
def pre_series_upgrade():
    status.blocked('Series upgrade in progress')


def remove_file_if_exists(filename):
    try:
        os.remove(filename)
    except FileNotFoundError:
        pass


def create_server_certificate(cn, san_list, name=None):
    '''Return a newly created server certificate and server key from a
    common name, list of Subject Alternate Names, and the certificate name.'''
    if name is None:
        name = 'server'
    server_cert = None
    server_key = None
    with chdir(easyrsa_directory):
        # Create the path to the server certificate.
        cert_file = 'pki/issued/{0}.crt'.format(name)
        # Create the path to the server key.
        key_file = 'pki/private/{0}.key'.format(name)
        # Create the path to the request file
        req_file = 'pki/reqs/{0}.req'.format(name)
        # Get a string compatible with easyrsa for the subject-alt-names.
        sans = get_sans(san_list)
        sans_arg = '--subject-alt-name={}'.format(sans) if sans else ''
        this_cert = {'sans': sans, 'cn': cn, 'name': name}
        changed = data_changed('server_cert.' + name, this_cert)
        cert_exists = os.path.isfile(cert_file) and os.path.isfile(key_file)
        # Do not regenerate the server certificate if it already exists
        # and the data hasn't changed.
        if changed and cert_exists:
            # We need to revoke the existing cert and regenerate it
            revoke = './easyrsa --batch revoke {0}'.format(name)
            check_call(split(revoke))
            # nuke old files if they exist
            remove_file_if_exists(cert_file)
            remove_file_if_exists(key_file)
            remove_file_if_exists(req_file)
        if changed or not cert_exists:
            # Create a server certificate for the server based on the CN.
            server = './easyrsa --batch --req-cn={0} {1} ' \
                     'build-server-full {2} nopass 2>&1'.format(cn,
                                                                sans_arg,
                                                                name)
            check_call(split(server))
        # Read the server certificate from the file system.
        with open(cert_file, 'r') as stream:
            server_cert = stream.read()
        # Read the server key from the file system.
        with open(key_file, 'r') as stream:
            server_key = stream.read()
    return server_cert, server_key


def create_client_certificate(name='client'):
    '''Return a newly created client certificate and client key, by name.'''
    client_cert = None
    client_key = None
    with chdir(easyrsa_directory):
        # Create a path to the client certificate.
        cert_file = 'pki/issued/{0}.crt'.format(name)
        # Create a path to the client key.
        key_file = 'pki/private/{0}.key'.format(name)
        # Do not regenerate the client certificate if it already exists.
        if not os.path.isfile(cert_file) and not os.path.isfile(key_file):
            # Create a client certificate and key.
            check_call(['./easyrsa', 'build-client-full', name, 'nopass'])
        # Read the client certificate from the file system.
        with open(cert_file, 'r') as stream:
            client_cert = stream.read()
        # Read the client key from the file system.
        with open(key_file, 'r') as stream:
            client_key = stream.read()
    return client_cert, client_key


def install_ca(certificate_authority):
    '''Install a certificiate authority on the system by calling the
    update-ca-certificates command.'''
    name = hookenv.service_name()
    ca_file = '/usr/local/share/ca-certificates/{0}.crt'.format(name)
    hookenv.log('Writing CA to {0}'.format(ca_file))
    # Write the contents of certificate authority to the file.
    with open(ca_file, 'w') as fp:
        fp.write(certificate_authority)
    # Update the trusted CAs on this system.
    check_call(['update-ca-certificates'])
    message = 'Generated ca-certificates.crt for {0}'.format(name)
    hookenv.log(message)


def get_sans(address_list=[]):
    '''Return a string suitable for the easy-rsa subjectAltNames.'''
    sans = []
    for address in address_list:
        if _is_ip(address):
            sans.append('IP:{0}'.format(address))
        else:
            sans.append('DNS:{0}'.format(address))
    return ','.join(sans)


def get_version(path):
    '''Return the version of EasyRSA by investigating the tar file.'''
    # Create a command that lists the tar file.
    cmd = 'tar -tf {0}'.format(path)
    # Get the listing of the directories and files in the tar file.
    output = check_output(split(cmd)).decode('utf-8')
    # Get the first listing which is the directory.
    directory = output.splitlines()[0]
    # Remove the path separator from the string.
    if '/' in directory:
        directory = directory.replace('/', '')
    # Get the version by splitting on the hypen.
    return directory.split('-')[1]


def _is_ip(address):
    '''Return True if the address is an IP address, false otherwise.'''
    import ipaddress
    try:
        # This method will raise a ValueError if argument is not an IP address.
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False
