import os
import shutil

from shlex import split
from subprocess import check_call
from subprocess import check_output

from charms.reactive import hook
from charms.reactive import is_state
from charms.reactive import remove_state
from charms.reactive import set_state
from charms.reactive import when
from charms.reactive import when_not
from charms.reactive.helpers import data_changed

from charmhelpers.core import hookenv
from charmhelpers.core import unitdata
from charmhelpers.core.host import chdir
from charmhelpers.core.hookenv import resource_get
from charmhelpers.core.hookenv import status_set

from charms.leadership import leader_set
from charms.leadership import leader_get


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
        hookenv.status_set('blocked', message)
        return

    if not easyrsa_resource:
        hookenv.status_set('blocked', 'The easyrsa resource is missing.')
        return

    # Get the filesize in bytes.
    filesize = os.stat(easyrsa_resource).st_size
    # When the filesize is less than 10 KB we do not have a real file.
    if filesize < 10240:
        hookenv.status_set('blocked', 'The easyrsa resource is not complete.')
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
    set_state('easyrsa.installed')


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
    set_state('easyrsa.configured')


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
def create_certificate_authority():
    '''Return the CA and server certificates for this system. If the CA is
    empty, generate a self signged certificate authority.'''
    with chdir(easyrsa_directory):
        # The Common Name (CN) for a certificate must be an IP or hostname.
        cn = hookenv.unit_public_ip()
        # Create a self signed CA with the CN, stored pki/ca.crt
        build_ca = './easyrsa --batch "--req-cn={0}" build-ca nopass 2>&1'
        # Build a self signed Certificate Authority.
        check_call(split(build_ca.format(cn)))

        ca_file = 'pki/ca.crt'
        # Read the CA so it can be returned in leader data.
        with open(ca_file, 'r') as stream:
            certificate_authority = stream.read()

        key_file = 'pki/private/ca.key'
        # Read the private key so it can be set in leader data.
        with open(key_file, 'r') as stream:
            ca_key = stream.read()

        # Set these values on the leadership data.
        leader_set({'certificate_authority': certificate_authority})
        leader_set({'certificate_authority_key': ca_key})
        # Install the CA on this system as a trusted CA.
        install_ca(certificate_authority)
        # Create a client certificate for this CA.
        client_cert, client_key = create_client_certificate()
        # Set the client certificate and key on leadership data.
        leader_set({'client_certificate': client_cert})
        leader_set({'client_key': client_key})
        status_set('active', 'Certificiate Authority available')
    set_state('easyrsa.certificate.authority.available')


@when('easyrsa.certificate.authority.available')
def message():
    '''Set a message to notify the user that this charm is ready.'''
    if is_state('client.available'):
        status_set('active', 'Certificate Authority connected.')
    else:
        status_set('active', 'Certificate Authority ready.')


@when('client.available', 'easyrsa.certificate.authority.available')
@when('leadership.is_leader')
def send_ca(tls):
    '''The client relationship has been established, read the CA and client
    certificate from leadership data to set them on the relationship object.'''
    certificate_authority = leader_get('certificate_authority')
    tls.set_ca(certificate_authority)
    # The client cert and key should be same for all connections.
    client_cert = leader_get('client_certificate')
    client_key = leader_get('client_key')
    # Set the client certificate and key on the relationship object.
    tls.set_client_cert(client_cert, client_key)


@when('client.server.cert.requested', 'easyrsa.configured')
def create_server_cert(tls):
    '''Create server certificates with the request information from the
    relation object.'''
    # Get the map of unit names to requests.
    requests = tls.get_server_requests()
    # Iterate over all items in the map.
    for unit_name, request in requests.items():
        cn = request.get('common_name')
        sans = request.get('sans')
        name = request.get('certificate_name')
        # Create the server certificate based on the information in request.
        server_cert, server_key = create_server_certificate(cn, sans, name)
        # Set the certificate and key for the unit on the relationship object.
        tls.set_server_cert(unit_name, server_cert, server_key)


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
    remove_state('easyrsa.installed')
    remove_state('easyrsa.configured')


def remove_file_if_exists(filename):
    try:
        os.remove(filename)
    except FileNotFoundError:
        pass


def create_server_certificate(cn, san_list, name='server'):
    '''Return a newly created server certificate and server key from a
    common name, list of Subject Alternate Names, and the certificate name.'''
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
            server = './easyrsa --batch --req-cn={0} --subject-alt-name={1} ' \
                     'build-server-full {2} nopass 2>&1'.format(cn, sans, name)
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
            client = './easyrsa build-client-full {0} nopass 2>&1'.format(name)
            check_call(split(client))
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
