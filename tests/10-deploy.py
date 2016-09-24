#!/usr/bin/env python3

# This is a functional test for the easyrsa charm.  It verifies the keys and
# certificates are generated correctly.

import amulet
import os
import unittest

seconds = 990


class TestDeployment(unittest.TestCase):
    '''A unittest class to test the results of deploying the easyrsa charm.'''

    @classmethod
    def setUpClass(cls):
        '''Set up the deployment in the class.'''
        cls.deployment = amulet.Deployment(series='xenial')
        charm_name = 'easyrsa'
        print('Starting tests for {0}'.format(charm_name))
        # Specify charm_name because this layer could be named something else.
        cls.deployment.add(charm_name)
        try:
            cls.deployment.setup(timeout=seconds)
            cls.deployment.sentry.wait()
        except amulet.helpers.TimeoutError:
            msg = 'The model did not set up in {0} seconds!'.format(seconds)
            amulet.raise_status(amulet.SKIP, msg=msg)
        except:
            raise
        cls.unit = cls.deployment.sentry[charm_name][0]

    def test_easyrsa_installed(self):
        '''Test that EasyRSA software is installed.'''
        charm_dir = '/var/lib/juju/agents/unit-{service}-{unit}/charm'.format(
            **self.unit.info)
        easyrsa_dir = os.path.join(charm_dir, 'EasyRSA')
        # Create a path to the easyrsa schell script.
        easyrsa_path = os.path.join(easyrsa_dir, 'easyrsa')
        # Get the contents of the easyrsa shell script.
        easyrsa = self.unit.file_contents(easyrsa_path)
        self.assertIsNotNone(easyrsa)
        self.assertNotEqual(easyrsa, '')
        self.assertTrue('Easy-RSA' in easyrsa)

    def test_ca(self):
        '''Test that the ca and key were created.'''
        charm_dir = '/var/lib/juju/agents/unit-{service}-{unit}/charm'.format(
            **self.unit.info)
        easyrsa_dir = os.path.join(charm_dir, 'EasyRSA')
        # Create an absolute path to the ca.crt file.
        ca_path = os.path.join(easyrsa_dir, 'pki/ca.crt')
        # Get the CA certificiate.
        ca_cert = self.unit.file_contents(ca_path)
        self.assertTrue(validate_certificate(ca_cert))
        # Create an absolute path to the ca.key
        key_path = os.path.join(easyrsa_dir, 'pki/private/ca.key')
        # Get the CA key.
        ca_key = self.unit.file_contents(key_path)
        self.assertTrue(validate_key(ca_key))
        # Create an absolute path to the installed location of the ca.
        installed_path = '/usr/local/share/ca-certificates/ca.crt'
        installed_ca = self.unit.file_contents(installed_path)
        self.assertTrue(validate_certificate(installed_ca))
        self.assertEqual(ca_cert, installed_ca)

    def test_client(self):
        '''Test that the client certificate and key were created.'''
        charm_dir = '/var/lib/juju/agents/unit-{service}-{unit}/charm'.format(
            **self.unit.info)
        easyrsa_dir = os.path.join(charm_dir, 'EasyRSA')
        # Create an absolute path to the client certificate.
        cert_path = os.path.join(easyrsa_dir, 'pki/issued/client.crt')
        client_cert = self.unit.file_contents(cert_path)
        self.assertTrue(validate_certificate(client_cert))
        key_path = os.path.join(easyrsa_dir, 'pki/private/client.key')
        client_key = self.unit.file_contents(key_path)
        self.assertTrue(validate_key(client_key))


def validate_certificate(cert):
    '''Return true if the certificate is valid, false otherwise.'''
    # The cert should not be empty and have begin and end statesments.
    return cert and 'BEGIN CERTIFICATE' in cert and 'END CERTIFICATE' in cert


def validate_key(key):
    '''Return true if the key is valid, false otherwise.'''
    # The key should not be empty string and have begin and end statements.
    return key and 'BEGIN PRIVATE KEY'in key and 'END PRIVATE KEY' in key


if __name__ == '__main__':
    unittest.main()
