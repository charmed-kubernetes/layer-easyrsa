"""Unit tests for easyrsa reactive layer."""
from os import path
from shlex import split
from unittest import TestCase
from unittest.mock import MagicMock, call, mock_open, patch

from charmhelpers.core import unitdata

from reactive import easyrsa

FLAG_INSTALLED = "easyrsa.installed"


class TestInstall(TestCase):
    """Tests regarding the installation steps."""

    EASYRSA_VERSION = "1.0"

    def setUp(self) -> None:
        # mock `os.stat` so that the install process passes by default
        self.resource_file_stat = MagicMock()
        self.resource_file_stat.st_size = 100000  # This filesize passes check
        os_stat_patch = patch.object(easyrsa.os, "stat")
        self.os_stat_mock = os_stat_patch.start()
        self.os_stat_mock.return_value = self.resource_file_stat

        # patch helper methods from charm/charmhelpers
        easyrsa.resource_get.return_value = "/path/to/easyrsa.tar.gz"
        get_version_patch = patch.object(easyrsa, "get_version")
        self.get_version_mock = get_version_patch.start()
        self.get_version_mock.return_value = self.EASYRSA_VERSION

        # patch methods that try to work with live system
        check_call_patch = patch.object(easyrsa, "check_call")
        self.check_call_mock = check_call_patch.start()

        copytree_patch = patch.object(easyrsa.shutil, "copytree")
        self.copytree_mock = copytree_patch.start()

        rmtree_patch = patch.object(easyrsa.shutil, "rmtree")
        self.rmtree_mock = rmtree_patch.start()

        is_link_patch = patch.object(easyrsa.os.path, "islink")
        self.is_link_mock = is_link_patch.start()
        self.is_link_mock.return_value = True

        is_file_patch = patch.object(easyrsa.os.path, "isfile")
        self.is_file_mock = is_file_patch.start()
        self.is_file_mock.return_value = True

        is_dir_patch = patch.object(easyrsa.os.path, "isdir")
        self.is_dir_mock = is_dir_patch.start()
        self.is_dir_mock.return_value = True

        # clean up mocks after test
        self.addCleanup(get_version_patch.stop)
        self.addCleanup(os_stat_patch.stop)
        self.addCleanup(check_call_patch.stop)
        self.addCleanup(copytree_patch.stop)
        self.addCleanup(rmtree_patch.stop)
        self.addCleanup(is_link_patch.stop)
        self.addCleanup(is_dir_patch.stop)
        self.addCleanup(is_file_patch.stop)

    def tearDown(self) -> None:
        easyrsa.resource_get.side_effect = None
        easyrsa.resource_get.return_value = None

        easyrsa.set_flag.reset_mock()
        easyrsa.clear_flag.reset_mock()

        easyrsa.leader_get.side_effect = None
        easyrsa.leader_get.return_value = None

        easyrsa.leader_set.reset_mock()

        easyrsa.status.blocked.reset_mock()

    def test_install_resource_fetch_failed(self):
        """Test that unit is blocked if "easyrsa" resource fetch fails."""
        easyrsa.resource_get.side_effect = Exception
        expected_msg = "An error occurred fetching the easyrsa resource."

        easyrsa.install()

        easyrsa.status.blocked.assert_called_once_with(expected_msg)
        self.assertNotIn((FLAG_INSTALLED,), easyrsa.set_flag.call_args_list)

    def test_install_resource_missing(self):
        """Test that unit is blocked if "easyrsa" resource is missing."""
        easyrsa.resource_get.return_value = None
        expected_msg = "The easyrsa resource is missing."

        easyrsa.install()

        easyrsa.status.blocked.assert_called_once_with(expected_msg)
        self.assertNotIn((FLAG_INSTALLED,), easyrsa.set_flag.call_args_list)

    def test_install_resource_size_check(self):
        """Test that install fails if "easyrsa" resource is too small."""
        expected_msg = "The easyrsa resource is not complete."

        # 10240 B is cut-off size under which the resource is considered
        # broken/suspicious
        self.resource_file_stat.st_size = 10239

        easyrsa.install()

        easyrsa.status.blocked.assert_called_once_with(expected_msg)
        self.assertNotIn((FLAG_INSTALLED,), easyrsa.set_flag.call_args_list)

    def test_install_easyrsa_generate_new_pki(self):
        """Test easyrsa installation which generates new PKI."""
        generate_pki = split("./easyrsa --batch init-pki 2>&1")
        rm_old_easyrsa = split("rm -v {}".format(easyrsa.easyrsa_directory))
        link_easyrsa_version = split(
            "ln -v -s {}/EasyRSA-{} {}".format(
                easyrsa.charm_directory,
                self.EASYRSA_VERSION,
                easyrsa.easyrsa_directory,
            )
        )
        # PKI directory not present, new PKI must be generated
        self.is_dir_mock.return_value = False

        easyrsa.install()

        # old easyrsa dir removed
        self.is_link_mock.assert_called_with(easyrsa.easyrsa_directory)
        self.check_call_mock.assert_has_calls(
            [
                call(rm_old_easyrsa),
                call(link_easyrsa_version),
                call(generate_pki),
            ]
        )
        easyrsa.set_flag.assert_called_with(FLAG_INSTALLED)

    def test_install_easyrsa_copy_pki(self):
        """Test easyrsa installation which copies existing PKI structure."""
        rm_old_easyrsa = split("rm -v {}".format(easyrsa.easyrsa_directory))
        new_pki_directory = path.join(easyrsa.easyrsa_directory, "pki")
        charm_pki_directory = path.join(easyrsa.charm_directory, "pki")
        link_easyrsa_version = split(
            "ln -v -s {}/EasyRSA-{} {}".format(
                easyrsa.charm_directory,
                self.EASYRSA_VERSION,
                easyrsa.easyrsa_directory,
            )
        )

        self.is_dir_mock.side_effect = (True, False)

        easyrsa.install()

        self.is_link_mock.assert_called_with(easyrsa.easyrsa_directory)
        self.check_call_mock.assert_has_calls(
            [call(rm_old_easyrsa), call(link_easyrsa_version)]
        )
        self.copytree_mock.assert_called_with(
            charm_pki_directory, new_pki_directory, symlinks=True
        )
        self.rmtree_mock.assert_called_with(charm_pki_directory)

    def test_upgrade(self):
        """Test charm upgrade."""
        # Simulate that all required data are in the leader storage
        easyrsa.leader_get.return_value = True

        pki_dir = path.join(easyrsa.easyrsa_directory, "pki")
        charm_pki_dir = path.join(easyrsa.charm_directory, "pki")
        expected_clear_flag_calls = [
            call("easyrsa.installed"),
            call("easyrsa.configured"),
        ]

        # execute upgrade
        easyrsa.upgrade()

        # assert that charm pki dir was replaced with easyrsa pki dir
        self.rmtree_mock.assert_called_once_with(charm_pki_dir)
        self.copytree_mock.assert_called_once_with(
            pki_dir, charm_pki_dir, symlinks=True
        )
        easyrsa.clear_flag.assert_has_calls(expected_clear_flag_calls)

    def test_upgrade_missing_serial(self):
        """Test charm upgrade when "CA serial" is missing.

        This scenario happens when previous easyrsa charm version did not store
         "certificate_authority_serial" in its leader storage on install.
        """
        # Simulate missing serial
        easyrsa.leader_get.side_effect = ("cert data", "key data", None)

        serial_data = "serial data"
        mock_file = mock_open(read_data=serial_data)
        pki_dir = path.join(easyrsa.easyrsa_directory, "pki")
        charm_pki_dir = path.join(easyrsa.charm_directory, "pki")
        expected_clear_flag_calls = [
            call("easyrsa.installed"),
            call("easyrsa.configured"),
        ]

        with patch("builtins.open", mock_file):
            easyrsa.upgrade()

        # assert that CA serial was loaded into leader storage and that
        # charm pki dir was replaced with easyrsa pki dir
        easyrsa.leader_set.assert_called_once_with(
            {"certificate_authority_serial": serial_data}
        )
        self.rmtree_mock.assert_called_once_with(charm_pki_dir)
        self.copytree_mock.assert_called_once_with(
            pki_dir, charm_pki_dir, symlinks=True
        )
        easyrsa.clear_flag.assert_has_calls(expected_clear_flag_calls)

    def test_series_upgrade(self):
        """Test that triggering series upgrade puts unit into blocked state."""
        expected_msg = "Series upgrade in progress"
        easyrsa.pre_series_upgrade()
        easyrsa.status.blocked.assert_called_once_with(expected_msg)


class TestConfiguration(TestCase):
    """Tests related to charm configuration."""

    def tearDown(self) -> None:
        """Cleanup side effects and return values."""
        easyrsa.is_flag_set.return_value = None
        easyrsa.is_flag_set.reset_mock()

        easyrsa.clear_flag.reset_mock()

        easyrsa.status.active.reset_mock()

    def test_set_version(self):
        """Test setting easyrsa charm version."""
        expected_version = "1.0"
        unitdata.kv().set("easyrsa-version", expected_version)

        easyrsa.set_easyrsa_version()

        easyrsa.hookenv.application_version_set.assert_called_once_with(
            expected_version
        )

    def test_configure_copy_extensions_when_missing(self):
        """Test that `copy_extensions` attribute is added to ssl config."""
        ssl_conf_file = path.join(easyrsa.easyrsa_directory, "openssl-1.0.cnf")
        ssl_conf = "[ CA_default ]"
        expected_ssl_config_lines = [ssl_conf, "copy_extensions = copy\n"]
        expected_open_calls = [
            call(ssl_conf_file, "r"),
            call(ssl_conf_file, "w+"),
        ]
        mock_file = mock_open(read_data=ssl_conf)

        # call configure_copy_extension and verify that
        # `copy_extensions = copy` line was added into [ CA_default ] section
        with patch("builtins.open", mock_file):
            easyrsa.configure_copy_extensions()

        mock_file.assert_has_calls(expected_open_calls, any_order=True)
        file_handle = mock_file()
        file_handle.writelines.assert_called_once_with(
            expected_ssl_config_lines
        )

    def test_configure_copy_extension_when_present(self):
        """Test that ssl config file is unchanged.

        If `copy_extension = copy` is already present in the ssl config file,
        it should not be changed.
        """
        ssl_conf_file = path.join(easyrsa.easyrsa_directory, "openssl-1.0.cnf")
        ssl_conf = "[ CA_default ]\ncopy_extensions = copy\n"
        mock_file = mock_open(read_data=ssl_conf)

        with patch("builtins.open", mock_file):
            easyrsa.configure_copy_extensions()

        mock_file.assert_called_with(ssl_conf_file, "r")
        file_handle = mock_file()
        file_handle.writelines.assert_not_called()

    def test_configure_client_authorization(self):
        """Test that 'clientAuth' is added as extendedUsage to server certs."""
        server_conf_file = path.join(
            easyrsa.easyrsa_directory, "x509-types/server"
        )
        # excerpt of easyrsa x509 server certificate conf
        default_server_conf = (
            "basicConstraints = CA:FALSE\n"
            "extendedKeyUsage = serverAuth\n"
            "subjectKeyIdentifier = hash\n"
        )
        # expected server certificate conf with "extendedUsage" modified
        expected_server_conf_lines = [
            "basicConstraints = CA:FALSE\n",
            "extendedKeyUsage = clientAuth, serverAuth\n",
            "subjectKeyIdentifier = hash\n",
        ]
        expected_open_calls = [
            call(server_conf_file, "r"),
            call(server_conf_file, "w+"),
        ]

        mock_file = mock_open(read_data=default_server_conf)

        with patch("builtins.open", mock_file):
            easyrsa.configure_client_authorization()

        mock_file.assert_has_calls(expected_open_calls, any_order=True)
        file_handle = mock_file()
        file_handle.writelines.assert_called_once_with(
            expected_server_conf_lines
        )

    @patch.object(easyrsa, "configure_copy_extensions")
    @patch.object(easyrsa, "configure_client_authorization")
    def test_configure_easyrsa_charm(self, mock_client_auth, mock_copy_ext):
        """Test that configuration hook performs expected tasks."""
        easyrsa.configure_easyrsa()

        mock_client_auth.assert_called_once_with()
        mock_copy_ext.assert_called_once_with()

    def test_message(self):
        """Test function that sets charm status."""
        ca_connected = "Certificate Authority connected."
        ca_ready = "Certificate Authority ready."

        # Test that "CA connected" charm message is set when
        # "client.available" flag is set
        easyrsa.is_flag_set.return_value = True

        easyrsa.message()

        easyrsa.status.active.assert_called_once_with(ca_connected)

        # Reset mocks and test that "CA ready" charm message is set when
        # "client.available" flag is not set
        easyrsa.status.active.reset_mock()
        easyrsa.is_flag_set.return_value = False

        easyrsa.message()

        easyrsa.status.active.assert_called_once_with(ca_ready)


class TestCertificateManagement(TestCase):
    """Tests creation and management of certificates using easyrsa."""

    BUILD_CA = './easyrsa --batch "--req-cn={0}" build-ca nopass 2>&1'
    CA_FILE = "pki/ca.crt"
    KEY_FILE = "pki/private/ca.key"
    SERIAL_FILE = "pki/serial"
    INDEX_FILE = "pki/index.txt"

    def setUp(self) -> None:
        self.cert_data = "ca cert data"
        self.key_data = "ca key data"
        self.serial_data = "serial data"
        self.client_cert = "client cert data"
        self.client_key = "client key data"
        self.server_cert = "server cert data"
        self.server_key = "server key data"

        self.leader_data = {
            "certificate_authority": self.cert_data,
            "certificate_authority_key": self.key_data,
            "certificate_authority_serial": self.serial_data,
            "client_certificate": self.client_cert,
            "client_key": self.client_key,
        }

        # Simulate `leader_get` calls returning appropriate data
        easyrsa.leader_get.side_effect = self.leader_data.get

        # Patch methods that try to work with live system
        check_call_patch = patch.object(easyrsa, "check_call")
        self.check_call_mock = check_call_patch.start()

        make_dirs_patch = patch.object(easyrsa.os, "makedirs")
        self.make_dirs_mock = make_dirs_patch.start()

        is_file_patch = patch.object(easyrsa.os.path, "isfile")
        self.is_file_mock = is_file_patch.start()

        chdir_patch = patch.object(easyrsa, "chdir")
        self.chdir_mock = chdir_patch.start()

        self.addCleanup(check_call_patch.stop)
        self.addCleanup(make_dirs_patch.stop)
        self.addCleanup(is_file_patch.stop)
        self.addCleanup(chdir_patch.stop)

    def tearDown(self) -> None:
        """Reset and cleanup mocks used by tests."""
        easyrsa.leader_get.side_effect = None
        easyrsa.leader_get.return_value = None
        easyrsa.leader_get.reset_mock()

        easyrsa.leader_set.reset_mock()

        easyrsa.endpoint_from_flag.return_value = None
        easyrsa.endpoint_from_flag.side_effect = None
        easyrsa.endpoint_from_flag.reset_mock()

        easyrsa.hookenv.unit_public_ip.return_value = None

        easyrsa.hookenv.service_name.return_value = None

        easyrsa.data_changed.reset_mock()
        easyrsa.data_changed.return_value = None

    def assert_ca_finalized(self, install_ca_mock: MagicMock):
        """Assert that finalization steps of CA creation are performed.

        :param install_ca_mock: Mock of easyrsa.install_ca function
        :return: None
        """
        # leader data are updated
        ca_cert = "certificate_authority"
        ca_key = "certificate_authority_key"
        ca_serial = "certificate_authority_serial"
        expected_calls = [
            call({ca_cert: self.leader_data[ca_cert]}),
            call({ca_key: self.leader_data[ca_key]}),
            call({ca_serial: self.leader_data[ca_serial]}),
        ]
        easyrsa.leader_set.assert_has_calls(expected_calls)

        # install_ca() is called
        install_ca_mock.assert_called_once_with(self.cert_data)

        # Status and flags are set
        unit_status = "Certificate Authority available"
        ca_available_flag = "easyrsa.certificate.authority.available"

        easyrsa.status.active.assert_called_with(unit_status)
        easyrsa.set_flag(ca_available_flag)

    @patch.object(easyrsa, "install_ca")
    def test_create_ca_from_leader_data(self, install_ca_mock: MagicMock):
        """Test creation of Certificate Authority using data from leader."""
        expected_file_opens = [
            call(self.CA_FILE, "w"),
            call(self.KEY_FILE, "w"),
            call(self.SERIAL_FILE, "w"),
            call(self.INDEX_FILE, "w"),
        ]
        expected_make_dirs = [
            call("pki/issued"),
            call("pki/certs_by_serial"),
        ]

        # Setup mocks and handlers for cert/key/serial files
        global_file_mock = mock_open()

        cert_file_mock = mock_open()
        cert_file_handle = cert_file_mock()

        key_file_mock = mock_open()
        key_file_handle = key_file_mock()

        serial_file_mock = mock_open()
        serial_file_handle = serial_file_mock()

        index_file_mock = mock_open()
        index_file_handle = index_file_mock()

        # each call to `open()` receives different file handle so we can verify
        # what is written to each file.
        global_file_mock.side_effect = (
            cert_file_handle,
            key_file_handle,
            serial_file_handle,
            index_file_handle,
        )

        with patch("builtins.open", global_file_mock):
            easyrsa.create_certificate_authority()

        # assert that files CA files are created with data form leader storage
        global_file_mock.assert_has_calls(expected_file_opens, any_order=True)
        cert_file_handle.write.assert_called_once_with(self.cert_data)
        key_file_handle.write.assert_called_once_with(self.key_data)
        serial_file_handle.write.assert_called_once_with(self.serial_data)
        self.make_dirs_mock.assert_has_calls(expected_make_dirs)

        # assert that easyrsa does not generate new CA
        self.check_call_mock.assert_not_called()

        # assert that leader data was updated and unit status and flags set
        self.assert_ca_finalized(install_ca_mock)

    @patch.object(easyrsa, "install_ca")
    def test_create_ca_from_scratch(self, install_ca_mock: MagicMock):
        """Test creation of Certificate Authority from scratch.

        This happens if leader storage does not have previously stored
        certificate authority data.
        """
        ca_ip = "10.0.0.1"
        build_ca_cmd = split(self.BUILD_CA.format(ca_ip))
        easyrsa.hookenv.unit_public_ip.return_value = ca_ip

        expected_file_opens = [
            call(self.CA_FILE, "r"),
            call(self.KEY_FILE, "r"),
            call(self.SERIAL_FILE, "r"),
        ]

        # Setup mocks and handlers for cert/key/serial files
        global_file_mock = mock_open()

        cert_file_mock = mock_open(read_data=self.cert_data)
        cert_file_handle = cert_file_mock()

        key_file_mock = mock_open(read_data=self.key_data)
        key_file_handle = key_file_mock()

        serial_file_mock = mock_open(read_data=self.serial_data)
        serial_file_handle = serial_file_mock()

        # each call to `open()` receives different file handle so we can
        # return different "read" value each time
        global_file_mock.side_effect = (
            cert_file_handle,
            key_file_handle,
            serial_file_handle,
        )

        # Simulate no data in leader_get storage
        easyrsa.leader_get.return_value = None
        easyrsa.leader_get.side_effect = None

        with patch("builtins.open", global_file_mock):
            easyrsa.create_certificate_authority()

        # assert expected files were opened for reading
        global_file_mock.assert_has_calls(expected_file_opens, any_order=True)
        # assert no writes were performed
        cert_file_handle.write.assert_not_called()
        key_file_handle.write.assert_not_called()
        serial_file_handle.write.assert_not_called()

        # assert easyrsa dirs were not overwritten
        self.make_dirs_mock.assert_not_called()

        # assert easyrsa generated new CA
        self.check_call_mock.assert_called_once_with(build_ca_cmd)

        # assert that leader data was updated and unit status and flags set
        self.assert_ca_finalized(install_ca_mock)

    def test_send_ca(self):
        """Test sending CA data over client:tls-certificates relation."""
        endpoint = MagicMock()
        easyrsa.endpoint_from_flag.return_value = endpoint

        easyrsa.send_ca()

        easyrsa.endpoint_from_flag.assert_called_once_with("client.available")
        endpoint.set_ca.assert_called_once_with(self.cert_data)

    @patch.object(easyrsa, "create_client_certificate")
    def test_create_global_client_cert(
        self, create_client_cert_mock: MagicMock
    ):
        """Test creation of shared client certificate."""
        # Make sure that global client cert is not in leader data
        self.leader_data.pop("client_certificate", None)
        self.leader_data.pop("client_key", None)

        cert_created_flag = "easyrsa.global-client-cert.created"
        create_client_cert_mock.return_value = (
            self.client_cert,
            self.client_key,
        )

        expected_leader_set_calls = [
            call({"client_certificate": self.client_cert}),
            call({"client_key": self.client_key}),
        ]
        # execute function
        easyrsa.create_global_client_cert()

        # assert that certificate was generated and stored in leader data
        create_client_cert_mock.assert_called_once_with()
        easyrsa.leader_set.assert_has_calls(expected_leader_set_calls)
        easyrsa.set_flag.assert_called_with(cert_created_flag)

    @patch.object(easyrsa, "create_client_certificate")
    def test_create_global_client_cert_skip(
        self, create_client_cert_mock: MagicMock
    ):
        """Test that shared client certificate is not re-created.

        When global client certificate is already present in leader data, it
        should not be re-created.
        """
        # Make sure that shared certificate is in the leader data
        self.leader_data["client_certificate"] = self.client_cert
        self.leader_data["client_key"] = self.client_key

        cert_created_flag = "easyrsa.global-client-cert.created"

        # execute function
        easyrsa.create_global_client_cert()

        # assert that global client cert was not re-created
        create_client_cert_mock.assert_not_called()
        easyrsa.leader_set.assert_not_called()
        easyrsa.set_flag.assert_called_with(cert_created_flag)

    def test_publish_global_client_cert(self):
        """Test publishing global client certificate to client relation."""
        endpoint = MagicMock()
        easyrsa.endpoint_from_flag.return_value = endpoint

        easyrsa.publish_global_client_cert()

        endpoint.set_client_cert.assert_called_once_with(
            self.client_cert, self.client_key
        )

    @patch.object(easyrsa, "create_server_certificate")
    def test_create_server_cert(self, create_cert_mock: MagicMock):
        """Test responding to requests for server certificates."""

        def cert_constructor(common_name: str, sans: str, name: str):
            """Function that mimics easyrsa.create_server_certificate."""
            host_hash = common_name + sans + name
            return host_hash + "-cert", host_hash + "-key"

        # mock requests in relation endpoint
        request_1 = MagicMock()
        request_1.common_name = "server1.local"
        request_1.sans = "s1"
        request_2 = MagicMock()
        request_2.common_name = "server2.local"
        request_2.sans = "s2"

        # expected certs
        expected_cert_1, expected_key_1 = cert_constructor(
            request_1.common_name, request_1.sans, request_1.common_name
        )
        expected_cert_2, expected_key_2 = cert_constructor(
            request_2.common_name, request_2.sans, request_2.common_name
        )
        # mock endpoint
        tls_endpoint = MagicMock()
        tls_endpoint.new_server_requests = [request_1, request_2]
        easyrsa.endpoint_from_flag.return_value = tls_endpoint

        # mock actual server cert creation
        create_cert_mock.side_effect = cert_constructor

        # execute function
        easyrsa.create_server_cert()

        # assert that certificates were created and stored in the relations
        request_1.set_cert.assert_called_once_with(
            expected_cert_1, expected_key_1
        )
        request_2.set_cert.assert_called_once_with(
            expected_cert_2, expected_key_2
        )

    @patch.object(easyrsa, "create_client_certificate")
    def test_create_client_cert(self, create_cert_mock: MagicMock):
        """Test responding to requests for client certificates."""

        # mock requests in relation endpoint
        request_1 = MagicMock()
        request_1.common_name = "client1.local"
        request_2 = MagicMock()
        request_2.common_name = "client2.local"

        # expected certs
        expected_cert_1 = request_1.common_name + "-cert"
        expected_key_1 = request_1.common_name + "-key"
        expected_cert_2 = request_2.common_name + "-cert"
        expected_key_2 = request_2.common_name + "-key"

        # mock tls endpoint
        tls_endpoint = MagicMock()
        tls_endpoint.new_client_requests = [request_1, request_2]
        easyrsa.endpoint_from_flag.return_value = tls_endpoint

        # mock actual client cert creation
        create_cert_mock.side_effect = lambda x: (x + "-cert", x + "-key")

        # execute function
        easyrsa.create_client_cert()

        # assert that certificates were created and stored in the relations
        request_1.set_cert.assert_called_once_with(
            expected_cert_1, expected_key_1
        )
        request_2.set_cert.assert_called_once_with(
            expected_cert_2, expected_key_2
        )

    def test_generate_server_certificate_new_default_name(self):
        """Test that server cert generating function creates new certificate.

        This test does not specify name for the certificate, so the function
        should default to using name "server" for generated files
        """
        common_name = "host1.local"
        ip_addr = "10.0.0.1"
        sans_arg = "--subject-alt-name=IP:{}".format(ip_addr)

        # simulate that certificate data changed and that it does not already
        # exists
        easyrsa.data_changed.return_value = True
        self.is_file_mock.return_value = False

        # command to generate new server certificate
        gen_cert_cmd = split(
            "./easyrsa --batch --req-cn={0} {1} build-server-full server "
            "nopass 2>&1".format(common_name, sans_arg)
        )

        # without supplying explicit name, default cert/key should
        # be named "server"
        cert_file = "pki/issued/server.crt"
        key_file = "pki/private/server.key"

        expected_file_opens = [
            call(cert_file, "r"),
            call(key_file, "r"),
        ]
        # mock opening of certificate and key files
        file_mock = mock_open()

        cert_file_mock = mock_open(read_data=self.server_cert)
        cert_file_handle = cert_file_mock()

        key_file_mock = mock_open(read_data=self.server_key)
        key_file_handle = key_file_mock()

        file_mock.side_effect = (cert_file_handle, key_file_handle)

        # execute function
        with patch("builtins.open", file_mock):
            new_cert, new_key = easyrsa.create_server_certificate(
                common_name, [ip_addr]
            )

        # assert that new server certificate was generated
        self.chdir_mock.assert_called_once_with(easyrsa.easyrsa_directory)
        self.check_call_mock.assert_called_once_with(gen_cert_cmd)
        file_mock.assert_has_calls(expected_file_opens)
        self.assertEqual(new_cert, self.server_cert)
        self.assertEqual(new_key, self.server_key)

    def test_generate_server_certificate_new_explicit_name(self):
        """Test that server cert generating function creates new certificate.

        This test uses specific name for the certificate, so the function
        should not default to using name "server" for generated files
        """
        common_name = "host1.local"
        ip_addr = "10.0.0.1"
        server = "host1"
        sans_arg = "--subject-alt-name=IP:{}".format(ip_addr)

        # simulate that certificate data changed and that it does not already
        # exist
        easyrsa.data_changed.return_value = True
        self.is_file_mock.return_value = False

        # command to generate new server certificate
        gen_cert_cmd = split(
            "./easyrsa --batch --req-cn={0} {1} build-server-full {2} "
            "nopass 2>&1".format(common_name, sans_arg, server)
        )

        # expect usage of explicit host name for certificate files
        cert_file = "pki/issued/{}.crt".format(server)
        key_file = "pki/private/{}.key".format(server)

        expected_file_opens = [
            call(cert_file, "r"),
            call(key_file, "r"),
        ]
        # mock opening of certificate and key files
        file_mock = mock_open()

        cert_file_mock = mock_open(read_data=self.server_cert)
        cert_file_handle = cert_file_mock()

        key_file_mock = mock_open(read_data=self.server_key)
        key_file_handle = key_file_mock()

        file_mock.side_effect = (cert_file_handle, key_file_handle)

        # execute function
        with patch("builtins.open", file_mock):
            new_cert, new_key = easyrsa.create_server_certificate(
                common_name, [ip_addr], server
            )

        # assert that new server certificate was generated
        self.chdir_mock.assert_called_once_with(easyrsa.easyrsa_directory)
        self.check_call_mock.assert_called_once_with(gen_cert_cmd)
        file_mock.assert_has_calls(expected_file_opens)
        self.assertEqual(new_cert, self.server_cert)
        self.assertEqual(new_key, self.server_key)

    @patch.object(easyrsa, "remove_file_if_exists")
    def test_generate_server_certificate_with_revoke(self, remove_file_mock):
        """Test re-generating server certificate for host.

        This function is also expected to revoke old certificate.
        """
        common_name = "host1.local"
        ip_addr = "10.0.0.1"
        server = "host1"
        sans_arg = "--subject-alt-name=IP:{}".format(ip_addr)

        # simulate that certificate data changed and that older certificate
        # for the same host already exists
        easyrsa.data_changed.return_value = True
        self.is_file_mock.return_value = True

        # expected easyrsa commands
        revoke_cmd = split("./easyrsa --batch revoke {}".format(server))
        gen_cert_cmd = split(
            "./easyrsa --batch --req-cn={0} {1} build-server-full {2} "
            "nopass 2>&1".format(common_name, sans_arg, server)
        )
        expected_easyrsa_calls = [
            call(revoke_cmd),
            call(gen_cert_cmd),
        ]

        # expect usage of explicit host name for certificate files
        cert_file = "pki/issued/{}.crt".format(server)
        key_file = "pki/private/{}.key".format(server)
        req_file = "pki/reqs/{0}.req".format(server)

        expected_file_opens = [
            call(cert_file, "r"),
            call(key_file, "r"),
        ]

        expected_file_remove_calls = [
            call(cert_file),
            call(key_file),
            call(req_file),
        ]

        # mock opening of certificate and key files
        file_mock = mock_open()

        cert_file_mock = mock_open(read_data=self.server_cert)
        cert_file_handle = cert_file_mock()

        key_file_mock = mock_open(read_data=self.server_key)
        key_file_handle = key_file_mock()

        file_mock.side_effect = (cert_file_handle, key_file_handle)

        # execute function
        with patch("builtins.open", file_mock):
            new_cert, new_key = easyrsa.create_server_certificate(
                common_name, [ip_addr], server
            )

        # assert that old certificate is revoked and its files are removed
        # assert that new server certificate is generated
        self.chdir_mock.assert_called_once_with(easyrsa.easyrsa_directory)
        self.check_call_mock.assert_has_calls(expected_easyrsa_calls)
        remove_file_mock.assert_has_calls(expected_file_remove_calls)
        file_mock.assert_has_calls(expected_file_opens)
        self.assertEqual(new_cert, self.server_cert)
        self.assertEqual(new_key, self.server_key)

    def test_create_client_certificate_default_name(self):
        """Test generating new default client certificate."""
        # Default name for client certificates is "client"
        cert_file = "pki/issued/client.crt"
        key_file = "pki/private/client.key"
        generate_cert_cmd = split("./easyrsa build-client-full client nopass")

        # expected file openings
        expected_file_opens = [
            call(cert_file, "r"),
            call(key_file, "r"),
        ]

        # simulate that cert and key do not already exist
        self.is_file_mock.return_value = False

        # mock file openings
        file_mock = mock_open()

        cert_file_mock = mock_open(read_data=self.client_cert)
        cert_file_handle = cert_file_mock()

        key_file_mock = mock_open(read_data=self.client_key)
        key_file_handle = key_file_mock()

        file_mock.side_effect = (cert_file_handle, key_file_handle)

        # execute function
        with patch("builtins.open", file_mock):
            cert, key = easyrsa.create_client_certificate()

        # assert that new certificate was created
        self.check_call_mock.assert_called_once_with(generate_cert_cmd)
        file_mock.assert_has_calls(expected_file_opens)
        self.assertEqual(cert, self.client_cert)
        self.assertEqual(key, self.client_key)

    def test_create_client_certificate_explicit_name(self):
        """Test generating new client certificate with explicit name."""
        client_name = "client1.local"
        cert_file = "pki/issued/{}.crt".format(client_name)
        key_file = "pki/private/{}.key".format(client_name)
        generate_cert_cmd = split(
            "./easyrsa build-client-full {} nopass".format(client_name)
        )

        # expected file openings
        expected_file_opens = [
            call(cert_file, "r"),
            call(key_file, "r"),
        ]

        # simulate that cert and key do not already exist
        self.is_file_mock.return_value = False

        # mock file openings
        file_mock = mock_open()

        cert_file_mock = mock_open(read_data=self.client_cert)
        cert_file_handle = cert_file_mock()

        key_file_mock = mock_open(read_data=self.client_key)
        key_file_handle = key_file_mock()

        file_mock.side_effect = (cert_file_handle, key_file_handle)

        # execute function
        with patch("builtins.open", file_mock):
            cert, key = easyrsa.create_client_certificate(client_name)

        # assert that new certificate was created
        self.check_call_mock.assert_called_once_with(generate_cert_cmd)
        file_mock.assert_has_calls(expected_file_opens)
        self.assertEqual(cert, self.client_cert)
        self.assertEqual(key, self.client_key)

    def test_create_client_certificate_return_existing(self):
        """Test that existing client certificate is returned if it exists.

        In such case, easyrsa should not be used to generate new cert.
        """
        client_name = "client1.local"
        cert_file = "pki/issued/{}.crt".format(client_name)
        key_file = "pki/private/{}.key".format(client_name)

        # expected file openings
        expected_file_opens = [
            call(cert_file, "r"),
            call(key_file, "r"),
        ]

        # simulate that cert and key files already exist
        self.is_file_mock.return_value = True

        # mock file openings
        file_mock = mock_open()

        cert_file_mock = mock_open(read_data=self.client_cert)
        cert_file_handle = cert_file_mock()

        key_file_mock = mock_open(read_data=self.client_key)
        key_file_handle = key_file_mock()

        file_mock.side_effect = (cert_file_handle, key_file_handle)

        # execute function
        with patch("builtins.open", file_mock):
            cert, key = easyrsa.create_client_certificate(client_name)

        # assert that new certificate was created
        self.check_call_mock.assert_not_called()
        file_mock.assert_has_calls(expected_file_opens)
        self.assertEqual(cert, self.client_cert)
        self.assertEqual(key, self.client_key)

    def test_install_ca(self):
        """Install the CA as trusted authority in the systems."""
        update_ca_call = split("update-ca-certificates")
        ca_name = "easyrsa_ca"
        ca_system_path = "/usr/local/share/ca-certificates/{0}.crt".format(
            ca_name
        )
        easyrsa.hookenv.service_name.return_value = ca_name

        file_mock = mock_open()
        file_handle = file_mock()

        # execute function
        with patch("builtins.open", file_mock):
            easyrsa.install_ca(self.cert_data)

        # assert that CA file was copied to expected location and system
        # CA list was updated
        file_mock.assert_has_calls([call(ca_system_path, "w")])
        file_handle.write.assert_called_once_with(self.cert_data)
        self.check_call_mock.assert_called_once_with(update_ca_call)


class TestHelpers(TestCase):
    """Test for helper functions in easyrsa layer."""

    def setUp(self) -> None:
        # Patch methods that try to work with live system
        check_output_patch = patch.object(easyrsa, "check_output")
        self.check_output_mock = check_output_patch.start()

        os_remove_patch = patch.object(easyrsa.os, "remove")
        self.os_remove_mock = os_remove_patch.start()

        # Clean up mocks
        self.addCleanup(check_output_patch.stop)
        self.addCleanup(os_remove_patch.stop)

    def test_is_ip(self):
        """Test helper that returns True if supplied arg is IP address."""
        ip_addr = "10.0.0.1"
        not_ip = "example.org"

        self.assertTrue(easyrsa._is_ip(ip_addr))
        self.assertFalse(easyrsa._is_ip(not_ip))

    def test_get_version(self):
        """Test parsing easyrsa version from easyrsa tar file."""
        tar_output = b"EasyRSA-3.0.8/\nEasyRSA-3.0.8/easyrsa"
        expected_version = "3.0.8"

        self.check_output_mock.return_value = tar_output

        version = easyrsa.get_version("/foo")

        self.assertEqual(version, expected_version)

    def test_get_sans(self):
        """Test generation of subjectAltNames.

        Returned names have prefix either "IP:" or "DNS:" based on whether
        supplied value was an IP address or not.
        """
        ip_addr = "10.0.0.1"
        hostname = "host1.local"
        expected_output = "IP:{},DNS:{}".format(ip_addr, hostname)

        sans = easyrsa.get_sans([ip_addr, hostname])

        self.assertEqual(sans, expected_output)

    def test_remove_file_if_exists(self):
        """Test function that removes files only if they exist.

        This function must mask FileNotFoundError if it occurs.
        """
        self.os_remove_mock.side_effect = FileNotFoundError
        file_to_remove = "/tmp/foo"
        easyrsa.remove_file_if_exists(file_to_remove)

        self.os_remove_mock.assert_called_once_with(file_to_remove)
