import logging
import re
from pathlib import Path
from juju.unit import Unit
import pytest
from pytest_operator.plugin import OpsTest

log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, series):
    """Build and deploy bundle"""
    charm = next(Path.cwd().glob("easyrsa*.charm"), None)
    if not charm:
        log.info("Build Charm...")
        charm = await ops_test.build_charm(".")

    resource = next(Path.cwd().glob("easyrsa*.tgz"), None)
    if not resource:
        log.info("Fetching Resource...")
        resources = await ops_test.download_resources(
            charm.resolve(), None, "latest/edge"
        )
    else:
        log.info("Using Resource...")
        resources = {"easyrsa": str(resource.resolve())}

    bundle = ops_test.render_bundle(
        "tests/data/bundle.yaml",
        main_charm=charm.resolve(),
        series=series,
        resources=resources,
    )
    await ops_test.model.deploy(bundle)
    await ops_test.model.wait_for_idle(status="active", timeout=60 * 60)


async def test_status_messages(ops_test):
    """Validate that the status messages are correct."""
    for unit in easyrsa_units(ops_test):
        assert unit.workload_status == "active"
        msg = re.compile(r"Certificate Authority (connected|ready).")
        assert msg.match(unit.workload_status_message)


async def test_easyrsa_installed(ops_test):
    """Test that EasyRSA software is installed."""

    for unit in easyrsa_units(ops_test):
        charm_dir = charm_path(unit)
        easyrsa_dir = Path(charm_dir, "EasyRSA")

        # Create a path to the easyrsa shell script.
        easyrsa_path = Path(easyrsa_dir, "easyrsa")
        # Get the contents of the easyrsa shell script.
        easyrsa = await file_contents(unit, easyrsa_path)
        assert easyrsa not in ["", None]
        assert "Easy-RSA" in easyrsa


async def test_ca(ops_test):
    """Test that the ca and key were created."""

    for unit in easyrsa_units(ops_test):
        charm_dir = charm_path(unit)
        easyrsa_dir = Path(charm_dir, "EasyRSA")
        # Create an absolute path to the ca.crt file.
        ca_path = Path(easyrsa_dir, "pki/ca.crt")
        # Get the CA certificate.
        ca_cert = await file_contents(unit, ca_path)
        assert validate_certificate(ca_cert)
        # Create an absolute path to the ca.key
        key_path = Path(easyrsa_dir, "pki/private/ca.key")
        # Get the CA key.
        ca_key = await file_contents(unit, key_path)
        assert validate_key(ca_key)


@pytest.mark.xfail(
    reason="Client certs are not created without a charm integration",
    raises=RuntimeError,
)
async def test_client(ops_test):
    """Test that the client certificate and key were created."""
    for unit in easyrsa_units(ops_test):
        charm_dir = charm_path(unit)
        easyrsa_dir = Path(charm_dir, "EasyRSA")
        # Create an absolute path to the client certificate.
        cert_path = Path(easyrsa_dir, "pki/issued/client.crt")
        client_cert = await file_contents(unit, cert_path)
        assert validate_certificate(client_cert)

        key_path = Path(easyrsa_dir, "pki/private/client.key")
        client_key = await file_contents(unit, key_path)
        assert validate_key(client_key)


def easyrsa_units(ops_test) -> list[Unit]:
    """Get the easyrsa units."""
    return [
        unit
        for name, app in ops_test.model.applications.items()
        if "easyrsa" in name
        for unit in app.units
    ]


def charm_path(unit: Unit) -> Path:
    """Get the path to the charm."""
    # Get the path to the charm.
    return Path(
        "/var/lib/juju/agents/unit-{}/charm".format(unit.name.replace("/", "-"))
    )


async def file_contents(unit: Unit, path: str) -> str:
    """Get the contents of a file."""
    # Get the contents of the file.
    event = await unit.run(
        f"cat '{path}'",
    )
    action = await event.wait()
    # Check if the command was successful.
    if action.results["return-code"] != 0:
        raise RuntimeError(f"Failed to get file contents: {action.results['stderr']}")
    # Get the contents of the file.
    return action.results["stdout"]


def validate_certificate(cert):
    """Return true if the certificate is valid, false otherwise."""
    # The cert should not be empty and have begin and end statements.
    return cert and "BEGIN CERTIFICATE" in cert and "END CERTIFICATE" in cert


def validate_key(key):
    """Return true if the key is valid, false otherwise."""
    # The key should not be empty string and have begin and end statements.
    return key and "BEGIN PRIVATE KEY" in key and "END PRIVATE KEY" in key
