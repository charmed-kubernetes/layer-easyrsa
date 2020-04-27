from reactive import easyrsa


def test_series_upgrade():
    assert easyrsa.status.blocked.call_count == 0
    easyrsa.pre_series_upgrade()
    assert easyrsa.status.blocked.call_count == 1
