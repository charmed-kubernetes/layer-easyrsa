from reactive import easyrsa


def test_series_upgrade():
    assert easyrsa.status_set.call_count == 0
    easyrsa.pre_series_upgrade()
    assert easyrsa.status_set.call_count == 1
