from elfparser.elfparser import valid_ip_adjacency


def test_valid_ip_adjacency():
    assert valid_ip_adjacency("1.1.1.1", [])
    assert valid_ip_adjacency("1.1.1.1", ["1.1.1.1abc"])
    assert valid_ip_adjacency("1.1.1.1", ["abc1.1.1.1"])
    assert valid_ip_adjacency("1.1.1.1", ["abc1.1.1.1abc"])
    assert valid_ip_adjacency("1.1.1.1", [".1.1.1.1"])
    assert valid_ip_adjacency("1.1.1.1", ["1.1.1.1."])
    assert valid_ip_adjacency("1.1.1.1", [".1.1.1.1."])
    assert not valid_ip_adjacency("1.1.1.1", ["9.1.1.1.1"])
    assert not valid_ip_adjacency("1.1.1.1", ["1.1.1.1.9"])
    assert not valid_ip_adjacency("1.1.1.1", ["9.1.1.1.1.9"])
    assert valid_ip_adjacency("1.1.1.1", ["a.1.1.1.1"])
    assert valid_ip_adjacency("1.1.1.1", ["1.1.1.1.a"])
    assert valid_ip_adjacency("1.1.1.1", ["a.1.1.1.1.a"])
    assert not valid_ip_adjacency("1.1.1.1", ["91.1.1.1"])
    assert not valid_ip_adjacency("1.1.1.1", ["1.1.1.19"])
    assert not valid_ip_adjacency("1.1.1.1", ["91.1.1.19"])

    assert valid_ip_adjacency("1.1.1.1", ["91.1.1.19", "abc1.1.1.1"])
