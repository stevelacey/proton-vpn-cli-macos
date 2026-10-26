from proton.vpn.macos.killswitch import rules


def test_rules_let_the_tunnel_and_server_out_and_block_the_rest():
    lines = rules("185.1.2.3").splitlines()
    assert "pass out quick inet from 10.2.0.2 to any" in lines
    assert "pass out quick to 185.1.2.3" in lines
    assert lines[-1] == "block drop out quick all"


def test_rules_without_a_server():
    assert not [line for line in rules(None).splitlines() if line.startswith("pass out quick to ") and "{" not in line]
