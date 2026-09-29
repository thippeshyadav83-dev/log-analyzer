from app import analyze


def make_log(ip, n):
    return "\n".join(f"Failed password for root from {ip} port 22 ssh2" for _ in range(n))


def test_brute_force_detected():
    alerts = analyze(make_log("1.2.3.4", 6))
    assert alerts[0]["ip"] == "1.2.3.4"
    assert alerts[0]["type"] == "Brute force"


def test_below_threshold_ignored():
    assert analyze(make_log("1.2.3.4", 2)) == []


def test_high_severity():
    assert analyze(make_log("1.2.3.4", 25))[0]["severity"] == "High"


def test_username_guessing():
    log = "\n".join(f"Failed password for invalid user u{i} from 9.9.9.9 port 22" for i in range(5))
    assert any(a["type"] == "Username guessing" for a in analyze(log))
