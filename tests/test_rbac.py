from bounty_hive.auth import User, can


def test_rbac_permissions():
    assert can(User("v", "viewer"), "read")
    assert not can(User("v", "viewer"), "confirm_scope")
    assert can(User("l", "lead"), "confirm_scope")
    assert can(User("c", "compliance"), "audit")
    assert can(User("a", "admin"), "confirm_scope")
