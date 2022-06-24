import pytest
import vault_lookup as vl


@pytest.fixture(scope="function")
def lookups_salt():
    return {}


@pytest.fixture(scope="function")
def env():
    return vl.get_default_jinja2_environment()


@pytest.fixture(scope="function")
def path_simple():
    return vl.LookupPath("secret/simple", False)


@pytest.fixture(scope="function")
def path_wildcard():
    return vl.LookupPath("secret/*/wildcard", False)


@pytest.fixture(scope="function")
def path_wildcard2():
    return vl.LookupPath("secret/*/wildcard/*/two", False)


@pytest.fixture(scope="function")
def path_wildcard_pillar():
    return vl.LookupPath("atar/hier/*", True)


@pytest.fixture(scope="function")
def path_lookup():
    return vl.LookupPath("secret/G@id/data", False)


@pytest.fixture(scope="function")
def path_lookup_match():
    return vl.LookupPath("secret/I@cluster=c1/data", False)


@pytest.fixture(scope="function")
def path_lookup_pillar_list():
    return vl.LookupPath("secret/I@cluster/data", False)


@pytest.fixture(scope="function")
def path_lookup_pillar_list2():
    return vl.LookupPath("secret/I@cluster/I@appslave/data", False)


@pytest.fixture(scope="function")
def path_lookup_mixed():
    return vl.LookupPath("secret/I@cluster/*/I@appslave/*/data", False)


@pytest.fixture(scope="function")
def path_lookup_mixed_pillar():
    return vl.LookupPath("srv/I@appslave/I@cluster/*/*", True)


@pytest.fixture(scope="function")
def path_lookup_single_mixed_pillar():
    return vl.LookupPath("to/I@appslave=s1/I@cluster=c1/G@id/one", True)


@pytest.fixture(scope="function")
def path_template_simple(config_template_simple):
    return config_template_simple.path


@pytest.fixture(scope="function")
def path_template_simple_pillar(config_template_simple):
    return config_template_simple.pillarpath


@pytest.fixture(scope="function")
def path_template_dependency(config_template_dependency):
    return config_template_dependency.path


@pytest.fixture(scope="function")
def path_template_dependency_pillar(config_template_dependency):
    return config_template_dependency.pillarpath


@pytest.fixture(scope="function")
def fixture_pillar1():
    """
    keys filter
    """
    return vl.Config.from_dict(
        "config 1",
        {
            "path": "secret/ssh/users/admin1/id_admin",
            "pillarpath": "users/id_admin",
            "keys": [
                "public",
            ],
            "matches": [
                {
                    "keys": ["host"],
                    "values": ["host1"],
                    "add_keys": [
                        "private",
                    ],
                }
            ],
        },
        {},
    )


@pytest.fixture(scope="function")
def fixture_pillar2():
    """
    no keys
    """
    return vl.Config.from_dict(
        "config 2",
        {
            "path": "secret/ssh/users/user1/id_new",
            "pillarpath": "users/id_new",
            "keys": [],
            "matches": [
                {
                    "keys": ["host"],
                    "values": ["host1"],
                    "add_keys": [
                        "private",
                    ],
                }
            ],
        },
        {},
    )


@pytest.fixture(scope="function")
def fixture_pillar3():
    return vl.Config.from_dict(
        "config 3",
        {
            "path": "concourse/*",
            "pillarpath": "keys/*",
            "keys": [
                "public",
            ],
            "matches": [
                {
                    "keys": ["master"],
                    "values": ["master2"],
                    "add_keys": [
                        "public",
                    ],
                }
            ],
        },
        {},
    )


@pytest.fixture(scope="function")
def fixture_pillar4():
    """
    grain
    """
    return vl.Config.from_dict(
        {
            "path": "hosts/G@id",
            "pillarpath": "keys",
            "keys": [
                "public",
                "private",
            ],
            "matches": [{}],
        },
        {},
    )


@pytest.fixture(scope="function")
def config_template_dependency():
    """
    config with templates and dependencies on a previous result

    ext_pillar_vault_ssh_keys:
      present:
        admin:
          - user: admin
            id: id_admin
        root:
          - user: root
            id: id_root
    """
    return vl.Config.from_dict(
        "config depend",
        {
            "path": "secret/ssh/users/{{user}}/{{id}}",
            "pillarpath": "users/present/{{puser}}/ssh_keys/{{id}}_{{user}}",
            "keys": [
                "public",
                "private",
            ],
            "matches": [
                {
                    "keys": ["host"],
                    "values": ["G@id"],
                    "add_keys": [
                        "private",
                    ],
                },
            ],
            "templates": [
                {
                    "keys": [
                        "puser",
                    ],
                    "lookup": "I@ext_pillar_vault_ssh_keys:present",
                },
                {
                    "keys": [
                        "id",
                        "user",
                    ],
                    "lookup": "I@ext_pillar_vault_ssh_keys:present:{{puser}}",
                },
                {
                    "keys": [
                        "ssh",
                    ],
                    "lookup": "I@ext_pillar_vault_ssh_keys:{{puser}}:{{id}}",
                },
            ],
        },
        {},
    )


@pytest.fixture(scope="function")
def fixture_data_template_dependency():
    """
    data result from template dependencies
    """
    return [
        {
            "users": {
                "present": {
                    "admin": {
                        "ssh_keys": {
                            "id_admin_admin1": {
                                "public": "random_pubkeyadmin",
                            },
                        },
                    },
                },
            }
        },
        {
            "users": {
                "present": {
                    "admin": {
                        "ssh_keys": {
                            "id_intranet_root": {
                                "private": "random_privkeyroot",
                                "public": "random_pubkeyroot",
                            },
                        },
                    },
                },
            }
        },
        {
            "users": {
                "present": {
                    "user1": {
                        "ssh_keys": {
                            "id_user_user1": {
                                "public": "random_pubkeyuser1",
                            },
                        },
                    },
                },
            }
        },
    ]


@pytest.fixture(scope="function")
def config_template_simple():
    """
    simple config with templates
    """
    return vl.Config.from_dict(
        "config simple",
        {
            "path": "secret/ssh/users/{{user}}",
            "pillarpath": "users/present/{{user}}",
            "keys": [],
            "matches": [],
            "templates": [
                {
                    "keys": [
                        "user",
                    ],
                    "lookup": "I@users",
                },
            ],
        },
        {},
    )


@pytest.fixture(scope="function")
def fixture_data_template_simple():
    """
    data result from a single lookup
    """
    return [
        {
            "users": {
                "present": {
                    "admin": {
                        "user": "admin",
                        "data": "random_data",
                    },
                },
            }
        },
        {
            "users": {
                "present": {
                    "user1": {
                        "user": "user1",
                        "data": "random_data",
                    },
                },
            }
        },
    ]


@pytest.fixture(scope="function")
def config_template_single_simple(config_template_simple):
    return config_template_simple.templates


@pytest.fixture(scope="function")
def config_template_single_dependency(config_template_dependency):
    return config_template_dependency.templates


@pytest.fixture(scope="function")
def templates_simple(config_template_simple, env):
    return vl.LookupTemplate.from_config(config_template_simple, env)


@pytest.fixture(scope="function")
def template_dependency(config_template_dependency, env):
    return vl.LookupTemplate.from_config(config_template_dependency, env)


@pytest.fixture(scope="function")
def fixture_data1():
    """
    data result from a single lookup
    """
    return {
        "private": "random_privkeyadmin",
        "public": "random_pubkeyadmin",
        "host": "host2",
        "trash": "noneedadmin",
    }


@pytest.fixture(scope="function")
def fixture_data2():
    """
    data result from a single lookup
    """
    return [
        {
            "users": {
                "id_new": {
                    "public": "pub",
                    "host": "host",
                    "user": "new",
                },
            }
        }
    ]


@pytest.fixture(scope="function")
def fixture_data3():
    """
    data result from a wildcard lookup
    """
    return [
        {
            "keys": {
                "one": {},
            },
        },
        {
            "keys": {
                "two": {
                    "public": "pub2",
                },
            },
        },
    ]
