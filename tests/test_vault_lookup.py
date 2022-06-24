import pytest
import vault_lookup as vl
from unittest.mock import MagicMock


@pytest.fixture()
def configure_loader_modules():
    return {
        vl: {
            "__salt__": {
                "vault.list_secrets": MagicMock(side_effect=list_secrets),
                "vault.read_secret": MagicMock(side_effect=read_secret),
                "grains.get": MagicMock(side_effect=get_grains),
                "pillar.get": MagicMock(side_effect=get_pillar),
            },
        }
    }


def list_secrets(path, *args, **kwargs):
    if path == "concourse":
        return {
            "keys": [
                "one",
                "two",
            ]
        }

    if path == "secret":
        return {
            "keys": [
                "host1",
                "host2",
                "host3",
            ]
        }
    if path in ["secret/c1", "secret/c2", "secret/c3"]:
        return {
            "keys": [
                "w1",
                "w2",
                "w3",
            ]
        }
    return {
        "keys": [
            "r1",
            "r2",
        ]
    }


def read_secret(path, *args, **kwargs):
    if path == "secret/ssh/users/admin1/id_admin":
        return {
            "private": "random_privkeyadmin",
            "public": "random_pubkeyadmin",
            "host": "host2",
            "trash": "noneedadmin",
        }
    if path == "secret/ssh/users/root/id_intranet":
        return {
            "private": "random_privkeyroot",
            "public": "random_pubkeyroot",
            "host": "host1",
            "trash": "noneedroot",
        }
    if path == "secret/ssh/users/user1/id_user":
        return {
            "private": "random_privkeyuser1",
            "public": "random_pubkeyuser1",
            "host": "h2",
            "trash": "noneeduser1",
        }
    if path == "secret/ssh/users/admin":
        return {
            "user": "admin",
            "data": "random_data",
        }
    if path == "secret/ssh/users/user1":
        return {
            "user": "user1",
            "data": "random_data",
        }
    if path == "concourse/one":
        return {
            "private": "priv1",
            "public": "pub1",
            "master": "master1",
        }
    if path == "concourse/two":
        return {
            "private": "priv2",
            "public": "pub2",
            "master": "master2",
        }
    return {
        "private": "priv",
        "public": "pub",
        "host": "host",
    }


def get_grains(path, *args, **kwargs):
    if path == "id":
        return "host1"
    if path == "user":
        return "admin"


def get_pillar(path, *args, **kwargs):
    if path == "user":
        return "admin"
    if path == "users":
        return ["admin", "user1"]
    if path == "cluster":
        return ["c1", "c2", "c3"]
    if path == "appslave":
        return ["s1", "s2"]
    if path == "backup":
        return ["b1", "b2"]
    if path == "ext_pillar_vault_ssh_keys:present":
        return {
            "admin": [
                {
                    "id": "id_admin",
                    "user": "admin1",
                },
                {
                    "id": "id_intranet",
                    "user": "root",
                },
            ],
            "user1": [
                {
                    "id": "id_user",
                    "user": "user1",
                },
            ],
        }
    if path == "ext_pillar_vault_ssh_keys:present:admin":
        return [
            {
                "id": "id_admin",
                "user": "admin1",
            },
            {
                "id": "id_intranet",
                "user": "root",
            },
        ]
    if path == "ext_pillar_vault_ssh_keys:present:user1":
        return [
            {
                "id": "id_user",
                "user": "user1",
            },
        ]
    if path == "ext_pillar_vault_ssh_keys:admin:id_admin":
        return "newadminkey"
    if path == "ext_pillar_vault_ssh_keys:admin:id_intranet":
        return "intranetkey"
    if path == "ext_pillar_vault_ssh_keys:user1:id_user":
        return {"name": "userkey"}


def list_of_dict_to_map(list_items):
    result = {}
    for items in list_items:
        result.update(items)
    return result


def test_lookup_single_data(fixture_pillar1, fixture_data1):
    expected = {}
    expected["users"] = {}
    expected["users"]["id_admin"] = {"public": "random_pubkeyadmin"}

    assert vl.get_mapped_pillar(fixture_pillar1) == [expected]
    fixture_pillar1.keys = []
    del fixture_data1["private"]
    expected["users"]["id_admin"] = fixture_data1
    assert vl.get_mapped_pillar(fixture_pillar1) == [expected]


def test_map_pillar_wildcard(fixture_pillar3, fixture_data3):
    for d in vl.get_mapped_pillar(fixture_pillar3):
        assert d in fixture_data3


def test_lookup_host_filter_single_data_all_keys(fixture_pillar2, fixture_data2):
    assert vl.get_mapped_pillar(fixture_pillar2) != [fixture_data2]
    del fixture_data2[0]["users"]["id_new"]["user"]
    assert vl.get_mapped_pillar(fixture_pillar2) == fixture_data2


def test_pillar_mapping_template_simple(
    config_template_simple, fixture_data_template_simple
):
    assert vl.get_mapped_pillar(config_template_simple) == fixture_data_template_simple


def test_pillar_mapping_template_dependency(
    config_template_dependency, fixture_data_template_dependency
):
    assert (
        vl.get_mapped_pillar(config_template_dependency)
        == fixture_data_template_dependency
    )


def test_get_values(fixture_data1):
    assert (
        vl.filter_values(
            fixture_data1,
            ["public"],
            [
                {
                    "keys": ["host"],
                    "values": ["host1"],
                    "add_keys": [
                        "public",
                    ],
                }
            ],
            {},
        )
        == {}
    )
    assert (
        vl.filter_values(
            fixture_data1,
            ["public"],
            [
                {
                    "keys": ["host"],
                    "values": ["host2"],
                    "add_keys": [
                        "public",
                    ],
                }
            ],
            {},
        )
        == {"public": "random_pubkeyadmin"}
    )

    assert (
        vl.filter_values(
            fixture_data1,
            ["public"],
            [
                {
                    "keys": [],
                    "values": ["I@cluster=c2"],
                    "add_keys": [
                        "public",
                    ],
                }
            ],
            {},
        )
        == {"public": "random_pubkeyadmin"}
    )

    assert (
        vl.filter_values(
            fixture_data1,
            ["public"],
            [
                {
                    "keys": [],
                    "values": ["I@cluster=c8"],
                    "add_keys": [
                        "public",
                    ],
                }
            ],
            {},
        )
        == {}
    )

    assert (
        vl.filter_values(
            fixture_data1,
            ["public"],
            [
                {
                    "keys": ["host"],
                    "values": ["G@id"],
                    "add_keys": [
                        "public",
                    ],
                }
            ],
            {},
        )
        == {}
    )

    fixture_data1["host"] = "host1"
    assert vl.filter_values(
        fixture_data1,
        ["private", "public"],
        [
            {
                "keys": ["host"],
                "values": ["G@id"],
                "add_keys": [
                    "private",
                ],
            }
        ],
        {},
    ) == {
        "public": "random_pubkeyadmin",
        "private": "random_privkeyadmin",
    }


def test_simple_path(path_simple):
    assert path_simple.wildcards() == 0
    assert path_simple.lookups() == 0
    assert path_simple.lookup_matchers() == 0
    assert path_simple.isvalid()


def test_path_wildcard(path_wildcard):
    assert path_wildcard.wildcards() == 1
    assert path_wildcard.lookups() == 0
    assert path_wildcard.lookup_matchers() == 0
    assert not path_wildcard.isvalid()
    assert path_wildcard.get_wildcard_prefix() == "secret"
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path_wildcard), {})
    assert sorted(vl.get_resolved_paths(path_wildcard, salt_lookup_map)) == sorted(
        [
            vl.LookupPath("secret/host1/wildcard", False),
            vl.LookupPath("secret/host2/wildcard", False),
            vl.LookupPath("secret/host3/wildcard", False),
        ]
    )


def test_path_lookup(path_lookup):
    assert path_lookup.wildcards() == 0
    assert path_lookup.lookups() == 1
    assert path_lookup.lookup_matchers() == 0
    assert not path_lookup.isvalid()
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path_lookup), {})
    assert vl.get_resolved_paths(path_lookup, salt_lookup_map) == [
        vl.LookupPath("secret/host1/data", False)
    ]


def test_path_lookup_match(path_lookup_match):
    assert path_lookup_match.wildcards() == 0
    assert path_lookup_match.lookups() == 1
    assert path_lookup_match.lookup_matchers() == 1
    assert not path_lookup_match.isvalid()
    salt_lookup_map = vl.get_salt_lookup_map(
        vl.collect_all_lookups(path_lookup_match), {}
    )
    assert vl.get_resolved_paths(path_lookup_match, salt_lookup_map) == [
        vl.LookupPath("secret/c1/data", False)
    ]


def test_path_lookup_pillar_list(path_lookup_pillar_list):
    assert path_lookup_pillar_list.wildcards() == 0
    assert path_lookup_pillar_list.lookups() == 1
    assert path_lookup_pillar_list.lookup_matchers() == 0
    assert not path_lookup_pillar_list.isvalid()
    salt_lookup_map = vl.get_salt_lookup_map(
        vl.collect_all_lookups(path_lookup_pillar_list), {}
    )
    assert sorted(
        vl.get_resolved_paths(path_lookup_pillar_list, salt_lookup_map)
    ) == sorted(
        [
            vl.LookupPath("secret/c1/data", False),
            vl.LookupPath("secret/c2/data", False),
            vl.LookupPath("secret/c3/data", False),
        ]
    )


def test_path_lookup_pillar_list2(path_lookup_pillar_list2):
    assert path_lookup_pillar_list2.wildcards() == 0
    assert path_lookup_pillar_list2.lookups() == 2
    assert path_lookup_pillar_list2.lookup_matchers() == 0
    assert not path_lookup_pillar_list2.isvalid()
    salt_lookup_map = vl.get_salt_lookup_map(
        vl.collect_all_lookups(path_lookup_pillar_list2), {}
    )
    assert sorted(
        vl.get_resolved_paths(path_lookup_pillar_list2, salt_lookup_map)
    ) == sorted(
        [
            vl.LookupPath("secret/c1/s1/data", False),
            vl.LookupPath("secret/c2/s1/data", False),
            vl.LookupPath("secret/c3/s1/data", False),
            vl.LookupPath("secret/c1/s2/data", False),
            vl.LookupPath("secret/c2/s2/data", False),
            vl.LookupPath("secret/c3/s2/data", False),
        ]
    )


def test_path_lookup_mixed(path_lookup_mixed):
    assert path_lookup_mixed.wildcards() == 2
    assert path_lookup_mixed.lookups() == 2
    assert path_lookup_mixed.lookup_matchers() == 0
    assert not path_lookup_mixed.isvalid()
    assert path_lookup_mixed.get_wildcard_prefix() == "secret/I@cluster"

    salt_lookup_map = vl.get_salt_lookup_map(
        vl.collect_all_lookups(path_lookup_mixed), {}
    )
    assert sorted(vl.get_resolved_paths(path_lookup_mixed, salt_lookup_map)) == sorted(
        [
            vl.LookupPath("secret/c1/w1/s1/r1/data", False),
            vl.LookupPath("secret/c1/w1/s1/r2/data", False),
            vl.LookupPath("secret/c1/w1/s2/r1/data", False),
            vl.LookupPath("secret/c1/w1/s2/r2/data", False),
            vl.LookupPath("secret/c1/w2/s1/r1/data", False),
            vl.LookupPath("secret/c1/w2/s1/r2/data", False),
            vl.LookupPath("secret/c1/w2/s2/r1/data", False),
            vl.LookupPath("secret/c1/w2/s2/r2/data", False),
            vl.LookupPath("secret/c1/w3/s1/r1/data", False),
            vl.LookupPath("secret/c1/w3/s1/r2/data", False),
            vl.LookupPath("secret/c1/w3/s2/r1/data", False),
            vl.LookupPath("secret/c1/w3/s2/r2/data", False),
            vl.LookupPath("secret/c2/w1/s1/r1/data", False),
            vl.LookupPath("secret/c2/w1/s1/r2/data", False),
            vl.LookupPath("secret/c2/w1/s2/r1/data", False),
            vl.LookupPath("secret/c2/w1/s2/r2/data", False),
            vl.LookupPath("secret/c2/w2/s1/r1/data", False),
            vl.LookupPath("secret/c2/w2/s1/r2/data", False),
            vl.LookupPath("secret/c2/w2/s2/r1/data", False),
            vl.LookupPath("secret/c2/w2/s2/r2/data", False),
            vl.LookupPath("secret/c2/w3/s1/r1/data", False),
            vl.LookupPath("secret/c2/w3/s1/r2/data", False),
            vl.LookupPath("secret/c2/w3/s2/r1/data", False),
            vl.LookupPath("secret/c2/w3/s2/r2/data", False),
            vl.LookupPath("secret/c3/w1/s1/r1/data", False),
            vl.LookupPath("secret/c3/w1/s1/r2/data", False),
            vl.LookupPath("secret/c3/w1/s2/r1/data", False),
            vl.LookupPath("secret/c3/w1/s2/r2/data", False),
            vl.LookupPath("secret/c3/w2/s1/r1/data", False),
            vl.LookupPath("secret/c3/w2/s1/r2/data", False),
            vl.LookupPath("secret/c3/w2/s2/r1/data", False),
            vl.LookupPath("secret/c3/w2/s2/r2/data", False),
            vl.LookupPath("secret/c3/w3/s1/r1/data", False),
            vl.LookupPath("secret/c3/w3/s1/r2/data", False),
            vl.LookupPath("secret/c3/w3/s2/r1/data", False),
            vl.LookupPath("secret/c3/w3/s2/r2/data", False),
        ]
    )


def test_salt_lookups():
    path = vl.LookupPath("secret/I@cluster/I@appslave", False)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path), {})
    assert sorted(path.get_salt_lookup(salt_lookup_map)) == sorted(
        [
            ("I@cluster", ["c1", "c2", "c3"]),
            ("I@appslave", ["s1", "s2"]),
        ]
    )

    path = vl.LookupPath("secret/G@id", False)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path), {})
    assert sorted(path.get_salt_lookup(salt_lookup_map)) == sorted(
        [
            ("G@id", "host1"),
        ]
    )


def test_valid_paths():
    # no pillarpath
    path1 = vl.LookupPath("secret/*", False)
    path2 = vl.LookupPath("secret/*", False)
    assert not vl.are_paths_valid(path1, path2)

    # wildcard missing in path
    path1 = vl.LookupPath("secret", False)
    path2 = vl.LookupPath("secret/*", True)
    assert not vl.are_paths_valid(path1, path2)

    # wildcard missing in pillar
    path1 = vl.LookupPath("secret/*", False)
    path2 = vl.LookupPath("secret", True)
    assert not vl.are_paths_valid(path1, path2)

    # invalid wildcard amount
    path1 = vl.LookupPath("secret/*", False)
    path2 = vl.LookupPath("secret/*/*", True)
    assert not vl.are_paths_valid(path1, path2)
    path1 = vl.LookupPath("secret/*/*/*", False)
    path2 = vl.LookupPath("secret/*/*", True)
    assert not vl.are_paths_valid(path1, path2)

    # 1. wildcards both
    path1 = vl.LookupPath("secret/*", False)
    path2 = vl.LookupPath("secret/*", True)
    salt_lookup_map = path1.get_lookups().union(path2.get_lookups())
    salt_lookup_map = vl.get_salt_lookup_map(salt_lookup_map, {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)

    # 2. salt lookup grains equal size and count
    path1 = vl.LookupPath("secret/G@id", False)
    path2 = vl.LookupPath("secret2/G@id", True)
    salt_lookup_map = path1.get_lookups().union(path2.get_lookups())
    salt_lookup_map = vl.get_salt_lookup_map(salt_lookup_map, {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)
    path1 = vl.LookupPath("secret/G@id", False)
    path2 = vl.LookupPath("test/G@id/works", True)
    salt_lookup_map = path1.get_lookups().union(path2.get_lookups())
    salt_lookup_map = vl.get_salt_lookup_map(salt_lookup_map, {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)

    # 2.x lookup grains unequal
    path1 = vl.LookupPath("secret/G@id", False)
    path2 = vl.LookupPath("secret2", True)
    salt_lookup_map = path1.get_lookups().union(path2.get_lookups())
    salt_lookup_map = vl.get_salt_lookup_map(salt_lookup_map, {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)

    # 2.1 salt lookups equal size and unequal count
    path1 = vl.LookupPath("secret/G@id", False)
    path2 = vl.LookupPath("secret2/I@user/G@id", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)

    # 3. salt lookup list
    path1 = vl.LookupPath("secret/c1/I@cluster", False)
    path2 = vl.LookupPath("secret2/I@cluster", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)
    path1 = vl.LookupPath("secret/c1/I@cluster", False)
    path2 = vl.LookupPath("secret2/I@cluster/nested", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)
    path1 = vl.LookupPath("secret/c1/I@cluster/nested", False)
    path2 = vl.LookupPath("secret2/I@cluster", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)

    # 3.1 salt lookup list, different lookups, unable to map
    path1 = vl.LookupPath("secret/c1/I@cluster", False)
    path2 = vl.LookupPath("secret2/I@backup", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths != len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert not vl.are_paths_valid(path1, path2)

    # 3.2 salt lookup list, wildcard in path
    path1 = vl.LookupPath("secret/c1/*", False)
    path2 = vl.LookupPath("secret2/I@cluster", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    with pytest.raises(vl.LookupException):
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    assert not vl.are_paths_valid(path1, path2)

    # 3.3 salt lookup list, wildcard in pillar
    path1 = vl.LookupPath("secret/c1/I@cluster", False)
    path2 = vl.LookupPath("secret2/*", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    with pytest.raises(vl.LookupException):
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    assert not vl.are_paths_valid(path1, path2)

    # 4. salt lookup list match one to one
    path1 = vl.LookupPath("secret/c1/I@cluster=c1", False)
    path2 = vl.LookupPath("secret2/I@cluster=c2", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)
    path1 = vl.LookupPath("secret/c1/I@cluster=c1", False)
    path2 = vl.LookupPath("secret2/I@appslave=s1", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)
    path1 = vl.LookupPath("secret/c1/G@id", False)
    path2 = vl.LookupPath("secret2/I@appslave=s1", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)
    path1 = vl.LookupPath("secret/c1/test", False)
    path2 = vl.LookupPath("secret2/I@appslave=s1", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    assert vl.are_paths_valid(path1, path2)
    path1 = vl.LookupPath("secret/c1/I@cluster=c1", False)
    path2 = vl.LookupPath("secret2/done", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)
    path1 = vl.LookupPath("secret/c1/I@cluster=c1/nested", False)
    path2 = vl.LookupPath("secret2/done", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)

    # 4.1 nonexistent match
    path1 = vl.LookupPath("secret/c1/I@cluster=doesnotexist", False)
    path2 = vl.LookupPath("secret2/done", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    with pytest.raises(vl.ResolveError):
        vl.get_resolved_paths(path1, salt_lookup_map)
    vl.get_resolved_paths(path2, salt_lookup_map)
    assert not vl.are_paths_valid(path1, path2)

    path1 = vl.LookupPath("secret/c1/test", False)
    path2 = vl.LookupPath("secret2/I@cluster=doesnotexist", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    with pytest.raises(vl.ResolveError):
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    assert not vl.are_paths_valid(path1, path2)

    # 5. mix
    path1 = vl.LookupPath("secret/*/I@cluster=c1/I@appslave", False)
    path2 = vl.LookupPath("secret2/I@appslave/done/*", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)
    # 2 wildcard
    path1 = vl.LookupPath("secret/*/test/*/I@cluster=c1/I@appslave", False)
    path2 = vl.LookupPath("secret2/*/I@appslave/done/*", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths == len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert vl.are_paths_valid(path1, path2)

    # 5.1 mix fail
    # no wildcards, no lookups in pillarpath
    path1 = vl.LookupPath("secret/*/I@cluster=c1/I@appslave", False)
    path2 = vl.LookupPath("secret2/done", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    with pytest.raises(vl.LookupException):
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    assert not vl.are_paths_valid(path1, path2)
    # no lookups
    path1 = vl.LookupPath("secret/*/I@cluster=c1/I@appslave", False)
    path2 = vl.LookupPath("secret2/done/*", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths != len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert not vl.are_paths_valid(path1, path2)
    # no wildcard
    path1 = vl.LookupPath("secret/*/I@cluster=c1/I@appslave", False)
    path2 = vl.LookupPath("secret2/done/I@appslave", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    with pytest.raises(vl.LookupException):
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    assert not vl.are_paths_valid(path1, path2)
    # different lookups
    path1 = vl.LookupPath("secret/*/I@cluster=c1/I@appslave", False)
    path2 = vl.LookupPath("secret2/*/I@cluster", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    len_path1_resolved_paths = len(vl.get_resolved_paths(path1, salt_lookup_map))
    assert len_path1_resolved_paths != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert len_path1_resolved_paths != len(
        vl.get_resolve_from_path(path1, path2, salt_lookup_map)
    )
    assert not vl.are_paths_valid(path1, path2)
    # doesnotexist
    path1 = vl.LookupPath("secret/*/I@cluster=c1/I@appslave=doesnotexist2", False)
    path2 = vl.LookupPath("secret2/*/done/I@appslave=doesnotexist", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    assert len(vl.get_resolved_paths(path1, salt_lookup_map)) != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert not vl.are_paths_valid(path1, path2)
    path1 = vl.LookupPath("secret/*/I@cluster=c1", False)
    path2 = vl.LookupPath("secret2/*/done/I@appslave=doesnotexist", True)
    salt_lookup_map = vl.get_salt_lookup_map(vl.collect_all_lookups(path1, path2), {})
    assert len(vl.get_resolved_paths(path1, salt_lookup_map)) != len(
        vl.get_resolved_paths(path2, salt_lookup_map)
    )
    assert not vl.are_paths_valid(path1, path2)


def test_pillar_path_wildcard(path_wildcard, path_wildcard_pillar):
    """
    resolve wildcard
    """
    salt_lookup_map = path_wildcard.get_lookups().union(
        path_wildcard_pillar.get_lookups()
    )
    salt_lookup_map = vl.get_salt_lookup_map(salt_lookup_map, {})
    pwresolved = vl.get_resolved_paths(path_wildcard, salt_lookup_map)
    assert sorted(pwresolved) == sorted(
        [
            vl.LookupPath("secret/host1/wildcard", False),
            vl.LookupPath("secret/host2/wildcard", False),
            vl.LookupPath("secret/host3/wildcard", False),
        ]
    )
    assert path_wildcard.lookups_salt == []
    assert path_wildcard.lookups_vault_wildcard == [["host1", "host2", "host3"]]
    assert not vl.are_paths_valid(path_wildcard, path_wildcard_pillar)

    salt_lookup_map = path_wildcard.get_lookups().union(
        path_wildcard_pillar.get_lookups()
    )
    salt_lookup_map = vl.get_salt_lookup_map(salt_lookup_map, {})
    pwpillar_resolved = vl.get_resolve_from_path(
        path_wildcard_pillar, path_wildcard, salt_lookup_map
    )
    assert vl.are_paths_valid(path_wildcard, path_wildcard_pillar)
    assert pwpillar_resolved == [
        vl.LookupPath("atar/hier/host1", True),
        vl.LookupPath("atar/hier/host2", True),
        vl.LookupPath("atar/hier/host3", True),
    ]


def test_path_from_wildcards(path_wildcard_pillar):
    wildcards = [
        [
            "replace1",
            "replace2",
            "replace3",
        ],
    ]
    assert sorted(
        vl.build_path_from_wildcards(path_wildcard_pillar, wildcards)
    ) == sorted(
        [
            vl.LookupPath("atar/hier/replace1", True),
            vl.LookupPath("atar/hier/replace2", True),
            vl.LookupPath("atar/hier/replace3", True),
        ]
    )

    with pytest.raises(vl.LookupException):
        vl.build_path_from_wildcards(vl.LookupPath("one/*/two/*/G@id", True), wildcards)

    wildcards = [
        [
            "replace1",
            "replace2",
            "replace3",
        ],
        [
            "h1",
            "h2",
            "h3",
        ],
    ]
    assert sorted(
        vl.build_path_from_wildcards(vl.LookupPath("one/*/two/*/G@id", True), wildcards)
    ) == sorted(
        [
            vl.LookupPath("one/replace1/two/h1/G@id", True),
            vl.LookupPath("one/replace1/two/h2/G@id", True),
            vl.LookupPath("one/replace1/two/h3/G@id", True),
            vl.LookupPath("one/replace2/two/h1/G@id", True),
            vl.LookupPath("one/replace2/two/h2/G@id", True),
            vl.LookupPath("one/replace2/two/h3/G@id", True),
            vl.LookupPath("one/replace3/two/h1/G@id", True),
            vl.LookupPath("one/replace3/two/h2/G@id", True),
            vl.LookupPath("one/replace3/two/h3/G@id", True),
        ]
    )


def test_vault_paths(path_wildcard, path_wildcard2, path_simple):
    assert not vl.build_vault_paths(path_simple.get_wildcard_prefix())

    assert vl.build_vault_paths(path_wildcard.get_wildcard_prefix()) == [
        "host1",
        "host2",
        "host3",
    ]


def test_vault_lookup():
    path = vl.LookupPath("secret/*/one", False)
    assert sorted(
        vl.build_path_from_vault_lookups(path, [path], vl.build_vault_paths)
    ) == sorted(
        [
            vl.LookupPath("secret/host1/one", False),
            vl.LookupPath("secret/host2/one", False),
            vl.LookupPath("secret/host3/one", False),
        ]
    )
    assert path.lookups_vault_wildcard == [["host1", "host2", "host3"]]

    path = vl.LookupPath("secret/*/one/*/two", False)
    assert sorted(
        vl.build_path_from_vault_lookups(path, [path], vl.build_vault_paths)
    ) == sorted(
        [
            vl.LookupPath("secret/host1/one/r1/two", False),
            vl.LookupPath("secret/host1/one/r2/two", False),
            vl.LookupPath("secret/host2/one/r1/two", False),
            vl.LookupPath("secret/host2/one/r2/two", False),
            vl.LookupPath("secret/host3/one/r1/two", False),
            vl.LookupPath("secret/host3/one/r2/two", False),
        ]
    )
    assert path.lookups_vault_wildcard == [["host1", "host2", "host3"], ["r1", "r2"]]

    path = vl.LookupPath("secret/*/I@cluster=c1/I@appslave", False)
    salt_lookup_map = vl.get_salt_lookup_map(path.get_lookups(), {})
    resolved_paths = vl.get_resolved_paths(path, salt_lookup_map)
    assert sorted(
        vl.build_path_from_vault_lookups(path, resolved_paths, vl.build_vault_paths)
    ) == sorted(
        [
            vl.LookupPath("secret/host1/c1/s1", False),
            vl.LookupPath("secret/host1/c1/s2", False),
            vl.LookupPath("secret/host2/c1/s1", False),
            vl.LookupPath("secret/host2/c1/s2", False),
            vl.LookupPath("secret/host3/c1/s1", False),
            vl.LookupPath("secret/host3/c1/s2", False),
        ]
    )
    assert path.lookups_vault_wildcard == [["host1", "host2", "host3"]]


def test_prefix_match():
    path1 = vl.LookupPath("secret", False)
    path2 = vl.LookupPath("secret", False)
    assert vl.prefixes_match(path1, path2) == 0

    path1 = vl.LookupPath("secret", False)
    path2 = vl.LookupPath("secret1", False)
    assert vl.prefixes_match(path1, path2) == -1

    path1 = vl.LookupPath("secret", False)
    path2 = vl.LookupPath("secret/test", False)
    assert vl.prefixes_match(path1, path2) == 1

    path1 = vl.LookupPath("secret", False)
    path2 = vl.LookupPath("secret/host3/one", False)
    assert vl.prefixes_match(path1, path2) == 1

    path1 = vl.LookupPath("secret", False)
    path2 = vl.LookupPath("secret/*/one", False)
    assert vl.prefixes_match(path1, path2) == 1

    path1 = vl.LookupPath("secret", False)
    path2 = vl.LookupPath("secret2/host3/one", False)
    assert vl.prefixes_match(path1, path2) == -1

    path1 = vl.LookupPath("secret/host2/one", False)
    path2 = vl.LookupPath("secret/host3/one", False)
    assert vl.prefixes_match(path1, path2) == 2


def test_resolved_paths_mapping(path_lookup_mixed, path_lookup_mixed_pillar):
    """
    map resolved paths
    """
    salt_lookup_map = path_lookup_mixed.get_lookups().union(
        path_lookup_mixed_pillar.get_lookups()
    )
    salt_lookup_map = vl.get_salt_lookup_map(salt_lookup_map, {})
    vl.get_resolved_paths(path_lookup_mixed, salt_lookup_map)
    vl.get_resolve_from_path(
        path_lookup_mixed_pillar, path_lookup_mixed, salt_lookup_map
    )
    assert vl.are_paths_valid(path_lookup_mixed, path_lookup_mixed_pillar)
    result = vl.map_resolved_paths(
        path_lookup_mixed, path_lookup_mixed_pillar, salt_lookup_map
    )
    values = []
    for d in result:
        values.extend(list(d.values()))
    assert sorted(values) == sorted(
        [
            vl.LookupPath("secret/c3/w3/s2/r2/data", False),
            vl.LookupPath("srv/s2/c3/w3/r2", True),
            vl.LookupPath("secret/c3/w3/s2/r1/data", False),
            vl.LookupPath("srv/s2/c3/w3/r1", True),
            vl.LookupPath("secret/c3/w2/s2/r2/data", False),
            vl.LookupPath("srv/s2/c3/w2/r2", True),
            vl.LookupPath("secret/c3/w2/s2/r1/data", False),
            vl.LookupPath("srv/s2/c3/w2/r1", True),
            vl.LookupPath("secret/c3/w1/s2/r2/data", False),
            vl.LookupPath("srv/s2/c3/w1/r2", True),
            vl.LookupPath("secret/c3/w1/s2/r1/data", False),
            vl.LookupPath("srv/s2/c3/w1/r1", True),
            vl.LookupPath("secret/c3/w3/s1/r2/data", False),
            vl.LookupPath("srv/s1/c3/w3/r2", True),
            vl.LookupPath("secret/c3/w3/s1/r1/data", False),
            vl.LookupPath("srv/s1/c3/w3/r1", True),
            vl.LookupPath("secret/c3/w2/s1/r2/data", False),
            vl.LookupPath("srv/s1/c3/w2/r2", True),
            vl.LookupPath("secret/c3/w2/s1/r1/data", False),
            vl.LookupPath("srv/s1/c3/w2/r1", True),
            vl.LookupPath("secret/c3/w1/s1/r2/data", False),
            vl.LookupPath("srv/s1/c3/w1/r2", True),
            vl.LookupPath("secret/c3/w1/s1/r1/data", False),
            vl.LookupPath("srv/s1/c3/w1/r1", True),
            vl.LookupPath("secret/c2/w3/s2/r2/data", False),
            vl.LookupPath("srv/s2/c2/w3/r2", True),
            vl.LookupPath("secret/c2/w3/s2/r1/data", False),
            vl.LookupPath("srv/s2/c2/w3/r1", True),
            vl.LookupPath("secret/c2/w2/s2/r2/data", False),
            vl.LookupPath("srv/s2/c2/w2/r2", True),
            vl.LookupPath("secret/c2/w2/s2/r1/data", False),
            vl.LookupPath("srv/s2/c2/w2/r1", True),
            vl.LookupPath("secret/c2/w1/s2/r2/data", False),
            vl.LookupPath("srv/s2/c2/w1/r2", True),
            vl.LookupPath("secret/c2/w1/s2/r1/data", False),
            vl.LookupPath("srv/s2/c2/w1/r1", True),
            vl.LookupPath("secret/c2/w3/s1/r2/data", False),
            vl.LookupPath("srv/s1/c2/w3/r2", True),
            vl.LookupPath("secret/c2/w3/s1/r1/data", False),
            vl.LookupPath("srv/s1/c2/w3/r1", True),
            vl.LookupPath("secret/c2/w2/s1/r2/data", False),
            vl.LookupPath("srv/s1/c2/w2/r2", True),
            vl.LookupPath("secret/c2/w2/s1/r1/data", False),
            vl.LookupPath("srv/s1/c2/w2/r1", True),
            vl.LookupPath("secret/c2/w1/s1/r2/data", False),
            vl.LookupPath("srv/s1/c2/w1/r2", True),
            vl.LookupPath("secret/c2/w1/s1/r1/data", False),
            vl.LookupPath("srv/s1/c2/w1/r1", True),
            vl.LookupPath("secret/c1/w3/s2/r2/data", False),
            vl.LookupPath("srv/s2/c1/w3/r2", True),
            vl.LookupPath("secret/c1/w3/s2/r1/data", False),
            vl.LookupPath("srv/s2/c1/w3/r1", True),
            vl.LookupPath("secret/c1/w2/s2/r2/data", False),
            vl.LookupPath("srv/s2/c1/w2/r2", True),
            vl.LookupPath("secret/c1/w2/s2/r1/data", False),
            vl.LookupPath("srv/s2/c1/w2/r1", True),
            vl.LookupPath("secret/c1/w1/s2/r2/data", False),
            vl.LookupPath("srv/s2/c1/w1/r2", True),
            vl.LookupPath("secret/c1/w1/s2/r1/data", False),
            vl.LookupPath("srv/s2/c1/w1/r1", True),
            vl.LookupPath("secret/c1/w3/s1/r2/data", False),
            vl.LookupPath("srv/s1/c1/w3/r2", True),
            vl.LookupPath("secret/c1/w3/s1/r1/data", False),
            vl.LookupPath("srv/s1/c1/w3/r1", True),
            vl.LookupPath("secret/c1/w2/s1/r2/data", False),
            vl.LookupPath("srv/s1/c1/w2/r2", True),
            vl.LookupPath("secret/c1/w2/s1/r1/data", False),
            vl.LookupPath("srv/s1/c1/w2/r1", True),
            vl.LookupPath("secret/c1/w1/s1/r2/data", False),
            vl.LookupPath("srv/s1/c1/w1/r2", True),
            vl.LookupPath("secret/c1/w1/s1/r1/data", False),
            vl.LookupPath("srv/s1/c1/w1/r1", True),
        ]
    )


def test_resolved_paths_mapping_single(path_lookup, path_lookup_single_mixed_pillar):
    salt_lookup_map = path_lookup.get_lookups().union(
        path_lookup_single_mixed_pillar.get_lookups()
    )
    salt_lookup_map = vl.get_salt_lookup_map(salt_lookup_map, {})
    vl.get_resolved_paths(path_lookup, salt_lookup_map)
    vl.get_resolve_from_path(
        path_lookup_single_mixed_pillar, path_lookup, salt_lookup_map
    )
    assert vl.are_paths_valid(path_lookup, path_lookup_single_mixed_pillar)
    assert vl.map_resolved_paths(
        path_lookup, path_lookup_single_mixed_pillar, salt_lookup_map
    )[0] == {
        "path": vl.LookupPath("secret/host1/data", False),
        "pillarpath": vl.LookupPath("to/s1/c1/host1/one", True),
    }


def test_resolved_paths_invalid():
    path1 = vl.LookupPath("not/I@appslave=doesnotexist/here", False)
    path2 = vl.LookupPath("some/path", True)
    salt_lookup_map = path1.get_lookups().union(path2.get_lookups())
    salt_lookup_map = vl.get_salt_lookup_map(salt_lookup_map, {})
    with pytest.raises(vl.ResolveError):
        vl.get_resolved_paths(path1, salt_lookup_map)
    with pytest.raises(vl.ResolveError):
        vl.get_resolve_from_path(path2, path1, salt_lookup_map)
    assert not vl.are_paths_valid(path1, path2)
    with pytest.raises(vl.ResolveError):
        vl.map_resolved_paths(path1, path2, salt_lookup_map)
    path1 = vl.LookupPath("some/path", False)
    path2 = vl.LookupPath("not/I@appslave=doesnotexist/here", True)
    vl.get_resolved_paths(path1, salt_lookup_map)
    with pytest.raises(vl.ResolveError):
        vl.get_resolve_from_path(path2, path1, salt_lookup_map)
    assert not vl.are_paths_valid(path1, path2)
    with pytest.raises(vl.ResolveError):
        vl.map_resolved_paths(path1, path2, salt_lookup_map)


def test_lookup_key():
    lookups_salt = [("I@cluster", ["c1", "c2", "c3"]), ("I@appslave", ["s1", "s2"])]
    lookups_vault_wildcard = [["w1", "w2", "w3"], ["r1", "r2"]]
    path = vl.LookupPath("srv/s2/c1/w1/r2", False)
    assert vl.get_path_lookup_key(path, lookups_salt, lookups_vault_wildcard) == (
        (("I@cluster", "c1"), ("I@appslave", "s2")),
        ("w1", "r2"),
    )


def test_templates_salt_resolve(
    templates_simple,
    template_dependency,
):
    templates_simple = vl.flat_dict_items(templates_simple)
    template_dependency = vl.flat_dict_items(template_dependency)

    user_template = templates_simple.get(("user",))
    assert user_template.get_resolved_entry(vl.resolve_pattern, {}) == {
        user_template: ["admin", "user1"]
    }
    temp_puser = template_dependency.get(("puser",))
    temp_id = template_dependency.get(("id", "user"))
    temp_ssh = template_dependency.get(("ssh",))

    assert temp_puser.get_resolved_entry(vl.resolve_pattern, {}) == {
        temp_puser: [
            "admin",
            "user1",
        ],
    }
    assert temp_id.get_resolved_entry(vl.resolve_pattern, {}) == {}
    assert temp_ssh.get_resolved_entry(vl.resolve_pattern, {}) == {}


def test_template_simple(env, config_template_simple):
    template_simple = vl.LookupTemplate.from_dict(
        config_template_simple.templates[0], env
    )
    assert template_simple.keys == ("user",)
    assert template_simple.dependencies == set()
    assert template_simple.to_dict() == {("user",): template_simple}
    templates = vl.LookupTemplate.from_config(config_template_simple, env)
    templates = vl.flat_dict_items(templates)
    assert template_simple == templates.get(("user",))


def test_template_dependency(env, config_template_dependency):
    template_parent = vl.LookupTemplate.from_dict(
        config_template_dependency.templates[0], env
    )
    assert template_parent.keys == ("puser",)
    assert template_parent.dependencies == set()
    assert template_parent.to_dict() == {("puser",): template_parent}
    templates = vl.LookupTemplate.from_config(config_template_dependency, env)
    templates = vl.flat_dict_items(templates)
    assert template_parent == templates.get(("puser",))

    template_map = {}
    assert not vl.check_template_dependencies(
        template_map,
        vl.LookupTemplate.from_dict(
            config_template_dependency.templates[1], env
        ).dependencies,
    )

    template_map.update(template_parent.to_dict())
    template_depends = vl.LookupTemplate.from_dict(
        config_template_dependency.templates[1], env
    )
    assert template_depends.keys == ("id", "user")
    assert template_depends.dependencies == {
        "puser",
    }
    assert template_depends.to_dict() == {("id", "user"): template_depends}
    templates = vl.LookupTemplate.from_config(config_template_dependency, env)
    templates = vl.flat_dict_items(templates)
    assert template_depends == templates.get(("id", "user"))

    assert not vl.check_template_dependencies(
        template_map,
        vl.LookupTemplate.from_dict(
            config_template_dependency.templates[2], env
        ).dependencies,
    )
    template_map.update(template_depends.to_dict())
    template_double = vl.LookupTemplate.from_dict(
        config_template_dependency.templates[2], env
    )
    assert template_double.keys == ("ssh",)
    assert template_double.dependencies == {"id", "puser"}
    assert template_double.to_dict() == {("ssh",): template_double}
    templates = vl.LookupTemplate.from_config(config_template_dependency, env)
    templates = vl.flat_dict_items(templates)
    assert template_double == templates.get(("ssh",))


def test_resolve_simple_template(env, config_template_simple):
    templates = vl.LookupTemplate.from_config(config_template_simple, env)
    vl.resolve_templates(config_template_simple, env)
    assert config_template_simple.map_template_salt_lookups == {
        vl.LookupTemplate("I@users", ("user",), set()): ["admin", "user1"]
    }
    assert config_template_simple.map_resolved_templates == {
        vl.LookupTemplate("I@users", ("user",), set()): []
    }
    assert config_template_simple.template_map == vl.flat_dict_items(templates)


def test_resolve_dependency_template(env, config_template_dependency):
    templates = vl.LookupTemplate.from_config(config_template_dependency, env)
    vl.resolve_templates(config_template_dependency, env)
    assert config_template_dependency.map_template_salt_lookups == {
        vl.LookupTemplate("I@ext_pillar_vault_ssh_keys:present", ("puser",), set()): [
            "admin",
            "user1",
        ],
        vl.LookupTemplate(
            "I@ext_pillar_vault_ssh_keys:present:admin", ("id", "user"), set()
        ): [
            {"id": "id_admin", "user": "admin1"},
            {"id": "id_intranet", "user": "root"},
        ],
        vl.LookupTemplate(
            "I@ext_pillar_vault_ssh_keys:present:user1", ("id", "user"), set()
        ): [
            {"id": "id_user", "user": "user1"},
        ],
        vl.LookupTemplate(
            "I@ext_pillar_vault_ssh_keys:admin:id_admin", ("ssh",), set()
        ): "newadminkey",
        vl.LookupTemplate(
            "I@ext_pillar_vault_ssh_keys:admin:id_intranet", ("ssh",), set()
        ): "intranetkey",
        vl.LookupTemplate(
            "I@ext_pillar_vault_ssh_keys:user1:id_user", ("ssh",), set()
        ): ["name"],
    }
    assert config_template_dependency.map_resolved_templates == {
        vl.LookupTemplate("I@ext_pillar_vault_ssh_keys:present", ("puser",), set()): [],
        vl.LookupTemplate(
            "I@ext_pillar_vault_ssh_keys:present:{{puser}}", ("id", "user"), {"puser"}
        ): sorted(
            [
                vl.LookupTemplate(
                    "I@ext_pillar_vault_ssh_keys:present:admin", ("id", "user"), set()
                ),
                vl.LookupTemplate(
                    "I@ext_pillar_vault_ssh_keys:present:user1", ("id", "user"), set()
                ),
            ]
        ),
        vl.LookupTemplate(
            "I@ext_pillar_vault_ssh_keys:{{puser}}:{{id}}", ("ssh",), {"puser", "id"}
        ): sorted(
            [
                vl.LookupTemplate(
                    "I@ext_pillar_vault_ssh_keys:admin:id_admin", ("ssh",), set()
                ),
                vl.LookupTemplate(
                    "I@ext_pillar_vault_ssh_keys:admin:id_intranet", ("ssh",), set()
                ),
                vl.LookupTemplate(
                    "I@ext_pillar_vault_ssh_keys:user1:id_user", ("ssh",), set()
                ),
            ]
        ),
    }
    assert config_template_dependency.template_map == vl.flat_dict_items(templates)


def test_resolve_template_paths(config_template_dependency, env):
    assert sorted(
        vl.get_path_pairs_from_template(config_template_dependency, env)
    ) == sorted(
        [
            (
                vl.LookupTemplate("secret/ssh/users/admin1/id_admin", "", set()),
                vl.LookupTemplate(
                    "users/present/admin/ssh_keys/id_admin_admin1", "", set()
                ),
            ),
            (
                vl.LookupTemplate("secret/ssh/users/root/id_intranet", "", set()),
                vl.LookupTemplate(
                    "users/present/admin/ssh_keys/id_intranet_root", "", set()
                ),
            ),
            (
                vl.LookupTemplate("secret/ssh/users/user1/id_user", "", set()),
                vl.LookupTemplate(
                    "users/present/user1/ssh_keys/id_user_user1", "", set()
                ),
            ),
        ]
    )


def test_path_pair_templates_valid(env, config_template_dependency):
    templates = vl.LookupTemplate.from_config(config_template_dependency, env)
    templates = list_of_dict_to_map(templates)
    path = vl.LookupTemplate.from_path(config_template_dependency.path, env)
    pillarpath = vl.LookupTemplate.from_path(config_template_dependency.pillarpath, env)
    assert vl.are_path_templates_valid(path, pillarpath, templates)


def test_retrieve_value_from_tuples():
    keymap = {
        ("t",): "t1",
        ("te", "h"): "t2",
        ("h", "e"): "t3",
        ("n", "k"): "t4",
        ("v", "v"): "t5",
    }
    assert vl.get_template_from_template_map("t", keymap) == "t1"
    assert vl.get_template_from_template_map("te", keymap) == "t2"
    assert vl.get_template_from_template_map("e", keymap) == "t3"

    with pytest.raises(vl.LookupException):
        assert vl.get_template_from_template_map("h", keymap) == "t2"
    with pytest.raises(vl.LookupException):
        assert vl.get_template_from_template_map("doesnotexist", keymap) == "nope"

    assert vl.get_template_from_template_map("v", keymap) == "t5"


def test_render_templates2(env):
    template_one = vl.LookupTemplate.from_dict(
        {
            "keys": [
                "one",
            ],
            "lookup": "I@test:item",
        },
        env,
    )
    template_dep_one = vl.LookupTemplate.from_dict(
        {
            "keys": [
                "puser",
            ],
            "lookup": "I@ok:{{one}}",
        },
        env,
    )
    template_map = {
        ("one",): template_one,
    }
    map_template_salt_lookups = {
        template_one: [
            "1",
            "2",
            "3",
        ],
    }
    map_resolved_templates = {}
    assert sorted(
        vl.render_template(
            template_dep_one,
            template_map,
            map_template_salt_lookups,
            map_resolved_templates,
            {},
            env,
        )
    ) == sorted(
        [
            vl.LookupTemplate.from_dict(
                {
                    "keys": [
                        "puser",
                    ],
                    "lookup": "I@ok:1",
                },
                env,
            ),
            vl.LookupTemplate.from_dict(
                {
                    "keys": [
                        "puser",
                    ],
                    "lookup": "I@ok:2",
                },
                env,
            ),
            vl.LookupTemplate.from_dict(
                {
                    "keys": [
                        "puser",
                    ],
                    "lookup": "I@ok:3",
                },
                env,
            ),
        ]
    )

    # now test for permutations which depend on a previous lookup
    template_one = vl.LookupTemplate.from_dict(
        {
            "keys": [
                "one",
            ],
            "lookup": "I@test:item",
        },
        env,
    )
    template_puser = vl.LookupTemplate.from_dict(
        {
            "keys": [
                "puser",
                "id",
            ],
            "lookup": "I@ok:{{one}}",
        },
        env,
    )
    template = vl.LookupTemplate.from_dict(
        {
            "keys": [
                "loc",
            ],
            "lookup": "I@loc:{{one}}:{{id}}",
        },
        env,
    )
    template_map = {
        ("one",): template_one,
        ("id", "puser"): template_puser,
        ("loc",): template,
    }
    template_puser1 = vl.LookupTemplate.from_dict(
        {
            "keys": [
                "puser",
                "id",
            ],
            "lookup": "I@ok:1",
        },
        env,
    )
    template_puser2 = vl.LookupTemplate.from_dict(
        {
            "keys": [
                "puser",
                "id",
            ],
            "lookup": "I@ok:2",
        },
        env,
    )
    map_template_salt_lookups = {
        template_one: [
            "1",
            "2",
        ],
        template_puser1: [
            {"puser": "user1", "id": "id1"},
            {"puser": "user1", "id": "id2"},
        ],
        template_puser2: [
            {"puser": "user2", "id": "id3"},
        ],
    }
    map_resolved_templates = {}
    assert sorted(
        vl.render_template(
            template_puser,
            template_map,
            map_template_salt_lookups,
            map_resolved_templates,
            {},
            env,
        )
    ) == sorted(
        [
            template_puser1,
            template_puser2,
        ]
    )


def test_ensure_dependencies_present(env, config_template_dependency):
    template1 = vl.LookupTemplate("test", ("one",))
    template2 = vl.LookupTemplate("{{one}}", ("l1", "l2"))
    template_ast = env.parse(template2.lookup)
    template_variables = vl.find_undeclared_variables(template_ast)
    template_map = {}
    template_map.update(template2.to_dict())

    assert not vl.check_template_dependencies(template_map, template_variables)
    template_map.update(template1.to_dict())
    assert vl.check_template_dependencies(template_map, template_variables)


def test_adj(config_template_dependency, env):
    config_template_dependency.templates.append(
        {
            "keys": [
                "one",
            ],
            "lookup": "I@t1:{{id}}",
        }
    )
    config_template_dependency.templates.append(
        {
            "keys": [
                "new",
            ],
            "lookup": "I@t1:{{id}}:{{ssh}}",
        }
    )
    config_template_dependency.templates.append(
        {
            "keys": [
                "me",
            ],
            "lookup": "I@t1:{{one}}:{{new}}:{{ssh}}",
        }
    )
    tmp_templates = vl.LookupTemplate.from_config(config_template_dependency, env)
    templates = {}
    for t in tmp_templates:
        templates.update(t)
    r = vl.TemplatesAdjacency(templates)
    assert r.get_resolve_path("me") == [
        ("puser",),
        ("id", "user"),
        ("ssh",),
        ("one",),
        ("new",),
        ("me",),
    ]
    r.reinit()
    assert r.get_resolve_path("ssh") == [("puser",), ("id", "user"), ("ssh",)]


def test_dict_subset():
    assert vl.isdict_subset(
        {
            "a": 1,
            "b": 2,
        },
        {
            "a": 1,
            "b": 2,
        },
    )
    assert vl.isdict_subset(
        {
            "a": 1,
            "b": 2,
        },
        {
            "a": 1,
            "c": 3,
        },
    )
    assert not vl.isdict_subset(
        {
            "a": 1,
            "b": 2,
        },
        {
            "a": 2,
            "c": 3,
        },
    )
    assert not vl.isdict_subset(
        {
            "a": 1,
            "b": 2,
        },
        {
            "c": 3,
            "d": 4,
        },
    )


@pytest.mark.parametrize(
    "pattern,pillar,expected",
    [
        pytest.param("G@id@wrong", {}, None),
        pytest.param("G@id", {}, "host1"),
        pytest.param("G@id", {"id": "nope"}, "host1"),
        pytest.param("I@user", {}, "admin"),
        pytest.param("I@user", {"user": "replaceduser"}, "replaceduser"),
        pytest.param("I@cluster", {}, ["c1", "c2", "c3"]),
        pytest.param("I@cluster=c1", {}, "c1"),
        pytest.param("I@cluster=c4", {}, None),
        pytest.param("I@cluster=c4", {"cluster": ["c4", "c5"]}, "c4"),
        pytest.param(
            "I@ext_pillar_vault_ssh_keys:present:user1",
            {},
            [
                {
                    "id": "id_user",
                    "user": "user1",
                },
            ],
        ),
        pytest.param(
            "I@ext_pillar_vault_ssh_keys:present:user1",
            {
                "ext_pillar_vault_ssh_keys": {
                    "present": {
                        "user1": "replaceduser1value",
                    },
                },
            },
            "replaceduser1value",
        ),
        pytest.param(
            "I@ext_pillar_vault_ssh_keys:present:user1",
            {
                "ext_pillar_vault_ssh_keys": {
                    "present": {
                        "user2": "replaceduser1value",
                    },
                },
            },
            [
                {
                    "id": "id_user",
                    "user": "user1",
                },
            ],
        ),
        pytest.param(
            "I@ext_pillar_vault_ssh_keys:present:user3",
            {
                "ext_pillar_vault_ssh_keys": {
                    "present": {
                        "user3": ["replaceduser3value"],
                    },
                },
            },
            ["replaceduser3value"],
        ),
        pytest.param(
            "I@ext_pillar_vault_ssh_keys:present:user4",
            {
                "ext_pillar_vault_ssh_keys": {
                    "present": {
                        "user3": ["replaceduser3value"],
                    },
                },
            },
            None,
        ),
        pytest.param(
            "I@test",
            {
                "test": {
                    "one": 2,
                    "ok": "what",
                },
            },
            {"one": 2, "ok": "what"},
        ),
    ],
)
def test_salt_pattern_resolve(pattern, pillar, expected):
    assert vl.resolve_pattern(pattern, pillar) == expected
