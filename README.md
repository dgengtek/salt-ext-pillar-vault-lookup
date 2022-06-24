# Saltstack pillar extension module for vault

This repository contains an implementation and tests for mapping vault paths to
pillar paths dynamically during runtime.

* filtering by keys of the vault data(select only keys you want in the pillar)
* filtering by matching keys and selected values
* supported lookup of grains and pillars 
  * in either vault path or pillar path 
  * for filling values of matchers
* templating of path via jinja and using lookup results

The module parses the configuration and collects all found lookups(grains G@, pillar I@) in a set. During its
first pass through it does a lookup for each unique lookup definition so that a
repeatedly defined lookup is not requested multiple times.

The code could be potentially used for a vault renderer.


## Installation

Drop [this file](./vault_lookup.py) in the <extension_modules>/pillar directory which is 
[configured on the salt-master](https://docs.saltproject.io/en/latest/ref/configuration/master.html#extension-modules)


## Run tests

    $ pip3 install -r requirements.txt
    $ pytest


## Configuration
### In salt master

Either in salt-master config

    ext_pillar:
      - vault_lookup:
          lookup_key: ext_pillar_vault_lookup
          config:
            "<some arbitrary key>":
              - path: secret/admin/id_admin
                pillarpath: users/admin/key


### In salt master and pillar

Or pull the configuration from pillar if defined in the default pillar key `ext_pillar_vault_lookup`.

    ext_pillar:
      - <some_other_module>: {}
      ...
      - vault_lookup: {}

Somewhere set the config in pillar before vault_lookup module

    ext_pillar_vault_lookup:
      "<some arbitrary key>":
        - path: secret/admin/id_admin
          pillarpath: users/admin/key


## Examples
### Single lookup 

Single lookup of mapping a vault path to a pillarpath

    ext_pillar:
      - vault_lookup:
          config:
            "simple lookup":
              # single mapping
              - path: secret/admin/id_admin
                pillarpath: users/admin/key

vault lookup:

    private: <value>
    public: <value>
    
mapped to pillar:

    users:
      admin:
        key:
          private: <value>
          public: <value>


### Wildcard

Example of using wildcards. There must be an equal amount of wildcards for both paths.

    ext_pillar:
      - vault_lookup:
          config:
            "wildcard 1.":
              # map each entry from list lookup of ../workers/* to ../worker_keys/* in pillar
              #  eg list returns ../workers/{worker1, worker2} which will map to pillar ../worker_keys/{worker1, worker2}
              - path: secret/workers/*
                pillarpath: somepath/*
            "wildcard 2.":
              - path: secret/nested/*/secrets/*
                pillarpath: mapped/*/secret/*/value

For the item wildcard 1.:

    path: secret/workers/*
    pillarpath: somepath/*

path wildcard of vault contains ["w1", "w2"]. For each item a lookup will be done and the result mapped to pillarpath

    secret/workers/w1 -> somepath/w1
    secret/workers/w2 -> somepath/w2

For the item wildcard 2.:

The products of each result will be combined and mapped to the pillarpath

    path: secret/*/items/* 
    pillarpath: mapped/*/secret/*/value

* eg secret/* returns ["s1", "s2"] 
* eg secret/s1/items/* returns ["i1", "i2"]
* eg secret/s2/items/* returns ["i3", "i4"]

The resulting mapping from vault(path) -> to pillar(pillarpath)

    secret/s1/items/i1 -> mapped/s1/secret/i2/value
    secret/s1/items/i2 -> mapped/s1/secret/i2/value
    secret/s2/items/i3 -> mapped/s2/secret/i3/value
    secret/s2/items/i4 -> mapped/s2/secret/i4/value


### Filtering with single lookup

Example of conditionally filtering with single lookup

    ext_pillar:
      - vault_lookup:
          config:
            "default":
              - path: secret/path
                pillarpath: path/value
                # use all keys from the vault path lookup
                keys: []
                matches:
                  - keys: 
                      - host
                    # if the value of the key 'host' matches any of the values defined here, keep them in the keyset from the vault lookup
                    values: 
                      - host3
                      - host7
                      - host9
                    # otherwise remove the listed keys here from the keyset defined in the outer definition 'keys'
                    # the keys here are added with their values to the result only if 'host' matches any of the values
                    add_keys:
                      - private

eg the data the vault lookup of secret/path returns:

    host: host3
    private: pkey
    anotherkey: anothervalue

value of key host is in the values of the matchers so the key 'private' will not be removed:

    path:
      value:
        host: host3
        private: pkey
        anotherkey: anothervalue
      

if the vault lookup was instead:

    host: host1
    private: pkey
    anotherkey: anothervalue

then the mapped pillar would look:

    path:
      value:
        host: host1
        anotherkey: anothervalue


### Using grains or pillars in values of matchers

    ext_pillar:
      - vault_lookup:
          config:
            "example 1":
              - path: secret/path
                pillarpath: path/value
                # only select the keys named 'public' and 'private' from the vault lookup keyset
                keys:
                  - public
                  - private
                matches:
                  - keys: 
                      - host
                    # lookup grain id to check against the value of the vault lookup
                    values: 
                      - G@id
                    # add keys if any of the values matched the lookup of the path, otherwise remove listed keys from the list of keys to add
                    add_keys:
                      - private
                  - keys: 
                      - location
                    # lookup pillar path 'locations:west:hosts' to check against the value of the vault lookup of the key 'location'
                    values: 
                      - I@locations:west:hosts
                      - I@hosts
                    # add keys if any of the values matched the lookup of the path, otherwise remove listed keys from the list of keys to add
                    add_keys:
                      - public
            "example 2":
              - path: secret/app1
                pillarpath: app1
                keys:
                  - token
                matches:
                  - keys: 
                      - slave
                    values: 
                      - I@appslaves
                    add_keys:
                      - token

vault lookup of example 1. secret/path:

    host: host3
    public: pubkey
    private: pkey
    anotherkey: anothervalue

if the value of the key host matches the result of G@id then the pillar would be:

    path:
      value:
        public: pubkey
        private: pkey
      

if the value of G@id was host1 instead then the mapped pillar would look:

    path:
      value:
        public: pubkey


### Adding all keys or none if the matcher is not true.

    ext_pillar:
      - vault_lookup:
          config:
            "default":
              - path: "secret/path"
                pillarpath: "path/values"
                # use all keys from the vault path lookup
                keys: []
                matches:
                # if keys empty and values are not empty then merge all keys
                  - keys: []
                    values: 
                      # only add all keys if the pillar lookup path 'somevalue:defined' is not empty
                      # otherwise no keys will be added
                      - 'I@somevalue:defined'
                    add_keys: []


### Matching against an exact value of a pillar lookup

    ext_pillar:
      - vault_lookup:
          config:
            "default":
              - path: "secret/salt/concourse/master/session_signing_key"
                pillarpath: "concourse/web/session_signing_key"
                # use all keys from the vault path lookup
                keys: []
                matches:
                # if keys empty and values are not empty then merge all keys, otherwise none are added
                  - keys: []
                    values: 
                      # only do it if the pillar lookup of 'tags' contains 'concourse-master'
                      - 'I@tags=concourse-master'
                    add_keys: []

### Using grains or pillars in the paths. 

These will expand and create multiple pairs matching their result. A lookup
result which contains a list will iterate over it. For a dictionary only the
keynames will be replaced for it.

If only either one of the paths contains a lookup definition its lookup value
must be a single value. If the lookup value contains a list or dict then both
paths need to have the same lookup definition otherwise it will be unable to
create pairs to map against.

    ext_pillar:
      - vault_lookup:
          config:
            # single value lookup is fine
            "example 1":
              - path: "secret/salt/concourse/workers/G@id"
                pillarpath: "concourse/worker/G@id/worker_key"
            # single value lookup is fine even if the other path contains no lookups
            "example 2":
              - path: "secret/salt/concourse/workers/G@id"
                pillarpath: "concourse/worker/secret"
            # this lookup must be a single value 
            "example 3":
              - path: "secret/personal/I@some:path"
                pillarpath: "private/secret"
            # if this lookup contains a list or dict then the other path must have the same lookup definition
            "example 4":
              - path: "secret/personal/I@persons"
                pillarpath: "private/I@persons"
            # if pillar clustermembers returns a list, run a vault lookup for each item
            #  or if it is a value only a single lookup
            "example 5":
              - path: hosts/I@clustermembers/secret
                # if the lookup was a single value, map to pillar 'myapp'
                #   if it was a list then the lookup is required to be in pillarpath too
                # pillarpath: myapp/I@clustermembers
                #   otherwise there is no way to know how to map
                pillarpath: myapp

Vault lookup for example 4:
  
I@persons returns a list of ["p1", "p2"] or if it returns a dict of {"p1": {...}, "p2": ...} 

    secret/personal/p1 -> private/p1
    secret/personal/p2 -> private/p2

Mapped pillar would be merged to:

    private:
      p1:
        # result from the vault lookup mapped
        # key: value 
        ...
      p2:
        ...


### Matching against a value of a lookup result in paths

Using multiple counts for lookups is fine since it will map to one path each.:

    ext_pillar:
      - vault_lookup:
          config:
            "single lookup result":
              # do a lookup of the pillar I@cluster and continue if it resolves to master1
              # do a lookup of the pillar I@role and continue only if it is 'backup'
              - path: hosts/I@cluster=master1/webtoken
                pillarpath: myapp/config/I@role=backup/token
              # this will map to:
                # path -> hosts/master1/webtoken
                # pillarpath -> myapp/config/backup/token
            "multiple single lookups":
              - path: hosts/I@cluster=master1/webtoken
                pillarpath: myapp/I@app=app1/I@role=backup/token
              - path: hosts/I@backupserver=b1/secret
                pillarpath: backup/hosts/G@id/I@location/token

If I@cluster returns ["master1", "master2"] and I@role returns ["server", "backup"] then it will be mapped hosts/master1/webtoken -> myapp/config/token


### Jinja template rendering

Templates are mainly used to do lookups of a result of a previous lookup(a template depends on a previous templates result).

The constraint for using the keys from a template definition in paths is that all keys are of the same root template definition and either

1. the used keys are from the same templates used

        # k1 and k2 are from the same template
        - path: secret/{{k1}}/{{k2}}
          pillarpath: new/{{k2}}
          template:
            - keys:
              - k1
              - k2
              lookup: "I@somelookup"
            - keys:
              - k3
              lookup: "I@otherlookup"

2. or all the templates of the keys used in pillarpath contain all the templates from path
    ie is the set of keys from the templates of a path a subset of the keys from the templates of pillarpath


Practically make sure that the templates can be resolved in order of the list they are defined in.

Example of using jinja2 templates in paths and template definitions which depend
on a previous template definition.

    ext_pillar:
      - vault_lookup:
          config:
            "jinja template rendering":
              # lookup keys for templates {{key}} defined in paths
              - path: "secret/ssh/users/{{user}}/{{id}}"
                pillarpath: "users/present/{{puser}}/ssh_keys/{{id}}"
                keys:
                  - public
                  - private
                matches:
                  - keys: 
                      - host
                    values: 
                      - G@id
                    add_keys:
                      - private
              # keys from a lookup can be used for the following lookups in the list
                template:
                  # keys gets the values from the lookup and is used for templating paths or templates which depend on this key
                  # if 'ext_pillar_vault_ssh_keys:present' is a dict, puser will be the keyname for each key of the dict lookup result
                  # if 'ext_pillar_vault_ssh_keys:present' is a list, puser will be the name for each item of the list
                  # invalid if there are multiple keys listed and the lookup only resolves to a single value, list of values and not a dict
                  # t1.
                  - keys:
                    - puser
                    lookup: "I@ext_pillar_vault_ssh_keys:present"
                  # multiple keys can be used to match the result
                  # if the lookup is a dict the listed keys will be used for the lookup of the dict
                  # if the lookup is a list of dict then the keys named here will be used from lookup for each dict in the list
                  # t2.
                  - keys:
                    - id
                    - user
                    lookup: "I@ext_pillar_vault_ssh_keys:present:{{puser}}"

The pillar lookup of template t1 'ext_pillar_vault_ssh_keys:present' returns

    admin:
      - user: backup
        id: id_backup
      - user: root
        id: intranet
    root:
      - user: root
        id: id_root

The values of the key 'puser' will be ["admin", "root"]


The pillar lookup of template t2 'ext_pillar_vault_ssh_keys:present:admin' returns

    - user: backup
      id: id_backup
    - user: root
      id: intranet

Keys and value pairs will be [(id: id_backup, user: backup), (id: intranet, user: root)]

The pillar lookup of template t2 'ext_pillar_vault_ssh_keys:present:root' returns

    - user: root
      id: intranet

Keys and value pairs will be [(id: id_root, user: root)]


mapping of values for each pair:

    secret/ssh/users/backup/id_backup -> users/present/admin/ssh_keys/id_backup
    secret/ssh/users/root/intranet -> users/present/admin/ssh_keys/intranet

    secret/ssh/users/root/id_root -> users/present/root/ssh_keys/intranet



### Mixing of templates, lookups, wildcards.

Order of rendering to get the resolved paths for vault lookup and pillarpath:

1. templates in the order of definition will be resolved first
2. then the lookups will be rendered on the results
3. wildcards are iterated over last


The config:

    ext_pillar:
      - vault_lookup:
          config:
            "mix":
              - path: "secret/apps/*/{{worker}}/I@appslaves"
                pillarpath: "app/*/users/{{keyid}}/ssh_keys/I@appslaves"
                template:
                # t1.
                  - keys:
                    - worker
                    lookup: "I@workers"
                # t2.
                  - keys:
                    - keyid
                    lookup: "I@workers:{{worker}}:config:keyid"


Order of processing:

1. Existing pillar :

        workers:
          w1:
            config:
              keyid: | ...
          w2:
            config:
              keyid: | ...

Result of template t1.

    worker: ["w1", "w2"]

Result of template t2.

    keyid: ["k1", "k2"]

2. Salt pillar lookup
  

        I@appslaves = ["s1", "s2"]

3. wildcard vault listing


        secret/apps/* -> ["app1", "app2"]


Result of rendering in order and their mapping

1. templates

    path: "secret/apps/*/{{worker}}/I@appslaves"

    pillarpath: "app/*/users/{{keyid}}/ssh_keys/I@appslaves"

        secret/apps/*/w1/I@appslaves -> app/*/users/k1/ssh_keys/I@appslaves
        secret/apps/*/w2/I@appslaves -> app/*/users/k2/ssh_keys/I@appslaves

2. lookups

        secret/apps/*/w1/s1 -> app/*/users/k1/ssh_keys/s1
        secret/apps/*/w1/s2 -> app/*/users/k1/ssh_keys/s2
        secret/apps/*/w2/s1 -> app/*/users/k2/ssh_keys/s1
        secret/apps/*/w2/s2 -> app/*/users/k2/ssh_keys/s2

3. wildcard

        secret/apps/app1/w1/s1 -> app/app1/users/k1/ssh_keys/s1
        secret/apps/app2/w1/s1 -> app/app2/users/k1/ssh_keys/s1
        secret/apps/app1/w1/s2 -> app/app1/users/k1/ssh_keys/s2
        secret/apps/app2/w1/s2 -> app/app2/users/k1/ssh_keys/s2
        secret/apps/app1/w2/s1 -> app/app1/users/k2/ssh_keys/s1
        secret/apps/app2/w2/s1 -> app/app2/users/k2/ssh_keys/s1
        secret/apps/app1/w2/s2 -> app/app1/users/k2/ssh_keys/s2
        secret/apps/app2/w2/s2 -> app/app2/users/k2/ssh_keys/s2


If anything fails the pair will not be considered for pillar merging.
