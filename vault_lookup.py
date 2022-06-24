"""
saltstack pillar extension module

drop this file in the <extension_modules>/pillar directory
"""
from queue import deque
import logging
import itertools
import copy

log = logging.getLogger(__name__)

__virtualname__ = "vault_lookup"


import_module = True
try:
    from jinja2 import Environment
    from jinja2.meta import find_undeclared_variables
except ImportError:
    import_module = False


def __virtual__():
    if import_module:
        return __virtualname__
    else:
        return False


def ext_pillar(
    minion_id,
    pillar,
    lookup_key="ext_pillar_vault_lookup",
    config=None,
):
    """
    Get pillar data from Vault for the given configuration either defined from the
    parameter 'config' or with the given parameter 'lookup_key' to retrieve the
    configuration from the pillar
    """
    vault_pillar = pillar.get(lookup_key, {})
    log.debug("vault_lookup: config {}".format(vault_pillar))
    if config:
        log.debug(
            "vault_lookup: adding config from master configuration {}".format(config)
        )
        vault_pillar.update(config)

    if not vault_pillar:
        log.info("No configuration given for vault_lookup")
        return {}
    log.debug("vault_lookup: final config {}".format(vault_pillar))

    new_pillar = {}
    for description, vault_lookup_config in vault_pillar.items():
        for item in vault_lookup_config:
            config = Config.from_dict(description, item, pillar)

            try:
                for d in get_mapped_pillar(config):
                    if d:
                        new_pillar = __salt__.slsutil.update(
                            d, new_pillar, recursive_update=True
                        )
            except Exception as e:
                log.error(
                    "vault_lookup: Unable to continue to merge pillars for {} config '{}' paths {} -> {}. {}".format(
                        minion_id, config.description, config.path, config.pillarpath, e
                    )
                )

    return new_pillar


class Config:
    def __init__(self, path, pillarpath, keys, matchers, templates, pillar):
        self.path = path
        self.pillarpath = pillarpath
        self.keys = keys
        self.matchers = matchers
        self.templates = templates
        self.pillar = pillar
        self.template_map = {}
        self.map_template_salt_lookups = {}
        self.map_resolved_templates = {}
        self.description = ""

    def __str__(self):
        return self.to_string()

    def to_string(self):
        description = self.description
        if not description:
            description = "no description"
        return "{{\"{}\", '{}', '{}', keys={}, matchers={}, templates={}, template_map={}, map_template_salt_lookups={}, map_resolved_templates={} }}".format(
            description,
            self.path,
            self.pillarpath,
            self.keys,
            self.matchers,
            self.templates,
            self.template_map,
            self.map_template_salt_lookups,
            self.map_resolved_templates,
        )

    def __repr__(self):
        return "Config{}".format(self.to_string())

    def get_lookups(self):
        return self.path.get_lookups().union(self.pillarpath.get_lookups())

    def has_templates(self):
        """
        are templates defined?
        """
        return bool(self.templates)

    @classmethod
    def from_dict(cls, description, item, pillar):
        config = cls(
            LookupPath(item.get("path"), False),
            LookupPath(item.get("pillarpath"), True),
            item.get("keys", []),
            item.get("matches", []),
            item.get("templates", []),
            pillar,
        )
        config.description = description
        return config


class LookupPath:
    def __init__(self, path, is_pillarpath, delimiter="/"):
        self.delimiter = delimiter
        self.path = path
        self.split_path = self.path.split(delimiter)
        self.resolved_paths = []
        self.is_pillarpath = is_pillarpath
        self.lookups_salt = []
        self.lookups_vault_wildcard = []

    def wildcards(self):
        return self.path.count("*")

    def lookups(self):
        return self.path.count("@")

    def get_lookups(self, matchers=True):
        lookups = set()
        for p in self.split_path:
            if "@" in p:
                if "=" in p and not matchers:
                    continue
                lookups.add(p)
        return lookups

    def get_lookup_matchers(self):
        lookups = set()
        for lookup in self.get_lookups(matchers=True):
            if "=" in lookup:
                lookups.add(lookup)
        return lookups

    def get_wildcard_prefix(self):
        wildcard = self.path.split("*")
        len_wildcard = len(wildcard)
        if len_wildcard == 1:
            return ""
        result = []
        for p in self.split_path:
            if p == "*":
                break
            result.append(p)
        return self.delimiter.join(result)

    def replace(self, old, new, count=-1):
        return LookupPath(
            self.path.replace(old, new, count), is_pillarpath=self.is_pillarpath
        )

    def get_salt_lookup(self, lookup_map):
        result = []
        for lookup in self.get_lookups():
            r = lookup_map.get(lookup, "")
            if r:
                result.append((lookup, r))
        return result

    def lookup_matchers(self):
        return self.path.count("=")

    def isvalid(self):
        """
        is this a path that is valid for a vault lookup?
        """
        return self.lookups() == 0 and self.wildcards() == 0

    def isresolved(self):
        """
        has this path been resolved?
        """
        # is not a resolved path itself and contains results from a resolve
        return not self.isvalid() and bool(self.resolved_paths)

    def __iter__(self):
        return self.split_path.__iter__()

    def __next__(self):
        return self.split_path.__next__()

    def __eq__(self, other):
        if isinstance(other, str):
            return self.path == other
        return self.path == other.path and self.is_pillarpath == other.is_pillarpath

    def __lt__(self, other):
        return self.path < other.path

    def __str__(self):
        return self.to_string()

    def to_string(self):
        return "{{'{}' Resolved?{} Pillarpath?{}}}".format(
            self.path, self.isvalid(), self.is_pillarpath
        )

    def __repr__(self):
        return "Lookuppath{}".format(self.to_string())

    @classmethod
    def from_template(cls, template, is_pillarpath):
        if template.has_dependencies():
            raise LookupException(
                "Template {} still has dependencies which were not rendered. Unable to convert to a path"
            )

        return cls(template.lookup, is_pillarpath)


class LookupTemplate:
    """
    stores data related to lookups of templates
    which can have jinja2 templating
    """

    def __init__(
        self,
        lookup,
        keys,
        dependencies=None,
    ):
        self.lookup = lookup
        self.__jinja_template = None
        self.keys = keys
        if not dependencies:
            dependencies = set()
        self.dependencies = dependencies
        self.parent_lookup = {}
        self.parent = None

    def __eq__(self, other):
        return self.lookup == other.lookup and self.keys == other.keys

    def __lt__(self, other):
        return self.lookup < other.lookup

    def to_dict(self):
        return {self.keys: self}

    def to_string(self):
        if self.parent:
            parent_lookup = self.parent.lookup
        else:
            parent_lookup = ""
        return '("{}", {}, {}, ^{}^, {})'.format(
            self.lookup, self.keys, self.dependencies, parent_lookup, self.parent_lookup
        )

    def __repr__(self):
        return "LookupTemplate{}".format(self.to_string())

    def has_dependencies(self):
        """
        if it has no dependencies then it means that this lookup can be resolved
        """
        return bool(self.dependencies)

    def get_ancestors(self):
        ancestors = []
        ancestors.append(self)

        template = self.parent
        if not template:
            return ancestors
        ancestors.append(template)
        while True:
            tmp = template.parent
            if not tmp:
                return ancestors
            template = tmp
            ancestors.append(template)

    def render(self, environment, **kwargs):
        """
        render lookup and create a new lookuptemplate from it
        """
        lookup = self.__jinja_template.render(kwargs)
        ast = environment.parse(lookup)
        dependencies = find_undeclared_variables(ast)
        template = LookupTemplate(lookup, self.keys, dependencies)
        template.__jinja_template = environment.from_string(lookup)
        template.parent_lookup = kwargs
        template.parent = self
        return template

    @classmethod
    def from_path(cls, path, environment):
        lookup = path.path
        ast = environment.parse(lookup)
        dependencies = find_undeclared_variables(ast)
        template = cls(
            lookup,
            "",
            dependencies,
        )

        template.__jinja_template = environment.from_string(template.lookup)
        return template

    @classmethod
    def from_dict(cls, template, environment):
        lookup = template.get("lookup")
        ast = environment.parse(lookup)
        dependencies = find_undeclared_variables(ast)
        template = cls(
            lookup,
            tuple(sorted(template.get("keys"))),
            dependencies,
        )

        template.__jinja_template = environment.from_string(template.lookup)
        return template

    @classmethod
    def from_config(cls, config, environment):
        """
        returns a list in order of the template mappings to be iterated over in order
        and converted to a map after the templates with dependencies have been
        resolved
        """
        result = []
        for template in config.templates:
            result.append(cls.from_dict(template, environment).to_dict())

        template_map = flat_dict_items(result)
        for template in template_map.values():
            if not check_template_dependencies(template_map, template.dependencies):
                raise LookupException(
                    "Cannot lookup dependencies of this template {}".format(template)
                )
        return result

    def get_resolved_entry(self, salt_resolver, pillar):
        """
        resolve lookup for this template and create an entry for a lookup map
        when looking for template
        """
        if self.has_dependencies():
            return {}
        value = salt_resolver(self.lookup, pillar)
        if not value:
            log.warning("Could not lookup value from salt for {}".format(self.lookup))
            return {}
        if isinstance(value, dict):
            value = list(value.keys())
        return {self: value}

    def __hash__(self):
        return hash(self.keys)


class TemplatesAdjacency:
    """
    Collection for directional dependency to other templates

    Used for finding the longest path to resolve template dependency chain
    """

    def __init__(self, templates_map):
        """ """
        self.templates_map = templates_map
        self.adj = {}
        self.reinit()

    def reinit(self):
        self._init_adjecency(self.templates_map)

    def _init_adjecency(self, templates):
        self.adj = {}
        has_root = False
        for k, v in templates.items():
            if not v.dependencies:
                has_root = True
            values = {}
            values["tsnr"] = 0
            values["visited"] = False
            values["deps"] = v.dependencies
            self.adj.update({k: values})
        if not has_root:
            raise TemplateError(
                "Templates {} have no root without any dependencies. Recursion not resolvable"
            )

    def get_resolve_path(self, key):
        tsnr = 0
        path = []
        found = False
        for k, v in self.adj.items():
            if found:
                break
            if v["tsnr"] != 0:
                continue
            ######
            queue = deque()
            queue.append((k, v))
            while len(queue) > 0:
                k, v = queue.popleft()
                if v["tsnr"]:
                    continue
                tsnr = tsnr + 1
                v["tsnr"] = tsnr
                path.append(k)
                if key in k:
                    found = True
                    break
                deep_edge_list = []
                for w in sorted(v["deps"]):

                    template_lookup = get_template_from_template_map(
                        w, self.templates_map
                    )
                    w_values = self.adj.get(template_lookup.keys)
                    if w_values["tsnr"]:
                        continue

                    deep_edge_list.append((w, w_values))

                for item in reversed(deep_edge_list):
                    queue.insert(0, item)
        return path


class LookupException(BaseException):
    pass


class ResolveError(BaseException):
    pass


class TemplateError(BaseException):
    pass


def collect_all_lookups(*args):
    """
    get lookups for each path and return the union
    """
    result = set()
    for arg in args:
        if isinstance(arg, LookupPath):
            result = result.union(arg.get_lookups())
        elif isinstance(arg, LookupTemplate):
            result = result.union({arg.lookup})
    return result


def get_path_pair(path_one, path_two):
    if path_one.is_pillarpath and not path_two.is_pillarpath:
        pillarpath = path_one
        path = path_two
    elif path_two.is_pillarpath and not path_one.is_pillarpath:
        pillarpath = path_two
        path = path_one
    else:
        return None
    return pillarpath, path


def are_paths_valid(path_one, path_two):
    lookup_pair = get_path_pair(path_one, path_two)
    if not lookup_pair:
        log.info(
            "Either {} and {} are marked as pillarpaths or none".format(
                path_one, path_two
            )
        )
        return False
    pillarpath, path = lookup_pair

    if path_one.wildcards() != path_two.wildcards():
        log.info(
            "Path {} and path {} contain an unequal amount of wildcards".format(
                path_one, path_two
            )
        )
        return False

    if (not path.isvalid() and not path.isresolved()) or (
        not pillarpath.isvalid() and not pillarpath.isresolved()
    ):
        log.info("{} or {} are not resolved paths".format(path_one, path_two))
        return False

    len_path_resolved = len(path.resolved_paths)
    len_pillarpath_resolved = len(pillarpath.resolved_paths)
    if len_path_resolved != len_pillarpath_resolved:
        log.info(
            "Path(resolved length): {}({}) and {}({}) have different resolved lengths".format(
                path, len_path_resolved, pillarpath, len_pillarpath_resolved
            )
        )
        return False

    # more than one resolved path so lookups must be equal to be matched
    if len_path_resolved > 1:
        path_salt_lookups = path.get_lookups(matchers=False)
        pillarpath_salt_lookups = pillarpath.get_lookups(matchers=False)
        if sorted(path_salt_lookups) != sorted(pillarpath_salt_lookups):
            log.info(
                "Too many resolved paths. Lookups for {} and {} are different".format(
                    path_one, path_two
                )
            )
            return False
    return True


def get_data(path):
    """
    retrieve data from vault for the path
    """
    if not path.isvalid():
        raise ResolveError("Path {} is not fully resolved.".format(path))

    return __salt__["vault.read_secret"](path.path)


def build_vault_paths(prefix):
    """
    get all subpaths of the prefix
    """
    if not prefix:
        return []
    return __salt__["vault.list_secrets"](prefix).get("keys", [])


def get_salt_lookup_map(lookups, pillar):
    """
    build map of the salt lookup pattern and its values
    """
    lookup_results = {}
    for lookup in lookups:
        value = resolve_pattern(lookup, pillar)
        if not value:
            log.warning("Could not lookup value from salt for {}".format(lookup))
            continue
        lookup_results[lookup] = value
    return lookup_results


def get_resolved_paths(path, salt_lookup_map, fresh=False):
    """
    create resolved paths with resolver for a path
    not for pillarpath
    """
    if (fresh or not path.isresolved()) and not path.is_pillarpath:
        path.resolved_paths = build_path(path, salt_lookup_map, build_vault_paths)
    return path.resolved_paths


def get_resolve_from_path(path_one, path_two, salt_lookup_map, fresh=False):
    """
    resolve a pillarpath from the given path
    """
    lookup_pair = get_path_pair(path_one, path_two)
    if not lookup_pair:
        raise LookupException(
            "Either {} and {} are marked as pillarpaths or none".format(
                path_one, path_two
            )
        )
    pillarpath, path = lookup_pair
    if not path.isresolved() and not path.isvalid():
        raise ResolveError("Path {} is not resolved. Unable to build from".format(path))

    if fresh or not pillarpath.isresolved():
        resolved_paths = build_pillarpath_from_path(pillarpath, path, salt_lookup_map)
        # if path is not itself valid for a vault resolve
        #  ie it has been resolved with vault previously
        if not path.isvalid():
            for rp in resolved_paths:
                pillarpath.resolved_paths.extend(
                    build_path_from_wildcards(rp, path.lookups_vault_wildcard)
                )
        else:
            pillarpath.resolved_paths = resolved_paths
    return pillarpath.resolved_paths


def build_pillarpath_from_path(pillarpath, path, salt_lookup_map):
    """
    use the resolved paths in path as a preset so queries for pillarpath
    are not necessary
    """
    if path.get_lookups() == pillarpath.get_lookups():
        lookups_salt = path.get_salt_lookup(salt_lookup_map)
    else:
        lookups_salt = pillarpath.get_salt_lookup(salt_lookup_map)
        if not lookups_salt and pillarpath.lookups():
            raise ResolveError(
                "Was unable to resolve salt lookups {} for path {} -> {}".format(
                    pillarpath.get_lookups(), pillarpath, lookups_salt
                )
            )

    return build_path_from_salt_lookup_map(pillarpath, lookups_salt)


def build_path_from_salt_lookup_map(path, lookups_salt):
    """
    generate new paths from path which have been resolved from salt lookups
    """
    product_lookups = []
    for lookup in lookups_salt:
        p, resolved = lookup
        if isinstance(resolved, dict):
            log.warning("Resolved a dict from {}. Skipping.".format(p))
            continue
        if not isinstance(resolved, list):
            resolved = [resolved]

        # generate product of lookups for each item in case a list was returned
        product_lookups.append(list(itertools.product([p], resolved)))

    # resolve paths from previous salt lookups
    new_paths = []
    for lookups in itertools.product(*product_lookups):
        new_path = copy.deepcopy(path)
        for lookup in lookups:
            p, resolved = lookup
            new_path = new_path.replace(p, resolved)
        new_paths.append(new_path)
    return new_paths


def build_path_from_vault_lookups(path, unresolved_paths, vault_resolver):
    """
    generate paths with the vault_resolver from the supplied unresolved paths

    the path is required to save results from the lookup for pillarpath
    """
    result = []

    # we need to remember previous lookups so that duplicate queries are not done
    previous_prefixes = []
    while True:
        if not unresolved_paths:
            break

        apath = unresolved_paths.pop()
        if isinstance(apath, tuple):
            apath = apath[1]
        if not apath.wildcards():
            result.append(apath)
            continue

        # resolve wildcard
        prefix = apath.get_wildcard_prefix()
        is_prefix_new = True
        prefix_similar = False
        prefix_index = 0
        for i, pref in enumerate(previous_prefixes):
            prev_prefixes, subpaths = pref
            break_outer_loop = False
            # check if any of the prefixes are in the new prefix
            for prev in prev_prefixes:
                matcher = prefixes_match(
                    LookupPath(prefix, False), LookupPath(prev, False)
                )
                # equal
                if matcher == 0:
                    is_prefix_new = False
                    break_outer_loop = True
                    break
                # parent exists
                if matcher == 1:
                    is_prefix_new = True
                    prefix_similar = False
                    break_outer_loop = False
                    break
                # similar
                if matcher == 2:
                    is_prefix_new = False
                    prefix_similar = True
                    break_outer_loop = True
                # unequal
                if matcher == -1:
                    is_prefix_new = True
                    prefix_similar = False
                    break_outer_loop = True

            prefix_index = i
            if break_outer_loop:
                break

        if is_prefix_new and not prefix_similar:
            subpaths = vault_resolver(prefix)
            previous_prefixes.append(([prefix], subpaths))
            path.lookups_vault_wildcard.append(subpaths)
        # not new add to other prefixes
        else:
            prev_pref, subpaths = previous_prefixes[prefix_index]
            prev_pref.append(prefix)

        vault_subpaths = []
        for sp in subpaths:
            vault_subpaths.append(
                (
                    sp,
                    apath.replace(
                        "{}/*".format(prefix),
                        "{}/{}".format(prefix, sp),
                    ),
                )
            )

        unresolved_paths.extend(vault_subpaths)
    return result


def prefixes_match(path_one, path_two):
    """
    returns
        0  if paths are equal
        1  if either path_one or path_two is a parent of the other
        2  if the path_one and path_two have equal length and have equal prefixes
       -1  if the paths are unequal
    """
    if path_one == path_two:
        return 0

    is_prefix_parent = False
    is_similar = False
    len_one = len(path_one.split_path)
    len_two = len(path_two.split_path)
    min_len = min(len_one, len_two)

    if len_one == len_two:
        is_similar = True

    for i in range(min_len):
        if path_one.split_path[i] == path_two.split_path[i]:
            is_prefix_parent = True
    if is_similar and is_prefix_parent:
        return 2
    elif is_prefix_parent:
        return 1
    return -1


def build_path_from_wildcards(path, wildcards):
    """
    build paths with the given path from the vault wildcard lookup
    """
    if len(wildcards) != path.wildcards():
        raise LookupException(
            "Path {} does not not have an equal amount of wildcards to {}".format(
                path, wildcards
            )
        )
    replace_paths = itertools.product([copy.deepcopy(path)], *wildcards)
    new_paths = []
    for wildcard in replace_paths:
        new_path = wildcard[0]
        item = wildcard[1:]

        for i in item:
            prefix = new_path.get_wildcard_prefix()
            new_path = new_path.replace(
                "{}/*".format(prefix),
                "{}/{}".format(prefix, i),
            )
        new_paths.append(new_path)
    return new_paths


def build_path(path, salt_lookup_map, vault_resolver):
    """
    build a path with the lookup tables
    """
    lookups = path.get_salt_lookup(salt_lookup_map)
    if not lookups and path.lookups():
        raise ResolveError(
            "Was unable to resolve salt lookups {} for path {} -> {}".format(
                path.get_lookups(), path, lookups
            )
        )

    new_paths = build_path_from_salt_lookup_map(path, lookups)

    # skip if there are no wildcards
    if not path.wildcards():
        return new_paths
    unresolved_paths = copy.deepcopy(new_paths)
    return build_path_from_vault_lookups(path, unresolved_paths, vault_resolver)


def resolve_pattern(pattern, pillar):
    """
    lookup salt values for the given pattern
    """
    pattern_id = pattern.split("@")
    lookup = ""
    is_match = False
    if len(pattern_id) != 2:
        log.warning("Not a lookup pattern? {}".format(pattern))
        return None
    value = pattern_id[1]

    is_pillar_pattern = False
    if pattern.startswith("G@"):
        lookup = "grains.get"
    elif pattern.startswith("I@"):
        is_pillar_pattern = True
        lookup = "pillar.get"

    values = value.split("=")
    len_values = len(values)
    if len_values >= 2:
        value = values[0]
        is_match = True
    elif len_values > 2:
        raise LookupException(
            "Path contains too many '=' separators for matching lookup {}".format(
                pattern
            )
        )

    fallback_lookup = False
    if is_pillar_pattern:
        try:
            result = get_nested_dict(value, pillar)
        except KeyError:
            fallback_lookup = True

    if not is_pillar_pattern or fallback_lookup:
        result = __salt__[lookup](value)

    if is_match:
        if result == values[1] or values[1] in result:
            return values[1]
        else:
            log.info("Lookup {} did not match value {}".format(values, result))
            return None
    return result


def get_pillar_data(config, path, pillarpath):
    """
    path and pillarpath without any dependencies(not requiring a template render)
    """
    pillar_data = []
    salt_lookup_map = get_salt_lookup_map(
        collect_all_lookups(path, pillarpath), config.pillar
    )
    get_resolved_paths(path, salt_lookup_map)
    get_resolve_from_path(path, pillarpath, salt_lookup_map)
    if not are_paths_valid(path, pillarpath):
        raise LookupException("Path {}, {} not valid.".format(path, pillarpath))
    mapped_paths = map_resolved_paths(path, pillarpath, salt_lookup_map)
    for d in mapped_paths:
        log.debug("vault_lookup: mapped paths {}".format(d))
        d_path = d.get("path")
        d_pillarpath = d.get("pillarpath")
        try:
            data = get_data(d_path)
        except Exception as e:
            log.error(
                "vault_lookup: Failed to get data from vault {}. {}".format(d_path, e)
            )
            data = ""

        if not data:
            log.warning(
                "vault_lookup: No data for lookup path {}. Skipping map to pillar.".format(
                    d_path
                )
            )
            continue

        pillar_data.append(
            build_nested_dict(
                d_pillarpath,
                filter_values(data, config.keys, config.matchers, config.pillar),
            )
        )
    return pillar_data


def get_mapped_pillar(config):
    """
    resolve path, pillarpath
    map each path
    retrieve data and map to its pillar path
    """
    pillar_result = []

    if config.has_templates():
        env = get_default_jinja2_environment()
        for templates_pair in get_path_pairs_from_template(config, env):
            log.debug("vault_lookup: template_pair {}".format(templates_pair))
            path, pillarpath = templates_pair
            path = LookupPath.from_template(path, False)
            pillarpath = LookupPath.from_template(pillarpath, True)
            pillar_result.extend(get_pillar_data(config, path, pillarpath))
    else:
        pillar_result.extend(get_pillar_data(config, config.path, config.pillarpath))

    return pillar_result


def filter_values(data, valid_keys, matchers, pillar):
    """
    filter only values from the data for which the keys are valid
    """
    valid_keys = set(valid_keys)
    if not valid_keys:
        valid_keys = set(data.keys())

    for f in matchers:
        if not f:
            continue
        added_keys = set(f.get("add_keys", []))
        if not added_keys:
            added_keys = set(data.keys())

        keys = set(f.get("keys", []))
        values = f.get("values")
        resolved_values = []
        for value in values:
            if "@" in value:
                res = resolve_pattern(value, pillar)
                if res != None:
                    resolved_values.append(res)
            else:
                resolved_values.append(value)

        # there are keys, then check if any keys match any of the values
        if keys:
            any_found = False
            key_values = []
            # get all values from data first
            for key in keys:
                res = data.get(key, "")
                if res:
                    key_values.append(res)

            for pair in itertools.product(key_values, resolved_values):
                if pair[0] == pair[1]:
                    valid_keys = valid_keys.union(added_keys)
                    any_found = True
                    break
            if not any_found:
                valid_keys = valid_keys.difference(added_keys)
        elif not keys and resolved_values:
            valid_keys = valid_keys.union(added_keys)
        else:
            valid_keys = valid_keys.difference(added_keys)

    values_pillar = {}
    for k in valid_keys:
        values_pillar[k] = data[k]
    return values_pillar


def build_nested_dict(path, values):
    """
    create a nested dictionary from a path

    pillar/path/example

    "pillar": {
        "path": {
            "example": {}
        },
    },
    """
    result = values
    for p in reversed(path.split_path):
        inter = {}
        inter[p] = result
        result = inter
    return result


def get_nested_dict(path, items, nested_key=":"):
    """
    get the value from a nested dict from a pillar path like

    some:value:required

    returns the values of 'required' in the dict {some: {value: {required: ...}}}
    """
    if nested_key not in path:
        # let caller handle exception if path does not exist
        return items[path]

    item = items
    for p in path.split(nested_key):
        # let caller handle exception if path does not exist
        item = item[p]
    return item


def map_resolved_paths(path, pillarpath, salt_lookup_map):
    """
    map a path and its pillarpath to a lookup key
    """
    len_path_resolved = path.resolved_paths
    len_pillarpath_resolved = pillarpath.resolved_paths
    if len_path_resolved == 1 and len_pillarpath_resolved == 1:
        return [
            {
                "path": path.resolved_paths[0],
                "pillarpath": pillarpath.resolved_paths[0],
            }
        ]
    elif not len_path_resolved:
        raise ResolveError("Resolved paths of path {} are empty.".format(path))
    elif not len_pillarpath_resolved:
        raise ResolveError(
            "Resolved paths of pillarpath {} are empty.".format(pillarpath)
        )

    lookup_table = {}
    lookups_salt = path.get_salt_lookup(salt_lookup_map)
    for p in path.resolved_paths:
        lookup_key = get_path_lookup_key(p, lookups_salt, path.lookups_vault_wildcard)
        lookup_table[lookup_key] = {}
        lookup_table[lookup_key]["path"] = p

    for p in pillarpath.resolved_paths:
        # using only results from path for pillarpath
        # since lookups must be equal anyway if resolved paths are more than one
        lookup_key = get_path_lookup_key(p, lookups_salt, path.lookups_vault_wildcard)
        p.pillarpath = True
        lookup_table[lookup_key]["pillarpath"] = p

    return list(lookup_table.values())


def get_path_lookup_key(path, lookups_salt, lookups_vault_wildcard):
    """
    build a lookup key of the given path and the lookup results
    """
    return_salt_keys = []
    for item in lookups_salt:
        lookup_type, lookup_result = item
        lookup_key = get_key_in_path(path, lookup_result)
        if lookup_key:
            return_salt_keys.append((lookup_type, lookup_key))
    return_wildcard_keys = []
    for item in lookups_vault_wildcard:
        lookup_key = get_key_in_path(path, item)
        if lookup_key:
            return_wildcard_keys.append(lookup_key)

    return (tuple(return_salt_keys), tuple(return_wildcard_keys))


def get_key_in_path(path, lookups):
    for look in lookups:
        if look in path:
            return look
    return ""


def flat_dict_items(items):
    result = {}
    for i in items:
        result.update(i)
    return result


def order_by_root(template, template_map, reverse=False):
    """
    order templates first which have no dependencies
    and after those templates which depend on each other in their specific order
    to resolve them
    """
    template_adjecency = TemplatesAdjacency(template_map)
    path = template_adjecency.get_resolve_path(template.keys)
    for p in path:
        yield get_template_from_template_map(p, template_map)


def render_template(
    template,
    template_map,
    map_template_salt_lookups,
    map_resolved_templates,
    pillar,
    environment,
    use_dependency_origin=False,
):
    results = []

    if not template.has_dependencies():
        log.debug("Template {} has no dependencies to render to".format(template))
        result = template.get_resolved_entry(resolve_pattern, pillar)
        map_template_salt_lookups.update(result)
        return results

    # need to walk the path to generate the filtered lookup for its parents
    for template_index in order_by_root(template, template_map):
        if not template_index:
            raise LookupException("Dependency {} not found in template_map".format(k))
        template_keys = template_index.keys

        resolved_templates = map_resolved_templates.get(template_index)
        if not resolved_templates:
            result = map_template_salt_lookups.get(template_index)
            if result:
                results.extend(get_key_from_items(template_keys, result))
        else:
            for rt in resolved_templates:
                filtered_values = {}
                parent_keys_in_result = False
                for parent_key, parent_value in rt.parent_lookup.items():
                    parent_key = (parent_key,)
                    item = {parent_key: parent_value}
                    for result in results:
                        if item != result:
                            continue
                        parent_keys_in_result = True
                        # remove the found item and remember it
                        results.remove(item)
                        filtered_values.update(item)

                if not parent_keys_in_result:
                    continue

                # parent key matched, get the salt lookups of this resolved template
                # for this iteration
                lookups = map_template_salt_lookups.get(rt, [])
                for lookup in lookups:
                    new_index = {
                        template_keys: lookup,
                    }
                    new_index.update(filtered_values)
                    results.append(new_index)

    all_templates = []
    for result in results:
        template_values = {}
        for dep in template.dependencies:
            value = get_template_from_template_map(dep, result)
            if not value:
                continue
            if isinstance(value, dict):
                template_values.update({dep: value.get(dep)})
            else:
                template_values.update({dep: value})
        t = template.render(environment, **template_values)
        if use_dependency_origin:
            t.dependencies = template.dependencies
        all_templates.append(t)
    return all_templates


def get_key_from_items(key, list_items):
    """
    get items in list form for retrieving in key pairs
    """
    result = []
    for i in list_items:
        if isinstance(i, dict):
            items = i.get(key)
        else:
            items = i
        for i in itertools.product([key], [items]):
            result.append({i[0]: i[1]})
    return result


def resolve_templates(config, environment):
    templates = LookupTemplate.from_config(config, environment)
    for t in templates:
        template = list(t.values())[0]

        resolved_templates = render_template(
            template,
            config.template_map,
            config.map_template_salt_lookups,
            config.map_resolved_templates,
            config.pillar,
            environment,
        )

        # do a salt lookup for each new resolved template
        for rt in resolved_templates:
            if rt not in config.map_template_salt_lookups:
                result = rt.get_resolved_entry(resolve_pattern, config.pillar)
                config.map_template_salt_lookups.update(result)

        config.template_map.update(t)
        config.map_resolved_templates.update({template: sorted(resolved_templates)})

    if len(config.template_map) != len(templates):
        raise LookupException(
            "Was unable to resolve all template dependencies. Make sure that dependencies can be resolved in order: resolved template map {} != given configuration templates {}".format(
                config.template_map, templates
            )
        )


def get_path_pairs_from_template(config, env):
    resolve_templates(config, env)
    log.debug("vault_lookup: configuration after template resolve {}".format(config))

    template_path = LookupTemplate.from_path(config.path, env)
    template_pillarpath = LookupTemplate.from_path(config.pillarpath, env)

    if not are_path_templates_valid(
        template_path, template_pillarpath, config.template_map
    ):
        raise TemplateError(
            "Either template path {} or pillarpath {} not valid. Unable to map each resolved path to each other".format(
                template_path, template_pillarpath
            )
        )

    resolved_template_paths = render_template(
        template_path,
        config.template_map,
        config.map_template_salt_lookups,
        config.map_resolved_templates,
        config.pillar,
        env,
    )
    resolved_template_pillarpaths = render_template(
        template_pillarpath,
        config.template_map,
        config.map_template_salt_lookups,
        config.map_resolved_templates,
        config.pillar,
        env,
    )

    path_pairs = []
    for resolved_path in resolved_template_paths:
        for resolved_pillarpath in resolved_template_pillarpaths:
            if isdict_subset(
                resolved_path.parent_lookup, resolved_pillarpath.parent_lookup
            ):
                path_pairs.append((resolved_path, resolved_pillarpath))
    return path_pairs


def isdict_subset(parent, child):
    for k, v in parent.items():
        if k not in child:
            continue
        child_value = child.get(k)
        if v == child_value:
            return True
    return False


def are_path_templates_valid(template_path, template_pillarpath, template_map):
    def _get_unique_templates_from_deps(template, template_map):
        templates = set()
        for dep in template.dependencies:
            templates.add(get_template_from_template_map(dep, template_map))
        return templates

    template_dependencies_path = _get_unique_templates_from_deps(
        template_path, template_map
    )
    template_dependencies_pillarpath = _get_unique_templates_from_deps(
        template_pillarpath, template_map
    )

    return (
        template_dependencies_path == template_dependencies_pillarpath
        or template_dependencies_path.issubset(template_dependencies_pillarpath)
    )


def get_template_from_template_map(key, keymap):
    if isinstance(key, tuple):
        result = keymap.get(key, "")
    else:
        result = keymap.get((key,), "")

    if result:
        return result
    # check if key is a value of the key pairs
    lookups = []
    for k in keymap:
        if key in k:
            lookups.append(k)
    if len(lookups) != 1:
        raise LookupException(
            "Lookups are not equal to 1 for match key '{}', {}".format(key, keymap)
        )
    return keymap.get(lookups[0], None)


def check_template_dependencies(template_map, dependencies):
    all_present = []

    if not dependencies:
        return True

    def var_in_keys(key_product):
        var, key = key_product
        return var in key or var == key

    for i, var in enumerate(dependencies):
        result = list(
            filter(var_in_keys, itertools.product([var], template_map.keys()))
        )
        if result:
            all_present.append(True)
        else:
            all_present.append(False)
    return all(all_present)


def get_default_jinja2_environment():
    return Environment(trim_blocks=True, lstrip_blocks=True)
