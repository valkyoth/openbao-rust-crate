"""Pinned profile inputs shared by normal and disposable maintenance builds."""

import generate_openbao_patch_registry as parent
import openbao_maintenance_capture as capture

registry = parent.registry
patch, base = capture.previous, capture.base
ARTIFACTS = {
    "2.6.6": ("acada321180b214f2810bf8ede4ced3cd88008b98c49bc3394989b5f3773a60a",
              "839bce14393dc4a4a7816befcfce96971ce79581ee411741e04172ee0121023c"),
    "2.7.3": ("b94f171efed6d6de10362673eb372cda6c660cecb143aef92b8e4b3c7c9b849c",
              "a0f7133be739eb0dc8dff76244f5c527e960321ef1bd780d710549c9e340c95f"),
}


def candidate():
    data = registry.read_regular_file(parent.OUTPUT, registry.MAX_OUTPUT_BYTES)
    patch.require(registry.sha256(data) == parent.EXPECTED_SHA256)
    result = registry.parse_json(data, registry.MAX_OUTPUT_BYTES)
    result["routable_versions"] = list(result["versions"])
    for version, predecessor in (("2.6.6", "2.6.5"), ("2.7.3", "2.7.2")):
        for name, digest in zip(("openapi", "report"), ARTIFACTS[version], strict=True):
            path = patch.ROOT / f"compat/onboarding/{version}/{name}.json"
            patch.require(base.sha256(base.read_regular_file(path, 2 * 1024 * 1024)) == digest)
        result["versions"].insert(result["versions"].index(predecessor) + 1, version)
        for group, key in (("operations", "ranges"), ("logical_endpoints", "variants")):
            for row in result[group]:
                cells = row[key]
                old = parent.selected(cells, predecessor, optional=key == "variants")
                overlap = parent.selected(cells, version, optional=True)
                if overlap is not None or old is None:
                    patch.require(overlap == old)
                    continue
                cells.insert(cells.index(old) + 1, {**old, "minimum": version, "maximum": version})
    result["scope"] = "maintenance-candidate-only"
    result["routable"] = False
    result["summary"] = {"operations": len(result["operations"]), "profile_count": len(result["versions"])}
    result["maintenance_evidence"] = ARTIFACTS
    return result


def normal_registry():
    reviewed = candidate()
    reviewed.update(scope="working-tree-maintenance", routable=True,
                    routable_versions=list(reviewed["versions"]))
    return reviewed


def verify_normal_reports():
    import verify_openbao_maintenance_normal as evidence
    evidence.verify()
