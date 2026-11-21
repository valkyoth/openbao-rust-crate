"""Release-only verification; report anchors are set after independent live runs."""

import re

import openbao_maintenance_sdk as sdk


REPORT_SHA256 = {
    "2.6.6": "1b1a47bed0d668372bf1ff2b82ce45d0e245101e8ce5ef5972fe0cdad7f749ee",
    "2.7.3": "468f6eaab0c918057f1e84be9aec6d597be992b350fc4cf65fb2fdac05fb0a65",
}


def verify():
    if REPORT_SHA256.keys() != sdk.TESTS.keys():
        raise sdk.registry.RegistryError("both reviewed maintenance normal SDK reports are required")
    proof, inputs = sdk.normal_provenance(), sdk.normal_hashes()
    for version, digest in REPORT_SHA256.items():
        path = sdk.patch.ROOT / f"compat/onboarding/{version}/sdk-normal-tls.json"
        raw = sdk.base.read_regular_file(path, 256 * 1024)
        report = sdk.base.parse_json(raw, 256 * 1024)
        index, platform = sdk.capture.PINS[version]
        expected = {**proof, **sdk.execution.EXECUTION_ASSURANCE, "inputs": inputs,
                    "test": sdk.TESTS[version], "features": sdk.FEATURES, "version": version,
                    "schema": "openbao-maintenance-normal-sdk/v1", "outcome": "passed",
                    "stages": list(sdk.STAGES[version]), "explicit_case_sensitive_alias_verified": True,
                    "image_index_digest": index, "image_linux_amd64_digest": platform}
        binary = report.get("test_binary_sha256")
        alias = report.get("new_auth_mount_reported_case_sensitive_alias")
        if (not isinstance(binary, str) or not re.fullmatch("[0-9a-f]{64}", binary)
                or (alias is not None and type(alias) is not bool)):
            raise sdk.registry.RegistryError("maintenance normal SDK metadata mismatch")
        expected.update(test_binary_sha256=binary, new_auth_mount_reported_case_sensitive_alias=alias)
        if sdk.base.sha256(raw) != digest or sdk.base.canonical_json(expected) != raw:
            raise sdk.registry.RegistryError("maintenance normal SDK report mismatch")
