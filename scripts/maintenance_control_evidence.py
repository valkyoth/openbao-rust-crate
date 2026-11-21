"""Reviewed 2.2.5 server evidence, not a current live server assessment."""

OLD_SYS = "673fc6b061f0a40e0d3ba3a49b0c5edb6b4ddf18b9f2f23f7a8eea209b3b65a9"
REVIEWED_SYS = "94043afc463af458c510680927055d0efacf3a1a73664a659046da73923d6486"
HISTORICAL = {
    "2.7.0": "3f94549a4e356c54a13a994dece42bfba19957e5c9a26ee14a9ed44f3e987686",
    "2.7.1": "5731d362fa9a907aad5c304a6ddba0935a4cf0e0b98f5b3d478429a605674d8d",
    "2.7.2": "d58796eaa4109f0b1602c129e4be39debeb0b4f147121017ef852ee44c631f92",
}


def expected_inputs(version, digest, current):
    # The reviewed production diff only affects the workflow CAS guard. Never
    # substitute inputs for another artifact, another edit, or another suite.
    if version in HISTORICAL and digest == HISTORICAL[version] and current.get("src/sys.rs") == REVIEWED_SYS:
        return {**current, "src/sys.rs": OLD_SYS}
    return current
