#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::error::Error;
use std::io;

use openbao::{
    OpenBaoCapabilityAvailability, OpenBaoCapabilityProfile, OpenBaoOperationDisposition,
    OpenBaoVersion,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct ContractMatrix {
    schema: String,
    operations: Vec<ContractOperation>,
    profiles: Vec<ContractProfile>,
}

#[derive(Deserialize)]
struct ContractOperation {
    id: String,
    disposition: String,
}

#[derive(Deserialize)]
struct ContractProfile {
    version: String,
    cells: Vec<ContractCell>,
    summary: ContractSummary,
}

#[derive(Deserialize)]
struct ContractCell {
    availability: String,
    implementation: String,
}

#[derive(Deserialize)]
struct ContractSummary {
    classified_coverage_basis_points: u64,
}

fn parse_version(value: &str) -> Result<OpenBaoVersion, Box<dyn Error>> {
    let parts = value
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()?;
    if parts.len() != 3 {
        return Err(io::Error::other("fixture version is not a semantic triplet").into());
    }
    Ok(OpenBaoVersion::new(parts[0], parts[1], parts[2]))
}

#[test]
fn public_profiles_match_every_generated_contract_cell() -> Result<(), Box<dyn Error>> {
    let matrix: ContractMatrix =
        serde_json::from_str(include_str!("../compat/version-contract-matrix.json"))?;
    assert_eq!(matrix.schema, "openbao-version-contract-matrix/v1");
    assert_eq!(matrix.operations.len(), 690);
    assert_eq!(matrix.profiles.len(), 22);

    for profile_fixture in matrix.profiles {
        assert_eq!(
            profile_fixture.summary.classified_coverage_basis_points,
            10_000
        );
        let version = parse_version(&profile_fixture.version)?;
        let profile = OpenBaoCapabilityProfile::for_version(version)
            .ok_or_else(|| io::Error::other("missing public compatibility profile"))?;
        let statuses = profile
            .operations()
            .map(|status| (status.operation().id(), status))
            .collect::<BTreeMap<_, _>>();
        assert!(statuses.len() >= matrix.operations.len());
        assert_eq!(profile_fixture.cells.len(), matrix.operations.len());

        for (operation, cell) in matrix.operations.iter().zip(profile_fixture.cells.iter()) {
            let status = statuses
                .get(operation.id.as_str())
                .ok_or_else(|| io::Error::other("historical operation identity was removed"))?;
            assert_eq!(status.operation().id(), operation.id);
            let expected_availability =
                match (cell.availability.as_str(), operation.disposition.as_str()) {
                    ("documented", "security-blocked") => {
                        OpenBaoCapabilityAvailability::SecurityBlocked
                    }
                    ("documented", _) => OpenBaoCapabilityAvailability::DocumentedRoute,
                    ("unavailable", _) => OpenBaoCapabilityAvailability::NotDocumented,
                    _ => return Err(io::Error::other("unknown cell availability").into()),
                };
            assert_eq!(status.availability(), expected_availability);

            let expected_disposition = match operation.disposition.as_str() {
                "typed" => OpenBaoOperationDisposition::Typed,
                "typed-gated" => OpenBaoOperationDisposition::TypedGated,
                "security-blocked" => OpenBaoOperationDisposition::SecurityBlocked,
                _ => return Err(io::Error::other("unknown operation disposition").into()),
            };
            assert_eq!(status.operation().disposition(), expected_disposition);
            assert_eq!(
                cell.implementation,
                if expected_availability == OpenBaoCapabilityAvailability::NotDocumented {
                    "not-applicable"
                } else {
                    operation.disposition.as_str()
                }
            );
        }
    }
    Ok(())
}
