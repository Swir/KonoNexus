use kononexus::{NatMappingBehavior, NatProfile};

#[test]
fn observations_from_independent_peers_build_a_nat_mapping_profile() {
    let mut profile = NatProfile::default();

    profile.observe(
        "knp1-observer-a".to_owned(),
        "203.0.113.44:51000".parse().unwrap(),
    );
    assert_eq!(profile.behavior(), NatMappingBehavior::SingleObservation);

    profile.observe(
        "knp1-observer-b".to_owned(),
        "203.0.113.44:51000".parse().unwrap(),
    );
    assert_eq!(profile.behavior(), NatMappingBehavior::StableEndpoint);
    assert_eq!(
        profile.preferred_endpoint(),
        Some("203.0.113.44:51000".parse().unwrap())
    );
}
