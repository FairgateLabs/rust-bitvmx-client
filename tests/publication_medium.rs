//! What publishing a dissection buys, at the one place it is decided.
//!
//! A committed dissection is read by Bitcoin Script, so each of the
//! `b - 1` state hashes is a one-time signature whose verifier is written
//! out in the witness, and the thousand-element stack limit -- not the
//! fee -- is what caps `b`. A published one is seen rather than read, so
//! the stage commits only its selection digit.
//!
//! These check the consequence arithmetically, where the dispute
//! backend's own unit tests check the scripts.

use emulator::decision::publication::PublicationMedium;

/// Witness stack elements one twenty-byte digest costs under the
/// Winternitz parameters BitVMX deploys: four-bit digits, so forty
/// message digits and four checksum digits, two elements each.
const ELEMENTS_PER_HASH: u32 = 88;

/// What a tapscript execution may hold, consensus-enforced.
const STACK_LIMIT: u32 = 1000;

/// Working room `verify_digits` needs for one digit.
const WORKING: u32 = 18;

/// One round's leaf witness: the `b - 1` midstates at 88 elements each,
/// plus eleven for the aggregated signature and the selection digit.
/// Measured, not modelled -- these are the figures BitVMX deploys
/// against, and the peak adds `verify_digits`' working room for one
/// digit.
fn committed_stack(hashes: u32) -> u32 {
    hashes * ELEMENTS_PER_HASH + 11 + WORKING
}

#[test]
fn the_committed_stack_matches_the_measured_ladder() {
    for (b, leaf, peak) in [(4u32, 275, 293), (8, 627, 645), (12, 979, 997),
                            (16, 1331, 1349), (32, 2739, 2757)] {
        assert_eq!((b - 1) * ELEMENTS_PER_HASH + 11, leaf, "b = {b}");
        assert_eq!(committed_stack(b - 1), peak, "b = {b}");
    }
}

#[test]
fn a_committed_dissection_is_capped_at_twelve() {
    assert!(committed_stack(11) <= STACK_LIMIT, "b = 12 fits");
    assert_eq!(STACK_LIMIT - committed_stack(11), 3, "with three to spare");
    assert!(committed_stack(15) > STACK_LIMIT, "b = 16 does not");
    assert!(
        committed_stack(191) > STACK_LIMIT * 16,
        "and b = 192 is not close"
    );
}

#[test]
fn a_published_dissection_costs_no_stack_for_its_hashes() {
    // Whatever b is, the stage commits the digit and nothing else.
    for hashes in [7u32, 11, 191, 383] {
        let published = 11 + WORKING;
        assert!(
            published + hashes * 0 < STACK_LIMIT,
            "b - 1 = {hashes} must not reach the stack at all"
        );
        assert!(
            published < committed_stack(hashes),
            "publishing must be cheaper in stack than committing"
        );
    }
}

#[test]
fn which_is_why_the_medium_sets_the_branching_factor() {
    assert!(!PublicationMedium::Committed.is_published());
    assert!(PublicationMedium::OpReturn.is_published());
    assert!(PublicationMedium::Annex.is_published());

    // And the two published media differ only in what a byte costs.
    assert_eq!(PublicationMedium::Annex.weight_per_byte(), Some(1));
    assert_eq!(PublicationMedium::OpReturn.weight_per_byte(), Some(4));
    assert_eq!(PublicationMedium::Committed.weight_per_byte(), None);
}

/// At b = 192 the dissection is 3,820 bytes. Published in an annex that
/// is 3,820 weight units before framing; committed it is beyond any
/// transaction, and beyond the stack besides.
#[test]
fn the_cost_of_a_192_ary_stage_either_way() {
    let hashes = 191u32;
    let bytes = hashes * 20;
    assert_eq!(bytes, 3_820);

    let annex = bytes * PublicationMedium::Annex.weight_per_byte().unwrap();
    let op_return = bytes * PublicationMedium::OpReturn.weight_per_byte().unwrap();
    assert_eq!(annex, 3_820);
    assert_eq!(op_return, 15_280);

    // Committed, at the deployed Winternitz rate of 70 WU a bit.
    let committed = hashes * 20 * 8 * 70;
    assert_eq!(committed, 2_139_200);
    assert!(
        committed > 400_000,
        "which does not fit a standard transaction, let alone the stack"
    );
}
