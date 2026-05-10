use safe_bundle::engine::{Policy, Redactor};
use safe_bundle::formats::{StructureCheck, validate_structure_preserved};
use safe_bundle::model::{PlaceholderStyle, Profile};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Corpus {
    cases: Vec<GoldenCase>,
    #[serde(default)]
    false_positive_cases: Vec<FalsePositiveCase>,
}

#[derive(Debug, Deserialize)]
struct GoldenCase {
    id: String,
    profile: Profile,
    format: String,
    input: String,
    min_redactions: usize,
    #[serde(default)]
    expected_detectors: Vec<String>,
    #[serde(default)]
    expected_classes: Vec<String>,
    #[serde(default)]
    must_redact: Vec<String>,
    #[serde(default)]
    must_keep: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FalsePositiveCase {
    id: String,
    profile: Profile,
    format: String,
    input: String,
    #[serde(default)]
    must_keep: Vec<String>,
}

fn corpus() -> Corpus {
    toml::from_str(include_str!("../fixtures/golden/redaction-corpus.toml"))
        .expect("golden corpus must parse")
}

#[test]
fn golden_corpus_redacts_expected_values_without_public_leaks() {
    let corpus = corpus();

    for case in corpus.cases {
        let mut redactor = Redactor::new(Policy::new(case.profile, PlaceholderStyle::Bracket));
        let document = redactor.redact_text(&case.input, &case.id, &case.format);

        assert!(
            document.events.len() >= case.min_redactions,
            "{} redacted {} values, expected at least {}",
            case.id,
            document.events.len(),
            case.min_redactions
        );

        let structure = validate_structure_preserved(&case.format, &case.input, &document.redacted)
            .unwrap_or_else(|err| panic!("{} structure validation failed: {err}", case.id));
        assert_ne!(
            structure,
            StructureCheck::SourceInvalid,
            "{} golden input must be valid {}",
            case.id,
            case.format
        );

        for value in &case.must_redact {
            assert!(
                !document.redacted.contains(value),
                "{} leaked expected-redacted value in output: {value}",
                case.id
            );
        }

        for value in &case.must_keep {
            assert!(
                document.redacted.contains(value),
                "{} removed expected-kept value: {value}",
                case.id
            );
        }

        let detector_ids = document
            .events
            .iter()
            .map(|event| event.detector_id.as_str())
            .collect::<Vec<_>>();
        for detector in &case.expected_detectors {
            assert!(
                detector_ids.contains(&detector.as_str()),
                "{} missing expected detector {detector}; got {:?}",
                case.id,
                detector_ids
            );
        }

        let classes = document
            .events
            .iter()
            .map(|event| event.class.as_str())
            .collect::<Vec<_>>();
        for class in &case.expected_classes {
            assert!(
                classes.contains(&class.as_str()),
                "{} missing expected class {class}; got {:?}",
                case.id,
                classes
            );
        }

        let public_json =
            serde_json::to_string(&document.events).expect("public events must serialize");
        for value in &case.must_redact {
            assert!(
                !public_json.contains(value),
                "{} leaked raw value in public event JSON: {value}",
                case.id
            );
        }
    }
}

#[test]
fn golden_false_positive_cases_keep_benign_configuration_values() {
    let corpus = corpus();

    for case in corpus.false_positive_cases {
        let mut redactor = Redactor::new(Policy::new(case.profile, PlaceholderStyle::Bracket));
        let document = redactor.redact_text(&case.input, &case.id, &case.format);

        assert!(
            document.events.is_empty(),
            "{} produced unexpected findings: {:?}",
            case.id,
            document
                .events
                .iter()
                .map(|event| (&event.detector_id, &event.placeholder))
                .collect::<Vec<_>>()
        );
        for value in &case.must_keep {
            assert!(
                document.redacted.contains(value),
                "{} removed benign value: {value}",
                case.id
            );
        }
    }
}
