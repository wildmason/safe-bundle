use anyhow::{Context, Result, bail};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StructureCheck {
    NotStructured,
    SourceInvalid,
    Preserved,
}

pub fn validate_structure_preserved(
    format: &str,
    before: &str,
    after: &str,
) -> Result<StructureCheck> {
    match format {
        "json" => validate_pair("JSON", parse_json, before, after),
        "jsonl" => validate_pair("JSONL", parse_jsonl, before, after),
        "toml" => validate_pair("TOML", parse_toml, before, after),
        "yaml" | "yml" => validate_pair("YAML", parse_yaml, before, after),
        "env" => validate_pair("env", parse_env, before, after),
        _ => Ok(StructureCheck::NotStructured),
    }
}

fn validate_pair(
    name: &'static str,
    parser: fn(&str) -> Result<()>,
    before: &str,
    after: &str,
) -> Result<StructureCheck> {
    if parser(before).is_err() {
        return Ok(StructureCheck::SourceInvalid);
    }

    parser(after).with_context(|| format!("redaction broke valid {name} structure"))?;
    Ok(StructureCheck::Preserved)
}

fn parse_json(input: &str) -> Result<()> {
    let _: serde_json::Value = serde_json::from_str(input)?;
    Ok(())
}

fn parse_jsonl(input: &str) -> Result<()> {
    for (index, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _: serde_json::Value = serde_json::from_str(trimmed)
            .with_context(|| format!("invalid JSONL line {}", index + 1))?;
    }
    Ok(())
}

fn parse_toml(input: &str) -> Result<()> {
    let _: toml::Value = toml::from_str(input)?;
    Ok(())
}

fn parse_yaml(input: &str) -> Result<()> {
    let _: serde_yml::Value = serde_yml::from_str(input)?;
    Ok(())
}

fn parse_env(input: &str) -> Result<()> {
    for (index, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("export ") {
            continue;
        }

        let Some((key, _value)) = trimmed.split_once('=') else {
            bail!("invalid env line {}: missing '='", index + 1);
        };

        let key = key.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
        {
            bail!("invalid env line {}: invalid key", index + 1);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Policy, Redactor};
    use crate::model::{PlaceholderStyle, Profile};

    fn redact(format: &str, input: &str) -> String {
        let mut redactor =
            Redactor::new(Policy::new(Profile::PublicIssue, PlaceholderStyle::Bracket));
        redactor.redact_text(input, "fixture", format).redacted
    }

    #[test]
    fn preserves_json_after_redaction() {
        let input = r#"{
  "api_key": "ghp_abcdefghijklmnopqrstuvwxyz",
  "database_url": "postgres://app:supersecret@db.internal/app",
  "email": "matt@example.com"
}"#;
        let redacted = redact("json", input);

        assert_eq!(
            validate_structure_preserved("json", input, &redacted).unwrap(),
            StructureCheck::Preserved
        );
        assert!(!redacted.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        assert!(!redacted.contains("supersecret"));
    }

    #[test]
    fn preserves_jsonl_after_redaction() {
        let input = "{\"token\":\"ghp_abcdefghijklmnopqrstuvwxyz\"}\n{\"ip\":\"10.1.2.3\"}\n";
        let redacted = redact("jsonl", input);

        assert_eq!(
            validate_structure_preserved("jsonl", input, &redacted).unwrap(),
            StructureCheck::Preserved
        );
        assert!(!redacted.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        assert!(!redacted.contains("10.1.2.3"));
    }

    #[test]
    fn preserves_toml_after_redaction() {
        let input = r#"
api_key = "ghp_abcdefghijklmnopqrstuvwxyz"
database_url = "postgres://app:supersecret@db.internal/app"
home = "C:\\Users\\Matt\\AppData\\Local\\app.log"
"#;
        let redacted = redact("toml", input);

        assert_eq!(
            validate_structure_preserved("toml", input, &redacted).unwrap(),
            StructureCheck::Preserved
        );
        assert!(!redacted.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        assert!(!redacted.contains("supersecret"));
    }

    #[test]
    fn preserves_yaml_after_redaction() {
        let input = r#"
api_key: "ghp_abcdefghijklmnopqrstuvwxyz"
endpoint: "http://api.internal/v1/status"
contact: "matt@example.com"
"#;
        let redacted = redact("yaml", input);

        assert_eq!(
            validate_structure_preserved("yaml", input, &redacted).unwrap(),
            StructureCheck::Preserved
        );
        assert!(!redacted.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        assert!(!redacted.contains("api.internal"));
    }

    #[test]
    fn preserves_env_after_redaction() {
        let input = "API_KEY=ghp_abcdefghijklmnopqrstuvwxyz\nDATABASE_URL=postgres://app:supersecret@db.internal/app\n";
        let redacted = redact("env", input);

        assert_eq!(
            validate_structure_preserved("env", input, &redacted).unwrap(),
            StructureCheck::Preserved
        );
        assert!(!redacted.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        assert!(!redacted.contains("supersecret"));
    }

    #[test]
    fn ignores_invalid_source_structures() {
        assert_eq!(
            validate_structure_preserved("json", "{", "{").unwrap(),
            StructureCheck::SourceInvalid
        );
    }

    #[test]
    fn generated_structured_fixtures_stay_parseable_after_redaction() {
        for suffix in ["", "_EXTRA_CONTEXT", "1234567890"] {
            let token = format!("ghp_abcdefghijklmnopqrstuvwxyz{suffix}");
            let cases = [
                (
                    "json",
                    format!(r#"{{"token":"{token}","ip":"10.1.2.3","ok":true}}"#),
                ),
                (
                    "jsonl",
                    format!("{{\"token\":\"{token}\"}}\n{{\"ip\":\"10.1.2.3\"}}\n"),
                ),
                (
                    "toml",
                    format!("token = \"{token}\"\nendpoint = \"http://api.internal/status\"\n"),
                ),
                (
                    "yaml",
                    format!("token: \"{token}\"\ncontact: \"matt@example.com\"\n"),
                ),
                (
                    "env",
                    format!("TOKEN={token}\nDATABASE_URL=postgres://app:secretpass@db/app\n"),
                ),
            ];

            for (format, input) in cases {
                let redacted = redact(format, &input);
                assert_eq!(
                    validate_structure_preserved(format, &input, &redacted).unwrap(),
                    StructureCheck::Preserved,
                    "{format} fixture was not preserved"
                );
                assert!(!redacted.contains(&token));
            }
        }
    }
}
