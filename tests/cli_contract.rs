use clap::CommandFactory;
use safe_bundle::cli::Cli;

#[test]
fn cli_top_level_commands_are_stable_for_1_0() {
    let command = Cli::command();
    let subcommands = command
        .get_subcommands()
        .map(|command| command.get_name().to_string())
        .collect::<Vec<_>>();

    for command in ["scrub", "bundle", "inspect", "rules"] {
        assert!(
            subcommands.contains(&command.to_string()),
            "top-level help is missing stable 1.0 command {command}"
        );
    }
}

#[test]
fn config_command_exposes_init_workflow() {
    let help = subcommand_help("config");

    assert!(help.contains("init"));
    assert!(help.contains("validate"));
    assert!(help.contains("inspect"));

    let init_help = nested_subcommand_help("config", "init");
    assert!(init_help.contains("--path"));
    assert!(init_help.contains("--force"));

    let validate_help = nested_subcommand_help("config", "validate");
    assert!(validate_help.contains("--path"));
    assert!(validate_help.contains("--require"));

    let inspect_help = nested_subcommand_help("config", "inspect");
    assert!(inspect_help.contains("--path"));
    assert!(inspect_help.contains("--require"));
    assert!(inspect_help.contains("--format"));
}

#[test]
fn completions_command_exposes_supported_shells() {
    let help = subcommand_help("completions");

    for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
        assert!(help.contains(shell), "completions help is missing {shell}");
    }
}

#[test]
fn scrub_cli_contract_includes_release_candidate_flags() {
    let help = subcommand_help("scrub");

    for flag in [
        "--profile",
        "--format",
        "--include",
        "--exclude",
        "--max-file-size",
        "--placeholder-style",
        "--fail-on",
        "--config",
        "--no-config",
        "--stdin",
        "--out",
        "--receipt",
        "--events",
        "--sarif",
        "--summary",
        "--dry-run",
        "--check",
    ] {
        assert!(help.contains(flag), "scrub help is missing {flag}");
    }
}

#[test]
fn bundle_cli_contract_includes_release_candidate_flags() {
    let help = subcommand_help("bundle");

    for flag in [
        "--profile",
        "--format",
        "--include",
        "--exclude",
        "--max-file-size",
        "--placeholder-style",
        "--fail-on",
        "--config",
        "--no-config",
        "--out",
        "--receipt",
        "--dry-run",
    ] {
        assert!(help.contains(flag), "bundle help is missing {flag}");
    }
}

#[test]
fn inspect_and_rules_cli_contracts_are_stable_for_1_0() {
    let inspect_help = subcommand_help("inspect");
    assert!(inspect_help.contains("--summary"));
    assert!(inspect_help.contains("--verify"));

    let rules_help = subcommand_help("rules");
    assert!(rules_help.contains("list"));
    assert!(rules_help.contains("test"));

    let rules_test_help = nested_subcommand_help("rules", "test");
    assert!(rules_test_help.contains("--profile"));
    assert!(rules_test_help.contains("--format"));
    assert!(rules_test_help.contains("--config"));
    assert!(rules_test_help.contains("--no-config"));
}

fn subcommand_help(name: &str) -> String {
    let command = Cli::command();
    let mut subcommand = command
        .get_subcommands()
        .find(|command| command.get_name() == name)
        .unwrap_or_else(|| panic!("missing {name} subcommand"))
        .clone();
    subcommand.render_long_help().to_string()
}

fn nested_subcommand_help(parent: &str, child: &str) -> String {
    let command = Cli::command();
    let mut subcommand = command
        .get_subcommands()
        .find(|command| command.get_name() == parent)
        .unwrap_or_else(|| panic!("missing {parent} subcommand"))
        .get_subcommands()
        .find(|command| command.get_name() == child)
        .unwrap_or_else(|| panic!("missing {parent} {child} subcommand"))
        .clone();
    subcommand.render_long_help().to_string()
}
