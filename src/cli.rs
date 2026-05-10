use crate::archive::{BundleOptions, build_bundle, inspect_bundle, verify_bundle};
use crate::config::RuntimeConfig;
use crate::detectors::detector_infos;
use crate::engine::{Policy, Redactor};
use crate::formats::validate_structure_preserved;
use crate::input::{InputOptions, collect_inputs, parse_size, read_stdin};
use crate::model::{
    FailOn, InputFormat, PlaceholderStyle, Profile, RedactionSummary, SummaryFormat,
};
use crate::report::{
    events_jsonl, private_events_json, sarif_json, summary_markdown, summary_text,
};
use anyhow::{Context, Result, bail};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "safe-bundle")]
#[command(about = "Local-first redaction and safe support bundle CLI")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scrub(ScrubArgs),
    Bundle(BundleArgs),
    Inspect(InspectArgs),
    Rules(RulesArgs),
    Completions(CompletionsArgs),
}

#[derive(Debug, Args)]
struct SharedRedactionArgs {
    #[arg(long, value_enum, default_value_t = Profile::Support)]
    profile: Profile,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    #[arg(long = "include")]
    include: Vec<String>,
    #[arg(long = "exclude")]
    exclude: Vec<String>,
    #[arg(long, default_value = "10MiB", value_parser = parse_size)]
    max_file_size: u64,
    #[arg(long, value_enum, default_value_t = PlaceholderStyle::Bracket)]
    placeholder_style: PlaceholderStyle,
    #[arg(long = "fail-on", value_enum)]
    fail_on: Vec<FailOn>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    no_config: bool,
}

impl SharedRedactionArgs {
    fn input_options(&self) -> InputOptions {
        let mut options = InputOptions {
            format: self.format,
            include: self.include.clone(),
            exclude: Vec::new(),
            max_file_size: self.max_file_size,
        };
        if self.exclude.is_empty() {
            options.exclude = InputOptions::default().exclude;
        } else {
            options.exclude = self.exclude.clone();
        }
        options
    }

    fn policy(&self) -> Policy {
        Policy::new(self.profile, self.placeholder_style)
    }

    fn runtime_config(&self) -> Result<RuntimeConfig> {
        RuntimeConfig::load(self.config.as_deref(), self.no_config)
    }

    fn redactor(&self, runtime_config: &RuntimeConfig) -> Redactor {
        Redactor::with_detectors(self.policy(), runtime_config.detector_set.clone())
    }
}

#[derive(Debug, Args)]
struct ScrubArgs {
    #[command(flatten)]
    shared: SharedRedactionArgs,
    #[arg()]
    paths: Vec<PathBuf>,
    #[arg(long)]
    stdin: bool,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    receipt: Option<PathBuf>,
    #[arg(long)]
    events: Option<PathBuf>,
    #[arg(long)]
    sarif: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = SummaryFormat::Text)]
    summary: SummaryFormat,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    check: bool,
}

#[derive(Debug, Args)]
struct BundleArgs {
    #[command(flatten)]
    shared: SharedRedactionArgs,
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    receipt: Option<PathBuf>,
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct InspectArgs {
    bundle: PathBuf,
    #[arg(long, value_enum, default_value_t = SummaryFormat::Text)]
    summary: SummaryFormat,
    #[arg(long)]
    verify: bool,
}

#[derive(Debug, Args)]
struct RulesArgs {
    #[command(subcommand)]
    command: RulesCommand,
}

#[derive(Debug, Args)]
struct CompletionsArgs {
    #[arg(value_enum)]
    shell: Shell,
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    List {
        #[arg(long, value_enum, default_value_t = SummaryFormat::Text)]
        format: SummaryFormat,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        no_config: bool,
    },
    Test {
        #[arg(required = true)]
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Profile::Support)]
        profile: Profile,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        no_config: bool,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scrub(args) => scrub(args),
        Command::Bundle(args) => bundle(args),
        Command::Inspect(args) => inspect(args),
        Command::Rules(args) => rules(args),
        Command::Completions(args) => completions(args),
    }
}

fn scrub(args: ScrubArgs) -> Result<()> {
    let runtime_config = args.shared.runtime_config()?;
    let mut redactor = args.shared.redactor(&runtime_config);
    let mut summary = RedactionSummary::default();
    let mut documents = Vec::new();
    let mut skipped = Vec::new();

    if args.stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        let input = read_stdin(&input, args.shared.format);
        let document = redactor.redact_text(&input.content, &input.source_file, &input.format);
        validate_structure_preserved(&input.format, &input.content, &document.redacted)?;
        summary.add_document(&document);
        documents.push((input.archive_path, document));
    }

    if !args.paths.is_empty() {
        let (inputs, skipped_files) = collect_inputs(&args.paths, &args.shared.input_options())?;
        skipped.extend(skipped_files);
        for input in inputs {
            let profile = runtime_config.profile_for_path(&input.archive_path, args.shared.profile);
            let document = redactor.redact_text_with_profile(
                &input.content,
                &input.archive_path,
                &input.format,
                profile,
            );
            validate_structure_preserved(&input.format, &input.content, &document.redacted)
                .with_context(|| {
                    format!("structured validation failed for {}", input.source_file)
                })?;
            summary.add_document(&document);
            documents.push((input.archive_path, document));
        }
    }

    if documents.is_empty() && skipped.is_empty() {
        bail!("nothing to scrub; provide paths or --stdin");
    }

    summary.skipped_files = skipped.len();
    let all_events = documents
        .iter()
        .flat_map(|(_, document)| document.events.clone())
        .collect::<Vec<_>>();
    let private_events = documents
        .iter()
        .flat_map(|(_, document)| document.private_events.clone())
        .collect::<Vec<_>>();

    if args.dry_run || args.check {
        if let Some(events_path) = args.events {
            write_events(&events_path, &all_events)?;
        }
        if let Some(sarif_path) = args.sarif {
            write_sarif(&sarif_path, &all_events)?;
        }
        print_summary(args.summary, &summary, &skipped)?;
        if args.check && summary.redaction_count > 0 {
            bail!("redactions were found and --check is set");
        }
        enforce_fail_on(&args.shared.fail_on, &summary)?;
        return Ok(());
    }

    let mut wrote_redacted_to_stdout = false;
    match &args.out {
        Some(out) => write_scrub_output(out, &documents)?,
        None if args.stdin && documents.len() == 1 => {
            print!("{}", documents[0].1.redacted);
            wrote_redacted_to_stdout = true;
        }
        None => bail!("--out is required when scrubbing files"),
    }

    if let Some(receipt_path) = args.receipt {
        write_receipt(&receipt_path, &private_events)?;
    }
    if let Some(events_path) = args.events {
        write_events(&events_path, &all_events)?;
    }
    if let Some(sarif_path) = args.sarif {
        write_sarif(&sarif_path, &all_events)?;
    }

    if wrote_redacted_to_stdout {
        print_summary_stderr(args.summary, &summary, &skipped)?;
    } else {
        print_summary(args.summary, &summary, &skipped)?;
    }
    if !all_events.is_empty() {
        eprintln!(
            "Use --events for public redaction JSONL or --receipt for private hash metadata."
        );
    }
    enforce_fail_on(&args.shared.fail_on, &summary)?;
    Ok(())
}

fn bundle(args: BundleArgs) -> Result<()> {
    let runtime_config = args.shared.runtime_config()?;
    if args.dry_run {
        let (inputs, skipped) = collect_inputs(&args.paths, &args.shared.input_options())?;
        let mut redactor = args.shared.redactor(&runtime_config);
        let mut summary = RedactionSummary::default();
        for input in inputs {
            let profile = runtime_config.profile_for_path(&input.archive_path, args.shared.profile);
            let document = redactor.redact_text_with_profile(
                &input.content,
                &input.archive_path,
                &input.format,
                profile,
            );
            validate_structure_preserved(&input.format, &input.content, &document.redacted)
                .with_context(|| {
                    format!("structured validation failed for {}", input.source_file)
                })?;
            summary.add_document(&document);
        }
        summary.skipped_files = skipped.len();
        print_summary(SummaryFormat::Text, &summary, &skipped)?;
        enforce_fail_on(&args.shared.fail_on, &summary)?;
        return Ok(());
    }

    let result = build_bundle(
        &args.paths,
        &args.out,
        BundleOptions {
            profile: args.shared.profile,
            placeholder_style: args.shared.placeholder_style,
            input_options: args.shared.input_options(),
            runtime_config,
        },
    )?;

    if let Some(receipt_path) = args.receipt {
        write_receipt(&receipt_path, &result.private_events)?;
    }

    println!(
        "Created {} with {} files and {} redactions.",
        args.out.display(),
        result.summary.scanned_files,
        result.summary.redaction_count
    );
    if !result.skipped.is_empty() {
        println!("Skipped {} files.", result.skipped.len());
    }
    enforce_fail_on(&args.shared.fail_on, &result.summary)?;
    Ok(())
}

fn inspect(args: InspectArgs) -> Result<()> {
    let verification = if args.verify {
        Some(verify_bundle(&args.bundle)?)
    } else {
        None
    };
    let manifest = match &verification {
        Some(verification) => verification.manifest.clone(),
        None => inspect_bundle(&args.bundle)?,
    };
    match args.summary {
        SummaryFormat::Json => {
            if let Some(verification) = verification {
                println!("{}", serde_json::to_string_pretty(&verification)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            }
        }
        SummaryFormat::Markdown => {
            println!("# Safe Bundle\n");
            println!("- Tool: `{}` {}", manifest.tool_name, manifest.tool_version);
            println!("- Created: `{}`", manifest.created_at);
            println!("- Profile: `{}`", manifest.profile);
            println!("- Files: `{}`", manifest.file_count);
            println!("- Redactions: `{}`", manifest.redaction_count);
            println!("- Bundle hash: `{}`", manifest.bundle_hash);
            if let Some(verification) = verification {
                println!("- Verified files: `{}`", verification.verified_file_count);
                println!(
                    "- Verified redactions: `{}`",
                    verification.verified_redaction_count
                );
            }
        }
        SummaryFormat::Text => {
            println!("Safe bundle: {}", args.bundle.display());
            println!("Tool: {} {}", manifest.tool_name, manifest.tool_version);
            println!("Profile: {}", manifest.profile);
            println!("Files: {}", manifest.file_count);
            println!("Redactions: {}", manifest.redaction_count);
            println!("Bundle hash: {}", manifest.bundle_hash);
            if let Some(verification) = verification {
                println!("Verified files: {}", verification.verified_file_count);
                println!(
                    "Verified redactions: {}",
                    verification.verified_redaction_count
                );
            }
        }
    }
    Ok(())
}

fn rules(args: RulesArgs) -> Result<()> {
    match args.command {
        RulesCommand::List {
            format,
            config,
            no_config,
        } => {
            let runtime_config = RuntimeConfig::load(config.as_deref(), no_config)?;
            let infos = if runtime_config.loaded_from.is_some() {
                runtime_config.detector_set.detector_infos()
            } else {
                detector_infos()
            };
            match format {
                SummaryFormat::Json => println!("{}", serde_json::to_string_pretty(&infos)?),
                SummaryFormat::Markdown => {
                    println!("| ID | Class | Confidence | Reason |");
                    println!("|---|---|---|---|");
                    for info in infos {
                        println!(
                            "| `{}` | `{}` | `{}` | {} |",
                            info.id,
                            info.class,
                            info.confidence.as_str(),
                            info.reason
                        );
                    }
                }
                SummaryFormat::Text => {
                    for info in infos {
                        println!(
                            "{} [{} {}] - {}",
                            info.id,
                            info.class,
                            info.confidence.as_str(),
                            info.reason
                        );
                    }
                }
            }
        }
        RulesCommand::Test {
            path,
            profile,
            config,
            no_config,
        } => {
            let shared = SharedRedactionArgs {
                profile,
                format: InputFormat::Auto,
                include: Vec::new(),
                exclude: Vec::new(),
                max_file_size: crate::input::parse_size("10MiB")?,
                placeholder_style: PlaceholderStyle::Bracket,
                fail_on: Vec::new(),
                config,
                no_config,
            };
            let runtime_config = shared.runtime_config()?;
            let (inputs, skipped) = collect_inputs(&[path], &shared.input_options())?;
            let mut redactor = shared.redactor(&runtime_config);
            let mut summary = RedactionSummary::default();
            for input in inputs {
                let profile = runtime_config.profile_for_path(&input.archive_path, shared.profile);
                let document = redactor.redact_text_with_profile(
                    &input.content,
                    &input.archive_path,
                    &input.format,
                    profile,
                );
                validate_structure_preserved(&input.format, &input.content, &document.redacted)
                    .with_context(|| {
                        format!("structured validation failed for {}", input.source_file)
                    })?;
                summary.add_document(&document);
            }
            summary.skipped_files = skipped.len();
            print_summary(SummaryFormat::Text, &summary, &skipped)?;
        }
    }
    Ok(())
}

fn completions(args: CompletionsArgs) -> Result<()> {
    let mut command = Cli::command();
    generate(args.shell, &mut command, "safe-bundle", &mut io::stdout());
    Ok(())
}

fn write_scrub_output(
    out: &Path,
    documents: &[(String, crate::model::RedactedDocument)],
) -> Result<()> {
    if documents.len() == 1 && (out.extension().is_some() || !out.exists()) {
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out, &documents[0].1.redacted)
            .with_context(|| format!("failed to write {}", out.display()))?;
        return Ok(());
    }

    fs::create_dir_all(out)?;
    for (archive_path, document) in documents {
        let destination = out.join(archive_path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&destination, &document.redacted)
            .with_context(|| format!("failed to write {}", destination.display()))?;
    }
    Ok(())
}

fn write_receipt(
    path: &Path,
    private_events: &[crate::model::PrivateRedactionEvent],
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, private_events_json(private_events)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn write_events(path: &Path, events: &[crate::model::RedactionEvent]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, events_jsonl(events)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn write_sarif(path: &Path, events: &[crate::model::RedactionEvent]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, sarif_json(events)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn print_summary(
    format: SummaryFormat,
    summary: &RedactionSummary,
    skipped: &[crate::model::SkippedFile],
) -> Result<()> {
    match format {
        SummaryFormat::Text => println!("{}", summary_text(summary)),
        SummaryFormat::Json => println!("{}", serde_json::to_string_pretty(summary)?),
        SummaryFormat::Markdown => println!("{}", summary_markdown(summary, skipped)),
    }
    Ok(())
}

fn print_summary_stderr(
    format: SummaryFormat,
    summary: &RedactionSummary,
    skipped: &[crate::model::SkippedFile],
) -> Result<()> {
    match format {
        SummaryFormat::Text => eprintln!("{}", summary_text(summary)),
        SummaryFormat::Json => eprintln!("{}", serde_json::to_string_pretty(summary)?),
        SummaryFormat::Markdown => eprintln!("{}", summary_markdown(summary, skipped)),
    }
    Ok(())
}

fn enforce_fail_on(fail_on: &[FailOn], summary: &RedactionSummary) -> Result<()> {
    if fail_on.contains(&FailOn::Findings) && summary.redaction_count > 0 {
        bail!("redactions were found and --fail-on findings is set");
    }
    if fail_on.contains(&FailOn::LowConfidence)
        && summary
            .by_confidence
            .get("low")
            .copied()
            .unwrap_or_default()
            > 0
    {
        bail!("low-confidence findings were found and --fail-on low-confidence is set");
    }
    Ok(())
}
