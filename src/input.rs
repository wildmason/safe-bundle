use crate::model::{InputFormat, SkippedFile};
use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::fs;
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct InputOptions {
    pub format: InputFormat,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub max_file_size: u64,
}

impl Default for InputOptions {
    fn default() -> Self {
        Self {
            format: InputFormat::Auto,
            include: Vec::new(),
            exclude: default_excludes(),
            max_file_size: DEFAULT_MAX_FILE_SIZE,
        }
    }
}

#[derive(Clone, Debug)]
pub struct InputFile {
    pub absolute_path: PathBuf,
    pub source_file: String,
    pub archive_path: String,
    pub format: String,
    pub content: String,
}

pub fn read_stdin(input: &str, format: InputFormat) -> InputFile {
    InputFile {
        absolute_path: PathBuf::from("<stdin>"),
        source_file: "<stdin>".to_string(),
        archive_path: "stdin.txt".to_string(),
        format: normalize_format(format, Path::new("stdin.txt"), input).to_string(),
        content: input.to_string(),
    }
}

pub fn collect_inputs(
    paths: &[PathBuf],
    options: &InputOptions,
) -> Result<(Vec<InputFile>, Vec<SkippedFile>)> {
    if paths.is_empty() {
        bail!("at least one input path is required");
    }

    let include = build_glob_set(&options.include)?;
    let exclude = build_glob_set(&options.exclude)?;
    let mut files = Vec::new();
    let mut skipped = Vec::new();

    for root in paths {
        let root = root
            .canonicalize()
            .with_context(|| format!("failed to resolve input path {}", root.display()))?;
        if root.is_file() {
            read_file(
                &root,
                archive_name_for_file(&root),
                options,
                &mut files,
                &mut skipped,
            )?;
            continue;
        }
        if !root.is_dir() {
            skipped.push(SkippedFile {
                path: root.display().to_string(),
                reason: "not a file or directory".to_string(),
            });
            continue;
        }

        let root_name = root
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "input".to_string());

        for entry in WalkDir::new(&root).follow_links(false) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    skipped.push(SkippedFile {
                        path: err
                            .path()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "<unknown>".to_string()),
                        reason: err.to_string(),
                    });
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            let relative = path.strip_prefix(&root).unwrap_or(path);
            let archive_path = sanitize_archive_path(Path::new(&root_name).join(relative))?;

            if !matches_globs(path, &include, &exclude) {
                continue;
            }

            read_file(path, archive_path, options, &mut files, &mut skipped)?;
        }
    }

    files.sort_by(|a, b| a.archive_path.cmp(&b.archive_path));
    skipped.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((files, skipped))
}

fn read_file(
    path: &Path,
    archive_path: String,
    options: &InputOptions,
    files: &mut Vec<InputFile>,
    skipped: &mut Vec<SkippedFile>,
) -> Result<()> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            skipped.push(SkippedFile {
                path: path.display().to_string(),
                reason: err.to_string(),
            });
            return Ok(());
        }
    };

    if metadata.len() > options.max_file_size {
        skipped.push(SkippedFile {
            path: path.display().to_string(),
            reason: format!("file exceeds max size of {} bytes", options.max_file_size),
        });
        return Ok(());
    }

    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            skipped.push(SkippedFile {
                path: path.display().to_string(),
                reason: err.to_string(),
            });
            return Ok(());
        }
    };

    if bytes.contains(&0) {
        skipped.push(SkippedFile {
            path: path.display().to_string(),
            reason: "binary file skipped".to_string(),
        });
        return Ok(());
    }

    let content = match String::from_utf8(bytes) {
        Ok(content) => content,
        Err(_) => {
            skipped.push(SkippedFile {
                path: path.display().to_string(),
                reason: "non-UTF-8 file skipped".to_string(),
            });
            return Ok(());
        }
    };

    let format = normalize_format(options.format, path, &content).to_string();
    files.push(InputFile {
        absolute_path: path.to_path_buf(),
        source_file: path.display().to_string(),
        archive_path,
        format,
        content,
    });

    Ok(())
}

fn archive_name_for_file(path: &Path) -> String {
    path.file_name()
        .map(PathBuf::from)
        .and_then(|name| sanitize_archive_path(name).ok())
        .unwrap_or_else(|| "input.txt".to_string())
}

pub fn sanitize_archive_path(path: impl AsRef<Path>) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.as_ref().components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_string_lossy();
                if !part.is_empty() {
                    parts.push(part.replace(['\\', '/'], "_"));
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                bail!(
                    "unsafe archive path component in {}",
                    path.as_ref().display()
                );
            }
        }
    }

    if parts.is_empty() {
        bail!("empty archive path");
    }

    Ok(parts.join("/"))
}

pub fn normalize_format(format: InputFormat, path: &Path, content: &str) -> &'static str {
    match format {
        InputFormat::Auto => sniff_format(path, content),
        other => other.as_str(),
    }
}

fn sniff_format(path: &Path, content: &str) -> &'static str {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match extension.as_str() {
        "env" => "env",
        "json" => {
            if content.lines().take(2).count() > 1
                && content.lines().all(|line| {
                    let trimmed = line.trim();
                    trimmed.is_empty() || trimmed.starts_with('{') || trimmed.starts_with('[')
                })
            {
                "jsonl"
            } else {
                "json"
            }
        }
        "jsonl" | "ndjson" => "jsonl",
        "yaml" | "yml" => "yaml",
        "toml" => "toml",
        "ini" | "conf" | "cfg" => "ini",
        "diff" | "patch" => "diff",
        "har" => "har",
        _ => {
            let trimmed = content.trim_start();
            if trimmed.starts_with("curl ") {
                "curl"
            } else if trimmed.starts_with("GET ")
                || trimmed.starts_with("POST ")
                || trimmed.starts_with("HTTP/")
            {
                "http"
            } else {
                "text"
            }
        }
    }
}

fn matches_globs(path: &Path, include: &Option<GlobSet>, exclude: &Option<GlobSet>) -> bool {
    if let Some(exclude) = exclude
        && exclude.is_match(path)
    {
        return false;
    }

    match include {
        Some(include) => include.is_match(path),
        None => true,
    }
}

fn build_glob_set(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).with_context(|| format!("invalid glob pattern {pattern}"))?);
    }
    Ok(Some(builder.build()?))
}

fn default_excludes() -> Vec<String> {
    vec![
        "**/.git/**".to_string(),
        "**/node_modules/**".to_string(),
        "**/target/**".to_string(),
        "**/dist/**".to_string(),
        "**/build/**".to_string(),
    ]
}

pub fn parse_size(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("size cannot be empty");
    }

    let (digits, suffix): (String, String) = trimmed
        .chars()
        .partition(|c| c.is_ascii_digit() || *c == '_');
    let value: u64 = digits.replace('_', "").parse()?;
    let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        other => bail!("unsupported size suffix {other}"),
    };

    Ok(value * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_archive_paths() {
        assert!(sanitize_archive_path("../secret.txt").is_err());
        assert_eq!(
            sanitize_archive_path("logs/app.txt").unwrap(),
            "logs/app.txt"
        );
    }

    #[test]
    fn parses_human_sizes() {
        assert_eq!(parse_size("10").unwrap(), 10);
        assert_eq!(parse_size("2kb").unwrap(), 2048);
        assert_eq!(parse_size("3 MiB").unwrap(), 3 * 1024 * 1024);
    }
}
