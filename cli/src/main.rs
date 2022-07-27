use anyhow::Result;
use clap::Parser;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::{fmt::Display, fs, path::PathBuf, str::FromStr};

const LDP_FUSE_PATH: &str = "LDP_FUSE_PATH";

#[derive(Parser, Debug)]
#[clap(
    about = "This is a CLI tool for running programs under LDP_FUSE file systems. See https://github.com/sholtrop/ldpfuse for info on how to make an LDP_FUSE file system."
)]
pub struct CliArgs {
    /// Program to execute, with the specified `.so` as its filesystem.
    #[clap(multiple_occurrences = true)]
    program: Vec<String>,

    #[clap(short, long)]
    /// Path to the shared object `.so` file that has been compiled using the `ldpfuse.h` library.
    /// This file will be used as a filesystem for the executed program.
    so_path: AbsolutePath,

    #[clap(short, long)]
    /// Path under which the filesystem is mounted (= active).
    /// The program that is executed will ignore the ldpfuse filesystem for paths that do not match this one.
    mount_path: AbsolutePath,

    #[clap(short = 'v')]
    /// List debug output.
    verbose: bool,
}

#[derive(Debug)]
struct AbsolutePath(PathBuf);

impl FromStr for AbsolutePath {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path = fs::canonicalize(s)
            .map_err(|e| anyhow::anyhow!("Error making path {} absolute: {}", s, e))?;
        Ok(Self(path))
    }
}

impl Display for AbsolutePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

fn main() {
    let CliArgs {
        mount_path,
        so_path,
        program,
        verbose,
    } = CliArgs::parse();
    let env = std::env::vars().chain([
        ("LD_PRELOAD".into(), so_path.to_string()),
        (LDP_FUSE_PATH.into(), mount_path.to_string()),
    ]);

    if verbose {
        eprintln!(
            "Running {}\nFilesystem shared object: {so_path}\nMounted under: {mount_path}",
            program.join(" ")
        );
    }
    let err = Command::new(&program[0])
        .args(&program[1..])
        .envs(env)
        .exec();
    eprintln!("{err}");
}
