//! bankrec-spine CLI entry point.

fn main() -> std::process::ExitCode {
    use clap::Parser;
    let cli = bankrec_spine::cli::Cli::parse();
    bankrec_spine::cli::run(cli)
}
