//! Thin binary entry: parse args, run the CLI, exit nonzero on refusal.

use clap::Parser;
use payroll_spine::cli::{run, Cli};

fn main() {
    let cli = Cli::parse();
    if let Err(message) = run(cli) {
        eprintln!("error: {message}");
        std::process::exit(1);
    }
}
