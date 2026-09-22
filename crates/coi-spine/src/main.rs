use clap::Parser;
use coi_spine::cli::{self, Cli};

fn main() {
    let cli = Cli::parse();
    std::process::exit(cli::run(cli));
}
