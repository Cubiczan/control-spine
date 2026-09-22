//! Thin binary shell over the library CLI: parse args, run, map the exit
//! code. No logic lives here.
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(ghg_ledger_spine::cli::run())
}
