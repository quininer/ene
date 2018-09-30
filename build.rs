#[path = "src/opts.rs"]
mod opts;

use std::env;
use clap::Shell;
use structopt::StructOpt;
use ene_core as core;
use self::opts::Options;


fn main() {
    if let Some(outdir) = env::var_os("OUT_DIR") {
        let mut app = Options::clap();
        let name = app.get_name().to_string();
        app.gen_completions(name.as_str(), Shell::Bash, &outdir);
        app.gen_completions(name.as_str(), Shell::Zsh, &outdir);
        app.gen_completions(name.as_str(), Shell::Fish, &outdir);
    }
}
