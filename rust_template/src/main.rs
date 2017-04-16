#[macro_use]
extern crate log;
extern crate log_panics;
extern crate getopts;

mod logging;

use std::env;

use getopts::Options;
use logging::set_log_level;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const PROGRAM: &'static str = env!("CARGO_PKG_NAME");

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn opts() -> Options {
    let mut opts = Options::new();

    opts.optflag("", "version", "show version and exit");
    opts.optflagmulti("v", "verbose", "verbosity (stacking)");
    opts.optflag("h", "help", "print this help menu");

    opts
}

fn main() {
	let args: Vec<String> = env::args().collect();
    let program = &args[0];
    let opts = opts();

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            error!("Failed to parse command line args: {}", f);
            return;
        }
    };

    if matches.opt_present("help") {
        print_usage(program, opts);
        return;
    }

    // initialize logging
    set_log_level(matches.opt_count("verbose"));
    log_panics::init();

    info!("{} {}", PROGRAM, VERSION);
}
