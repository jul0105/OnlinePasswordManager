use common::hash::compute_password_hash;
use log::LevelFilter;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use structopt::StructOpt;
use dotenv::dotenv;

#[macro_use]
extern crate diesel;

mod client;
mod common;
mod server;

#[derive(Debug, StructOpt)]
#[structopt(
    author = "Gil Balsiger <gil.balsiger@heig-vd.ch> and Julien Béguin <julien.beguin@heig-vd.ch>"
)]
struct Opts {}

fn main() {
    let _opts: Opts = StructOpt::from_args();
    dotenv().ok();

    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .unwrap();
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_ok() {
        assert_eq!(4, 2 + 2);
    }
}
