//! Online password manager cli

use dialoguer::{console::Term, theme::ColorfulTheme, Select};
use dotenv::dotenv;
use log::LevelFilter;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use structopt::StructOpt;
use crate::client::user_interaction::start_client;

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

    start_client();
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_ok() {
        assert_eq!(4, 2 + 2);
    }
}
