// SEC : Labo project - Authentication
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
//! Online password manager cli

use std::fs::create_dir_all;

use crate::client::user_interaction::{handle_registration, start_client};
use dotenv::dotenv;
use log::LevelFilter;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use structopt::StructOpt;

#[macro_use]
extern crate diesel;

#[allow(unused_imports)]
#[macro_use]
extern crate diesel_migrations;

#[allow(unused_imports)]
#[macro_use]
extern crate lazy_static;

mod client;
mod common;
mod server;

#[derive(Debug, StructOpt)]
#[structopt(
    author = "Gil Balsiger <gil.balsiger@heig-vd.ch> and Julien Béguin <julien.beguin@heig-vd.ch>"
)]
struct Opts {
    /// Manually add a user to database (used for development)
    #[structopt(long)]
    add_user: bool,
}

fn main() {
    let opts: Opts = StructOpt::from_args();
    dotenv().ok();

    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .unwrap();

    // Create server_data dir
    create_dir_all("server_data").ok();

    if opts.add_user {
        handle_registration();
    } else {
        start_client();
    }
}

#[cfg(test)]
pub mod tests {
    use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

    pub fn init_test_logger() {
        TermLogger::init(
            LevelFilter::Trace,
            Config::default(),
            TerminalMode::Stdout,
            ColorChoice::Auto,
        )
        .unwrap();
    }
}
