// SEC : Labo project - Authentication
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
//! Online password manager cli

use std::fs::create_dir_all;

use crate::client::user_interaction::start_client;
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
struct Opts {}

fn main() {
    let _ : Opts = StructOpt::from_args();
    dotenv().ok();

    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    ).unwrap();

    // Create server_data dir
    create_dir_all("server_data").ok();

    // Start system
    start_client();
}