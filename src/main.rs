//! Online password manager cli

use std::fs::create_dir_all;

use crate::client::user_interaction::{ask_totp_code, start_client};
use crate::server::authentication::totp::{display_totp, verify_code};
use crate::server::repository::DatabaseConnection;
use client::hash::compute_password_hash;
use client::user_interaction::{ask_email, ask_password};
use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm};
use dotenv::dotenv;
use log::LevelFilter;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use structopt::StructOpt;

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate diesel_migrations;

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

    // TODO set to info
    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .unwrap(); // TODO log in file ?

    // Create server_data dir
    create_dir_all("server_data").ok();

    // TODO remove that ?
    if opts.add_user {
        let email = ask_email();
        let password = ask_password();
        let totp_secret = if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Enable 2FA?")
            .default(false)
            .wait_for_newline(true)
            .interact()
            .unwrap()
        {
            // let secret = generate_secret();
            let secret = "abcdabcdabcdabcd";
            Some(loop {
                display_totp(&email, &secret);
                let code = ask_totp_code();
                if verify_code(&secret, &code) {
                    break secret;
                }
                println!("Invalid code. Please try again");
            })
        } else {
            None
        };

        let db = DatabaseConnection::new();
        match db.add_user(
            &email,
            &compute_password_hash(&email, &password).server_auth_password,
            totp_secret.as_deref(),
        ) {
            Ok(_) => println!("{}", style("User successfully added").green()),
            Err(_) => println!(
                "{}",
                style("Error while adding the user. Please try again").red()
            ),
        }
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
        ).unwrap();
    }


}
