//! Online password manager cli

use crate::client::user_interaction::start_client;
use client::user_interaction::{ask_password, ask_username};
use common::{hash::compute_password_hash, totp::new_totp_secret};
use console::style;
use dialoguer::{Confirm, theme::ColorfulTheme};
use dotenv::dotenv;
use log::LevelFilter;
use server::repository::add_user;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use structopt::StructOpt;

#[macro_use]
extern crate diesel;

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
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .unwrap();

    if opts.add_user {
        let email = ask_username();
        let password = ask_password();
        let totp_secret = if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Enable 2FA?")
            .default(false)
            .wait_for_newline(true)
            .interact()
            .unwrap()
        {
            Some(new_totp_secret(&email))
        } else {
            None
        };
        match add_user(
            &email,
            &compute_password_hash(&email, &password).master_password_hash,
            totp_secret.as_deref(),
        ) {
            Ok(_) => println!("{}", style("User successfully added").green()),
            Err(_) => println!("{}", style("Error while adding the user. Please try again").red()),
        }
    } else {
        start_client();
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_ok() {
        assert_eq!(4, 2 + 2);
    }
}
