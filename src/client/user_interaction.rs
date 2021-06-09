//! CLI user interaction

use crate::client::action::Session;
use crate::common::error_message::ErrorMessage;
use console::Emoji;
use console::style;
use dialoguer::console::Term;
use dialoguer::theme::ColorfulTheme;
use dialoguer::Input;
use dialoguer::Password;
use dialoguer::Select;
use regex::Regex;
use strum::EnumMessage;
use strum::IntoEnumIterator;

use super::action::Action;

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#).unwrap();
}

pub fn start_client() {
    println!("Welcome to password manager\n");

    let session = ask_login();
    let action = ask_action();

    match action {
        Some(a) => {
            handle_action(&session, a);
        }
        None => {
            println!("No action choosen. Quitting...");
        }
    }
}

pub fn ask_username() -> String {
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Email")
        .validate_with(|val: &String| {
            if check_email(val) {
                return Ok(());
            } else {
                return Err("Please enter a valid email address");
            }
        })
        .interact_text()
        .unwrap()
}

fn check_email(input: &str) -> bool {
    EMAIL_REGEX.is_match(input)
}

pub fn ask_password() -> String {
    // TODO Check length
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact()
        .unwrap()
}

pub fn ask_totp_code() -> String {
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("2FA code")
        .interact_text()
        .unwrap()
}

pub fn ask_login() -> Session {
    loop {
        let username = ask_username();
        let password = ask_password();

        // First try with no totp code
        match Session::login(&username, &password, None) {
            Ok(session) => return session,
            Err(error) => match error {
                ErrorMessage::TotpRequired => loop {
                    // If totp is required we ask it after we are sure the password is correct
                    let totp_code = ask_totp_code();
                    match Session::login(&username, &password, Some(&totp_code)) {
                        Ok(session) => return session,
                        Err(e) => display_error(e),
                    }
                },
                e => display_error(e)
            },
        }
    }
}

pub fn ask_action() -> Option<Action> {
    let actions: Vec<Action> = Action::iter().collect();
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an action")
        .items(&actions)
        .default(0)
        .interact_on_opt(&Term::stderr())
        .unwrap();

    selection.map_or(None, |i| Some(actions[i]))
}

fn handle_action(session: &Session, action: Action) {
    match action {
        Action::ReadPassword => read_password(session),
        Action::AddNewPassword => add_new_password(session),
        Action::EditPassword => modify_password(session),
        Action::DeletePassword => delete_password(session),
    }
}

fn read_password(session: &Session) {
    todo!();
}

fn add_new_password(session: &Session) {
    todo!();
}

fn modify_password(session: &Session) {
    todo!();
}

fn delete_password(session: &Session) {
    todo!();
}

fn display_error(e: ErrorMessage) {
    if e.get_message().is_some() {
        let msg = format!("{} {}. Please try again", Emoji("✘", ""), e.get_message().unwrap());
        println!("{}", style(&msg).red());
    }
}