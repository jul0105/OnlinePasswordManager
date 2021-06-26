//! CLI user interaction

use crate::client::action::Session;
use crate::common::error_message::ErrorMessage;
use console::style;
use console::Emoji;
use dialoguer::console::Term;
use dialoguer::theme::ColorfulTheme;
use dialoguer::Input;
use dialoguer::Password;
use dialoguer::Select;
use strum::EnumMessage;
use strum::IntoEnumIterator;

use super::action::Action;
use crate::server::authentication::email::validate_email;

pub fn start_client() {
    println!("Welcome to password manager\n");

    let mut session = ask_login();

    loop {
        let action = ask_action();

        match action {
            Some(a) => {
                handle_action(&mut session, a);
            }
            None => {
                println!("No action choosen. Quitting...");
                return;
            }
        }
    }
}

pub fn ask_email() -> String {
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Email")
        .validate_with(|val: &String| {
            if validate_email(val) {
                return Ok(());
            } else {
                return Err("Please enter a valid email address");
            }
        })
        .interact_text()
        .unwrap()
}

pub fn ask_password() -> String {
    // TODO Check password client-side (it's the only way, we cannot send the password to the server)
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact()
        .unwrap()
}

pub fn ask_totp_code() -> String {
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter 6 digits code")
        .interact_text()
        .unwrap()
}

pub fn ask_login() -> Session {
    loop {
        let username = ask_email();
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
                e => display_error(e),
            },
        }
    }
}

pub fn ask_action() -> Option<Action> {
    println!();
    let actions: Vec<Action> = Action::iter().collect();
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an action")
        .items(&actions)
        .default(0)
        .interact_on_opt(&Term::stderr())
        .unwrap();

    selection.map_or(None, |i| Some(actions[i]))
}

fn handle_action(session: &mut Session, action: Action) {
    match action {
        Action::ReadPassword => read_password(session),
        Action::AddNewPassword => add_new_password(session),
        Action::EditPassword => modify_password(session),
        Action::DeletePassword => delete_password(session),
    }
}

fn read_password(session: &Session) {
    let entries = session.get_entries();
    let labels = entries
        .iter()
        .map(|entry| entry.label.clone())
        .collect::<Vec<String>>();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose a label")
        .paged(true)
        .items(&labels)
        .default(0)
        .interact_on_opt(&Term::stderr())
        .unwrap();

    if let Some(index) = selection {
        println!("\n{}", entries[index]);
    }
}

fn ask_label() -> String {
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Label")
        .interact_text()
        .unwrap()
}

fn ask_username() -> String {
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Username")
        .interact_text()
        .unwrap()
}

fn ask_new_password() -> String {
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact_text()
        .unwrap()
}

fn add_new_password(session: &mut Session) {
    let label = ask_label();
    let username = ask_username();
    let new_password = ask_new_password();
    match session.add_password(&label, &username, &new_password) {
        Ok(_) => {
            println!(
                "{}",
                style(format!("\n{} Password successfully added", Emoji("✔", ""))).green()
            );
        }
        Err(e) => display_error(e),
    }
}

fn modify_password(session: &Session) {
    todo!();
}

fn delete_password(session: &Session) {
    todo!();
}

fn display_error(e: ErrorMessage) {
    if e.get_message().is_some() {
        let msg = format!(
            "{} {}. Please try again",
            Emoji("✘", ""),
            e.get_message().unwrap()
        );
        println!("{}", style(&msg).red());
    }
}
