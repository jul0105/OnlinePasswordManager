// Online Password Manager
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
// Modified on the 24.12.2021 by Julien Béguin
// For Bachelor Thesis KHAPE use case
//
//! CLI user interaction

use crate::client::action::Session;
use crate::common::error_message::ErrorMessage;
use crate::client::password::validate;
use crate::server::authentication::totp::{display_totp, generate_secret, verify_code};
use console::style;
use console::Emoji;
use dialoguer::console::Term;
use dialoguer::theme::ColorfulTheme;
use dialoguer::Password;
use dialoguer::Select;
use dialoguer::{Confirm, Input};
use strum::EnumMessage;
use strum::IntoEnumIterator;
use strum::{Display, EnumIter, EnumString};

use crate::server::authentication::email::{store, validate_email};
use crate::common::password_registry::IndexablePasswordRegistry;

#[derive(Debug, Clone, Copy, Display, EnumIter, EnumString)]
enum Action {
    #[strum(to_string = "Read one password")]
    ReadPassword,
    #[strum(to_string = "Add a new password")]
    AddNewPassword,
    #[strum(to_string = "Edit an existing password")]
    EditPassword,
    #[strum(to_string = "Delete an existing password")]
    DeletePassword,
}

#[derive(Debug, Clone, Copy, Display, EnumIter, EnumString)]
enum AuthChoice {
    #[strum(to_string = "Register")]
    Register,
    #[strum(to_string = "Login")]
    Login,
}

pub fn start_client() {
    println!("-----------------------------------");
    println!("|   WELCOME TO PASSWORD MANAGER   |");
    println!("-----------------------------------");

    // Register
    loop {
        match ask_auth_choice() {
            Some(choice) => {
                match choice {
                    AuthChoice::Register => handle_registration(),
                    AuthChoice::Login => break,
                }
            }
            None => {
                println!("No action choosen. Quitting...");
                return;
            }
        }

    }

    // Login
    let mut session = ask_login();

    // Actions
    loop {
        match ask_action() {
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

fn ask_email() -> String {
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

fn ask_password() -> String {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact()
        .unwrap()
}

fn ask_totp_code() -> String {
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter 6 digits code (2FA)")
        .interact_text()
        .unwrap()
}

fn ask_login() -> Session {
    loop {
        let email = store(&ask_email());
        let password = ask_password();

        // First try with no totp code
        match Session::login(&email, &password, None) {
            Ok(session) => return session,
            Err(error) => match error {
                ErrorMessage::TotpRequired => loop {
                    // If totp is required we ask it after we are sure the password is correct
                    let totp_code = ask_totp_code();
                    match Session::login(&email, &password, Some(&totp_code)) {
                        Ok(session) => return session,
                        Err(e) => display_error(e),
                    }
                },
                e => display_error(e),
            },
        }
    }
}

fn ask_action() -> Option<Action> {
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

fn ask_auth_choice() -> Option<AuthChoice> {
    println!();
    let auth_choice: Vec<AuthChoice> = AuthChoice::iter().collect();
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an action:")
        .items(&auth_choice)
        .default(0)
        .interact_on_opt(&Term::stderr())
        .unwrap();

    selection.map_or(None, |i| Some(auth_choice[i]))
}

fn handle_action(session: &mut Session, action: Action) {
    match action {
        Action::ReadPassword => read_password(session),
        Action::AddNewPassword => add_new_password(session),
        Action::EditPassword => modify_password(session),
        Action::DeletePassword => delete_password(session),
    }
}

fn select_password_entry(registry: &IndexablePasswordRegistry) -> Option<usize> {
    let labels = registry
        .entries
        .iter()
        .map(|entry| entry.label.clone())
        .collect::<Vec<String>>();

    if labels.len() == 0 {
        println!("Your vault is currently empty. Add a password first.");
        return None;
    }

    Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose a label")
        .paged(true)
        .items(&labels)
        .default(0)
        .interact_on_opt(&Term::stderr())
        .unwrap()
}

fn read_password(session: &Session) {
    let selection = select_password_entry(&session.envelope.registry);
    if let Some(index) = selection {

        match session.read_password(index) {
            Ok(entry) => {
                println!(
                    "Label: {}\nUsername: {}\nPassword: {}",
                    entry.label,
                    entry.username,
                    entry.password
                );
            },
            Err(e) => display_error(e),
        }

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

    // Check if the label exists, ask the user in this case
    if session
        .envelope
        .registry
        .entries
        .iter()
        .find(|e| e.label == label)
        .is_some()
    {
        if !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "Label '{}' already exists. Would you like to add it anyway ?",
                label
            ))
            .default(false)
            .interact()
            .unwrap()
        {
            return;
        }
    }

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

fn modify_password(session: &mut Session) {
    let selection = select_password_entry(&session.envelope.registry);
    if let Some(index) = selection {
        let label = ask_label();
        let username = ask_username();
        let new_password = ask_new_password();

        match session.modify_password(index, &label, &username, &new_password) {
            Ok(_) => {
                println!(
                    "{}",
                    style(format!(
                        "\n{} Password successfully modified",
                        Emoji("✔", "")
                    ))
                    .green()
                );
            }
            Err(e) => display_error(e),
        }
    }
}

fn delete_password(session: &mut Session) {
    let selection = select_password_entry(&session.envelope.registry);
    if let Some(index) = selection {
        match session.delete_password(index) {
            Ok(_) => println!(
                "{}",
                style(format!(
                    "\n{} Password successfully deleted",
                    Emoji("✔", "")
                ))
                .green()
            ),
            Err(e) => display_error(e),
        }
    }
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

fn ask_registration_password() -> String {
    loop {
        let password = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("New Password")
            .interact()
            .unwrap();

        match validate(&password) {
            Ok(_) => return password,
            Err(e) => println!("{}", style(e).red()),
        }
    }
}

fn handle_registration() {
    let email = store(&ask_email());
    let password = ask_registration_password();
    let totp_secret = if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable 2FA?")
        .default(false)
        .wait_for_newline(true)
        .interact()
        .unwrap()
    {
        let secret = generate_secret();
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

    match Session::register(&email, &password, totp_secret.as_deref()) {
        Ok(_) => println!("{}", style("Registration successful").green()),
        Err(e) => display_error(e),
    }
}
