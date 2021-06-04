//! CLI user interaction

use dialoguer::theme::ColorfulTheme;
use dialoguer::Select;
use dialoguer::console::Term;
use crate::client::action::Session;
use crate::common::error_message::ErrorMessage;

pub fn start_client() {
    println!("Welcome to password manager\n");

    let session = login();
    action(&session);
}

fn login() -> Session {
    loop {
        let username = ""; // TODO ask input
        let password = ""; // TODO ask input
        let totp_code = ""; // TODO ask input
        match Session::login(username, password, totp_code) {
            Err(error) => {}, // TODO handle error message
            Ok(session) => return session,
        }
    }
}

fn action(session: &Session) {
    let items = vec!["Read password", "Add new password", "Edit password", "Delete password"];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an action")
        .items(&items)
        .default(0)
        .interact_on_opt(&Term::stderr())
        .unwrap();

    match selection {
        Some(index) => match index {
            0 => read_password(session),
            1 => add_new_password(session),
            2 => modify_password(session),
            3 => delete_password(session),
            _ => println!("Unexpected behavior while selecting action. Please try again")
        }
        None => println!("Exiting..."),
    }
}

fn read_password(session: &Session) {
    // TODO implement
}

fn add_new_password(session: &Session) {
    // TODO implement
}

fn modify_password(session: &Session) {
    // TODO implement
}

fn delete_password(session: &Session) {
    // TODO implement
}