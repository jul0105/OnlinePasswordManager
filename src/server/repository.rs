// SEC : Labo project - Authentication
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
//! Used database related actions

use super::models::*;
use super::schema::*;
use crate::common::error_message::ErrorMessage;
use crate::server::authentication::token::validate_token;
use diesel::prelude::*;
use diesel::{RunQueryDsl, update};
use diesel::{insert_into, Connection, QueryResult, SqliteConnection};
use std::env;
use khape::{FileEntry, PreRegisterSecrets, EphemeralKeys};
use diesel::result::Error;

pub struct DatabaseConnection {
    pub conn: SqliteConnection,
}

impl DatabaseConnection {
    pub fn new() -> DatabaseConnection {
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let conn =
            SqliteConnection::establish(&database_url).expect("Impossible to connect to database");
        DatabaseConnection { conn }
    }

    pub fn pre_register_user(&self, uid: &str, pre_register_secrets: PreRegisterSecrets, totp_secret: Option<&str>) -> Result<(), ErrorMessage> {
        let serialized_value = serde_json::to_string(&pre_register_secrets).unwrap();

        let new_user = NewUser {
            email: uid,
            pre_register_secrets: Some(&serialized_value),
            totp_secret,
        };
        // pre register user (incomplete, can be overridden)
        match insert_into(users::table)
            .values(&new_user)
            .execute(&self.conn) {
            Ok(_) => Ok(()),
            Err(_) => Err(ErrorMessage::DatabaseError)
        }
    }

    pub fn finish_register_user(&self, uid: &str, file_entry: FileEntry) -> Result<(), ErrorMessage> {
        let serialized_value = serde_json::to_string(&file_entry).unwrap();

        // finish register user (complete, cannot be overridden)
        match update(users::table.filter(users::email.eq(uid)))
            .set((users::file_entry.eq(serialized_value), users::pre_register_secrets.eq::<Option<String>>(None)))
            .execute(&self.conn) {
            Ok(_) => Ok(()),
            Err(_) => Err(ErrorMessage::DatabaseError)
        }
    }

    pub fn user_add_ephemeral_keys(&self, uid: &str, ephemeral_keys: EphemeralKeys) -> Result<(), ErrorMessage> {
        let serialized_value = serde_json::to_string(&ephemeral_keys).unwrap();

        // add ephemeral keys
        match update(users::table.filter(users::email.eq(uid)))
            .set(users::ephemeral_keys.eq(serialized_value))
            .execute(&self.conn) {
            Ok(_) => Ok(()),
            Err(_) => Err(ErrorMessage::DatabaseError)
        }
    }

    pub fn user_add_session_key(&self, uid: &str, session_token: &Token) -> Result<(), ErrorMessage>{
        // remove ephemeral keys
        match update(users::table.filter(users::email.eq(uid)))
            .set(users::ephemeral_keys.eq::<Option<String>>(None))
            .execute(&self.conn) {
            Err(_) => Err(ErrorMessage::DatabaseError),
            Ok(_) => self.add_token(session_token) // add session key
        }
    }

    pub fn user_get_file_entry(&self, uid: &str) -> Result<FileEntry, ErrorMessage> {
        match self.get_user(uid)?.file_entry {
            Some(serialized_val) => match serde_json::from_str::<FileEntry>(&serialized_val) {
                Ok(val) => Ok(val),
                Err(_) => Err(ErrorMessage::DeserializeError)
            }
            None => Err(ErrorMessage::AuthFailed)
        }
    }

    pub fn user_get_pre_register_secrets(&self, uid: &str) -> Result<PreRegisterSecrets, ErrorMessage> {
        match self.get_user(uid)?.pre_register_secrets {
            Some(serialized_val) => match serde_json::from_str::<PreRegisterSecrets>(&serialized_val) {
                Ok(val) => Ok(val),
                Err(_) => Err(ErrorMessage::DeserializeError)
            }
            None => Err(ErrorMessage::AuthFailed)
        }
    }

    pub fn user_get_ephemeral_keys(&self, uid: &str) -> Result<EphemeralKeys, ErrorMessage> {
        match self.get_user(uid)?.ephemeral_keys {
            Some(serialized_val) => match serde_json::from_str::<EphemeralKeys>(&serialized_val) {
                Ok(val) => Ok(val),
                Err(_) => Err(ErrorMessage::DeserializeError)
            }
            None => Err(ErrorMessage::AuthFailed)
        }
    }

    pub fn get_user(&self, user_email: &str) -> Result<User, ErrorMessage> {
        use super::schema::users::dsl::*;

        match users.filter(email.eq(user_email)).first::<User>(&self.conn) {
            Ok(val) => Ok(val),
            Err(_) => Err(ErrorMessage::AuthFailed)
        }
    }

    pub fn add_token(&self, new_token: &Token) -> Result<(), ErrorMessage> {
        use super::schema::tokens::dsl::*;

        match insert_into(tokens).values(new_token).execute(&self.conn) {
            Ok(_) => Ok(()),
            Err(_) => Err(ErrorMessage::DatabaseError)
        }
    }

    pub fn get_user_from_token(&self, given_token: &str) -> Result<User, ErrorMessage> {
        use super::schema::tokens::dsl::*;
        use super::schema::users::dsl::*;
        match users
            .inner_join(tokens)
            .filter(session_key.eq(given_token))
            .first::<(User, Token)>(&self.conn)
        {
            Ok((user_found, token_found)) => {
                validate_token(&token_found)?;
                Ok(user_found)
            }
            Err(_) => return Err(ErrorMessage::NoUserFound),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::server::authentication::token;
    use diesel::{Connection, SqliteConnection};
    use std::{
        fs::{create_dir, remove_dir_all},
        sync::Mutex,
    };

    lazy_static! {
        pub static ref DATABASE: Mutex<DatabaseConnection> = {
            remove_dir_all("test_data").ok();
            create_dir("test_data").ok();
            embed_migrations!("migrations");
            let conn = SqliteConnection::establish("test_data/test.db")
                .expect("Unable to connect to database");
            embedded_migrations::run(&conn).expect("Cannot run migrations");
            env::set_var("DATABASE_URL", "test_data/test.db");
            env::set_var("SERVER_DATA", "test_data");

            Mutex::new(DatabaseConnection { conn })
        };
    }
}
