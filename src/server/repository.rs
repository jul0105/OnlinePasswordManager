//! Used database related actions

use std::env;

use base64::encode;
use chrono::Duration;
use chrono::Utc;
use diesel::prelude::*;
use diesel::RunQueryDsl;
use diesel::{Connection, QueryResult, SqliteConnection, insert_into};
use rand::RngCore;
use rand::rngs::OsRng;

use super::models::*;
use super::schema::*;
use crate::server::repository::tokens::dsl::tokens;
use crate::server::schema::tokens::dsl::user_id;


pub struct DatabaseConnection {
    pub conn: SqliteConnection
}

impl DatabaseConnection {
    pub fn new() -> DatabaseConnection {
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let conn = SqliteConnection::establish(&database_url).expect("Impossible to connect to database");

        DatabaseConnection {
            conn,
        }
    }

    pub fn add_user(&self, email: &str, password_hash: &str, totp_secret: Option<&str>) -> QueryResult<usize> {
        let new_user = NewUser {
            email,
            password_hash,
            totp_secret,
        };
        insert_into(users::table)
            .values(&new_user)
            .execute(&self.conn)
    }

    pub fn get_user(&self, user_email: &str) -> QueryResult<User> {
        use super::schema::users::dsl::*;

        users.filter(email.eq(user_email)).first::<User>(&self.conn)
    }

    pub fn auth_user(&self, user_email: &str, hashed_password: &str) -> QueryResult<User> {
        use super::schema::users::dsl::*;

        users.filter(email.eq(user_email).and(password_hash.eq(hashed_password))).first::<User>(&self.conn)
    }

    pub fn add_token(&self, new_token: &Token) {
        use super::schema::tokens::dsl::*;

        insert_into(tokens).values(new_token).execute(&self.conn);

        // self.delete_expired_token(user);
    }

    pub fn get_user_tokens(&self, user: i32) -> QueryResult<Token> {
        // TODO return more than one token
        tokens.filter(user_id.eq(user)).first::<Token>(&self.conn)
    }

    pub fn delete_expired_token(&self, user: &User) {
        todo!();
    }
}