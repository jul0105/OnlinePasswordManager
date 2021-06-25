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


pub fn get_connection() -> SqliteConnection {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url).expect("Impossible to connect to database")
}

pub fn add_user(email: &str, password_hash: &str, totp_secret: Option<&str>) -> QueryResult<usize> {
    let connection = get_connection();
    let new_user = NewUser {
        email,
        password_hash,
        totp_secret,
    };
    insert_into(users::table)
        .values(&new_user)
        .execute(&connection)
}

pub fn get_user(user_email: &str) -> QueryResult<User> {
    use super::schema::users::dsl::*;

    let connection = get_connection();
    users.filter(email.eq(user_email)).first::<User>(&connection)
}

pub fn auth_user(user_email: &str, hashed_password: &str) -> QueryResult<User> {
    use super::schema::users::dsl::*;

    let connection = get_connection();
    users.filter(email.eq(user_email).and(password_hash.eq(hashed_password))).first::<User>(&connection)
}

pub fn check_password(user: &User, password_hash: &str) -> bool {
    user.password_hash == password_hash
}

pub fn new_token(user: &User) -> String {
    use super::schema::tokens::dsl::*;
    let conn = get_connection();
    let mut buffer = [0u8; 24];
    OsRng.fill_bytes(&mut buffer);
    let result = Token {
        token: encode(buffer),
        expire_at: Utc::now().naive_utc() + Duration::hours(1),
        user_id: user.id
    };
    insert_into(tokens).values(&result).execute(&conn).unwrap();
    return result.token;
}