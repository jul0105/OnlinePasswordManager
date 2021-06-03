//! Used database related actions

use std::env;

use diesel::prelude::*;
use diesel::RunQueryDsl;
use diesel::{Connection, QueryResult, SqliteConnection, insert_into};

use super::models::{NewUser, User};
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