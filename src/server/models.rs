//! Representation of the database in structs

use chrono::NaiveDateTime;

use crate::server::schema::*;
use std::time::SystemTime;

#[derive(Identifiable, Queryable, Debug)]
#[table_name = "users"]
pub struct User {
    pub id: i32,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub totp_secret: Option<String>,
}

#[derive(Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub email: &'a str,
    pub password_hash: &'a str,
    pub totp_secret: Option<&'a str>,
}

#[derive(Queryable, Insertable, Debug, Clone, PartialEq)]
#[table_name = "tokens"]
pub struct Token {
    pub token: String,
    pub validity_start: NaiveDateTime,
    pub validity_end: NaiveDateTime,
    pub user_id: i32,
}
