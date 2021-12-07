// SEC : Labo project - Authentication
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
//! Representation of the database in structs

use chrono::NaiveDateTime;

use crate::server::schema::*;

#[derive(Identifiable, Queryable, Debug)]
#[table_name = "users"]
pub struct User {
    pub id: i32,
    pub email: String,
    pub file_entry: Option<String>,
    pub pre_register_secrets: Option<String>,
    pub ephemeral_keys: Option<String>,
    pub role: String,
    pub totp_secret: Option<String>,
}

#[derive(Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub email: &'a str,
    pub pre_register_secrets: Option<&'a str>,
    pub totp_secret: Option<&'a str>,
}

#[derive(Queryable, Insertable, Debug, Clone, PartialEq)]
#[table_name = "tokens"]
pub struct Token {
    pub session_key: String,
    pub validity_start: NaiveDateTime,
    pub validity_end: NaiveDateTime,
    pub user_id: i32,
}
