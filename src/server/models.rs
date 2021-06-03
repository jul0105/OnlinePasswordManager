//! Representation of the database in structs

use crate::server::schema::*;

#[derive(Identifiable, Queryable, Clone, Debug)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub password_hash: String,
    pub totp_secret: Option<String>,
}

#[derive(Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub email: &'a str,
    pub password_hash: &'a str,
    pub totp_secret: Option<&'a str>,
}