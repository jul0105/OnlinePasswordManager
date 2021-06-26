//! Used database related actions

use super::models::*;
use super::schema::*;
use crate::common::error_message::ErrorMessage;
use crate::server::authentication::password::hash;
use crate::server::authentication::token::validate_token;
use crate::server::repository::tokens::dsl::tokens;
use crate::server::schema::tokens::dsl::user_id;
use diesel::prelude::*;
use diesel::RunQueryDsl;
use diesel::{insert_into, Connection, QueryResult, SqliteConnection};
use std::env;

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

    pub fn add_user(
        &self,
        email: &str,
        password: &str,
        totp_secret: Option<&str>,
    ) -> QueryResult<usize> {
        let new_user = NewUser {
            email,
            password_hash: &hash(password),
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

    pub fn add_token(&self, new_token: &Token) {
        use super::schema::tokens::dsl::*;

        insert_into(tokens).values(new_token).execute(&self.conn);
        // TODO handle result
        // self.delete_expired_token(user);
    }

    pub fn delete_expired_token(&self, user: &User) {
        todo!();
    }

    pub fn get_user_from_token(&self, given_token: &str) -> Result<User, ErrorMessage> {
        use super::schema::tokens::dsl::*;
        use super::schema::users::dsl::*;
        match users
            .inner_join(tokens)
            .filter(token.eq(given_token))
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
    use std::env;
    use tempfile::TempDir;

    // This macro from `diesel_migrations` defines an `embedded_migrations` module
    // containing a function named `run`. This allows the example to be run and
    // tested without any outside setup of the database.
    embed_migrations!("migrations");

    /// Get a clean db connection to the test-specific DB environment
    pub fn get_test_db() -> (DatabaseConnection, TempDir) {
        // Create temporary dir where db will be stored
        let tmp_dir = tempfile::Builder::new()
            .prefix(env!("CARGO_PKG_NAME"))
            .rand_bytes(5)
            .tempdir()
            .expect("not possible to create tempfile");

        let db_path = tmp_dir.path().join("test.db");
        let conn = SqliteConnection::establish(db_path.to_str().unwrap())
            .expect("Unable to connect to database");

        // Execute migration to have a clean db
        embedded_migrations::run(&conn).expect("Migration not possible to run");

        // Override environment variable
        env::set_var("DATABASE_URL", db_path);

        // Return db and tempdir because the temp directory is deleted when this var is out of scope, making the db unusable.
        (DatabaseConnection { conn }, tmp_dir)
    }

    #[test]
    fn test() {
        let (db, _) = get_test_db();

        assert!(db
            .add_user("julien@heig-vd.com", "password hash", None)
            .is_ok());
        assert!(db.get_user("julien@heig-vd.com").is_ok());
    }

    #[test]
    fn test_add_token() {
        let (db, _) = get_test_db();

        let id_user = 0;
        let token = token::generate_token(id_user);

        db.add_token(&token);
        let user = db.get_user_from_token(&token.token);
        assert!(user.is_ok());
        assert_eq!(id_user, user.unwrap().id);
    }
}
