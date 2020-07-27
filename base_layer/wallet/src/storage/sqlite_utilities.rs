// Copyright 2020. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{
    contacts_service::storage::sqlite_db::ContactsServiceSqliteDatabase,
    error::WalletStorageError,
    output_manager_service::storage::sqlite_db::OutputManagerSqliteDatabase,
    storage::{database::WalletDatabase, sqlite_db::WalletSqliteDatabase},
    transaction_service::storage::sqlite_db::TransactionServiceSqliteDatabase,
};
use aes_gcm::{
    aead::{generic_array::GenericArray, NewAead},
    Aes256Gcm,
};
use diesel::{Connection, SqliteConnection};
use digest::Digest;
use log::*;
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tari_crypto::common::Blake256;

const LOG_TARGET: &str = "wallet::storage:sqlite_utilities";

pub type WalletDbConnection = Arc<Mutex<SqliteConnection>>;

pub fn run_migration_and_create_sqlite_connection<P: AsRef<Path>>(
    db_path: P,
) -> Result<WalletDbConnection, WalletStorageError> {
    let path_str = db_path
        .as_ref()
        .to_str()
        .ok_or_else(|| WalletStorageError::InvalidUnicodePath)?;
    let connection = SqliteConnection::establish(path_str)?;
    connection.execute("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 60000;")?;

    embed_migrations!("./migrations");
    embedded_migrations::run_with_output(&connection, &mut io::stdout())
        .map_err(|err| WalletStorageError::DatabaseMigrationError(format!("Database migration failed {}", err)))?;

    Ok(Arc::new(Mutex::new(connection)))
}

/// This function will copy a wallet database to the provided path and then clear the CommsPrivateKey from the database.
pub async fn partial_wallet_backup<P: AsRef<Path>>(current_db: P, backup_path: P) -> Result<(), WalletStorageError> {
    // Copy the current db to the backup path
    let db_path = current_db
        .as_ref()
        .to_str()
        .ok_or_else(|| WalletStorageError::InvalidUnicodePath)?;
    let backup_path = backup_path
        .as_ref()
        .to_str()
        .ok_or_else(|| WalletStorageError::InvalidUnicodePath)?;
    std::fs::copy(db_path, backup_path)
        .map_err(|_| WalletStorageError::FileError("Could not copy database file for backup".to_string()))?;

    // open a connection and clear the Comms Private Key
    let connection = run_migration_and_create_sqlite_connection(backup_path)?;
    let db = WalletDatabase::new(WalletSqliteDatabase::new(connection, None)?);
    db.clear_comms_secret_key().await?;

    Ok(())
}

pub fn initialize_sqlite_database_backends(
    db_path: PathBuf,
    passphrase: Option<String>,
) -> Result<
    (
        WalletSqliteDatabase,
        TransactionServiceSqliteDatabase,
        OutputManagerSqliteDatabase,
        ContactsServiceSqliteDatabase,
    ),
    WalletStorageError,
>
{
    let cipher = match passphrase {
        None => None,
        Some(passphrase_str) => {
            let passphrase_hash = Blake256::new().chain(passphrase_str.as_bytes()).result().to_vec();
            let key = GenericArray::from_slice(passphrase_hash.as_slice());
            Some(Aes256Gcm::new(key))
        },
    };

    let connection = run_migration_and_create_sqlite_connection(&db_path).map_err(|e| {
        error!(
            target: LOG_TARGET,
            "Error creating Sqlite Connection in Wallet: {:?}", e
        );
        e
    })?;

    let wallet_backend = WalletSqliteDatabase::new(connection.clone(), cipher.clone())?;
    let transaction_backend = TransactionServiceSqliteDatabase::new(connection.clone(), cipher.clone());
    let output_manager_backend = OutputManagerSqliteDatabase::new(connection.clone(), cipher);
    let contacts_backend = ContactsServiceSqliteDatabase::new(connection);

    Ok((
        wallet_backend,
        transaction_backend,
        output_manager_backend,
        contacts_backend,
    ))
}
