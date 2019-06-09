//  Copyright 2019 The Tari Project
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//  following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//  disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//  following disclaimer in the documentation and/or other materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//  products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
//  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::{borrow::Borrow, collections::HashMap, hash::Hash, sync::Arc};

use lmdb_zero as lmdb;

use derive_error::Error;

pub enum KeyValueStoreError {
       /// An error occurred with the underlying data store implementation
    InternalError(String),
    /// An error occurred during a put query
    #[error(embedded_msg, no_from, non_std)]
    InsertError(String),
    /// An error occurred during a get query
    #[error(embedded_msg, no_from, non_std)]
    GetError(String),
}

pub trait KeyValueStore<K, V> {
    fn get(&self, key: &K) -> Result<&V, KeyValueStoreError>;
    fn insert(&mut self, key: K, value: V) -> Result<V, KeyValueStoreError>;
    fn contains_key<Q: ?Sized>(&self, key: &Q) -> bool;
    fn remove<Q: ?Sized>(&mut self, key: &Q) -> Result<V, KeyValueStoreError>;
}

pub struct LmdbStore<'a> {
    env: Arc<lmdb::Environment>,
    database: lmdb::Database<'a>,
}

impl<K, V> KeyValueStore<K, V> for LmdbStore {
    fn get(&self, key: &K) -> Result<&V, KeyValueStoreError> {
        let txn = lmdb::ReadTransaction::new(self.env.clone())?;
        let accessor = txn.access();
        match accessor.get::<[u8], [u8]>(&self.database, key).to_opt() {
            Ok(None) => Ok(None),
            Ok(Some(v)) => Ok(Some(v.to_vec())),
            Err(e) => Err(KeyValueStoreError::GetError(format!("LMDB get error: {}", e.to_string()))),
        }
    }

    fn insert(&mut self, key: K, value: V) -> Result<V, KeyValueStoreError> {
        let tx = lmdb::WriteTransaction::new(self.env.clone())?;
        {
            let mut accessor = tx.access();
            accessor.put(&self.database, key, &value, lmdb::put::Flags::empty())?;
        }
        tx.commit().map_err(|e| e.into())
    }

    fn contains_key<Q: ?Sized>(&self, key: &Q) -> bool {
        unimplemented!()
    }

    fn remove<Q: ?Sized>(&mut self, key: &Q) -> Result<V, KeyValueStoreError> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn new() {
        let m = HashMap::new();
        m.contains_key()
    }
}
