#![crate_name = "mutiny_core"]
// wasm is considered "extra_unused_type_parameters"
#![allow(incomplete_features, clippy::extra_unused_type_parameters)]
#![feature(io_error_other)]
#![feature(async_fn_in_trait)]
// background file is mostly an LDK copy paste
mod background;

mod bdkstorage;
mod chain;
mod encrypt;
pub mod error;
pub mod esplora;
mod event;
mod fees;
mod gossip;
mod indexed_db;
mod keymanager;
mod ldkstorage;
mod localstorage;
mod logging;
mod lspclient;
mod node;
pub mod nodemanager;
mod peermanager;
mod proxy;
mod socket;
mod utils;
mod wallet;

#[cfg(test)]
mod test {
    use gloo_storage::{LocalStorage, Storage};

    macro_rules! log {
        ( $( $t:tt )* ) => {
            web_sys::console::log_1(&format!( $( $t )* ).into());
        }
    }
    pub(crate) use log;
    use rexie::Rexie;

    use crate::gossip::GOSSIP_DATABASE_NAME;
    use crate::indexed_db::MutinyStorage;

    pub(crate) fn cleanup_test() {
        LocalStorage::clear();
    }

    pub(crate) async fn cleanup_gossip_test() {
        cleanup_test();
        Rexie::delete(GOSSIP_DATABASE_NAME).await.unwrap();
    }

    pub(crate) async fn cleanup_wallet_test() {
        cleanup_test();
        MutinyStorage::clear().await.unwrap();
    }
}
