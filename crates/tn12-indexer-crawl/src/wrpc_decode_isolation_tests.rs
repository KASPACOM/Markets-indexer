use super::*;
use tn12_indexer_core::{KnownTemplate, blake2b_256};
use tn12_indexer_decoder::{TemplateDecoder, registry::DecoderRegistry};
use tn12_indexer_db::PgPersister;
use crate::live_recovery::{LiveWriteJournal, PgLiveWriteJournal};

struct BrokenDecoder;
impl TemplateDecoder for BrokenDecoder {
    fn template(&self) -> KnownTemplate { KnownTemplate::TimeLockVault }
    fn script_hash(&self) -> [u8;32] { blake2b_256(&[0x51]) }
    fn matches_reveal_script(&self, reveal: &[u8]) -> bool { reveal == [0x51] }
    fn decode_constructor(&self, _: &[u8]) -> Result<serde_json::Value> { anyhow::bail!("unrecognized fixture state") }
    fn decode_state(&self, bytes: &[u8]) -> Result<serde_json::Value> { self.decode_constructor(bytes) }
    fn decode_action(&self, _: &[u8]) -> Option<String> { Some("spend".into()) }
}
fn body(id:u8,parent:Option<u8>) -> RestTransaction {
    let spk=format!("aa20{}87",hex::encode(blake2b_256(&[0x51])));
    RestTransaction {
        transaction_id:hex::encode([id;32]),is_accepted:true,
        accepting_block_hash:Some(hex::encode([id;32])),accepting_block_blue_score:Some(u64::from(id)),accepting_block_time:Some(1000),
        inputs:parent.into_iter().map(|p|RestTxInput { previous_outpoint_hash:hex::encode([p;32]),previous_outpoint_index:"0".into(),signature_script:"0151".into(),previous_outpoint_script:Some(spk.clone()),..Default::default() }).collect(),
        outputs:vec![RestTxOutput { transaction_id:hex::encode([id;32]),index:0,amount:1,script_public_key:spk,..Default::default() }],..Default::default()
    }
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn shared_decode_failure_releases_journal_and_accepts_next_event(pool:sqlx::PgPool) {
    let mut registry=DecoderRegistry::new();registry.register(Arc::new(BrokenDecoder));
    let writer=Arc::new(PgPersister::with_decoders(pool.clone(),registry).with_generic_bulk_persist(true));
    writer.persist_tx(&body(1,None)).await.unwrap();
    let journal=Arc::new(PgLiveWriteJournal::new(pool.clone(),"testnet-10","decode-isolation"));
    let watcher=WrpcVirtualChainWatcher::new(writer.clone(),
        Box::new(crate::PgCursorStore::with_key(pool.clone(),"decode-reorg")),
        Box::new(crate::PgCursorStore::with_key(pool.clone(),"decode-live")),
        Box::new(crate::PgCursorStore::with_key(pool.clone(),"decode-heartbeat")),
        WrpcWatcherConfig::with_default_cache("ws://unused".into(),"testnet-10".into())
    ).with_write_journal(journal.clone());
    let mut stats=WrpcWatcherStats::default();
    watcher.persist_candidates(vec![body(2,Some(1))],&mut stats).await.unwrap();
    assert!(journal.load().await.unwrap().is_none());
    assert_eq!(tn12_indexer_db::deferred_decode::summary(&pool).await.unwrap().pending,1);
    watcher.persist_candidates(vec![body(3,None)],&mut stats).await.unwrap();
    assert!(journal.load().await.unwrap().is_none());
    assert!(writer.has_utxo(&body(3,None).transaction_id,0).await.unwrap());
}
