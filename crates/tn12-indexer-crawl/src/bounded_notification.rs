//! Validate the pinned wRPC wire layout without allocation before SDK decoding.
//! workflow-serializer 0.18 allocates vectors directly from declared lengths.
//! Unknown versions fail closed and leave the durable entry available for repair.
use anyhow::{ensure, Context, Result};
use borsh::BorshDeserialize;
use kaspa_rpc_core::api::ops::RpcApiOps;
use kaspa_wrpc_client::prelude::Notification;
use workflow_rpc::messages::borsh::{BorshServerMessage, ServerMessageKind};
use workflow_serializer::prelude::Serializable;

const DECODE_BUDGET: usize = 32 * 1024 * 1024;
const MAX_FRAME: usize = crate::durable_inbox::NOTIFICATION_FRAME_BYTES;

/// Preflight request responses before workflow-serializer can allocate vectors.
/// Only the three read operations used by the shadow follower are admitted.
pub(crate) fn validate_shadow_response(op: RpcApiOps, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX_FRAME, "RPC response exceeds frame limit");
    let mut budget = DECODE_BUDGET;
    let mut w = Wire { bytes, budget: &mut budget };
    ensure!(w.u8()? == 1, "node returned RPC error"); // Borsh Result::Ok
    w.payload(|w| match op {
        RpcApiOps::GetVirtualChainFromBlock => virtual_chain(w),
        RpcApiOps::GetBlock => { w.version16(1)?; w.payload(block) }
        RpcApiOps::GetServerInfo => {
            w.version16(1)?;
            w.skip(4)?;
            w.blob()?; // server version
            ensure!(w.u8()? <= 3, "invalid network type");
            match w.u8()? { 0 => {}, 1 => w.skip(4)?, _ => anyhow::bail!("invalid network suffix") }
            ensure!(w.u8()? <= 1 && w.u8()? <= 1, "invalid server flags");
            w.skip(8)
        }
        _ => anyhow::bail!("unsupported shadow RPC operation"),
    })?;
    w.finish()
}

pub fn decode_notification(frame: &[u8]) -> Result<Notification> {
    ensure!(frame.len() <= MAX_FRAME, "notification exceeds frame limit");
    let message: BorshServerMessage<RpcApiOps, u64> = frame.try_into()?;
    ensure!(
        matches!(message.header.kind, ServerMessageKind::Notification)
            && message.header.id.is_none(),
        "expected notification frame"
    );
    let mut budget = DECODE_BUDGET;
    let mut wire = Wire {
        bytes: message.payload,
        budget: &mut budget,
    };
    let mut tag = None;
    wire.payload(|wire| {
        wire.version16(1)?;
        let kind = wire.u16()?;
        tag = Some(kind);
        wire.payload(|wire| match kind {
            0 => {
                wire.version16(1)?;
                wire.payload(block)
            }
            1 => virtual_chain(wire),
            _ => anyhow::bail!("unsupported notification kind"),
        })
    })?;
    wire.finish()?;
    ensure!(
        matches!(
            (message.header.op, tag),
            (Some(RpcApiOps::BlockAddedNotification), Some(0))
                | (Some(RpcApiOps::VirtualChainChangedNotification), Some(1))
        ),
        "notification operation/body mismatch"
    );
    Ok(
        Serializable::<Notification>::try_from_slice(message.payload)
            .context("decode validated notification")?
            .0,
    )
}

struct Wire<'a, 'b> {
    bytes: &'a [u8],
    budget: &'b mut usize,
}
impl Wire<'_, '_> {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        *self.budget = self
            .budget
            .checked_sub(bytes)
            .context("notification decode budget exceeded")?;
        Ok(())
    }
    fn skip(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self.bytes.get(bytes..).context("truncated notification")?;
        Ok(())
    }
    fn u8(&mut self) -> Result<u8> {
        let n = *self.bytes.first().context("truncated byte")?;
        self.skip(1)?;
        Ok(n)
    }
    fn u16(&mut self) -> Result<u16> {
        let n = u16::from_le_bytes(self.bytes.get(..2).context("truncated u16")?.try_into()?);
        self.skip(2)?;
        Ok(n)
    }
    fn length(&mut self) -> Result<usize> {
        let n = u32::from_le_bytes(
            self.bytes
                .get(..4)
                .context("truncated length")?
                .try_into()?,
        );
        self.skip(4)?;
        Ok(n as usize)
    }
    fn version16(&mut self, expected: u16) -> Result<()> {
        ensure!(self.u16()? == expected, "unsupported struct version");
        Ok(())
    }
    fn version8(&mut self, max: u8) -> Result<u8> {
        let v = self.u8()?;
        ensure!((1..=max).contains(&v), "unsupported struct version");
        Ok(v)
    }
    fn finish(&self) -> Result<()> {
        ensure!(self.bytes.is_empty(), "trailing notification bytes");
        Ok(())
    }
    fn payload(&mut self, f: impl FnOnce(&mut Wire<'_, '_>) -> Result<()>) -> Result<()> {
        let len = self.length()?;
        let bytes = self.bytes.get(..len).context("truncated payload")?;
        // SDK payload wrappers copy their entire encoded body before decoding.
        self.charge(len.checked_mul(2).context("payload budget overflow")?)?;
        let mut child = Wire {
            bytes,
            budget: self.budget,
        };
        f(&mut child)?;
        child.finish()?;
        self.skip(len)
    }
    fn blob(&mut self) -> Result<()> {
        let len = self.length()?;
        // Borsh growth and conversion into ScriptPublicKey can coexist.
        self.charge(len.checked_mul(4).context("blob budget overflow")?)?;
        self.skip(len)
    }
    fn hashes(&mut self) -> Result<()> {
        let len = self
            .length()?
            .checked_mul(32)
            .context("hash vector overflow")?;
        // Borsh Vec grows geometrically; charge twice the final storage.
        self.charge(len.checked_mul(2).context("hash budget overflow")?)?;
        self.skip(len)
    }
    fn option(&mut self, f: impl FnOnce(&mut Wire<'_, '_>) -> Result<()>) -> Result<()> {
        self.payload(|wire| match wire.u8()? {
            0 => Ok(()),
            1 => wire.payload(f),
            _ => anyhow::bail!("invalid option"),
        })
    }
    fn items(&mut self, f: fn(&mut Wire<'_, '_>) -> Result<()>) -> Result<()> {
        self.payload(|wire| {
            let count = wire.length()?;
            ensure!(count <= wire.bytes.len() / 4, "impossible item count");
            // Every current RPC transaction/input/output object is below 1 KiB.
            wire.charge(count.checked_mul(1024).context("item budget overflow")?)?;
            for _ in 0..count {
                wire.payload(f)?;
            }
            Ok(())
        })
    }
}
fn virtual_chain(w: &mut Wire<'_, '_>) -> Result<()> {
    w.version16(1)?;
    w.hashes()?;
    w.hashes()?;
    let count = w.length()?;
    ensure!(
        count <= w.bytes.len() / 36,
        "impossible acceptance group count"
    );
    w.charge(
        count
            .checked_mul(128)
            .context("acceptance budget overflow")?,
    )?;
    for _ in 0..count {
        w.skip(32)?;
        w.hashes()?;
    }
    Ok(())
}
fn block(w: &mut Wire<'_, '_>) -> Result<()> {
    w.version16(1)?;
    w.payload(|w| {
        w.version16(1)?;
        w.skip(34)?;
        let levels = w.length()?;
        ensure!(levels <= w.bytes.len() / 4, "impossible parent count");
        w.charge(levels.checked_mul(48).context("parent budget overflow")?)?;
        for _ in 0..levels {
            w.hashes()?;
        }
        w.skip(32 * 3 + 8 + 4 + 8 + 8 + 24 + 8 + 32)
    })?;
    w.items(transaction)?;
    w.option(|w| {
        w.version8(1)?;
        w.skip(32 + 8 + 32)?;
        w.hashes()?;
        w.skip(1 + 8)?;
        w.hashes()?;
        w.hashes()?;
        w.hashes()?;
        w.skip(1)
    })
}
fn transaction(w: &mut Wire<'_, '_>) -> Result<()> {
    w.version16(1)?;
    w.skip(2)?;
    w.items(input)?;
    w.items(output)?;
    w.skip(8 + 20 + 8)?;
    w.blob()?;
    w.skip(8)?;
    w.option(|w| {
        w.version8(1)?;
        w.skip(32 + 32 + 8 + 32 + 8)
    })
}
fn input(w: &mut Wire<'_, '_>) -> Result<()> {
    let version = w.version8(2)?;
    w.payload(|w| {
        w.version8(1)?;
        w.skip(32 + 4)
    })?;
    w.blob()?;
    w.skip(8 + 1)?;
    w.option(|w| {
        w.version8(1)?;
        Ok(())
    })?;
    if version == 2 {
        w.skip(2)?;
    }
    Ok(())
}
fn output(w: &mut Wire<'_, '_>) -> Result<()> {
    let version = w.version8(2)?;
    w.skip(8 + 2)?;
    w.blob()?;
    w.option(|w| {
        w.version8(1)?;
        w.skip(1 + 1)?;
        let address_version = w.u8()?;
        let expected = match address_version {
            0 | 8 => 32,
            1 => 33,
            _ => anyhow::bail!("unsupported address version"),
        };
        let len = w.length()?;
        ensure!(len == expected, "invalid address payload length");
        w.charge(4 * len)?;
        w.skip(len)
    })?;
    if version == 2 {
        w.option(|w| {
            w.version8(1)?;
            w.skip(2 + 32)
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_wrpc_client::prelude::VirtualChainChangedNotification;
    use workflow_rpc::messages::borsh::BorshServerMessageHeader;
    fn frame(op: RpcApiOps, payload: Vec<u8>) -> Vec<u8> {
        let header = BorshServerMessageHeader {
            id: None::<u64>,
            kind: ServerMessageKind::Notification,
            op: Some(op),
        };
        let mut bytes = borsh::to_vec(&header).unwrap();
        bytes.extend(payload);
        bytes
    }
    #[test]
    fn validates_notification_kind_and_every_payload_boundary() {
        let n = Notification::VirtualChainChanged(VirtualChainChangedNotification {
            removed_chain_block_hashes: vec![Default::default()].into(),
            added_chain_block_hashes: vec![Default::default()].into(),
            accepted_transaction_ids: vec![].into(),
        });
        let payload = borsh::to_vec(&Serializable(n)).unwrap();
        let bytes = frame(RpcApiOps::VirtualChainChangedNotification, payload.clone());
        assert!(matches!(
            decode_notification(&bytes).unwrap(),
            Notification::VirtualChainChanged(_)
        ));
        for end in 0..bytes.len() {
            assert!(decode_notification(&bytes[..end]).is_err());
        }
        assert!(decode_notification(&frame(RpcApiOps::BlockAddedNotification, payload)).is_err());
        let mut extra = bytes;
        extra.push(0);
        assert!(decode_notification(&extra).is_err());
    }
    #[test]
    fn rejects_declared_allocations_before_decoding() {
        let mut budget = DECODE_BUDGET;
        let mut w = Wire {
            bytes: &[4, 0, 0, 0, 255, 255, 255, 255],
            budget: &mut budget,
        };
        assert!(w.items(transaction).is_err());
        let mut budget = 128;
        let mut w = Wire {
            bytes: &[255, 255, 255, 255],
            budget: &mut budget,
        };
        assert!(w.hashes().is_err());
    }
    #[test]
    fn conservative_object_budget_covers_pinned_sdk_types() {
        use kaspa_wrpc_client::prelude::{
            RpcAcceptedTransactionIds, RpcTransaction, RpcTransactionInput, RpcTransactionOutput,
        };
        assert!(std::mem::size_of::<RpcTransaction>() <= 1024);
        assert!(std::mem::size_of::<RpcTransactionInput>() <= 1024);
        assert!(std::mem::size_of::<RpcTransactionOutput>() <= 1024);
        assert!(2 * std::mem::size_of::<RpcAcceptedTransactionIds>() <= 128);
    }
}
