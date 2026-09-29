// SPDX-License-Identifier: AGPL-3.0-or-later
//! The domain-separation labels of spec Appendix A (rev 2.2), exhaustively. Labels are ASCII, used as raw bytes
//! without length prefix or terminator; the set is prefix-free (ADR-035), which the unit test below checks
//! against the text of the spec itself. Adding a label is a spec change.

/// One label of spec Appendix A.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Label {
    /// `"SecMP-HybridKEM-768/1"`
    HybridKem768,
    /// `"SecMP-HybridKEM-1024/1"`
    HybridKem1024,
    /// `"SecMP-HybridSign/1"`
    HybridSign,
    /// `"SecMP-commit/1"`
    Commit,
    /// `"SecMP-FP/1"`
    Fp,
    /// `"SecMP-SAS/1"`
    Sas,
    /// `"SecMP-INV/1 blob"`
    InvBlob,
    /// `"SecMP-INV/1 linkdata"`
    InvLinkdata,
    /// `"SecMP-HX/1 transcript"`
    HxTranscript,
    /// `"SecMP-HX/1 sk"`
    HxSk,
    /// `"SecMP-HX/1 idkey"`
    HxIdkey,
    /// `"SecMP-HX/1 bundle"`
    HxBundle,
    /// `"SecMP-HX/1 initkey"`
    HxInitkey,
    /// `"SecMP-HX/1 initcell"`
    HxInitcell,
    /// `"SecMP-HX/1 inner"`
    HxInner,
    /// `"SecMP-TR/1 init"`
    TrInit,
    /// `"SecMP-TR/1 rk"`
    TrRk,
    /// `"SecMP-TR/1 msgkeys"`
    TrMsgkeys,
    /// `"SecMP-TR/1 hdr"`
    TrHdr,
    /// `"SecMP-TR/1 body"`
    TrBody,
    /// `"SecMP-TR/1 keychange"`
    TrKeychange,
    /// `"SecMP-LINK/1 relay-fp"`
    LinkRelayFp,
    /// `"SecMP-LINK/1 relayinfo"`
    LinkRelayinfo,
    /// `"SecMP-LINK/1 h0"`
    LinkH0,
    /// `"SecMP-LINK/1 hs1"`
    LinkHs1,
    /// `"SecMP-LINK/1 hs2"`
    LinkHs2,
    /// `"SecMP-LINK/1 keys"`
    LinkKeys,
    /// `"SecMP-LINK/1 frame"`
    LinkFrame,
    /// `"SecMP-Q/1 rid"`
    QRid,
    /// `"SecMP-Q/1 sid"`
    QSid,
    /// `"SecMP-Q/1 akc"`
    QAkc,
    /// `"SecMP-Q/1 token"`
    QToken,
    /// `"SecMP-Q/1 QUEUE_NEW"`
    QQueueNew,
    /// `"SecMP-Q/1 SEND"`
    QSend,
    /// `"SecMP-Q/1 FETCH"`
    QFetch,
    /// `"SecMP-Q/1 MFETCH"`
    QMfetch,
    /// `"SecMP-Q/1 QUEUE_DEL"`
    QQueueDel,
    /// `"SecMP-Q/1 LINK_PUT"`
    QLinkPut,
    /// `"SecMP-Q/1 LINK_GET"`
    QLinkGet,
    /// `"SecMP-STORE/1 identity"`
    StoreIdentity,
    /// `"SecMP-STORE/1 prekeys"`
    StorePrekeys,
    /// `"SecMP-STORE/1 relays"`
    StoreRelays,
    /// `"SecMP-STORE/1 contacts"`
    StoreContacts,
    /// `"SecMP-STORE/1 sessions"`
    StoreSessions,
    /// `"SecMP-STORE/1 outbox"`
    StoreOutbox,
    /// `"SecMP-STORE/1 messages"`
    StoreMessages,
    /// `"SecMP-STORE/1 invitations"`
    StoreInvitations,
    /// `"SecMP-STORE/1 settings"`
    StoreSettings,
    /// `"SecMP-vectors/1"`
    Vectors,
}

impl Label {
    /// Every label, in the order of spec Appendix A.
    pub const ALL: [Self; 49] = [
        Self::HybridKem768,
        Self::HybridKem1024,
        Self::HybridSign,
        Self::Commit,
        Self::Fp,
        Self::Sas,
        Self::InvBlob,
        Self::InvLinkdata,
        Self::HxTranscript,
        Self::HxSk,
        Self::HxIdkey,
        Self::HxBundle,
        Self::HxInitkey,
        Self::HxInitcell,
        Self::HxInner,
        Self::TrInit,
        Self::TrRk,
        Self::TrMsgkeys,
        Self::TrHdr,
        Self::TrBody,
        Self::TrKeychange,
        Self::LinkRelayFp,
        Self::LinkRelayinfo,
        Self::LinkH0,
        Self::LinkHs1,
        Self::LinkHs2,
        Self::LinkKeys,
        Self::LinkFrame,
        Self::QRid,
        Self::QSid,
        Self::QAkc,
        Self::QToken,
        Self::QQueueNew,
        Self::QSend,
        Self::QFetch,
        Self::QMfetch,
        Self::QQueueDel,
        Self::QLinkPut,
        Self::QLinkGet,
        Self::StoreIdentity,
        Self::StorePrekeys,
        Self::StoreRelays,
        Self::StoreContacts,
        Self::StoreSessions,
        Self::StoreOutbox,
        Self::StoreMessages,
        Self::StoreInvitations,
        Self::StoreSettings,
        Self::Vectors,
    ];

    /// The ASCII label exactly as in spec Appendix A.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HybridKem768 => "SecMP-HybridKEM-768/1",
            Self::HybridKem1024 => "SecMP-HybridKEM-1024/1",
            Self::HybridSign => "SecMP-HybridSign/1",
            Self::Commit => "SecMP-commit/1",
            Self::Fp => "SecMP-FP/1",
            Self::Sas => "SecMP-SAS/1",
            Self::InvBlob => "SecMP-INV/1 blob",
            Self::InvLinkdata => "SecMP-INV/1 linkdata",
            Self::HxTranscript => "SecMP-HX/1 transcript",
            Self::HxSk => "SecMP-HX/1 sk",
            Self::HxIdkey => "SecMP-HX/1 idkey",
            Self::HxBundle => "SecMP-HX/1 bundle",
            Self::HxInitkey => "SecMP-HX/1 initkey",
            Self::HxInitcell => "SecMP-HX/1 initcell",
            Self::HxInner => "SecMP-HX/1 inner",
            Self::TrInit => "SecMP-TR/1 init",
            Self::TrRk => "SecMP-TR/1 rk",
            Self::TrMsgkeys => "SecMP-TR/1 msgkeys",
            Self::TrHdr => "SecMP-TR/1 hdr",
            Self::TrBody => "SecMP-TR/1 body",
            Self::TrKeychange => "SecMP-TR/1 keychange",
            Self::LinkRelayFp => "SecMP-LINK/1 relay-fp",
            Self::LinkRelayinfo => "SecMP-LINK/1 relayinfo",
            Self::LinkH0 => "SecMP-LINK/1 h0",
            Self::LinkHs1 => "SecMP-LINK/1 hs1",
            Self::LinkHs2 => "SecMP-LINK/1 hs2",
            Self::LinkKeys => "SecMP-LINK/1 keys",
            Self::LinkFrame => "SecMP-LINK/1 frame",
            Self::QRid => "SecMP-Q/1 rid",
            Self::QSid => "SecMP-Q/1 sid",
            Self::QAkc => "SecMP-Q/1 akc",
            Self::QToken => "SecMP-Q/1 token",
            Self::QQueueNew => "SecMP-Q/1 QUEUE_NEW",
            Self::QSend => "SecMP-Q/1 SEND",
            Self::QFetch => "SecMP-Q/1 FETCH",
            Self::QMfetch => "SecMP-Q/1 MFETCH",
            Self::QQueueDel => "SecMP-Q/1 QUEUE_DEL",
            Self::QLinkPut => "SecMP-Q/1 LINK_PUT",
            Self::QLinkGet => "SecMP-Q/1 LINK_GET",
            Self::StoreIdentity => "SecMP-STORE/1 identity",
            Self::StorePrekeys => "SecMP-STORE/1 prekeys",
            Self::StoreRelays => "SecMP-STORE/1 relays",
            Self::StoreContacts => "SecMP-STORE/1 contacts",
            Self::StoreSessions => "SecMP-STORE/1 sessions",
            Self::StoreOutbox => "SecMP-STORE/1 outbox",
            Self::StoreMessages => "SecMP-STORE/1 messages",
            Self::StoreInvitations => "SecMP-STORE/1 invitations",
            Self::StoreSettings => "SecMP-STORE/1 settings",
            Self::Vectors => "SecMP-vectors/1",
        }
    }

    /// The label as the raw bytes that enter hashes, KDF infos, AD and signed messages.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        self.as_str().as_bytes()
    }

    /// The label whose ASCII text is `s`, if any.
    #[must_use]
    pub fn from_ascii(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.as_str() == s)
    }

    /// Whether `HybridSign` accepts this label (spec §3.5: exactly `"SecMP-HX/1 bundle"` and
    /// `"SecMP-TR/1 keychange"`).
    #[must_use]
    pub const fn is_hybrid_sign_label(self) -> bool {
        matches!(self, Self::HxBundle | Self::TrKeychange)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// The quoted strings of the code block of spec Appendix A.
    fn appendix_a_labels() -> Vec<String> {
        let spec = include_str!("../../../docs/03-protocol-spec.md");
        let start = spec
            .find("## Appendix A")
            .map_or("", |i| spec.get(i..).unwrap_or_default());
        let block = start.split("```").nth(1).unwrap_or_default();
        block
            .split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn enum_equals_appendix_a_of_the_spec() {
        let spec: Vec<String> = appendix_a_labels();
        let ours: Vec<String> = Label::ALL.iter().map(|l| l.as_str().to_owned()).collect();
        assert_eq!(spec.len(), 49, "Appendix A should list 49 labels: {spec:?}");
        assert_eq!(ours, spec, "Label::ALL must list Appendix A in order");
    }

    #[test]
    fn label_set_is_prefix_free() {
        let spec = appendix_a_labels();
        let unique: BTreeSet<&str> = spec.iter().map(String::as_str).collect();
        assert_eq!(unique.len(), spec.len(), "duplicate label");
        for a in &spec {
            for b in &spec {
                if a != b {
                    assert!(!b.starts_with(a.as_str()), "{a:?} is a prefix of {b:?}");
                }
            }
        }
    }

    #[test]
    fn labels_are_ascii_and_round_trip() {
        for l in Label::ALL {
            assert!(l.as_str().is_ascii());
            assert_eq!(l.as_bytes(), l.as_str().as_bytes());
            assert_eq!(Label::from_ascii(l.as_str()), Some(l));
        }
        assert_eq!(
            Label::from_ascii("SecMP-HX/1 init"),
            None,
            "renamed in rev 2.2"
        );
        assert_eq!(Label::from_ascii("SecMP-INV/1"), None, "renamed in rev 2.2");
        assert_eq!(
            Label::from_ascii("SecMP-Q/1 FETCH_MULTI"),
            None,
            "MFETCH since rev 2.2"
        );
    }

    #[test]
    fn exactly_two_hybrid_sign_labels() {
        let hs: Vec<Label> = Label::ALL
            .into_iter()
            .filter(|l| l.is_hybrid_sign_label())
            .collect();
        assert_eq!(hs, vec![Label::HxBundle, Label::TrKeychange]);
    }
}
