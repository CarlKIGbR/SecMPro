// SPDX-License-Identifier: AGPL-3.0-or-later
//! The user-visible strings: two static tables, `en` and `de`, with the same keys. Every string a screen shows comes from
//! here; no screen text is written into a `.slint` component or into a view model.

/// A language of the interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    /// English (the default).
    En,
    /// German.
    De,
}

impl Lang {
    /// The language the environment asks for (`LC_ALL`, `LC_MESSAGES`, `LANG`; a value starting with `de` is German), else
    /// English.
    #[must_use]
    pub fn from_env() -> Self {
        for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Ok(value) = std::env::var(var)
                && !value.is_empty()
            {
                return if value.starts_with("de") {
                    Self::De
                } else {
                    Self::En
                };
            }
        }
        Self::En
    }
}

/// The keys of the tables.
pub mod key {
    /// The line under the product name.
    pub const APP_TAGLINE: &str = "app.tagline";
    /// The title of the onboarding screen.
    pub const ONBOARDING_TITLE: &str = "onboarding.title";
    /// The label of the profile name field.
    pub const ONBOARDING_NAME: &str = "onboarding.name";
    /// The label of the passphrase field.
    pub const ONBOARDING_PASS: &str = "onboarding.pass";
    /// The label of the passphrase confirmation field.
    pub const ONBOARDING_PASS_AGAIN: &str = "onboarding.pass_again";
    /// The label of the mode choice.
    pub const ONBOARDING_MODE: &str = "onboarding.mode";
    /// The heading of the list of what the relay can see.
    pub const ONBOARDING_RELAY_VIEW: &str = "onboarding.relay_view";
    /// The button that creates the profile.
    pub const ONBOARDING_CREATE: &str = "onboarding.create";
    /// The mode Strict.
    pub const MODE_STRICT: &str = "mode.strict";
    /// The mode Balanced.
    pub const MODE_BALANCED: &str = "mode.balanced";
    /// The mode Low-bandwidth.
    pub const MODE_LOWBW: &str = "mode.lowbw";
    /// The title of the unlock screen.
    pub const UNLOCK_TITLE: &str = "unlock.title";
    /// The label of the unlock passphrase field.
    pub const UNLOCK_PASS: &str = "unlock.pass";
    /// The button that unlocks the profile.
    pub const UNLOCK_BUTTON: &str = "unlock.button";
    /// The title of the contacts screen.
    pub const CONTACTS_TITLE: &str = "contacts.title";
    /// The text of an empty contact list.
    pub const CONTACTS_EMPTY: &str = "contacts.empty";
    /// A verified contact.
    pub const CONTACTS_VERIFIED: &str = "contacts.verified";
    /// A contact that is not verified.
    pub const CONTACTS_UNVERIFIED: &str = "contacts.unverified";
    /// A contact that has to be invited again.
    pub const CONTACTS_REINVITE: &str = "contacts.reinvite";
    /// A contact that removed this client.
    pub const CONTACTS_REMOVED: &str = "contacts.removed";
    /// A contact without a name.
    pub const CONTACTS_UNNAMED: &str = "contacts.unnamed";
    /// The two passphrases differ.
    pub const ERROR_MISMATCH: &str = "error.mismatch";
    /// The passphrase is empty.
    pub const ERROR_EMPTY_PASS: &str = "error.empty_pass";
    /// The profile name is not usable.
    pub const ERROR_NAME: &str = "error.name";
    /// The profile could not be created.
    pub const ERROR_CREATE: &str = "error.create";
    /// The profile did not unlock (a wrong passphrase and a damaged store look the same).
    pub const ERROR_UNLOCK: &str = "error.unlock";
    /// The engine is busy with earlier requests.
    pub const ERROR_BUSY: &str = "error.busy";
    /// Something is under way.
    pub const WORKING: &str = "working";
    /// A row of the contact list while the display is not protected.
    pub const CONTENT_LOCKED: &str = "content.locked";
    /// The indicator while the display is not verified as protected.
    pub const INDICATOR_LOCKED: &str = "indicator.locked";
    /// The indicator while the display is verified as protected.
    pub const INDICATOR_PROTECTED: &str = "indicator.protected";
    /// The indicator while the user chose to show content on an unprotected display.
    pub const INDICATOR_OVERRIDDEN: &str = "indicator.overridden";
    /// The button that shows content on an unprotected display for this session.
    pub const OVERRIDE_SHOW: &str = "override.show";
    /// The engine ended or its thread is gone.
    pub const ERROR_STOPPED: &str = "error.stopped";
    /// The engine could not work on something just now; it tries again.
    pub const ENGINE_UNAVAILABLE: &str = "engine.unavailable";
    /// The profile was created but the traffic mode was not stored.
    pub const ONBOARDING_MODE_NOT_SAVED: &str = "onboarding.mode_not_saved";
    /// The button that opens the invitation screen.
    pub const CONTACTS_INVITE: &str = "contacts.invite";
    /// The button that leaves a screen.
    pub const NAV_BACK: &str = "nav.back";
    /// The title of the invitation screen.
    pub const INVITE_TITLE: &str = "invite.title";
    /// The button that issues an invitation.
    pub const INVITE_CREATE: &str = "invite.create";
    /// The label of the invitation text.
    pub const INVITE_URI_LABEL: &str = "invite.uri_label";
    /// The button that copies the invitation.
    pub const INVITE_COPY: &str = "invite.copy";
    /// The label of the field for an invitation to accept.
    pub const INVITE_ACCEPT_LABEL: &str = "invite.accept_label";
    /// The button that accepts an invitation.
    pub const INVITE_ACCEPT: &str = "invite.accept";
    /// The invitation was taken; the contact follows.
    pub const INVITE_ACCEPTING: &str = "invite.accepting";
    /// An invitation made a contact.
    pub const INVITE_CONTACT_ADDED: &str = "invite.contact_added";
    /// An invitation was retired.
    pub const INVITE_RETIRED: &str = "invite.retired";
    /// An invitation was consumed by someone else.
    pub const INVITE_USED_ELSEWHERE: &str = "invite.used_elsewhere";
    /// The pool has no spare queue.
    pub const ERROR_INVITE_POOL_EMPTY: &str = "error.invite_pool_empty";
    /// Issuing an invitation failed.
    pub const ERROR_INVITE_CREATE: &str = "error.invite_create";
    /// Every refused invitation.
    pub const ERROR_INVITE_ACCEPT: &str = "error.invite_accept";
}

/// The English table.
pub static EN: &[(&str, &str)] = &[
    (key::APP_TAGLINE, "Private messaging without metadata"),
    (key::ONBOARDING_TITLE, "Create your profile"),
    (key::ONBOARDING_NAME, "Profile name"),
    (key::ONBOARDING_PASS, "Passphrase"),
    (key::ONBOARDING_PASS_AGAIN, "Repeat the passphrase"),
    (key::ONBOARDING_MODE, "Traffic mode"),
    (key::ONBOARDING_RELAY_VIEW, "What the relay can see"),
    (key::ONBOARDING_CREATE, "Create profile"),
    (key::MODE_STRICT, "Strict"),
    (key::MODE_BALANCED, "Balanced"),
    (key::MODE_LOWBW, "Low bandwidth"),
    (key::UNLOCK_TITLE, "Unlock your profile"),
    (key::UNLOCK_PASS, "Passphrase"),
    (key::UNLOCK_BUTTON, "Unlock"),
    (key::CONTACTS_TITLE, "Contacts"),
    (key::CONTACTS_EMPTY, "No contacts yet."),
    (key::CONTACTS_VERIFIED, "Verified"),
    (key::CONTACTS_UNVERIFIED, "Not verified"),
    (key::CONTACTS_REINVITE, "Invite again"),
    (key::CONTACTS_REMOVED, "Removed you"),
    (key::CONTACTS_UNNAMED, "(no name)"),
    (key::ERROR_MISMATCH, "The two passphrases are not the same."),
    (key::ERROR_EMPTY_PASS, "Enter a passphrase."),
    (
        key::ERROR_NAME,
        "Use 1 to 32 letters, digits, hyphens or underscores for the profile name.",
    ),
    (key::ERROR_CREATE, "The profile could not be created."),
    (key::ERROR_UNLOCK, "The profile could not be unlocked."),
    (key::ERROR_BUSY, "Still working on the last request."),
    (key::WORKING, "Working…"),
    (key::CONTENT_LOCKED, "Content hidden"),
    (
        key::INDICATOR_LOCKED,
        "Unprotected display — content locked",
    ),
    (key::INDICATOR_PROTECTED, "Protected display"),
    (
        key::INDICATOR_OVERRIDDEN,
        "Unprotected display — shown by your choice for this session",
    ),
    (
        key::OVERRIDE_SHOW,
        "Show content anyway (this session only)",
    ),
    (
        key::ERROR_STOPPED,
        "The engine has stopped. Close and start the application again.",
    ),
    (
        key::ENGINE_UNAVAILABLE,
        "The engine could not finish something just now and will try again.",
    ),
    (
        key::ONBOARDING_MODE_NOT_SAVED,
        "The profile was created, but the traffic mode was not saved. The default (Strict) is in use.",
    ),
    (key::CONTACTS_INVITE, "Invitations"),
    (key::NAV_BACK, "Back"),
    (key::INVITE_TITLE, "Invitations"),
    (key::INVITE_CREATE, "Create an invitation"),
    (
        key::INVITE_URI_LABEL,
        "Your invitation — whoever has it can use it once",
    ),
    (key::INVITE_COPY, "Copy"),
    (key::INVITE_ACCEPT_LABEL, "Paste an invitation you received"),
    (key::INVITE_ACCEPT, "Accept invitation"),
    (key::INVITE_ACCEPTING, "Accepting the invitation …"),
    (
        key::INVITE_CONTACT_ADDED,
        "A contact was added. Verify its safety number.",
    ),
    (key::INVITE_RETIRED, "The invitation is no longer valid."),
    (
        key::INVITE_USED_ELSEWHERE,
        "The invitation was used by someone else.",
    ),
    (
        key::ERROR_INVITE_POOL_EMPTY,
        "No invitation can be made yet. Try again in a few minutes.",
    ),
    (
        key::ERROR_INVITE_CREATE,
        "The invitation could not be created.",
    ),
    (
        key::ERROR_INVITE_ACCEPT,
        "This invitation cannot be accepted.",
    ),
];

/// The German table.
pub static DE: &[(&str, &str)] = &[
    (key::APP_TAGLINE, "Private Nachrichten ohne Metadaten"),
    (key::ONBOARDING_TITLE, "Profil anlegen"),
    (key::ONBOARDING_NAME, "Profilname"),
    (key::ONBOARDING_PASS, "Passphrase"),
    (key::ONBOARDING_PASS_AGAIN, "Passphrase wiederholen"),
    (key::ONBOARDING_MODE, "Verkehrsmodus"),
    (key::ONBOARDING_RELAY_VIEW, "Was das Relay sehen kann"),
    (key::ONBOARDING_CREATE, "Profil anlegen"),
    (key::MODE_STRICT, "Strikt"),
    (key::MODE_BALANCED, "Ausgewogen"),
    (key::MODE_LOWBW, "Geringe Bandbreite"),
    (key::UNLOCK_TITLE, "Profil entsperren"),
    (key::UNLOCK_PASS, "Passphrase"),
    (key::UNLOCK_BUTTON, "Entsperren"),
    (key::CONTACTS_TITLE, "Kontakte"),
    (key::CONTACTS_EMPTY, "Noch keine Kontakte."),
    (key::CONTACTS_VERIFIED, "Verifiziert"),
    (key::CONTACTS_UNVERIFIED, "Nicht verifiziert"),
    (key::CONTACTS_REINVITE, "Erneut einladen"),
    (key::CONTACTS_REMOVED, "Hat Sie entfernt"),
    (key::CONTACTS_UNNAMED, "(ohne Namen)"),
    (
        key::ERROR_MISMATCH,
        "Die beiden Passphrasen sind nicht gleich.",
    ),
    (key::ERROR_EMPTY_PASS, "Geben Sie eine Passphrase ein."),
    (
        key::ERROR_NAME,
        "Der Profilname besteht aus 1 bis 32 Buchstaben, Ziffern, Bindestrichen oder Unterstrichen.",
    ),
    (
        key::ERROR_CREATE,
        "Das Profil konnte nicht angelegt werden.",
    ),
    (
        key::ERROR_UNLOCK,
        "Das Profil konnte nicht entsperrt werden.",
    ),
    (key::ERROR_BUSY, "Die letzte Anfrage läuft noch."),
    (key::WORKING, "Bitte warten …"),
    (key::CONTENT_LOCKED, "Inhalt verborgen"),
    (
        key::INDICATOR_LOCKED,
        "Ungeschützte Anzeige — Inhalt gesperrt",
    ),
    (key::INDICATOR_PROTECTED, "Geschützte Anzeige"),
    (
        key::INDICATOR_OVERRIDDEN,
        "Ungeschützte Anzeige — auf Ihren Wunsch für diese Sitzung angezeigt",
    ),
    (
        key::OVERRIDE_SHOW,
        "Inhalt trotzdem anzeigen (nur diese Sitzung)",
    ),
    (
        key::ERROR_STOPPED,
        "Die Verarbeitung wurde beendet. Schließen Sie die Anwendung und starten Sie sie neu.",
    ),
    (
        key::ENGINE_UNAVAILABLE,
        "Die Verarbeitung konnte etwas gerade nicht abschließen und versucht es erneut.",
    ),
    (
        key::ONBOARDING_MODE_NOT_SAVED,
        "Das Profil wurde angelegt, aber der Verkehrsmodus wurde nicht gespeichert. Es gilt der Standard (Strikt).",
    ),
    (key::CONTACTS_INVITE, "Einladungen"),
    (key::NAV_BACK, "Zurück"),
    (key::INVITE_TITLE, "Einladungen"),
    (key::INVITE_CREATE, "Einladung erstellen"),
    (
        key::INVITE_URI_LABEL,
        "Ihre Einladung — wer sie hat, kann sie einmal verwenden",
    ),
    (key::INVITE_COPY, "Kopieren"),
    (
        key::INVITE_ACCEPT_LABEL,
        "Eine erhaltene Einladung einfügen",
    ),
    (key::INVITE_ACCEPT, "Einladung annehmen"),
    (key::INVITE_ACCEPTING, "Die Einladung wird angenommen …"),
    (
        key::INVITE_CONTACT_ADDED,
        "Ein Kontakt wurde hinzugefügt. Prüfen Sie seine Sicherheitsnummer.",
    ),
    (key::INVITE_RETIRED, "Die Einladung ist nicht mehr gültig."),
    (
        key::INVITE_USED_ELSEWHERE,
        "Die Einladung wurde von jemand anderem verwendet.",
    ),
    (
        key::ERROR_INVITE_POOL_EMPTY,
        "Noch keine Einladung möglich. Versuchen Sie es in einigen Minuten erneut.",
    ),
    (
        key::ERROR_INVITE_CREATE,
        "Die Einladung konnte nicht erstellt werden.",
    ),
    (
        key::ERROR_INVITE_ACCEPT,
        "Diese Einladung kann nicht angenommen werden.",
    ),
];

/// The table of `lang`.
#[must_use]
pub const fn table(lang: Lang) -> &'static [(&'static str, &'static str)] {
    match lang {
        Lang::En => EN,
        Lang::De => DE,
    }
}

/// The string of `key` in `lang`; a key a table lacks (the test `locale_tables_en_de_have_identical_key_sets` rules that out
/// for the keys of [`key`]) is shown as the key itself.
#[must_use]
pub fn text(lang: Lang, key: &'static str) -> &'static str {
    table(lang)
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(key, |(_, v)| *v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T3: the two tables hold the same keys, each once, and no value is empty.
    #[test]
    fn locale_tables_en_de_have_identical_key_sets() {
        let keys = |t: &[(&'static str, &'static str)]| {
            let mut k: Vec<&str> = t.iter().map(|(k, _)| *k).collect();
            k.sort_unstable();
            k
        };
        let (en, de) = (keys(EN), keys(DE));
        assert_eq!(en, de);
        let mut unique = en.clone();
        unique.dedup();
        assert_eq!(unique, en, "a key appears twice");
        for (k, v) in EN.iter().chain(DE.iter()) {
            assert!(!v.trim().is_empty(), "{k} is empty");
        }
    }
}
