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
}

use key::{
    APP_TAGLINE, CONTACTS_EMPTY, CONTACTS_REINVITE, CONTACTS_REMOVED, CONTACTS_TITLE,
    CONTACTS_UNNAMED, CONTACTS_UNVERIFIED, CONTACTS_VERIFIED, CONTENT_LOCKED, ENGINE_UNAVAILABLE,
    ERROR_BUSY, ERROR_CREATE, ERROR_EMPTY_PASS, ERROR_MISMATCH, ERROR_NAME, ERROR_STOPPED,
    ERROR_UNLOCK, INDICATOR_LOCKED, INDICATOR_OVERRIDDEN, INDICATOR_PROTECTED, MODE_BALANCED,
    MODE_LOWBW, MODE_STRICT, ONBOARDING_CREATE, ONBOARDING_MODE, ONBOARDING_MODE_NOT_SAVED,
    ONBOARDING_NAME, ONBOARDING_PASS, ONBOARDING_PASS_AGAIN, ONBOARDING_RELAY_VIEW,
    ONBOARDING_TITLE, OVERRIDE_SHOW, UNLOCK_BUTTON, UNLOCK_PASS, UNLOCK_TITLE, WORKING,
};

/// The English table.
pub static EN: &[(&str, &str)] = &[
    (APP_TAGLINE, "Private messaging without metadata"),
    (ONBOARDING_TITLE, "Create your profile"),
    (ONBOARDING_NAME, "Profile name"),
    (ONBOARDING_PASS, "Passphrase"),
    (ONBOARDING_PASS_AGAIN, "Repeat the passphrase"),
    (ONBOARDING_MODE, "Traffic mode"),
    (ONBOARDING_RELAY_VIEW, "What the relay can see"),
    (ONBOARDING_CREATE, "Create profile"),
    (MODE_STRICT, "Strict"),
    (MODE_BALANCED, "Balanced"),
    (MODE_LOWBW, "Low bandwidth"),
    (UNLOCK_TITLE, "Unlock your profile"),
    (UNLOCK_PASS, "Passphrase"),
    (UNLOCK_BUTTON, "Unlock"),
    (CONTACTS_TITLE, "Contacts"),
    (CONTACTS_EMPTY, "No contacts yet."),
    (CONTACTS_VERIFIED, "Verified"),
    (CONTACTS_UNVERIFIED, "Not verified"),
    (CONTACTS_REINVITE, "Invite again"),
    (CONTACTS_REMOVED, "Removed you"),
    (CONTACTS_UNNAMED, "(no name)"),
    (ERROR_MISMATCH, "The two passphrases are not the same."),
    (ERROR_EMPTY_PASS, "Enter a passphrase."),
    (
        ERROR_NAME,
        "Use 1 to 32 letters, digits, hyphens or underscores for the profile name.",
    ),
    (ERROR_CREATE, "The profile could not be created."),
    (ERROR_UNLOCK, "The profile could not be unlocked."),
    (ERROR_BUSY, "Still working on the last request."),
    (WORKING, "Working…"),
    (CONTENT_LOCKED, "Content hidden"),
    (INDICATOR_LOCKED, "Unprotected display — content locked"),
    (INDICATOR_PROTECTED, "Protected display"),
    (
        INDICATOR_OVERRIDDEN,
        "Unprotected display — shown by your choice for this session",
    ),
    (OVERRIDE_SHOW, "Show content anyway (this session only)"),
    (
        ERROR_STOPPED,
        "The engine has stopped. Close and start the application again.",
    ),
    (
        ENGINE_UNAVAILABLE,
        "The engine could not finish something just now and will try again.",
    ),
    (
        ONBOARDING_MODE_NOT_SAVED,
        "The profile was created, but the traffic mode was not saved. The default (Strict) is in use.",
    ),
];

/// The German table.
pub static DE: &[(&str, &str)] = &[
    (APP_TAGLINE, "Private Nachrichten ohne Metadaten"),
    (ONBOARDING_TITLE, "Profil anlegen"),
    (ONBOARDING_NAME, "Profilname"),
    (ONBOARDING_PASS, "Passphrase"),
    (ONBOARDING_PASS_AGAIN, "Passphrase wiederholen"),
    (ONBOARDING_MODE, "Verkehrsmodus"),
    (ONBOARDING_RELAY_VIEW, "Was das Relay sehen kann"),
    (ONBOARDING_CREATE, "Profil anlegen"),
    (MODE_STRICT, "Strikt"),
    (MODE_BALANCED, "Ausgewogen"),
    (MODE_LOWBW, "Geringe Bandbreite"),
    (UNLOCK_TITLE, "Profil entsperren"),
    (UNLOCK_PASS, "Passphrase"),
    (UNLOCK_BUTTON, "Entsperren"),
    (CONTACTS_TITLE, "Kontakte"),
    (CONTACTS_EMPTY, "Noch keine Kontakte."),
    (CONTACTS_VERIFIED, "Verifiziert"),
    (CONTACTS_UNVERIFIED, "Nicht verifiziert"),
    (CONTACTS_REINVITE, "Erneut einladen"),
    (CONTACTS_REMOVED, "Hat Sie entfernt"),
    (CONTACTS_UNNAMED, "(ohne Namen)"),
    (ERROR_MISMATCH, "Die beiden Passphrasen sind nicht gleich."),
    (ERROR_EMPTY_PASS, "Geben Sie eine Passphrase ein."),
    (
        ERROR_NAME,
        "Der Profilname besteht aus 1 bis 32 Buchstaben, Ziffern, Bindestrichen oder Unterstrichen.",
    ),
    (ERROR_CREATE, "Das Profil konnte nicht angelegt werden."),
    (ERROR_UNLOCK, "Das Profil konnte nicht entsperrt werden."),
    (ERROR_BUSY, "Die letzte Anfrage läuft noch."),
    (WORKING, "Bitte warten …"),
    (CONTENT_LOCKED, "Inhalt verborgen"),
    (INDICATOR_LOCKED, "Ungeschützte Anzeige — Inhalt gesperrt"),
    (INDICATOR_PROTECTED, "Geschützte Anzeige"),
    (
        INDICATOR_OVERRIDDEN,
        "Ungeschützte Anzeige — auf Ihren Wunsch für diese Sitzung angezeigt",
    ),
    (
        OVERRIDE_SHOW,
        "Inhalt trotzdem anzeigen (nur diese Sitzung)",
    ),
    (
        ERROR_STOPPED,
        "Die Verarbeitung wurde beendet. Schließen Sie die Anwendung und starten Sie sie neu.",
    ),
    (
        ENGINE_UNAVAILABLE,
        "Die Verarbeitung konnte etwas gerade nicht abschließen und versucht es erneut.",
    ),
    (
        ONBOARDING_MODE_NOT_SAVED,
        "Das Profil wurde angelegt, aber der Verkehrsmodus wurde nicht gespeichert. Es gilt der Standard (Strikt).",
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
