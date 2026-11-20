// SPDX-License-Identifier: AGPL-3.0-or-later
//! The window and its screens (Slint). The component holds no user-visible text of its own: every string is a property the
//! application sets from the [`locale`](crate::locale) tables, the title is the product name on every screen, and the
//! passphrase fields are cleared by the application after use.

slint::slint! {
    import { Button, LineEdit, ComboBox, ListView, ScrollView } from "std-widgets.slint";

    export struct ContactRowData {
        name: string,
        key: string,
        status: string,
        verified: bool,
    }

    export component MainWindow inherits Window {
        // the product name; the title never carries content (docs/04)
        title: "SecMPro";
        preferred-width: 600px;
        preferred-height: 600px;
        min-width: 420px;
        min-height: 440px;

        // 0 onboarding, 1 unlock, 2 contacts
        in property <int> screen: 0;
        in property <string> tagline;
        // the protection indicator is always shown; the override button only while the display is locked
        in property <string> indicator-text;
        in property <bool> indicator-locked: true;
        in property <bool> show-override: false;
        in property <string> override-text;
        callback override-requested();
        in property <bool> busy: false;
        in property <string> busy-text;
        in property <string> error-text;

        // onboarding
        in property <string> onboarding-title;
        in property <string> name-label;
        in property <string> pass-label;
        in property <string> pass-again-label;
        in property <string> mode-label;
        in property <string> relay-view-title;
        in property <string> create-text;
        in property <[string]> mode-names;
        in property <[string]> relay-lines;
        in-out property <string> profile-name;
        in-out property <string> pass1;
        in-out property <string> pass2;
        in-out property <int> mode-index: 0;
        callback create(string, string, string, int);
        callback mode-picked(int);

        // unlock
        in property <string> unlock-title;
        in property <string> unlock-pass-label;
        in property <string> unlock-text;
        in property <string> unlock-profile;
        in-out property <string> unlock-pass;
        callback unlock(string);

        // contacts
        in property <string> contacts-title;
        in property <string> contacts-empty;
        in property <[ContactRowData]> contacts;

        VerticalLayout {
            padding: 16px;
            spacing: 10px;
            alignment: start;

            Text {
                text: "SecMPro";
                font-size: 24px;
                font-weight: 700;
                accessible-role: text;
            }
            Text {
                text: root.tagline;
                accessible-role: text;
            }
            Text {
                text: root.indicator-text;
                color: root.indicator-locked ? #b3261e : #1b6e2d;
                font-weight: 700;
                wrap: word-wrap;
                accessible-role: text;
            }
            if root.show-override : Button {
                text: root.override-text;
                clicked => { root.override-requested(); }
            }
            Text {
                text: root.error-text;
                color: #b3261e;
                wrap: word-wrap;
                visible: root.error-text != "";
                accessible-role: text;
            }
            Text {
                text: root.busy-text;
                visible: root.busy;
                accessible-role: text;
            }

            if root.screen == 0 : VerticalLayout {
                spacing: 8px;
                Text { text: root.onboarding-title; font-size: 18px; font-weight: 700; }
                Text { text: root.name-label; }
                LineEdit {
                    text <=> root.profile-name;
                    accessible-label: root.name-label;
                    enabled: !root.busy;
                }
                Text { text: root.pass-label; }
                LineEdit {
                    text <=> root.pass1;
                    input-type: password;
                    accessible-label: root.pass-label;
                    enabled: !root.busy;
                }
                Text { text: root.pass-again-label; }
                LineEdit {
                    text <=> root.pass2;
                    input-type: password;
                    accessible-label: root.pass-again-label;
                    enabled: !root.busy;
                }
                Text { text: root.mode-label; }
                ComboBox {
                    model: root.mode-names;
                    current-index <=> root.mode-index;
                    accessible-label: root.mode-label;
                    enabled: !root.busy;
                    selected => { root.mode-picked(self.current-index); }
                }
                Text { text: root.relay-view-title; font-weight: 700; }
                for line in root.relay-lines : Text {
                    text: "• " + line;
                    wrap: word-wrap;
                }
                Button {
                    text: root.create-text;
                    enabled: !root.busy;
                    clicked => {
                        root.create(root.profile-name, root.pass1, root.pass2, root.mode-index);
                    }
                }
            }

            if root.screen == 1 : VerticalLayout {
                spacing: 8px;
                Text { text: root.unlock-title; font-size: 18px; font-weight: 700; }
                Text { text: root.unlock-profile; }
                Text { text: root.unlock-pass-label; }
                LineEdit {
                    text <=> root.unlock-pass;
                    input-type: password;
                    accessible-label: root.unlock-pass-label;
                    enabled: !root.busy;
                    accepted => { root.unlock(root.unlock-pass); }
                }
                Button {
                    text: root.unlock-text;
                    enabled: !root.busy;
                    clicked => { root.unlock(root.unlock-pass); }
                }
            }

            if root.screen == 2 : VerticalLayout {
                spacing: 8px;
                Text { text: root.contacts-title; font-size: 18px; font-weight: 700; }
                Text {
                    text: root.contacts-empty;
                    visible: root.contacts.length == 0;
                }
                ListView {
                    height: 320px;
                    for contact in root.contacts : Rectangle {
                        height: 44px;
                        HorizontalLayout {
                            spacing: 12px;
                            Text {
                                text: contact.name;
                                vertical-alignment: center;
                                horizontal-stretch: 1;
                            }
                            Text {
                                text: contact.key;
                                vertical-alignment: center;
                                color: #606060;
                            }
                            Text {
                                text: contact.status;
                                vertical-alignment: center;
                                color: contact.verified ? #1b6e2d : #8a5a00;
                            }
                        }
                    }
                }
            }
        }
    }
}
