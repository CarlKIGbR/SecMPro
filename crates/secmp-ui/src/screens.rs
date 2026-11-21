// SPDX-License-Identifier: AGPL-3.0-or-later
//! The window and its screens (Slint). The component holds no user-visible text of its own: every string is a property the
//! application sets from the [`locale`](crate::locale) tables, the title is the product name on every screen, and the
//! passphrase fields are cleared by the application after use.

slint::slint! {
    import { Button, LineEdit, ComboBox, ListView, ScrollView, CheckBox } from "std-widgets.slint";

    export struct ContactRowData {
        name: string,
        key: string,
        status: string,
        verified: bool,
    }

    export struct MessageRowData {
        text: string,
        meta: string,
        incoming: bool,
        hold: bool,
    }

    export component MainWindow inherits Window {
        // the product name; the title never carries content (docs/04)
        title: "SecMPro";
        preferred-width: 600px;
        preferred-height: 760px;
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
        in property <string> unavailable-text;
        // the connection line and the notice of the last action
        in property <string> status-text;
        in property <string> notice-text;
        // a pending action waits for its confirm click; nothing was sent before it
        in property <string> confirm-text;
        in property <string> confirm-button-text;
        in property <string> cancel-button-text;
        callback confirm-clicked();
        callback cancel-clicked();

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
        callback open-contact(int);
        in property <string> contacts-invite-text;
        callback open-invitations();
        in property <string> contacts-settings-text;
        callback open-settings();

        // leaving a screen for the contact list
        in property <string> back-text;
        callback back();

        // invitations (4)
        in property <string> invite-title;
        in property <string> invite-create-text;
        in property <string> invite-uri-label;
        in property <string> invite-copy-text;
        in property <string> invite-accept-label;
        in property <string> invite-accept-text;
        in property <string> invite-uri;
        in property <bool> invite-input-enabled: false;
        in property <bool> invite-copyable: false;
        in property <image> invite-qr;
        in property <string> invite-status;
        in-out property <string> invite-input;
        callback invite-create();
        callback invite-accept(string);

        // conversation (5)
        in property <string> conv-title;
        in property <[string]> conv-banners;
        in property <[MessageRowData]> conv-messages;
        in property <bool> conv-input-enabled: false;
        in property <string> conv-empty;
        in property <string> conv-input-label;
        in property <string> conv-send-text;
        in property <string> conv-safety-text;
        in property <string> conv-options-text;
        in property <string> conv-load-earlier-text;
        in property <bool> conv-more: false;
        callback conv-load-earlier();
        callback open-options();
        in-out property <string> conv-draft;
        callback conv-send(string);
        callback reveal-pressed(int);
        callback reveal-released();
        callback open-safety();

        // safety number (6)
        in property <string> safety-title;
        in property <string> safety-hint;
        in property <string> safety-verify-text;
        in property <string> safety-digits;
        in property <string> safety-status;
        in property <image> safety-qr;
        in property <bool> safety-can-verify: false;
        callback safety-verify();

        // settings (7)
        in property <string> settings-title;
        in property <string> settings-relay-title;
        in property <string> settings-retention-label;
        in property <string> settings-delivered-label;
        in property <string> settings-read-text;
        in property <string> settings-screen-title;
        in property <string> settings-screen-hint;
        in property <string> settings-profile-title;
        in property <string> identity-text;
        in property <string> export-path-label;
        in property <string> export-pass-label;
        in property <string> export-pass-again-label;
        in property <bool> export-locked: false;
        in property <string> export-text;
        in property <[string]> retention-names;
        in property <[string]> delivered-names;
        in property <bool> settings-enabled: false;
        in-out property <int> settings-mode-index: 0;
        in-out property <int> retention-index: 0;
        in-out property <int> delivered-index: 0;
        in-out property <bool> settings-read: false;
        in-out property <string> export-path;
        in-out property <string> export-pass;
        in-out property <string> export-pass2;
        callback settings-mode-picked(int);
        callback settings-retention-picked(int);
        callback settings-delivered-picked(int);
        callback settings-read-toggled(bool);
        callback ask-identity();
        callback ask-export(string, string, string);

        // contact options (8)
        in property <string> options-title;
        in property <string> rotate-text;
        in property <string> reset-text;
        in property <string> remove-text;
        callback ask-rotate();
        callback ask-reset();
        callback ask-remove();

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
            Text {
                text: root.status-text;
                visible: root.status-text != "";
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
                text: root.unavailable-text;
                color: #8a5a00;
                wrap: word-wrap;
                visible: root.unavailable-text != "";
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
                HorizontalLayout {
                    spacing: 6px;
                    Button {
                        text: root.contacts-invite-text;
                        clicked => { root.open-invitations(); }
                    }
                    Button {
                        text: root.contacts-settings-text;
                        clicked => { root.open-settings(); }
                    }
                }
                Text {
                    text: root.contacts-empty;
                    visible: root.contacts.length == 0;
                }
                ListView {
                    height: 320px;
                    for contact[index] in root.contacts : Rectangle {
                        height: 44px;
                        TouchArea {
                            clicked => { root.open-contact(index); }
                        }
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

            if root.screen == 4 : VerticalLayout {
                spacing: 8px;
                Text { text: root.invite-title; font-size: 18px; font-weight: 700; }
                Button {
                    text: root.invite-create-text;
                    enabled: !root.busy;
                    clicked => { root.invite-create(); }
                }
                if root.invite-uri != "" : VerticalLayout {
                    spacing: 6px;
                    Text { text: root.invite-uri-label; wrap: word-wrap; }
                    invite-field := LineEdit {
                        text: root.invite-uri;
                        read-only: true;
                        accessible-label: root.invite-uri-label;
                    }
                    Button {
                        text: root.invite-copy-text;
                        enabled: root.invite-copyable;
                        clicked => {
                            invite-field.select-all();
                            invite-field.copy();
                        }
                    }
                    Image {
                        source: root.invite-qr;
                        width: 200px;
                        height: 200px;
                        image-rendering: pixelated;
                    }
                }
                Text {
                    text: root.invite-status;
                    wrap: word-wrap;
                    visible: root.invite-status != "";
                    accessible-role: text;
                }
                Text { text: root.invite-accept-label; wrap: word-wrap; }
                LineEdit {
                    text <=> root.invite-input;
                    accessible-label: root.invite-accept-label;
                    enabled: root.invite-input-enabled;
                    accepted => { root.invite-accept(root.invite-input); }
                }
                Button {
                    text: root.invite-accept-text;
                    enabled: root.invite-input-enabled;
                    clicked => { root.invite-accept(root.invite-input); }
                }
                Button {
                    text: root.back-text;
                    clicked => { root.back(); }
                }
            }

            if root.screen == 5 : VerticalLayout {
                spacing: 8px;
                Text { text: root.conv-title; font-size: 18px; font-weight: 700; }
                for banner in root.conv-banners : Text {
                    text: banner;
                    color: #b3261e;
                    wrap: word-wrap;
                    accessible-role: text;
                }
                Text {
                    text: root.conv-empty;
                    visible: root.conv-messages.length == 0;
                }
                if root.conv-more : Button {
                    text: root.conv-load-earlier-text;
                    clicked => { root.conv-load-earlier(); }
                }
                conv-list := ListView {
                    height: 280px;
                    // older messages load when the user scrolls back up to the top (not at the first view of the list)
                    property <bool> armed: false;
                    changed content-y => {
                        if (self.content-y < -20px) {
                            self.armed = true;
                        } else if (self.content-y >= 0px && self.armed) {
                            self.armed = false;
                            if (root.conv-more) {
                                root.conv-load-earlier();
                            }
                        }
                    }
                    for message[index] in root.conv-messages : Rectangle {
                        height: message-body.preferred-height;
                        message-body := VerticalLayout {
                            padding: 4px;
                            spacing: 2px;
                            Text {
                                text: message.text;
                                wrap: word-wrap;
                                horizontal-alignment: message.incoming ? left : right;
                            }
                            Text {
                                text: message.meta;
                                color: #606060;
                                font-size: 11px;
                                horizontal-alignment: message.incoming ? left : right;
                            }
                        }
                        // a view-once is shown while it is held; the area stays while the text shows, so the release reaches it
                        if message.hold : Rectangle {
                            background: #00000010;
                            TouchArea {
                                pointer-event(event) => {
                                    if (event.button == PointerEventButton.left && event.kind == PointerEventKind.down) {
                                        root.reveal-pressed(index);
                                    }
                                    if (event.kind == PointerEventKind.up || event.kind == PointerEventKind.cancel) {
                                        root.reveal-released();
                                    }
                                }
                            }
                        }
                    }
                }
                HorizontalLayout {
                    spacing: 6px;
                    LineEdit {
                        text <=> root.conv-draft;
                        placeholder-text: root.conv-input-label;
                        accessible-label: root.conv-input-label;
                        enabled: root.conv-input-enabled;
                        horizontal-stretch: 1;
                        accepted => { root.conv-send(root.conv-draft); }
                    }
                    Button {
                        text: root.conv-send-text;
                        enabled: root.conv-input-enabled;
                        clicked => { root.conv-send(root.conv-draft); }
                    }
                }
                HorizontalLayout {
                    spacing: 6px;
                    Button {
                        text: root.conv-safety-text;
                        clicked => { root.open-safety(); }
                    }
                    Button {
                        text: root.conv-options-text;
                        clicked => { root.open-options(); }
                    }
                    Button {
                        text: root.back-text;
                        clicked => { root.back(); }
                    }
                }
            }

            if root.screen == 6 : VerticalLayout {
                spacing: 8px;
                Text { text: root.safety-title; font-size: 18px; font-weight: 700; }
                Text { text: root.safety-hint; wrap: word-wrap; }
                Text {
                    text: root.safety-digits;
                    font-size: 20px;
                    font-weight: 700;
                    wrap: word-wrap;
                    accessible-role: text;
                }
                Image {
                    source: root.safety-qr;
                    width: 200px;
                    height: 200px;
                    image-rendering: pixelated;
                }
                Text {
                    text: root.safety-status;
                    color: #1b6e2d;
                    visible: root.safety-status != "";
                    accessible-role: text;
                }
                Button {
                    text: root.safety-verify-text;
                    enabled: root.safety-can-verify && !root.busy;
                    clicked => { root.safety-verify(); }
                }
                Button {
                    text: root.back-text;
                    clicked => { root.back(); }
                }
            }

            if root.confirm-text != "" : VerticalLayout {
                spacing: 6px;
                Text {
                    text: root.confirm-text;
                    wrap: word-wrap;
                    color: #8a5a00;
                    font-weight: 700;
                    accessible-role: text;
                }
                // the confirm button sits at the far end of its row, away from the buttons that asked for it
                HorizontalLayout {
                    spacing: 6px;
                    Button {
                        text: root.cancel-button-text;
                        clicked => { root.cancel-clicked(); }
                    }
                    Rectangle { horizontal-stretch: 1; }
                    Button {
                        text: root.confirm-button-text;
                        enabled: !root.busy;
                        clicked => { root.confirm-clicked(); }
                    }
                }
            }
            Text {
                text: root.notice-text;
                visible: root.notice-text != "";
                color: #1b6e2d;
                wrap: word-wrap;
                accessible-role: text;
            }

            if root.screen == 7 : VerticalLayout {
                spacing: 8px;
                Text { text: root.settings-title; font-size: 18px; font-weight: 700; }
                Text { text: root.mode-label; }
                ComboBox {
                    model: root.mode-names;
                    current-index <=> root.settings-mode-index;
                    accessible-label: root.mode-label;
                    enabled: root.settings-enabled;
                    selected => { root.settings-mode-picked(self.current-index); }
                }
                Text { text: root.settings-relay-title; font-weight: 700; }
                for line in root.relay-lines : Text {
                    text: "• " + line;
                    wrap: word-wrap;
                }
                Text { text: root.settings-retention-label; }
                ComboBox {
                    model: root.retention-names;
                    current-index <=> root.retention-index;
                    accessible-label: root.settings-retention-label;
                    enabled: root.settings-enabled;
                    selected => { root.settings-retention-picked(self.current-index); }
                }
                Text { text: root.settings-delivered-label; }
                ComboBox {
                    model: root.delivered-names;
                    current-index <=> root.delivered-index;
                    accessible-label: root.settings-delivered-label;
                    enabled: root.settings-enabled;
                    selected => { root.settings-delivered-picked(self.current-index); }
                }
                CheckBox {
                    text: root.settings-read-text;
                    checked <=> root.settings-read;
                    enabled: root.settings-enabled;
                    toggled => { root.settings-read-toggled(self.checked); }
                }
                Text { text: root.settings-screen-title; font-weight: 700; }
                Text { text: root.indicator-text; wrap: word-wrap; accessible-role: text; }
                Text { text: root.settings-screen-hint; wrap: word-wrap; }
                if root.show-override : Button {
                    text: root.override-text;
                    clicked => { root.override-requested(); }
                }
                Text { text: root.settings-profile-title; font-weight: 700; }
                Text { text: root.export-path-label; }
                LineEdit {
                    text <=> root.export-path;
                    accessible-label: root.export-path-label;
                    enabled: !root.busy && !root.export-locked;
                }
                if root.confirm-text == "" : VerticalLayout {
                    spacing: 6px;
                    Button {
                        text: root.identity-text;
                        enabled: !root.busy;
                        clicked => { root.ask-identity(); }
                    }
                    Text { text: root.export-pass-label; }
                    LineEdit {
                        text <=> root.export-pass;
                        input-type: password;
                        accessible-label: root.export-pass-label;
                        enabled: !root.busy;
                    }
                    Text { text: root.export-pass-again-label; }
                    LineEdit {
                        text <=> root.export-pass2;
                        input-type: password;
                        accessible-label: root.export-pass-again-label;
                        enabled: !root.busy;
                    }
                    Button {
                        text: root.export-text;
                        enabled: !root.busy;
                        clicked => { root.ask-export(root.export-path, root.export-pass, root.export-pass2); }
                    }
                }
                Button {
                    text: root.back-text;
                    clicked => { root.back(); }
                }
            }

            if root.screen == 8 : VerticalLayout {
                spacing: 8px;
                Text { text: root.options-title; font-size: 18px; font-weight: 700; }
                Text { text: root.conv-title; }
                if root.confirm-text == "" : VerticalLayout {
                    spacing: 6px;
                    Button {
                        text: root.rotate-text;
                        enabled: !root.busy;
                        clicked => { root.ask-rotate(); }
                    }
                    Button {
                        text: root.reset-text;
                        enabled: !root.busy;
                        clicked => { root.ask-reset(); }
                    }
                    Button {
                        text: root.remove-text;
                        enabled: !root.busy;
                        clicked => { root.ask-remove(); }
                    }
                }
                Button {
                    text: root.back-text;
                    clicked => { root.back(); }
                }
            }
        }
    }
}
