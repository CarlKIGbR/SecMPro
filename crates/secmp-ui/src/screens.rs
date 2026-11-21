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
                Button {
                    text: root.contacts-invite-text;
                    clicked => { root.open-invitations(); }
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
                    enabled: !root.busy;
                    accepted => { root.invite-accept(root.invite-input); }
                }
                Button {
                    text: root.invite-accept-text;
                    enabled: !root.busy;
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
                ListView {
                    height: 280px;
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
        }
    }
}
