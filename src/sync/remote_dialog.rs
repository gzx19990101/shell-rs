//! The dialog of 同步 for a place reached over the network: a WebDAV
//! server (its address, username and password) or an S3 bucket (the
//! service's address, region, bucket, folder and keys). It sets sync up
//! there, or signs in again once the place refused the login.
//!
//! Setting up, it looks whether the place has sync already and goes on to
//! the sync password's dialog (create or join), handing it the login: the
//! keychain keeps the password or secret key only once sync is set up.

use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Sizable as _, WindowExt as _,
    button::{Button, ButtonVariants as _},
    checkbox::Checkbox,
    dialog::{DialogAction, DialogClose, DialogFooter},
    form::{Field, Form},
    h_flex,
    input::{Input, InputContentType, InputState},
    notification::Notification,
    v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use zeroize::Zeroizing;

use super::sync_dialog::{JoinReason, PasswordDialog, open_password_dialog};
use super::{JobError, SyncService};
use crate::i18n::t;
use crate::settings::SyncLocation;
use crate::shared::{dismiss_form_error, form_error_notification};

/// Which kind of place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteKind {
    WebDav,
    S3,
}

/// What the dialog does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteDialog {
    /// Set sync up at a new place of this kind: create it there, or join.
    SetUp(RemoteKind),
    /// Sign in anew to the place sync goes through.
    Login(SyncLocation),
}

/// The fields of each kind.
enum Fields {
    WebDav {
        url: Entity<InputState>,
        username: Entity<InputState>,
        password: Entity<InputState>,
    },
    S3 {
        endpoint: Entity<InputState>,
        region: Entity<InputState>,
        bucket: Entity<InputState>,
        prefix: Entity<InputState>,
        access_key: Entity<InputState>,
        secret_key: Entity<InputState>,
        path_style: bool,
    },
}

/// The dialog's job: look at a new place, or sign in to the one there.
enum Job {
    Inspect(Task<Result<bool, JobError>>),
    Login(Task<Result<(), JobError>>),
}

pub struct RemoteForm {
    service: Entity<SyncService>,
    dialog: RemoteDialog,
    fields: Fields,
    working: bool,
    testing: bool,
}

impl RemoteForm {
    fn new(
        service: Entity<SyncService>,
        dialog: RemoteDialog,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let mut field = |value: &str, placeholder: &'static str, masked: bool| {
            let value = value.to_owned();
            cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder(placeholder)
                    .default_value(value)
                    .masked(masked)
            })
        };
        let fields = match &dialog {
            RemoteDialog::SetUp(RemoteKind::WebDav)
            | RemoteDialog::Login(SyncLocation::Folder { .. }) => Fields::WebDav {
                url: field("", "https://dav.example.com/ShellRS", false),
                username: field("", "", false),
                password: field("", "", true),
            },
            RemoteDialog::Login(SyncLocation::WebDav { url, username }) => Fields::WebDav {
                url: field(url, "", false),
                username: field(username, "", false),
                password: field("", "", true),
            },
            RemoteDialog::SetUp(RemoteKind::S3) => Fields::S3 {
                endpoint: field("", "https://<ACCOUNT_ID>.r2.cloudflarestorage.com", false),
                region: field("", "us-east-1", false),
                bucket: field("", "", false),
                prefix: field("ShellRS", "", false),
                access_key: field("", "", false),
                secret_key: field("", "", true),
                path_style: false,
            },
            RemoteDialog::Login(SyncLocation::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                path_style,
                access_key,
            }) => Fields::S3 {
                endpoint: field(endpoint, "", false),
                region: field(region, "", false),
                bucket: field(bucket, "", false),
                prefix: field(prefix, "", false),
                access_key: field(access_key, "", false),
                secret_key: field("", "", true),
                path_style: *path_style,
            },
        };
        Self {
            service,
            dialog,
            fields,
            working: false,
            testing: false,
        }
    }

    fn signing_in(&self) -> bool {
        matches!(self.dialog, RemoteDialog::Login(_))
    }

    fn focus(&self, window: &mut Window, cx: &mut App) {
        let first = match (&self.fields, self.signing_in()) {
            (Fields::WebDav { url, .. }, false) => url,
            (Fields::WebDav { password, .. }, true) => password,
            (Fields::S3 { endpoint, .. }, false) => endpoint,
            (Fields::S3 { secret_key, .. }, true) => secret_key,
        };
        first.update(cx, |state, cx| state.focus(window, cx));
    }

    /// The place and the login the fields name, or what is wrong with them.
    fn login(&self, cx: &App) -> Result<(SyncLocation, Zeroizing<String>), SharedString> {
        let text = |field: &Entity<InputState>| field.read(cx).value().trim().to_string();
        let address = |text: &str| {
            url::Url::parse(text).ok().is_some_and(|address| {
                matches!(address.scheme(), "http" | "https") && address.host_str().is_some()
            })
        };
        match &self.fields {
            Fields::WebDav {
                url,
                username,
                password,
            } => {
                let (url, username) = (text(url), text(username));
                let password = Zeroizing::new(password.read(cx).value().to_string());
                if !address(&url) {
                    return Err(t!("sync.webdav.url_invalid"));
                }
                if username.is_empty() {
                    return Err(t!("sync.webdav.username_missing"));
                }
                if password.is_empty() {
                    return Err(t!("sync.webdav.password_missing"));
                }
                Ok((SyncLocation::WebDav { url, username }, password))
            }
            Fields::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                access_key,
                secret_key,
                path_style,
            } => {
                let endpoint = text(endpoint);
                let bucket = text(bucket);
                let access_key = text(access_key);
                let secret_key = Zeroizing::new(secret_key.read(cx).value().trim().to_string());
                if !address(&endpoint) {
                    return Err(t!("sync.s3.endpoint_invalid"));
                }
                if bucket.is_empty() || bucket.contains(['/', '\\', ' ']) {
                    return Err(t!("sync.s3.bucket_invalid"));
                }
                if access_key.is_empty() {
                    return Err(t!("sync.s3.access_key_missing"));
                }
                if secret_key.is_empty() {
                    return Err(t!("sync.s3.secret_key_missing"));
                }
                let location = SyncLocation::S3 {
                    endpoint,
                    region: text(region),
                    bucket,
                    prefix: text(prefix).trim_matches('/').to_string(),
                    path_style: *path_style,
                    access_key,
                };
                Ok((location, secret_key))
            }
        }
    }

    fn test(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.testing {
            return;
        }
        let (location, login) = match self.login(cx) {
            Ok(login) => login,
            Err(error) => {
                window.push_notification(form_error_notification(error), cx);
                return;
            }
        };
        let test = self.service.update(cx, |service, cx| {
            service.test_connection(location, Some(login), cx)
        });
        self.testing = true;
        cx.notify();
        cx.spawn_in(window, async move |this, cx| {
            let result = test.await;
            this.update_in(cx, |this, window, cx| {
                this.testing = false;
                cx.notify();
                window.push_notification(tested(result), cx);
            })
            .ok();
        })
        .detach();
    }

    /// Check the fields and start. Returns whether the dialog may close:
    /// never at once, the job closes it when it went through.
    fn commit(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        if self.working {
            return false;
        }
        let (location, login) = match self.login(cx) {
            Ok(login) => login,
            Err(error) => {
                window.push_notification(form_error_notification(error), cx);
                return false;
            }
        };
        self.working = true;
        cx.notify();
        let service = self.service.clone();
        let setting_up = !self.signing_in();
        let job = if setting_up {
            Job::Inspect(service.update(cx, |service, cx| {
                service.inspect(location.clone(), Some(login.clone()), cx)
            }))
        } else {
            Job::Login(service.update(cx, |service, cx| {
                service.change_login(location.clone(), login.clone(), cx)
            }))
        };
        cx.spawn_in(window, async move |this, cx| {
            // Setting up, whether sync is there already.
            let result = match job {
                Job::Inspect(inspect) => inspect.await.map(Some),
                Job::Login(change) => change.await.map(|()| None),
            };
            this.update_in(cx, |this, window, cx| {
                this.working = false;
                cx.notify();
                match result {
                    Ok(found) => {
                        dismiss_form_error(window, cx);
                        window.close_dialog(cx);
                        if let Some(present) = found {
                            let dialog = if present {
                                PasswordDialog::Join {
                                    location,
                                    reason: JoinReason::First,
                                }
                            } else {
                                PasswordDialog::Create { location }
                            };
                            open_password_dialog(service, dialog, Some(login), window, cx);
                        }
                    }
                    Err(error) => {
                        window.push_notification(form_error_notification(error.describe()), cx)
                    }
                }
            })
            .ok();
        })
        .detach();
        false
    }

    fn render_fields(&self, cx: &mut Context<Self>) -> Form {
        let busy = self.working;
        // Signing in again changes the login only: another place is
        // another sync.
        let fixed = self.signing_in() || busy;
        let plain = |state: &Entity<InputState>, id: &'static str, disabled: bool| {
            Input::new(state).id(id).small().disabled(disabled)
        };
        let secret = |state: &Entity<InputState>, id: &'static str| {
            Input::new(state)
                .id(id)
                .small()
                .mask_toggle()
                .content_type(InputContentType::Password)
                .disabled(busy)
        };
        match &self.fields {
            Fields::WebDav {
                url,
                username,
                password,
            } => Form::new()
                .child(
                    Field::new()
                        .label(t!("sync.webdav.url"))
                        .required(true)
                        .child(plain(url, "webdav-url", fixed)),
                )
                .child(
                    Field::new()
                        .label(t!("sync.webdav.username"))
                        .required(true)
                        .child(plain(username, "webdav-username", busy)),
                )
                .child(
                    Field::new()
                        .label(t!("sync.webdav.password"))
                        .required(true)
                        .child(secret(password, "webdav-password")),
                ),
            Fields::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                access_key,
                secret_key,
                path_style,
            } => Form::new()
                .child(
                    Field::new()
                        .label(t!("sync.s3.endpoint"))
                        .required(true)
                        .child(plain(endpoint, "s3-endpoint", fixed)),
                )
                .child(Field::new().label(t!("sync.s3.region")).child(plain(
                    region,
                    "s3-region",
                    fixed,
                )))
                .child(
                    Field::new()
                        .label(t!("sync.s3.bucket"))
                        .required(true)
                        .child(plain(bucket, "s3-bucket", fixed)),
                )
                .child(Field::new().label(t!("sync.s3.prefix")).child(plain(
                    prefix,
                    "s3-prefix",
                    fixed,
                )))
                .child(
                    Field::new().child(
                        Checkbox::new("s3-path-style")
                            .label(t!("sync.s3.path_style"))
                            .checked(*path_style)
                            .small()
                            .disabled(fixed)
                            .on_click(cx.listener(|this, checked: &bool, _, cx| {
                                if let Fields::S3 { path_style, .. } = &mut this.fields {
                                    *path_style = *checked;
                                    cx.notify();
                                }
                            })),
                    ),
                )
                .child(
                    Field::new()
                        .label(t!("sync.s3.access_key"))
                        .required(true)
                        .child(plain(access_key, "s3-access-key", busy)),
                )
                .child(
                    Field::new()
                        .label(t!("sync.s3.secret_key"))
                        .required(true)
                        .child(secret(secret_key, "s3-secret-key")),
                ),
        }
    }
}

/// What 测试连接 found: it reads and writes there, or why not.
fn tested(result: Result<(), JobError>) -> Notification {
    match result {
        Ok(()) => Notification::success(t!("sync.webdav.test_ok")),
        Err(error) => Notification::error(error.describe()).title(t!("sync.webdav.test_failed")),
    }
}

impl Render for RemoteForm {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let note = match self.fields {
            Fields::WebDav { .. } => t!("sync.webdav.app_password"),
            Fields::S3 { .. } => t!("sync.s3.note"),
        };
        let form = self.render_fields(cx);
        v_flex()
            .gap_3()
            .w_full()
            .child(form)
            .child(div().text_sm().text_color(muted).child(note))
            .when(self.working, |view| {
                view.child(
                    div()
                        .id("remote-working")
                        .test_support()
                        .text_sm()
                        .text_color(muted)
                        .child(t!("sync.webdav.connecting")),
                )
            })
    }
}

/// The footer: 测试连接 on the left, 取消 and the commit on the right, as
/// the host dialog has them.
fn footer(form: &Entity<RemoteForm>, commit_label: SharedString, cx: &App) -> DialogFooter {
    let testing = form.read(cx).testing;
    DialogFooter::new()
        .w_full()
        .justify_between()
        .child(
            Button::new("remote-test")
                .label(t!("sync.webdav.test"))
                .icon(crate::app::CatalogIcon::Plug)
                .small()
                .loading(testing)
                .disabled(testing)
                .on_click({
                    let form = form.clone();
                    move |_, window, cx| form.update(cx, |form, cx| form.test(window, cx))
                }),
        )
        .child(
            h_flex()
                .gap_2()
                .child(DialogClose::new().trigger(|button| button.label(t!("common.cancel"))))
                .child(
                    DialogAction::new()
                        .child(Button::new("remote-commit").primary().label(commit_label)),
                ),
        )
}

/// Open the dialog for a WebDAV server or an S3 bucket.
pub fn open_remote_dialog(
    service: Entity<SyncService>,
    dialog: RemoteDialog,
    window: &mut Window,
    cx: &mut App,
) {
    let kind = match &dialog {
        RemoteDialog::SetUp(kind) => *kind,
        RemoteDialog::Login(SyncLocation::S3 { .. }) => RemoteKind::S3,
        RemoteDialog::Login(_) => RemoteKind::WebDav,
    };
    let (title, commit_label) = match (&dialog, kind) {
        (RemoteDialog::SetUp(_), RemoteKind::WebDav) => {
            (t!("sync.webdav.set_up_title"), t!("sync.webdav.next"))
        }
        (RemoteDialog::SetUp(_), RemoteKind::S3) => {
            (t!("sync.s3.set_up_title"), t!("sync.webdav.next"))
        }
        (RemoteDialog::Login(_), RemoteKind::WebDav) => {
            (t!("sync.webdav.login_title"), t!("common.save"))
        }
        (RemoteDialog::Login(_), RemoteKind::S3) => (t!("sync.s3.login_title"), t!("common.save")),
    };
    let form = cx.new(|cx| RemoteForm::new(service, dialog, window, cx));
    window.open_dialog(cx, {
        let form = form.clone();
        move |dialog, _, cx| {
            dialog
                .title(title.clone())
                .overlay_closable(false)
                .child(form.clone())
                .footer(footer(&form, commit_label.clone(), cx))
                .on_ok({
                    let form = form.clone();
                    move |_, window, cx| form.update(cx, |form, cx| form.commit(window, cx))
                })
                .on_close(|_, window, cx| dismiss_form_error(window, cx))
        }
    });
    form.update(cx, |form, cx| form.focus(window, cx));
}
