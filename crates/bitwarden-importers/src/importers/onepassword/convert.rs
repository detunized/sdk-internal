//! Maps downloaded 1Password vaults onto the importer's [`ParsedImport`].
//!
//! Skeleton only: vaults become folders, items carry their title and note, and a Login item picks
//! up its username, password, website addresses and one-time password. Everything a category
//! mapping does not claim survives as a custom field, with dates, month/year values and addresses
//! rendered as text. The remaining categories land in the following steps.

use bitwarden_exporters::{
    Card, CipherType, Field, Identity, ImportingCipher, Login, LoginUri, SecureNote,
    SecureNoteType, SshKey,
};
use bitwarden_ssh::import::import_key;
use chrono::{DateTime, TimeDelta, Utc};

use super::access::{
    model::{Item, ItemCategory, Vault},
    wire::{SshKeyAttributes, VaultItemDetails, VaultItemOverview},
};
use crate::pipeline::ParsedImport;

/// Stands in for a title 1Password left empty, matching the KDBX importer.
const UNTITLED_ITEM: &str = "--";

/// Stands in for a vault name 1Password left empty, matching the KDBX importer's group naming.
const UNNAMED_VAULT: &str = "-";

/// Bitwarden's custom field types.
const TEXT_FIELD: u8 = 0;
const HIDDEN_FIELD: u8 = 1;

/// 1Password stores a one-time password in a section field whose stable id carries this prefix.
const TOTP_PREFIX: &str = "TOTP_";

/// Names the custom field that keeps an item's tags. Bitwarden has nothing else to put them in.
const TAGS_FIELD: &str = "tags";

/// Added to a Document item's note. The item is the file, and an import moves vault data rather
/// than files, so the note is all that is left to say so.
const DOCUMENT_NOTE: &str = "This was a 1Password document. The attached file was not imported.";

/// What a category mapping already read, so the leftover pass does not repeat it.
#[derive(Default)]
struct Claimed {
    /// Designations of consumed top-level fields.
    designations: &'static [&'static str],
    /// IDs of consumed fields inside sections.
    field_ids: Vec<String>,
}

/// Converts every downloaded vault into ciphers, one folder per vault.
pub fn convert(vaults: Vec<Vault>) -> ParsedImport {
    let mut result = ParsedImport {
        ciphers: Vec::new(),
        folders: Vec::new(),
        folder_relationships: Vec::new(),
    };

    for vault in vaults {
        let folder_index = result.folders.len();
        result.folders.push(folder_name(&vault));

        for item in vault.items {
            let cipher_index = result.ciphers.len();
            result.ciphers.push(convert_item(item));
            result
                .folder_relationships
                .push((cipher_index, folder_index));
        }
    }

    result
}

fn folder_name(vault: &Vault) -> String {
    non_blank(&vault.name).unwrap_or(UNNAMED_VAULT).to_string()
}

fn convert_item(item: Item) -> ImportingCipher {
    let now = Utc::now();
    let (r#type, claimed) = cipher_type(&item);
    let mut fields = fields_from_details(&item.details, &claimed);
    fields.extend(tags_field(&item.overview));

    ImportingCipher {
        folder_id: None,
        name: item
            .overview
            .title
            .as_deref()
            .and_then(non_blank)
            .unwrap_or(UNTITLED_ITEM)
            .to_string(),
        notes: notes(&item),
        r#type,
        favorite: false,
        reprompt: 0,
        fields,
        // 1Password sends both timestamps; `now` only stands in for an item that arrived without
        // them.
        revision_date: item.updated_at.unwrap_or(now),
        creation_date: item.created_at.unwrap_or(now),
        deleted_date: None,
    }
}

/// The item's note, with a line added when the item was a document whose file could not come
/// along.
fn notes(item: &Item) -> Option<String> {
    let note = item.details.note.as_deref().and_then(non_blank);

    match (item.category == ItemCategory::Document, note) {
        (true, Some(note)) => Some(format!("{note}\n\n{DOCUMENT_NOTE}")),
        (true, None) => Some(DOCUMENT_NOTE.to_string()),
        (false, note) => note.map(str::to_string),
    }
}

/// Keeps an item's tags in a custom field. They are multi-valued and Bitwarden has no equivalent,
/// so they arrive as one comma-separated field rather than being dropped.
fn tags_field(overview: &VaultItemOverview) -> Option<Field> {
    let tags: Vec<&str> = overview
        .tags
        .iter()
        .flatten()
        .filter_map(|tag| non_blank(tag))
        .collect();

    (!tags.is_empty()).then(|| Field {
        name: Some(TAGS_FIELD.to_string()),
        value: Some(tags.join(", ")),
        r#type: TEXT_FIELD,
        linked_id: None,
    })
}

/// Picks the Bitwarden cipher type for an item's 1Password category, and reports which of the
/// item's fields it read. Categories without a mapping yet fall back to a secure note, which loses
/// nothing because every field then becomes a custom field.
fn cipher_type(item: &Item) -> (CipherType, Claimed) {
    match item.category {
        ItemCategory::Login => {
            let (login, claimed) = login(&item.overview, &item.details);
            (CipherType::Login(Box::new(login)), claimed)
        }
        ItemCategory::CreditCard => card(&item.details),
        ItemCategory::Identity => identity(&item.details),
        // Categories built around a credential: each one keeps its own ids for the same three
        // slots, and everything else rides along as a custom field.
        ItemCategory::Password => password(&item.details),
        ItemCategory::Server => credential_login(&item.overview, &item.details, SERVER_FIELDS),
        ItemCategory::Database => credential_login(&item.overview, &item.details, DATABASE_FIELDS),
        ItemCategory::ApiCredential => {
            credential_login(&item.overview, &item.details, API_CREDENTIAL_FIELDS)
        }
        ItemCategory::EmailAccount => {
            credential_login(&item.overview, &item.details, EMAIL_ACCOUNT_FIELDS)
        }
        ItemCategory::WirelessRouter => {
            credential_login(&item.overview, &item.details, WIRELESS_ROUTER_FIELDS)
        }
        // An SSH item whose key cannot be used stays a note, with the key material kept in its
        // fields.
        ItemCategory::SshKey => match ssh_key(&item.details) {
            Some(key) => key,
            None => secure_note(),
        },
        _ => secure_note(),
    }
}

/// Reads a payment card. Every slot is optional, so an item that fills none of them still becomes
/// a card rather than losing its category.
fn card(details: &VaultItemDetails) -> (CipherType, Claimed) {
    let mut field_ids = Vec::new();
    let mut take = |id: &str| {
        let value = section_value(details, id)?;
        field_ids.push(id.to_string());
        Some(value)
    };

    let cardholder_name = take("cardholder");
    let number = take("ccnum");
    let code = take("cvv");
    // An unrecognized card type stays a custom field rather than reaching the vault as a brand
    // Bitwarden does not know.
    let brand = section_value(details, "type")
        .as_deref()
        .and_then(card_brand)
        .inspect(|_| field_ids.push("type".to_string()));
    let expiry = expiry_month_year(details).inspect(|_| field_ids.push("expiry".to_string()));
    let (exp_month, exp_year) = expiry.unzip();

    let card = Card {
        cardholder_name,
        exp_month,
        exp_year,
        code,
        brand,
        number,
    };

    (
        CipherType::Card(Box::new(card)),
        Claimed {
            designations: &[],
            field_ids,
        },
    )
}

/// The field IDs a credential-carrying category uses for the username, the password and the
/// address the credential belongs to. An id the category does not have is left empty.
struct CredentialFields {
    username: &'static str,
    password: &'static str,
    address: &'static str,
}

const SERVER_FIELDS: CredentialFields = CredentialFields {
    username: "username",
    password: "password",
    address: "url",
};

const DATABASE_FIELDS: CredentialFields = CredentialFields {
    username: "username",
    password: "password",
    address: "hostname",
};

const API_CREDENTIAL_FIELDS: CredentialFields = CredentialFields {
    username: "username",
    password: "credential",
    address: "hostname",
};

const EMAIL_ACCOUNT_FIELDS: CredentialFields = CredentialFields {
    username: "pop_username",
    password: "pop_password",
    address: "provider_website",
};

/// A router has no account name, and its own password is the base station's; the wireless network
/// key is a separate field and stays with the rest.
const WIRELESS_ROUTER_FIELDS: CredentialFields = CredentialFields {
    username: "",
    password: "password",
    address: "server",
};

/// Maps a category that carries a credential onto a login. The item's own website addresses come
/// first; the category's address field follows, so a server or database is reachable by its host.
fn credential_login(
    overview: &VaultItemOverview,
    details: &VaultItemDetails,
    fields: CredentialFields,
) -> (CipherType, Claimed) {
    let mut field_ids = Vec::new();
    let mut take = |id: &str| {
        if id.is_empty() {
            return None;
        }
        let value = section_value(details, id)?;
        field_ids.push(id.to_string());
        Some(value)
    };

    let username = take(fields.username);
    let password = take(fields.password);
    let address = take(fields.address);

    let mut login = Login {
        username,
        password,
        login_uris: login_uris(overview),
        totp: None,
        fido2_credentials: None,
    };

    if let Some(address) = address {
        login.login_uris.push(LoginUri {
            uri: Some(address),
            r#match: None,
        });
    }
    login.sanitize_uris();

    let totp = first_totp(details);
    if let Some((id, secret)) = totp {
        login.totp = Some(secret);
        field_ids.push(id);
    }

    (
        CipherType::Login(Box::new(login)),
        Claimed {
            designations: &[],
            field_ids,
        },
    )
}

/// A Password item keeps its secret in the details, not in a field, and has no username.
fn password(details: &VaultItemDetails) -> (CipherType, Claimed) {
    let login = Login {
        username: None,
        password: details
            .password
            .as_deref()
            .and_then(non_blank)
            .map(str::to_string),
        login_uris: Vec::new(),
        totp: None,
        fido2_credentials: None,
    };

    (CipherType::Login(Box::new(login)), Claimed::default())
}

/// Reads a personal identity. 1Password's template is far wider than Bitwarden's: the birth date,
/// job title, messenger handles and the other phone numbers have no slot and stay custom fields.
fn identity(details: &VaultItemDetails) -> (CipherType, Claimed) {
    let mut field_ids = Vec::new();
    let mut take = |id: &str| {
        let value = section_value(details, id)?;
        field_ids.push(id.to_string());
        Some(value)
    };

    let identity = Identity {
        title: None,
        first_name: take("firstname"),
        middle_name: take("initial"),
        last_name: take("lastname"),
        address1: address_part(details, "street"),
        address2: None,
        address3: None,
        city: address_part(details, "city"),
        state: address_part(details, "state"),
        postal_code: address_part(details, "zip"),
        country: address_part(details, "country"),
        company: take("company"),
        email: take("email"),
        phone: take("defphone"),
        username: take("username"),
        // 1Password keeps these in categories of their own, never on an identity.
        ssn: None,
        passport_number: None,
        license_number: None,
    };

    // The address object holds street, city, state, zip and country, all of which have a slot, so
    // the whole field is spoken for.
    if find_section_field(details, "address").is_some() {
        field_ids.push("address".to_string());
    }

    (
        CipherType::Identity(Box::new(identity)),
        Claimed {
            designations: &[],
            field_ids,
        },
    )
}

/// Reads one part of the address object 1Password stores as a single field.
fn address_part(details: &VaultItemDetails, part: &str) -> Option<String> {
    find_section_field(details, "address")?
        .value
        .as_ref()?
        .get(part)?
        .as_str()
        .and_then(non_blank)
        .map(str::to_string)
}

/// Splits 1Password's `202811` into the month and year Bitwarden keeps apart. The month drops its
/// leading zero, the form the rest of the vault uses.
fn expiry_month_year(details: &VaultItemDetails) -> Option<(String, String)> {
    let value = find_section_field(details, "expiry")?
        .value
        .as_ref()?
        .as_i64()?;
    let (year, month) = (value / 100, value % 100);

    (1..=12)
        .contains(&month)
        .then(|| (month.to_string(), year.to_string()))
}

/// Maps a 1Password card type onto a Bitwarden brand. 1Password writes its own ids, so `mc` and
/// `diners` have to be spelled out rather than passed through.
fn card_brand(kind: &str) -> Option<String> {
    let brand = match kind.to_lowercase().replace(' ', "").as_str() {
        "visa" => "Visa",
        "mc" | "mastercard" => "Mastercard",
        "amex" | "americanexpress" => "Amex",
        "discover" => "Discover",
        "diners" | "dinersclub" => "Diners Club",
        "jcb" => "JCB",
        "maestro" => "Maestro",
        "unionpay" => "UnionPay",
        "rupay" => "RuPay",
        _ => return None,
    };

    Some(brand.to_string())
}

fn find_section_field<'a>(
    details: &'a VaultItemDetails,
    id: &str,
) -> Option<&'a super::access::wire::VaultItemSectionField> {
    details
        .sections
        .iter()
        .flatten()
        .flat_map(|section| section.fields.iter().flatten())
        .find(|field| field.id.as_deref() == Some(id))
}

/// Reads a section field's value as text, by the stable id 1Password gives it.
fn section_value(details: &VaultItemDetails, id: &str) -> Option<String> {
    let field = find_section_field(details, id)?;
    render_value(field.kind.as_deref(), field.value.as_ref()?)
}

fn secure_note() -> (CipherType, Claimed) {
    (
        CipherType::SecureNote(Box::new(SecureNote {
            r#type: SecureNoteType::Generic,
        })),
        Claimed::default(),
    )
}

/// Reads an SSH key from the attributes 1Password hangs off the private key field, in the OpenSSH
/// form the SSH agent and Credential Exchange read. 1Password stores PKCS#8, which neither of them
/// does, so the key is normalized and the public key and fingerprint are derived from it.
///
/// The first key that normalizes wins. A template field with no material and a key in a form
/// `bitwarden_ssh` cannot read are both passed over.
fn ssh_key(details: &VaultItemDetails) -> Option<(CipherType, Claimed)> {
    details
        .sections
        .iter()
        .flatten()
        .flat_map(|section| section.fields.iter().flatten())
        .find_map(|field| {
            let attributes = field.attributes.as_ref()?.ssh_key.as_ref()?;
            let private_key = non_blank(attributes.private_key.as_deref()?)?;
            // 1Password strips the passphrase when a key is added, so none is offered.
            let key = import_key(private_key.to_string(), None).ok()?;

            let key = SshKey {
                private_key: key.private_key,
                public_key: key.public_key,
                fingerprint: key.fingerprint,
            };
            let claimed = Claimed {
                designations: &[],
                field_ids: field.id.clone().into_iter().collect(),
            };

            Some((CipherType::SshKey(Box::new(key)), claimed))
        })
}

fn login(overview: &VaultItemOverview, details: &VaultItemDetails) -> (Login, Claimed) {
    let totp = first_totp(details);

    let mut login = Login {
        username: designation(details, "username"),
        password: designation(details, "password"),
        login_uris: login_uris(overview),
        totp: totp.as_ref().map(|(_, secret)| secret.clone()),
        fido2_credentials: None,
    };
    login.sanitize_uris();

    let claimed = Claimed {
        designations: &["username", "password"],
        field_ids: totp.map(|(id, _)| id).into_iter().collect(),
    };

    (login, claimed)
}

/// Reads the item's first one-time password, with the id of the field it came from. An item can
/// hold several; the rest stay custom fields, since a cipher has room for only one.
fn first_totp(details: &VaultItemDetails) -> Option<(String, String)> {
    details
        .sections
        .iter()
        .flatten()
        .flat_map(|section| section.fields.iter().flatten())
        .find(|field| {
            field
                .id
                .as_deref()
                .is_some_and(|id| id.starts_with(TOTP_PREFIX))
        })
        .and_then(|field| {
            let secret = field.value.as_ref()?.as_str().and_then(non_blank)?;
            Some((field.id.clone()?, secret.to_string()))
        })
}

/// Collects the item's website addresses. 1Password keeps the primary one in `url` and repeats it
/// in `URLs`, so identical addresses collapse into a single URI.
fn login_uris(overview: &VaultItemOverview) -> Vec<LoginUri> {
    let mut uris: Vec<String> = Vec::new();

    for uri in overview
        .url
        .as_deref()
        .into_iter()
        .chain(
            overview
                .urls
                .iter()
                .flatten()
                .filter_map(|u| u.url.as_deref()),
        )
        .filter_map(non_blank)
    {
        if !uris.iter().any(|seen| seen == uri) {
            uris.push(uri.to_string());
        }
    }

    uris.into_iter()
        .map(|uri| LoginUri {
            uri: Some(uri),
            r#match: None,
        })
        .collect()
}

/// Collects every field a category mapping did not claim, so no part of an item is lost.
///
/// Fields without a value are skipped: 1Password stores its whole category template on every item,
/// so most of them are empty.
fn fields_from_details(details: &VaultItemDetails, claimed: &Claimed) -> Vec<Field> {
    let mut fields = Vec::new();

    for field in details.fields.iter().flatten() {
        let designation = field.designation.as_deref().unwrap_or_default();
        if claimed.designations.contains(&designation) {
            continue;
        }

        push_field(
            &mut fields,
            field
                .name
                .as_deref()
                .and_then(non_blank)
                .or(non_blank(designation)),
            field
                .value
                .as_deref()
                .and_then(non_blank)
                .map(str::to_string),
            field.kind.as_deref() == Some("P"),
        );
    }

    for section in details.sections.iter().flatten() {
        for field in section.fields.iter().flatten() {
            if field
                .id
                .as_deref()
                .is_some_and(|id| claimed.field_ids.iter().any(|taken| taken == id))
            {
                continue;
            }

            let name = field
                .name
                .as_deref()
                .and_then(non_blank)
                .or(field.id.as_deref().and_then(non_blank));
            let hidden = matches!(field.kind.as_deref(), Some("concealed" | "sshKey"));
            if let Some(attributes) = field.attributes.as_ref().and_then(|a| a.ssh_key.as_ref()) {
                push_ssh_attributes(&mut fields, attributes);
                // The value repeats the private key, which the attributes have just kept.
                if field.value.as_ref().and_then(serde_json::Value::as_str)
                    == attributes.private_key.as_deref()
                {
                    continue;
                }
            }
            let Some(value) = field.value.as_ref() else {
                continue;
            };

            match (field.kind.as_deref(), value) {
                // An attachment's value is the envelope that unwraps the stored file, encryption
                // keys included. The file cannot come along, so only its name does.
                (Some("file"), _) => push_field(
                    &mut fields,
                    name,
                    Some(format!("<attachment: {}>", attachment_name(value, name))),
                    false,
                ),
                // An address has no single text form, so each part it fills in becomes its own
                // field.
                (Some("address"), serde_json::Value::Object(parts)) => {
                    for (part, value) in parts {
                        push_field(&mut fields, Some(part), render_value(None, value), hidden);
                    }
                }
                _ => push_field(
                    &mut fields,
                    name,
                    render_value(field.kind.as_deref(), value),
                    hidden,
                ),
            }
        }
    }

    fields
}

fn attachment_name<'a>(value: &'a serde_json::Value, fallback: Option<&'a str>) -> &'a str {
    value
        .get("fileName")
        .and_then(serde_json::Value::as_str)
        .and_then(non_blank)
        .or(fallback)
        .unwrap_or("unnamed")
}

/// Keeps the material of a key that could not be used, so nothing is lost when the item stays a
/// note. Only the private key is a secret.
fn push_ssh_attributes(fields: &mut Vec<Field>, attributes: &SshKeyAttributes) {
    for (name, value, hidden) in [
        ("private key", &attributes.private_key, true),
        ("public key", &attributes.public_key, false),
        ("fingerprint", &attributes.fingerprint, false),
    ] {
        push_field(
            fields,
            Some(name),
            value.as_deref().and_then(non_blank).map(str::to_string),
            hidden,
        );
    }
}

/// A field is hidden when 1Password treats its value as a secret. The `guarded` attribute is not
/// that signal: the Identity template sets it on plain fields such as the first name.
fn push_field(fields: &mut Vec<Field>, name: Option<&str>, value: Option<String>, hidden: bool) {
    let Some(value) = value else {
        return;
    };

    fields.push(Field {
        name: name.map(str::to_string),
        value: Some(value),
        r#type: if hidden { HIDDEN_FIELD } else { TEXT_FIELD },
        linked_id: None,
    });
}

/// Renders a field value as the text of one custom field. 1Password stores dates as unix seconds
/// and month/year as an integer such as `202112`; anything else it sends stays in its JSON form.
fn render_value(kind: Option<&str>, value: &serde_json::Value) -> Option<String> {
    match (kind, value) {
        (_, serde_json::Value::Null) => None,
        (_, serde_json::Value::String(text)) => non_blank(text).map(str::to_string),
        (Some("date"), serde_json::Value::Number(seconds)) => seconds
            .as_i64()
            .map(render_date)
            .or(Some(value.to_string())),
        (Some("monthYear"), serde_json::Value::Number(number)) => Some(
            number
                .as_i64()
                .and_then(render_month_year)
                .unwrap_or_else(|| value.to_string()),
        ),
        (_, other) => Some(other.to_string()),
    }
}

/// 1Password writes a date as midnight in the writer's own time zone, which it does not record.
/// Reading the timestamp at noon lands on the day that was meant whatever that zone was.
fn render_date(seconds: i64) -> String {
    DateTime::from_timestamp(seconds, 0)
        .and_then(|date| date.checked_add_signed(TimeDelta::hours(12)))
        .map(|date| date.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| seconds.to_string())
}

/// `202112` is December 2021.
fn render_month_year(value: i64) -> Option<String> {
    let (year, month) = (value / 100, value % 100);
    (1..=12)
        .contains(&month)
        .then(|| format!("{year:04}-{month:02}"))
}

/// Reads one of the login fields 1Password tags with a `designation`. The designation is stable,
/// unlike the field's localized `name`.
fn designation(details: &VaultItemDetails, designation: &str) -> Option<String> {
    details
        .fields
        .iter()
        .flatten()
        .find(|field| field.designation.as_deref() == Some(designation))
        .and_then(|field| field.value.as_deref())
        .and_then(non_blank)
        .map(str::to_string)
}

fn non_blank(value: &str) -> Option<&str> {
    (!value.trim().is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::{super::access::replay::download_captured_account, *};

    /// Converts the captured account. The vaults come out of the production download path, driven
    /// over the recorded server responses, so these tests see exactly what an import would.
    async fn converted() -> ParsedImport {
        convert(download_captured_account().await)
    }

    fn cipher<'a>(parsed: &'a ParsedImport, name: &str) -> &'a ImportingCipher {
        parsed
            .ciphers
            .iter()
            .find(|cipher| cipher.name == name)
            .unwrap_or_else(|| panic!("no cipher named {name}"))
    }

    fn uris(login: &Login) -> Vec<&str> {
        login
            .login_uris
            .iter()
            .map(|uri| uri.uri.as_deref().expect("a uri"))
            .collect()
    }

    /// The cipher's custom fields as `(type, name, value)`, in order.
    fn fields_of(cipher: &ImportingCipher) -> Vec<(u8, &str, &str)> {
        cipher
            .fields
            .iter()
            .map(|field| {
                (
                    field.r#type,
                    field.name.as_deref().expect("a name"),
                    field.value.as_deref().expect("a value"),
                )
            })
            .collect()
    }

    fn identity_of(cipher: &ImportingCipher) -> &Identity {
        match &cipher.r#type {
            CipherType::Identity(identity) => identity,
            other => panic!("{} is a {other}, expected an identity", cipher.name),
        }
    }

    fn card_of(cipher: &ImportingCipher) -> &Card {
        match &cipher.r#type {
            CipherType::Card(card) => card,
            other => panic!("{} is a {other}, expected a card", cipher.name),
        }
    }

    fn ssh_key_of(cipher: &ImportingCipher) -> &SshKey {
        match &cipher.r#type {
            CipherType::SshKey(key) => key,
            other => panic!("{} is a {other}, expected an ssh key", cipher.name),
        }
    }

    fn login_of(cipher: &ImportingCipher) -> &Login {
        match &cipher.r#type {
            CipherType::Login(login) => login,
            other => panic!("{} is a {other}, expected a login", cipher.name),
        }
    }

    /// Builds a value the way 1Password sends it, for the shapes the captured account has no
    /// example of.
    fn fields_from_json(details: serde_json::Value) -> Vec<(u8, String, String)> {
        let details: VaultItemDetails = serde_json::from_value(details).expect("valid details");
        rendered(&details, &Claimed::default())
    }

    /// The custom fields left over after `claimed`, as `(type, name, value)`.
    fn rendered(details: &VaultItemDetails, claimed: &Claimed) -> Vec<(u8, String, String)> {
        fields_from_details(details, claimed)
            .into_iter()
            .map(|field| {
                (
                    field.r#type,
                    field.name.expect("a name"),
                    field.value.expect("a value"),
                )
            })
            .collect()
    }

    fn section_field(kind: &str, value: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "sections": [{"name": "s", "title": "Section", "fields": [
                {"n": "id", "t": "the field", "k": kind, "v": value}
            ]}]
        })
    }

    /// An ed25519 key in the form 1Password stores it and one in the form OpenSSH writes it.
    const PKCS8_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
        MFECAQEwBQYDK2VwBCIEIDY6/OAdDr3PbDss9NsLXK4CxiKUvz5/R9uvjtIzj4Sz\n\
        gSEAxsxm1xpZ/4lKIRYm0JrJ5gRZUh7H24/YT/0qGVGzPa0=\n\
        -----END PRIVATE KEY-----\n";
    const OPENSSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
        QyNTUxOQAAACAyQo22TXXNqvF+L8jUSSNeu8UqrsDjvf9pwIwDC9ML6gAAAJDSHpL60h6S\n\
        +gAAAAtzc2gtZWQyNTUxOQAAACAyQo22TXXNqvF+L8jUSSNeu8UqrsDjvf9pwIwDC9ML6g\n\
        AAAECLdlFLIJbEiFo/f0ROdXMNZAPHGPNhvbbftaPsUZEjaDJCjbZNdc2q8X4vyNRJI167\n\
        xSquwOO9/2nAjAML0wvqAAAAB3Rlc3RrZXkBAgMEBQY=\n\
        -----END OPENSSH PRIVATE KEY-----\n";

    /// A key backed by a security key, which the vault has no way to use.
    const SK_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAASgAAABpzay1zc2\n\
        gtZWQyNTUxOUBvcGVuc3NoLmNvbQAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAARzc2g6AAAAiHneT6B53k+gAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY2\n\
        9tAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABHNzaDoAAAAAEAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAE3NrLXRlc3RAZXhhbXBsZS5jb20BAgMEBQY=\n\
        -----END OPENSSH PRIVATE KEY-----\n";

    /// An SSH key field the way 1Password sends it: the value repeats the private key, and the
    /// public key and fingerprint are only in the attributes.
    fn ssh_field(id: &str, private_key: &str) -> serde_json::Value {
        serde_json::json!({
            "n": id, "t": "private key", "k": "sshKey", "v": private_key,
            "a": {"sshKeyAttributes": {
                "privateKey": private_key,
                "publicKey": "ssh-ed25519 AAAA stored",
                "fingerprint": "SHA256:stored",
            }},
        })
    }

    fn ssh_details(private_key: &str) -> VaultItemDetails {
        serde_json::from_value(serde_json::json!({
            "sections": [{"fields": [ssh_field("private_key", private_key)]}]
        }))
        .expect("valid details")
    }

    #[tokio::test]
    async fn every_vault_becomes_a_folder_holding_its_items() {
        let parsed = converted().await;

        assert_eq!(parsed.folders, vec!["Personal", "Importer"]);
        assert_eq!(parsed.ciphers.len(), 28);
        // Nothing is dropped and nothing is left folderless.
        assert_eq!(parsed.folder_relationships.len(), parsed.ciphers.len());

        let personal = parsed
            .folder_relationships
            .iter()
            .filter(|(_, folder)| *folder == 0)
            .count();
        assert_eq!(personal, 1);
    }

    #[tokio::test]
    async fn login_takes_its_credentials_from_the_designation_fields() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "Login: username, password and one URL");
        let login = login_of(cipher);

        assert_eq!(
            cipher.notes.as_deref(),
            Some("A login with nothing but the basics.")
        );
        assert_eq!(login.username.as_deref(), Some("plain@example.com"));
        assert_eq!(login.password.as_deref(), Some("plain-pass"));
        // Both designation fields were claimed, so nothing is left over.
        assert_eq!(fields_of(cipher), []);
    }

    /// The overview carries the primary address twice, in `url` and again in `URLs`.
    #[tokio::test]
    async fn a_repeated_website_address_becomes_one_uri() {
        let parsed = converted().await;
        let login = login_of(cipher(&parsed, "Login: username, password and one URL"));

        assert_eq!(uris(login), ["https://plain.example.com"]);
    }

    #[tokio::test]
    async fn every_website_address_arrives_in_order() {
        let parsed = converted().await;
        let login = login_of(cipher(&parsed, "Login: three website URLs"));

        assert_eq!(
            uris(login),
            [
                "https://primary.example.com",
                "https://admin.example.com",
                "https://unlabelled.example.com",
            ]
        );
    }

    #[tokio::test]
    async fn a_login_takes_its_one_time_password() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "Login: TOTP field");

        assert_eq!(
            login_of(cipher).totp.as_deref(),
            Some(
                "otpauth://totp/totp.example.com:totp@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
            )
        );
        // The field it came from was claimed, so it is not repeated as a custom field.
        assert_eq!(fields_of(cipher), []);
    }

    /// A cipher has room for one one-time password, so the others stay custom fields rather than
    /// being dropped.
    #[tokio::test]
    async fn a_second_one_time_password_stays_a_custom_field() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "Login: two TOTP fields");

        assert_eq!(
            login_of(cipher).totp.as_deref(),
            Some("otpauth://totp/first?secret=JBSWY3DPEHPK3PXP&issuer=First")
        );
        assert_eq!(
            fields_of(cipher),
            [(
                1,
                "second code",
                "otpauth://totp/second?secret=KRSXG5CTMVRXEZLU&issuer=Second"
            )]
        );
    }

    /// The public key and the fingerprint are only ever in the field's attributes, so a mapping
    /// that read the value alone would lose both. The captured key is PKCS#8 and arrives as
    /// OpenSSH, with the fingerprint 1Password showed.
    #[tokio::test]
    async fn an_ssh_key_takes_its_material_from_the_field_attributes() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "SSH key: ed25519 with a custom section");
        let key = ssh_key_of(cipher);

        assert!(
            key.private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert!(key.public_key.starts_with("ssh-ed25519 "));
        assert_eq!(
            key.fingerprint,
            "SHA256:FlyEkMObqGorzjukxrU4+K89uD9ODaeeQUVMvQDGnk8"
        );
        // The key field was claimed; the item's own section survives beside it.
        assert_eq!(
            fields_of(cipher),
            [(0, "purpose", "deploy key for the test host")]
        );
    }

    #[tokio::test]
    async fn an_rsa_key_maps_the_same_way() {
        let parsed = converted().await;
        let key = ssh_key_of(cipher(&parsed, "SSH key: RSA 4096"));

        assert!(key.public_key.starts_with("ssh-rsa "));
        assert_eq!(
            key.fingerprint,
            "SHA256:iykJ4i2Txk1Owsd9HT6cf5+n546m+q1Ikr4LtapwFBY"
        );
    }

    /// 1Password stores a private key as PKCS#8, which neither the SSH agent nor Credential
    /// Exchange reads, so a key arrives in OpenSSH form whichever way it was stored.
    #[test]
    fn a_key_in_either_form_becomes_a_usable_openssh_key() {
        for private_key in [PKCS8_KEY, OPENSSH_KEY] {
            let details = ssh_details(private_key);
            let Some((CipherType::SshKey(key), claimed)) = ssh_key(&details) else {
                panic!("expected an ssh key");
            };

            assert!(
                key.private_key
                    .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
            );
            assert!(bitwarden_ssh::export_pkcs8_der_key(&key.private_key).is_ok());
            assert!(key.public_key.starts_with("ssh-ed25519 "));
            assert!(key.fingerprint.starts_with("SHA256:"));
            // The key field is spoken for, so none of its material is repeated.
            assert_eq!(rendered(&details, &claimed), []);
        }
    }

    /// A key in a form the vault cannot use stays a note, with its material in the fields rather
    /// than lost. The value repeats the private key and is not kept twice.
    #[test]
    fn a_key_the_vault_cannot_use_keeps_its_material_in_the_note() {
        for private_key in ["not a key", SK_KEY] {
            let details = ssh_details(private_key);

            assert!(ssh_key(&details).is_none());
            assert_eq!(
                rendered(&details, &Claimed::default()),
                [
                    (1, "private key".to_string(), private_key.to_string()),
                    (
                        0,
                        "public key".to_string(),
                        "ssh-ed25519 AAAA stored".to_string()
                    ),
                    (0, "fingerprint".to_string(), "SHA256:stored".to_string()),
                ]
            );
        }
    }

    /// The template's own key field arrives empty when the key sits in a section of its own, and
    /// a key the vault cannot use must not hide one it can.
    #[test]
    fn the_first_usable_key_is_taken_and_the_rest_stay_in_the_fields() {
        let details: VaultItemDetails = serde_json::from_value(serde_json::json!({
            "sections": [{"fields": [
                {"n": "private_key", "k": "sshKey", "a": {"sshKeyAttributes": {}}},
                ssh_field("old_key", "not a key"),
                ssh_field("new_key", PKCS8_KEY),
            ]}]
        }))
        .expect("valid details");

        let Some((CipherType::SshKey(_), claimed)) = ssh_key(&details) else {
            panic!("expected an ssh key");
        };
        assert_eq!(
            rendered(&details, &claimed),
            [
                (1, "private key".to_string(), "not a key".to_string()),
                (
                    0,
                    "public key".to_string(),
                    "ssh-ed25519 AAAA stored".to_string()
                ),
                (0, "fingerprint".to_string(), "SHA256:stored".to_string()),
            ]
        );
    }

    /// Tags are multi-valued and Bitwarden has nowhere to put them, so they ride along in a field
    /// of their own rather than being dropped.
    #[tokio::test]
    async fn tags_arrive_as_a_field_of_their_own() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "Login: tags and favorite");

        assert_eq!(fields_of(cipher), [(0, "tags", "work, archive, two words")]);
    }

    /// 1Password sends both timestamps, so an imported item keeps the history it had.
    #[tokio::test]
    async fn an_item_keeps_the_dates_1password_sent() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "Login: TOTP field");

        assert_eq!(
            cipher.creation_date.to_rfc3339(),
            "2026-08-31T13:08:40+00:00"
        );
        assert!(cipher.revision_date >= cipher.creation_date);
        assert!(cipher.creation_date < Utc::now());
    }

    /// An import moves vault data, not files, so a document says in its note that its file stayed
    /// behind rather than arriving as an empty item.
    #[tokio::test]
    async fn a_document_says_its_file_did_not_come_along() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "Document: uploaded text file");

        assert!(matches!(cipher.r#type, CipherType::SecureNote(_)));
        assert_eq!(
            cipher.notes.as_deref(),
            Some("This was a 1Password document. The attached file was not imported.")
        );
    }

    #[tokio::test]
    async fn secure_note_keeps_its_multiline_note() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "Note: multiline text only");

        assert!(matches!(cipher.r#type, CipherType::SecureNote(_)));
        assert_eq!(
            cipher.notes.as_deref(),
            Some("A secret note.\nWith a second line.")
        );
    }

    /// 1Password stores its whole category template on every item, so most fields arrive empty.
    /// The API credential has seven: three fill login slots, three were filled in by hand, and the
    /// empty one is gone.
    #[tokio::test]
    async fn an_item_keeps_only_the_fields_it_filled_in() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "API credential: concealed value and two dates");
        let login = login_of(cipher);

        assert_eq!(login.username.as_deref(), Some("svc-account"));
        assert_eq!(login.password.as_deref(), Some("sk-test-abc123xyz"));
        assert_eq!(uris(login), ["https://api.example.com"]);
        assert_eq!(
            fields_of(cipher),
            [
                (0, "filename", "service-account.json"),
                (0, "valid from", "2026-01-05"),
                (0, "expires", "2027-06-30"),
            ]
        );
    }

    #[tokio::test]
    async fn a_concealed_field_imports_as_hidden() {
        let parsed = converted().await;

        assert_eq!(
            fields_of(cipher(&parsed, "Note: text plus custom fields")),
            [
                (0, "visible", "note text field"),
                (1, "secret", "note hidden field"),
            ]
        );
    }

    /// Every category built around a credential lands on the same three login slots, each reading
    /// the ids its own template uses.
    #[tokio::test]
    async fn a_credential_category_becomes_a_login() {
        let parsed = converted().await;

        let server = login_of(cipher(
            &parsed,
            "Server: credentials plus two extra sections",
        ));
        assert_eq!(server.username.as_deref(), Some("root"));
        assert_eq!(server.password.as_deref(), Some("serverpass"));
        assert_eq!(uris(server), ["https://server.example.com"]);

        let email = login_of(cipher(&parsed, "Email account: POP and SMTP credentials"));
        assert_eq!(email.username.as_deref(), Some("mail@example.com"));
        assert_eq!(email.password.as_deref(), Some("pop-secret"));
        assert_eq!(uris(email), ["https://mail.example.com"]);
    }

    /// A database is reachable by its host, which is not a URL until the shared sanitizer makes it
    /// one. A router's address is an IP, which becomes plain http.
    #[tokio::test]
    async fn a_host_or_an_ip_becomes_the_login_address() {
        let parsed = converted().await;

        let database = login_of(cipher(&parsed, "Database: host, port and credentials"));
        assert_eq!(database.username.as_deref(), Some("dbuser"));
        assert_eq!(uris(database), ["https://db.example.com"]);

        let router = login_of(cipher(
            &parsed,
            "Wireless router: base station and network passwords",
        ));
        assert_eq!(uris(router), ["http://192.168.1.1"]);
    }

    /// A router has no account name, and its own password is the base station's. The wireless key
    /// is a field of its own and stays with the item.
    #[tokio::test]
    async fn a_wireless_router_keeps_its_second_password() {
        let parsed = converted().await;
        let cipher = cipher(
            &parsed,
            "Wireless router: base station and network passwords",
        );

        assert_eq!(login_of(cipher).username, None);
        assert_eq!(login_of(cipher).password.as_deref(), Some("admin-secret"));

        let fields = fields_of(cipher);
        assert!(fields.contains(&(1, "wireless network password", "wifi-secret")));
        assert!(fields.contains(&(1, "attached storage password", "disk-secret")));
        assert!(fields.contains(&(0, "network name", "TestNet")));
    }

    /// A Password item has no fields at all: its secret is in the details.
    #[tokio::test]
    async fn a_password_item_takes_its_secret_from_the_details() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "Password: secret in details plus a custom section");
        let login = login_of(cipher);

        assert_eq!(login.username, None);
        assert_eq!(login.password.as_deref(), Some("Sup3rS3cret!"));
        assert_eq!(
            fields_of(cipher),
            [
                (0, "plain note", "a text field on a password item"),
                (1, "hidden value", "s3cret-on-a-password-item"),
            ]
        );
    }

    /// A section 1Password stores without labels names each field by its stable id instead.
    #[tokio::test]
    async fn a_field_without_a_label_is_named_by_its_id() {
        let parsed = converted().await;

        assert_eq!(
            fields_of(cipher(&parsed, "Login: section and fields with no label")),
            [
                (
                    0,
                    "6d6s6bmocbmogfgrvx6czy5hha",
                    "a field whose label is empty"
                ),
                (
                    0,
                    "gjxykv6pufvfme5y2unkccugzq",
                    "https://nolabel.example.com"
                ),
            ]
        );
    }

    /// The same label in two sections lands twice: Bitwarden custom fields are a flat list.
    #[tokio::test]
    async fn two_sections_may_repeat_a_field_label() {
        let parsed = converted().await;

        assert_eq!(
            fields_of(cipher(&parsed, "Login: same field label in two sections")),
            [
                (1, "api key", "prod-key-111"),
                (0, "host", "prod.example.com"),
                (1, "api key", "staging-key-222"),
                (0, "host", "staging.example.com"),
            ]
        );
    }

    #[tokio::test]
    async fn text_survives_whatever_it_is_made_of() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "Login: unicode, emoji and multiline values");
        let login = login_of(cipher);

        assert_eq!(login.username.as_deref(), Some("ünïcödé@example.com"));
        assert_eq!(login.password.as_deref(), Some("пароль-密码-🔑"));

        let fields = fields_of(cipher);
        assert!(fields.contains(&(0, "cjk", "日本語のテキストと中文文本")));
        assert!(fields.contains(&(
            0,
            "multiline",
            "first line\nsecond line\n\nfourth line after a blank one"
        )));
    }

    #[tokio::test]
    async fn an_identity_fills_the_slots_bitwarden_has() {
        let parsed = converted().await;
        let cipher = cipher(
            &parsed,
            "Identity: name, phones, birth date and internet details",
        );
        let identity = identity_of(cipher);

        assert_eq!(identity.first_name.as_deref(), Some("Jane"));
        assert_eq!(identity.middle_name.as_deref(), Some("Q"));
        assert_eq!(identity.last_name.as_deref(), Some("Tester"));
        assert_eq!(identity.company.as_deref(), Some("Test Corp"));
        assert_eq!(identity.email.as_deref(), Some("jane.tester@example.com"));
        assert_eq!(identity.phone.as_deref(), Some("+1 555 0100"));
        assert_eq!(identity.username.as_deref(), Some("jane.tester"));

        // 1Password's template is far wider than Bitwarden's, so the rest rides along.
        let fields = fields_of(cipher);
        assert!(fields.contains(&(0, "birth date", "1990-03-15")));
        assert!(fields.contains(&(0, "job title", "Senior Tester")));
        assert!(fields.contains(&(0, "cell", "+1 555 0102")));
        assert!(fields.contains(&(0, "skype", "jane.tester")));
        // The claimed ones are not repeated.
        assert!(!fields.iter().any(|(_, name, _)| *name == "first name"));
        assert!(!fields.iter().any(|(_, name, _)| *name == "email"));
    }

    /// 1Password keeps the whole address in one field. Its five parts each have a slot, so none of
    /// them is left to become a custom field. The captured account has no filled address: the
    /// 1Password CLI cannot write one.
    #[test]
    fn an_identity_address_fills_the_address_slots() {
        let details: VaultItemDetails = serde_json::from_value(serde_json::json!({
            "sections": [{"name": "address", "title": "Address", "fields": [
                {"n": "address", "t": "address", "k": "address", "v": {
                    "street": "221B Baker Street",
                    "city": "London",
                    "state": "Greater London",
                    "zip": "NW1 6XE",
                    "country": "gb",
                }}
            ]}]
        }))
        .expect("valid details");

        let (cipher_type, claimed) = identity(&details);
        let CipherType::Identity(identity) = cipher_type else {
            panic!("expected an identity");
        };

        assert_eq!(identity.address1.as_deref(), Some("221B Baker Street"));
        assert_eq!(identity.city.as_deref(), Some("London"));
        assert_eq!(identity.state.as_deref(), Some("Greater London"));
        assert_eq!(identity.postal_code.as_deref(), Some("NW1 6XE"));
        assert_eq!(identity.country.as_deref(), Some("gb"));
        assert_eq!(fields_from_details(&details, &claimed), []);
    }

    #[tokio::test]
    async fn a_card_fills_its_typed_slots() {
        let parsed = converted().await;
        let cipher = cipher(&parsed, "Card: monthYear expiry, CVV and PIN");
        let card = card_of(cipher);

        assert_eq!(card.cardholder_name.as_deref(), Some("Jane Q. Tester"));
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.code.as_deref(), Some("123"));
        // 1Password sends `202811`, which Bitwarden keeps as two values.
        assert_eq!(card.exp_month.as_deref(), Some("11"));
        assert_eq!(card.exp_year.as_deref(), Some("2028"));
        // The item leaves its card type empty, so there is no brand to map.
        assert_eq!(card.brand, None);

        // Everything the card type has no room for stays with the item.
        let fields = fields_of(cipher);
        assert!(fields.contains(&(0, "valid from", "2024-01")));
        assert!(fields.contains(&(1, "PIN", "1357")));
        assert!(fields.contains(&(0, "interest rate", "19.9%")));
        assert!(!fields.iter().any(|(_, name, _)| *name == "number"));
    }

    /// 1Password writes its own card type ids, so `mc` has to become `Mastercard` rather than
    /// reaching the vault as it stands. An id with no Bitwarden brand keeps its own field.
    #[test]
    fn a_card_type_maps_onto_a_bitwarden_brand() {
        assert_eq!(card_brand("visa").as_deref(), Some("Visa"));
        assert_eq!(card_brand("mc").as_deref(), Some("Mastercard"));
        assert_eq!(card_brand("americanexpress").as_deref(), Some("Amex"));
        assert_eq!(card_brand("diners").as_deref(), Some("Diners Club"));
        assert_eq!(card_brand("jcb").as_deref(), Some("JCB"));
        assert_eq!(card_brand("mercadolivre"), None);
    }

    /// A month outside 1..=12 is not a month/year at all, so the raw value survives instead.
    #[test]
    fn a_malformed_month_year_keeps_its_digits() {
        assert_eq!(
            fields_from_json(section_field("monthYear", serde_json::json!(209913))),
            [(0, "the field".to_string(), "209913".to_string())]
        );
    }

    #[tokio::test]
    async fn a_date_renders_as_a_calendar_day() {
        let parsed = converted().await;
        let fields = fields_of(cipher(&parsed, "Passport: three date fields and text"));

        assert!(fields.contains(&(0, "date of birth", "1990-03-15")));
        assert!(fields.contains(&(0, "issued on", "2020-07-01")));
        assert!(fields.contains(&(0, "expiry date", "2030-06-30")));
    }

    /// 1Password writes midnight in the writer's own zone: the first stamp is midnight in Berlin,
    /// the second midnight in New York, and both mean the fourth of March.
    #[test]
    fn a_date_lands_on_the_same_day_from_either_side_of_utc() {
        for seconds in [1772578800, 1772600400] {
            assert_eq!(
                fields_from_json(section_field("date", serde_json::json!(seconds))),
                [(0, "the field".to_string(), "2026-03-04".to_string())],
                "{seconds} landed on the wrong day"
            );
        }
    }

    /// The parts keep the order 1Password sent them in.
    #[test]
    fn an_address_becomes_one_field_per_part_it_fills_in() {
        let address = serde_json::json!({
            "street": "221B Baker Street",
            "city": "London",
            "state": "",
            "zip": "NW1 6XE",
        });

        assert_eq!(
            fields_from_json(section_field("address", address)),
            [
                (0, "street".to_string(), "221B Baker Street".to_string()),
                (0, "city".to_string(), "London".to_string()),
                (0, "zip".to_string(), "NW1 6XE".to_string()),
            ]
        );
    }

    /// An attachment's value carries the keys that unwrap the stored file, so only its name is
    /// kept: the file itself cannot be imported.
    #[tokio::test]
    async fn an_attachment_keeps_only_its_name() {
        let parsed = converted().await;

        assert_eq!(
            fields_of(cipher(&parsed, "Login: file attachment")),
            [(0, "attached", "<attachment: attached>")]
        );
    }

    /// The categories still waiting for a mapping. Each one leaves this list as its step lands, so
    /// the assertion failing is the reminder to move it into a test of its own.
    #[tokio::test]
    async fn unmapped_categories_are_still_secure_notes() {
        let parsed = converted().await;

        for name in [
            "Bank account: concealed PIN and branch section",
            "Passport: three date fields and text",
            "Document: uploaded text file",
        ] {
            let cipher = cipher(&parsed, name);
            assert!(
                matches!(cipher.r#type, CipherType::SecureNote(_)),
                "{name} is mapped now, give it its own test"
            );
        }
    }
}
