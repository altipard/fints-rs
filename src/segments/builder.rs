//! Segment builders: functions that create `Vec<DEG>` for each request segment type.
//!
//! All builders are `pub(crate)` — they are internal implementation details.
//! External consumers should use the typed methods on `Dialog<Open>` instead.

use chrono::{Local, NaiveDate};

use crate::error::{FinTSError, Result};
use crate::parser::{DataElement, DEG};
use crate::types::*;

// ---- KTI (Kontoverbindung International) ----

/// Typed representation of a KTI DEG (Kontoverbindung International, version 1).
///
/// Per the FinTS spec, KTI has 5 data elements in this order:
///   1. IBAN
///   2. BIC
///   3. Konto-/Depotnummer (account number, optional)
///   4. Unterkontomerkmal (sub-account feature, optional)
///   5. Kreditinstitutskennung (bank identifier DEG: country_code:blz, optional)
///
/// All fields except IBAN and BIC are optional. When using SEPA accounts,
/// only IBAN and BIC are populated — the serializer strips trailing empties,
/// so the wire format is simply `IBAN:BIC`.
///
/// Using a struct instead of a raw `Vec<DataElement>` ensures the field order
/// and presence are correct at compile time.
struct Kti {
    iban: String,
    bic: String,
}

impl Kti {
    /// Create a new KTI for the given IBAN and BIC.
    /// Fails if either is empty (use the bank's BIC as fallback).
    fn new(iban: &str, bic: &str) -> Result<Self> {
        if iban.is_empty() {
            return Err(FinTSError::Dialog("IBAN must not be empty in KTI DEG".into()));
        }
        if bic.is_empty() {
            return Err(FinTSError::Dialog(
                "BIC must not be empty in KTI DEG — use the bank's BIC as fallback".into(),
            ));
        }
        Ok(Self {
            iban: iban.to_string(),
            bic: bic.to_string(),
        })
    }

    /// Serialize into a DEG: `IBAN:BIC`.
    ///
    /// Only IBAN and BIC are populated. The remaining optional fields
    /// (account_number, sub-account, bank_identifier) are omitted — the
    /// serializer strips trailing empties automatically.
    fn to_deg(&self) -> DEG {
        deg(vec![
            DataElement::Text(self.iban.clone()),
            DataElement::Text(self.bic.clone()),
        ])
    }
}

// ---- Segment Header ----

/// Create a segment header DEG: `TYPE:NUMBER:VERSION`
pub(crate) fn seg_header(seg_type: &str, number: u16, version: u16) -> DEG {
    deg(vec![de_text(seg_type), de_num(number), de_num(version)])
}

/// Create a segment header with reference: `TYPE:NUMBER:VERSION:REFERENCE`
pub(crate) fn seg_header_ref(seg_type: &str, number: u16, version: u16, reference: u16) -> DEG {
    deg(vec![
        de_text(seg_type),
        de_num(number),
        de_num(version),
        de_num(reference),
    ])
}

// ---- HNHBK (Nachrichtenkopf) - Message Header, version 3 ----

/// Build HNHBK:1:3 (message header).
/// `message_size` should be 12-digit zero-padded. Caller must update this after final serialization.
pub(crate) fn hnhbk(message_size: u32, dialog_id: &str, message_number: u16) -> Vec<DEG> {
    vec![
        seg_header("HNHBK", 1, 3),
        deg1(de_text(&format!("{:012}", message_size))), // message size (12 digits)
        deg1(de_text("300")),                            // HBCI version 3.0
        deg1(de_text(dialog_id)),                        // dialog ID
        deg1(de_num(message_number)),                    // message number
    ]
}

// ---- HNHBS (Nachrichtenabschluss) - Message Trailer, version 1 ----

pub(crate) fn hnhbs(segment_number: u16, message_number: u16) -> Vec<DEG> {
    vec![
        seg_header("HNHBS", segment_number, 1),
        deg1(de_num(message_number)),
    ]
}

// ---- HNVSK (Verschlüsselungskopf) - Encryption Header, version 3 ----

/// Security profile DEG "PIN:<version>". Version 1 is the one-step procedure
/// (security function 999), every two-step procedure (9xx) needs version 2.
/// HNVSK and HNSHK of one message must carry the same profile.
fn pin_profile(security_function: &str) -> DEG {
    let version = if security_function == "999" { "1" } else { "2" };
    deg(vec![de_text("PIN"), de_text(version)])
}

/// Build HNVSK:998:3 with PinTan dummy encryption parameters.
/// `security_function` is the one used for the HNSHK of the same message.
pub(crate) fn hnvsk(blz: &str, user_id: &str, system_id: &str, security_function: &str) -> Vec<DEG> {
    vec![
        seg_header("HNVSK", 998, 3),
        // Security profile: PIN:1 (one-step) or PIN:2 (two-step)
        pin_profile(security_function),
        // Security function: 998 (encryption)
        deg1(de_text("998")),
        // Security role: 1 = ISS (issuer)
        deg1(de_text("1")),
        // Security identification: party=1 (MS, message sender), cid=empty, system_id
        deg(vec![de_text("1"), de_empty(), de_text(system_id)]),
        // Security timestamp: type=1 (STS), date (YYYYMMDD), time (HHMMSS)
        {
            let now = Local::now();
            deg(vec![
                de_text("1"),
                de_text(&now.format("%Y%m%d").to_string()),
                de_text(&now.format("%H%M%S").to_string()),
            ])
        },
        // Encryption algorithm: dummy 2-key 3DES CBC
        // usage=2, op_mode=2, alg=13, key=@8@00000000, param_name=5, param_iv_name=1
        deg(vec![
            de_text("2"),
            de_text("2"),
            de_text("13"),
            de_binary(vec![0u8; 8]),
            de_text("5"),
            de_text("1"),
        ]),
        // Key name: country:blz:user_id:V(cipher):0:0
        deg(vec![
            de_text("280"),
            de_text(blz),
            de_text(user_id),
            de_text("V"),
            de_text("0"),
            de_text("0"),
        ]),
        // Compression: 0 = NULL
        deg1(de_text("0")),
    ]
}

// ---- HNVSD (Verschlüsselte Daten) - Encrypted Data Container, version 1 ----

/// Build HNVSD:999:1 wrapping inner segment bytes.
pub(crate) fn hnvsd(inner_bytes: &[u8]) -> Vec<DEG> {
    vec![
        seg_header("HNVSD", 999, 1),
        deg1(de_binary(inner_bytes.to_vec())),
    ]
}

// ---- HNSHK (Signaturkopf) - Signature Header, version 4 ----

/// Build HNSHK:n:4 with PinTan signature parameters.
pub(crate) fn hnshk(
    segment_number: u16,
    security_function: &str,
    security_reference: u32,
    blz: &str,
    user_id: &str,
    system_id: &str,
) -> Vec<DEG> {
    vec![
        seg_header("HNSHK", segment_number, 4),
        // Security profile: PIN:1 (one-step) or PIN:2 (two-step)
        pin_profile(security_function),
        // Security function (e.g. "999" for one-step, "912" for pushTAN)
        deg1(de_text(security_function)),
        // Security reference (random number linking HNSHK <-> HNSHA)
        deg1(de_num(security_reference)),
        // Security application area: 1 = SHM
        deg1(de_text("1")),
        // Security role: 1 = ISS
        deg1(de_text("1")),
        // Security identification: party=1 (MS, message sender), cid=empty, system_id
        deg(vec![de_text("1"), de_empty(), de_text(system_id)]),
        // Security reference number: 2 (as sent by clients the HVB accepts)
        deg1(de_text("2")),
        // Security timestamp: type=1 (STS), date (YYYYMMDD), time (HHMMSS)
        {
            let now = Local::now();
            deg(vec![
                de_text("1"),
                de_text(&now.format("%Y%m%d").to_string()),
                de_text(&now.format("%H%M%S").to_string()),
            ])
        },
        // Hash algorithm: dummy (usage=1, alg=999, param=1)
        deg(vec![de_text("1"), de_text("999"), de_text("1")]),
        // Signature algorithm: dummy (usage=6, alg=10, mode=16)
        deg(vec![de_text("6"), de_text("10"), de_text("16")]),
        // Key name: country:blz:user_id:S(signing):0:0
        deg(vec![
            de_text("280"),
            de_text(blz),
            de_text(user_id),
            de_text("S"),
            de_text("0"),
            de_text("0"),
        ]),
    ]
}

// ---- HNSHA (Signaturabschluss) - Signature Trailer, version 2 ----

/// Build HNSHA:n:2 with PIN and optional TAN.
pub(crate) fn hnsha(
    segment_number: u16,
    security_reference: u32,
    pin: &str,
    tan: Option<&str>,
) -> Vec<DEG> {
    let mut user_sig_elements = vec![de_text(pin)];
    if let Some(t) = tan {
        // For empty TAN (after decoupled confirmation), force an empty-but-present field.
        // de_text("") returns DataElement::Empty which the serializer omits entirely.
        // We need DataElement::Text("") to produce the ':' separator in the output.
        if t.is_empty() {
            user_sig_elements.push(crate::parser::DataElement::Text(String::new()));
        } else {
            user_sig_elements.push(de_text(t));
        }
    }
    vec![
        seg_header("HNSHA", segment_number, 2),
        // Security reference (must match HNSHK)
        deg1(de_num(security_reference)),
        // Validation result: empty
        deg1(de_empty()),
        // User defined signature: PIN[:TAN]
        deg(user_sig_elements),
    ]
}

// ---- HKIDN (Identifikation) - version 2 ----

pub(crate) fn hkidn(segment_number: u16, blz: &str, user_id: &str, system_id: &str) -> Vec<DEG> {
    vec![
        seg_header("HKIDN", segment_number, 2),
        // Bank identifier: country(280):blz
        deg(vec![de_text("280"), de_text(blz)]),
        // Customer ID
        deg1(de_text(user_id)),
        // System ID (0 = not yet assigned)
        deg1(de_text(system_id)),
        // System ID required: 1
        deg1(de_text("1")),
    ]
}

// ---- HKVVB (Verarbeitungsvorbereitung) - Processing Preparation, version 3 ----

pub(crate) fn hkvvb(
    segment_number: u16,
    bpd_version: u16,
    upd_version: u16,
    product_id: &str,
) -> Vec<DEG> {
    vec![
        seg_header("HKVVB", segment_number, 3),
        // BPD version (0 = request full BPD)
        deg1(de_num(bpd_version)),
        // UPD version (0 = request full UPD)
        deg1(de_num(upd_version)),
        // Dialog language: 1 = German
        deg1(de_text("1")),
        // Product ID
        deg1(de_text(product_id)),
        // Product version
        deg1(de_text("1.0")),
    ]
}

// ---- HKSYN (Synchronisierung) - Synchronization, version 3 ----

/// Build HKSYN:n:3 to request a new system ID.
pub(crate) fn hksyn(segment_number: u16) -> Vec<DEG> {
    vec![
        seg_header("HKSYN", segment_number, 3),
        // Synchronization mode: 0 = request new system ID
        deg1(de_text("0")),
    ]
}

// ---- HKEND (Dialogende) - Dialog End, version 1 ----

pub(crate) fn hkend(segment_number: u16, dialog_id: &str) -> Vec<DEG> {
    vec![
        seg_header("HKEND", segment_number, 1),
        deg1(de_text(dialog_id)),
    ]
}

// ---- HKTAN (TAN-Verfahren) - TAN Segment, version 6/7 ----

/// Build HKTAN for process 4 (request challenge) — used in dialog init.
pub(crate) fn hktan_process4(
    segment_number: u16,
    version: u16,
    segment_type: &str,
    tan_medium_name: Option<&str>,
) -> Vec<DEG> {
    let mut degs = vec![
        seg_header("HKTAN", segment_number, version),
        // TAN process: 4 = request challenge
        deg1(de_text("4")),
        // Segment type (e.g. "HKIDN")
        deg1(de_text(segment_type)),
    ];

    if version >= 6 {
        // account, order_hash_value, order_reference, further_tan_follows,
        // cancel_order, sms_charge_account, challenge_class,
        // challenge_class_params, tan_medium_name. Trailing empty DEs are
        // omitted, banks reject superfluous ones.
        let mut tail: Vec<Option<&str>> = vec![None; 8];
        tail.push(tan_medium_name);
        while matches!(tail.last(), Some(None)) {
            tail.pop();
        }
        degs.extend(tail.into_iter().map(|f| match f {
            Some(v) => deg1(de_text(v)),
            None => deg1(de_empty()),
        }));
    } else if let Some(name) = tan_medium_name {
        degs.push(deg1(de_text(name)));
    }

    degs
}

/// Build HKTAN for process 2 (submit TAN) — completing a two-step operation.
pub(crate) fn hktan_process2(
    segment_number: u16,
    version: u16,
    task_reference: &str,
    tan_medium_name: Option<&str>,
) -> Vec<DEG> {
    let mut degs = vec![
        seg_header("HKTAN", segment_number, version),
        // TAN process: 2 = submit TAN
        deg1(de_text("2")),
    ];

    if version >= 6 {
        degs.push(deg1(de_empty())); // segment_type (not needed for process 2)
        degs.push(deg1(de_empty())); // account
        degs.push(deg1(de_empty())); // order_hash_value
        degs.push(deg1(de_text(task_reference))); // task reference (from HITAN)
        degs.push(deg1(de_bool(false))); // further_tan_follows = N
        // cancel_order only as filler in front of the medium name, trailing empty DEs are rejected
        if tan_medium_name.is_some() {
            degs.push(deg1(de_empty())); // cancel_order
        }
    } else {
        degs.push(deg1(de_empty())); // segment_type
        degs.push(deg1(de_empty())); // account
        degs.push(deg1(de_text(task_reference))); // task reference
        degs.push(deg1(de_bool(false))); // further_tan_follows
    }

    if let Some(name) = tan_medium_name {
        if version >= 6 {
            degs.push(deg1(de_empty())); // sms_charge_account
            degs.push(deg1(de_empty())); // challenge_class
            degs.push(deg1(de_empty())); // challenge_class_params
        }
        degs.push(deg1(de_text(name)));
    }

    degs
}

/// Build HKTAN for process S (decoupled polling).
pub(crate) fn hktan_process_s(
    segment_number: u16,
    version: u16,
    task_reference: &str,
    tan_medium_name: Option<&str>,
) -> Vec<DEG> {
    let mut degs = vec![
        seg_header("HKTAN", segment_number, version),
        // TAN process: S = decoupled status check
        deg1(de_text("S")),
    ];

    if version >= 6 {
        degs.push(deg1(de_empty())); // segment_type
        degs.push(deg1(de_empty())); // account
        degs.push(deg1(de_empty())); // order_hash_value
        degs.push(deg1(de_text(task_reference))); // task reference
        degs.push(deg1(de_bool(false))); // further_tan_follows
        degs.push(deg1(de_empty())); // cancel_order
    } else {
        degs.push(deg1(de_empty()));
        degs.push(deg1(de_empty()));
        degs.push(deg1(de_text(task_reference)));
        degs.push(deg1(de_bool(false)));
    }

    if let Some(name) = tan_medium_name {
        if version >= 6 {
            degs.push(deg1(de_empty()));
            degs.push(deg1(de_empty()));
            degs.push(deg1(de_empty()));
        }
        degs.push(deg1(de_text(name)));
    }

    degs
}

// ---- HKTAB (TAN-Medium anfordern) - TAN Media List Request, version 4/5 ----

/// Build HKTAB to request the list of registered TAN media (devices).
/// Returns HITAB response with device names needed for pushTAN.
pub(crate) fn hktab(segment_number: u16, version: u16) -> Vec<DEG> {
    vec![
        seg_header("HKTAB", segment_number, version),
        // TAN medium class: A = all
        deg1(de_text("A")),
    ]
}

// ---- HKSPA (SEPA-Kontoverbindung anfordern) - SEPA Account Info, version 1-3 ----

pub(crate) fn hkspa(segment_number: u16, version: u16) -> Vec<DEG> {
    vec![seg_header("HKSPA", segment_number, version)]
}

// ---- Account reference for HKSAL/HKKAZ ----

/// Account as addressed in HKSAL/HKKAZ. Versions up to 6 take the national
/// account (KTV: number:sub-account:280:BLZ), version 7 the international one (KTI).
pub(crate) struct AccountRef<'a> {
    pub iban: &'a str,
    pub bic: &'a str,
    /// Account number, sub-account feature and BLZ of the account, from HIUPD.
    pub national: Option<(&'a str, &'a str, &'a str)>,
}

impl AccountRef<'_> {
    /// Account DEG for the given segment version.
    fn to_deg(&self, version: u16) -> Result<DEG> {
        if version >= 7 {
            return Ok(Kti::new(self.iban, self.bic)?.to_deg());
        }
        match self.national {
            Some((number, sub_account, blz)) if !number.is_empty() && !blz.is_empty() => Ok(deg(vec![
                de_text(number),
                if sub_account.is_empty() { de_empty() } else { de_text(sub_account) },
                de_text("280"),
                de_text(blz),
            ])),
            _ => Err(FinTSError::Dialog(format!(
                "account number and BLZ of {} missing in HIUPD, needed for version {}",
                self.iban, version
            ))),
        }
    }
}

// ---- HKSAL (Saldenabfrage) - Balance Request, version 5-7 ----

/// Build HKSAL. Version 7 uses the international account (IBAN/BIC), older ones the national one.
pub(crate) fn hksal(
    segment_number: u16,
    version: u16,
    account: &AccountRef<'_>,
    touchdown: Option<&str>,
) -> Result<Vec<DEG>> {
    let mut degs = vec![
        seg_header("HKSAL", segment_number, version),
        account.to_deg(version)?,
        deg1(de_text("N")),
    ];

    // Max entries (optional)
    degs.push(deg1(de_empty()));

    // Touchdown point
    if let Some(td) = touchdown {
        degs.push(deg1(de_text(td)));
    }

    Ok(degs)
}

// ---- HKKAZ (Kontoumsätze anfordern) - Statement Request (MT940), version 5-7 ----

pub(crate) fn hkkaz(
    segment_number: u16,
    version: u16,
    account: &AccountRef<'_>,
    start_date: NaiveDate,
    end_date: NaiveDate,
    touchdown: Option<&str>,
) -> Result<Vec<DEG>> {
    let mut degs = vec![
        seg_header("HKKAZ", segment_number, version),
        account.to_deg(version)?,
        deg1(de_text("N")),
        deg1(de_date(start_date)),
        deg1(de_date(end_date)),
    ];

    // Max entries
    degs.push(deg1(de_empty()));

    // Touchdown
    if let Some(td) = touchdown {
        degs.push(deg1(de_text(td)));
    }

    Ok(degs)
}

// ---- HKWPD (Wertpapierdepotaufstellung) - Securities Holdings Request, version 1-7 ----

/// Build HKWPD to request the securities depot listing for a SEPA account.
/// HKWPD returns HIWPD response with depot positions.
///
/// FinTS spec structure:
///   DEG0 = header (HKWPD:seg_num:version)
///   DEG1 = account connection (KTI: IBAN:BIC)
///   DEG2 = currency (optional, e.g. "EUR" — request prices in this currency)
///   DEG3 = quality of data (1=current, 2=cached/last known — optional)
///   DEG4 = max entries (optional)
///   DEG5 = touchdown point (optional, for pagination)
pub(crate) fn hkwpd(
    segment_number: u16,
    version: u16,
    iban: &str,
    bic: &str,
    currency: Option<&str>,
    touchdown: Option<&str>,
) -> Result<Vec<DEG>> {
    let mut degs = if version >= 6 {
        // Version 6+: international account (KTI)
        vec![
            seg_header("HKWPD", segment_number, version),
            Kti::new(iban, bic)?.to_deg(),
        ]
    } else {
        // Older versions: national account format
        vec![
            seg_header("HKWPD", segment_number, version),
            deg(vec![
                de_text(iban),
                de_empty(),
                de_text("280"),
                de_text(bic),
            ]),
        ]
    };

    // Currency (optional)
    degs.push(deg1(if let Some(cur) = currency {
        de_text(cur)
    } else {
        de_empty()
    }));

    // Quality of data (optional) — request current data
    degs.push(deg1(de_empty()));

    // Max entries (optional)
    degs.push(deg1(de_empty()));

    // Touchdown point (optional)
    if let Some(td) = touchdown {
        degs.push(deg1(de_text(td)));
    }

    Ok(degs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serializer::{serialize_deg, serialize_segment};

    #[test]
    fn kti_produces_two_data_elements() {
        let kti = Kti::new("DE04120300001084174299", "BYLADEM1001").unwrap();
        let deg = kti.to_deg();
        // KTI DEG: IBAN:BIC (optional trailing fields omitted)
        assert_eq!(deg.0.len(), 2, "KTI DEG must have exactly 2 data elements");
        assert_eq!(deg.get_str(0), "DE04120300001084174299");
        assert_eq!(deg.get_str(1), "BYLADEM1001");
    }

    #[test]
    fn kti_serializes_as_iban_colon_bic() {
        let kti = Kti::new("DE04120300001084174299", "BYLADEM1001").unwrap();
        let bytes = serialize_deg(&kti.to_deg()).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        // Wire format: IBAN:BIC
        assert_eq!(wire, "DE04120300001084174299:BYLADEM1001");
    }

    #[test]
    fn hksal_v7_wire_format() {
        let degs = hksal(3, 7, &AccountRef { iban: "DE04120300001084174299", bic: "BYLADEM1001", national: None }, None).unwrap();
        let bytes = serialize_segment(&degs).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert_eq!(wire, "HKSAL:3:7+DE04120300001084174299:BYLADEM1001+N'");
    }

    #[test]
    fn hkkaz_v7_wire_format() {
        let start = chrono::NaiveDate::from_ymd_opt(2025, 3, 29).unwrap();
        let end = chrono::NaiveDate::from_ymd_opt(2026, 3, 29).unwrap();
        let acct = AccountRef { iban: "DE04120300001084174299", bic: "BYLADEM1001", national: None };
        let degs = hkkaz(3, 7, &acct, start, end, None).unwrap();
        let bytes = serialize_segment(&degs).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert_eq!(
            wire,
            "HKKAZ:3:7+DE04120300001084174299:BYLADEM1001+N+20250329+20260329'"
        );
    }

    #[test]
    fn hkwpd_v7_wire_format() {
        let degs = hkwpd(3, 7, "DE04120300001084174299", "BYLADEM1001", None, None).unwrap();
        let bytes = serialize_segment(&degs).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert_eq!(wire, "HKWPD:3:7+DE04120300001084174299:BYLADEM1001'");
    }

    #[test]
    fn hkwpd_v7_with_currency() {
        let degs = hkwpd(
            3,
            7,
            "DE04120300001084174299",
            "BYLADEM1001",
            Some("EUR"),
            None,
        )
        .unwrap();
        let bytes = serialize_segment(&degs).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert_eq!(wire, "HKWPD:3:7+DE04120300001084174299:BYLADEM1001+EUR'");
    }

    #[test]
    fn hkwpd_v7_with_touchdown() {
        let degs = hkwpd(
            3,
            7,
            "DE04120300001084174299",
            "BYLADEM1001",
            None,
            Some("TOUCH123"),
        )
        .unwrap();
        let bytes = serialize_segment(&degs).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        // DEGs: header + KTI + currency(empty) + quality(empty) + max_entries(empty) + touchdown
        assert_eq!(
            wire,
            "HKWPD:3:7+DE04120300001084174299:BYLADEM1001++++TOUCH123'"
        );
    }

    #[test]
    fn kti_errors_on_empty_iban() {
        let e = Kti::new("", "BYLADEM1001").err().expect("error");
        assert!(e.to_string().contains("IBAN must not be empty"), "{e}");
    }

    #[test]
    fn kti_errors_on_empty_bic() {
        let e = Kti::new("DE04120300001084174299", "").err().expect("error");
        assert!(e.to_string().contains("BIC must not be empty"), "{e}");
    }

    fn wire(degs: &[crate::parser::DEG]) -> String {
        String::from_utf8(serialize_segment(degs).unwrap()).unwrap()
    }

    #[test]
    fn hktan_process4_v6_omits_trailing_empty_des() {
        assert_eq!(wire(&hktan_process4(5, 6, "HKIDN", None)), "HKTAN:5:6+4+HKIDN'");
    }

    #[test]
    fn hktan_process4_v6_pads_up_to_tan_medium() {
        assert_eq!(
            wire(&hktan_process4(5, 6, "HKIDN", Some("iPhone"))),
            "HKTAN:5:6+4+HKIDN+++++++++iPhone'"
        );
    }

    #[test]
    fn hktan_process2_v6_carries_reference_without_trailing_empty_des() {
        assert_eq!(
            wire(&hktan_process2(7, 6, "REF123", None)),
            "HKTAN:7:6+2++++REF123+N'"
        );
        assert_eq!(
            wire(&hktan_process2(7, 6, "REF123", Some("iPhone"))),
            "HKTAN:7:6+2++++REF123+N+++++iPhone'"
        );
    }

    #[test]
    fn hnvsk_hnshk_profile_is_pin1_for_one_step() {
        assert!(wire(&hnvsk("12030000", "user", "sys", "999")).starts_with("HNVSK:998:3+PIN:1+998+"));
        assert!(wire(&hnshk(2, "999", 4711, "12030000", "user", "sys")).starts_with("HNSHK:2:4+PIN:1+999+4711+"));
    }

    #[test]
    fn hnvsk_hnshk_profile_is_pin2_for_two_step() {
        assert!(wire(&hnvsk("70020270", "user", "sys", "904")).starts_with("HNVSK:998:3+PIN:2+998+"));
        assert!(wire(&hnshk(2, "904", 4711, "70020270", "user", "sys")).starts_with("HNSHK:2:4+PIN:2+904+4711+"));
    }

    const HVB_ACCOUNT: AccountRef<'static> = AccountRef {
        iban: "DE02600202900000123456",
        bic: "HYVEDEMM",
        national: Some(("0000123456", "EUR", "60020290")),
    };

    #[test]
    fn hksal_v6_uses_national_account_from_hiupd() {
        assert_eq!(
            wire(&hksal(3, 6, &HVB_ACCOUNT, None).unwrap()),
            "HKSAL:3:6+0000123456:EUR:280:60020290+N'"
        );
    }

    #[test]
    fn hkkaz_v6_uses_national_account_without_sub_account() {
        let acct = AccountRef { national: Some(("0000123456", "", "60020290")), ..HVB_ACCOUNT };
        let start = chrono::NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        let end = chrono::NaiveDate::from_ymd_opt(2026, 10, 23).unwrap();
        assert_eq!(
            wire(&hkkaz(3, 6, &acct, start, end, None).unwrap()),
            "HKKAZ:3:6+0000123456::280:60020290+N+20261017+20261023'"
        );
    }

    #[test]
    fn hksal_v6_without_hiupd_account_is_an_error() {
        let acct = AccountRef { national: None, ..HVB_ACCOUNT };
        assert!(hksal(3, 6, &acct, None).is_err());
    }

    #[test]
    fn hksal_v7_keeps_iban_and_bic() {
        assert_eq!(
            wire(&hksal(3, 7, &HVB_ACCOUNT, None).unwrap()),
            "HKSAL:3:7+DE02600202900000123456:HYVEDEMM+N'"
        );
    }

    /// Replace the volatile parts (timestamp) so the message head can be compared exactly.
    fn mask_timestamp(wire: &str) -> String {
        let mut out = String::new();
        let mut rest = wire;
        while let Some(i) = rest.find("+1:20") {
            out.push_str(&rest[..i]);
            out.push_str("+1:DATE:TIME");
            let tail = &rest[i + 5..];
            let end = tail.find(|c| c == '+' || c == '\'').unwrap_or(tail.len());
            rest = &tail[end..];
        }
        out.push_str(rest);
        out
    }

    #[test]
    fn hnvsk_hnshk_two_step_match_recorded_client() {
        assert_eq!(
            mask_timestamp(&wire(&hnvsk("70020270", "USER", "SYS", "904"))),
            "HNVSK:998:3+PIN:2+998+1+1::SYS+1:DATE:TIME+2:2:13:@8@\0\0\0\0\0\0\0\0:5:1+280:70020270:USER:V:0:0+0'"
        );
        assert_eq!(
            mask_timestamp(&wire(&hnshk(2, "904", 807727152, "70020270", "USER", "SYS"))),
            "HNSHK:2:4+PIN:2+904+807727152+1+1+1::SYS+2+1:DATE:TIME+1:999:1+6:10:16+280:70020270:USER:S:0:0'"
        );
    }
}
