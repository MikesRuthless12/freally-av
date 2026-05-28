//! Browser autofill profile inventory (TASK-270, FEAT-215, Phase 10 Wave 2).
//!
//! Read-only category-level inventory of stored PII. Reads Chromium
//! `Web Data` (`autofill_profiles` + `autofill` + `credit_cards` +
//! `addresses` tables) and Firefox `formhistory.sqlite`
//! (`moz_formhistory`). **Never renders values** — only counts the
//! categories of PII present.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use super::BrowserFamily;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiCategory {
    Email,
    Phone,
    Card,
    Address,
    Name,
    Other,
}

impl PiiCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            PiiCategory::Email => "email",
            PiiCategory::Phone => "phone",
            PiiCategory::Card => "card",
            PiiCategory::Address => "address",
            PiiCategory::Name => "name",
            PiiCategory::Other => "other",
        }
    }
}

/// One inventory row per `(family, category)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutofillInventoryRow {
    pub family: BrowserFamily,
    pub category: PiiCategory,
    pub count: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum AutofillError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
}

/// Map a Chromium `autofill.name` / Firefox `moz_formhistory.fieldname`
/// to a category. Public so the closeout UI can re-use the same logic
/// over its tabular display.
pub fn classify_field(name: &str) -> PiiCategory {
    let lc = name.to_ascii_lowercase();
    if lc.contains("email") || lc.contains("e-mail") {
        return PiiCategory::Email;
    }
    if lc.contains("phone") || lc.contains("tel") || lc.contains("mobile") || lc.contains("cell") {
        return PiiCategory::Phone;
    }
    if lc.contains("card")
        || lc.contains("cc-")
        || lc.contains("ccnum")
        || lc.contains("cvv")
        || lc.contains("cvc")
    {
        return PiiCategory::Card;
    }
    if lc.contains("address")
        || lc.contains("street")
        || lc.contains("city")
        || lc.contains("state")
        || lc.contains("zip")
        || lc.contains("postal")
        || lc.contains("country")
    {
        return PiiCategory::Address;
    }
    if lc.contains("name") || lc.contains("first") || lc.contains("last") || lc.contains("full") {
        return PiiCategory::Name;
    }
    PiiCategory::Other
}

/// Inventory rows from a Chromium `Web Data` SQLite path. Caller is
/// expected to snapshot the live file (browser holds the lock).
pub fn read_chromium_inventory(
    db_path: &Path,
    family: BrowserFamily,
) -> Result<Vec<AutofillInventoryRow>, AutofillError> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    read_chromium_inventory_from_conn(&conn, family)
}

/// Variant of [`read_chromium_inventory`] over an already-open
/// connection — used by tests against `:memory:`.
pub fn read_chromium_inventory_from_conn(
    conn: &Connection,
    family: BrowserFamily,
) -> Result<Vec<AutofillInventoryRow>, AutofillError> {
    let mut counts: HashMap<PiiCategory, i64> = HashMap::new();

    // `autofill` covers free-form web-form history (one row per
    // `name`). We count distinct names, not values.
    if table_exists(conn, "autofill")? {
        let mut stmt = conn.prepare("SELECT DISTINCT name FROM autofill")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for r in rows {
            *counts.entry(classify_field(&r?)).or_insert(0) += 1;
        }
    }

    // `autofill_profiles` are structured address rows.
    if table_exists(conn, "autofill_profiles")? {
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM autofill_profiles")?;
        let n: i64 = stmt.query_row([], |row| row.get(0))?;
        if n > 0 {
            *counts.entry(PiiCategory::Address).or_insert(0) += n;
        }
    }

    // `credit_cards` is its own table; one row per saved card.
    if table_exists(conn, "credit_cards")? {
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM credit_cards")?;
        let n: i64 = stmt.query_row([], |row| row.get(0))?;
        if n > 0 {
            *counts.entry(PiiCategory::Card).or_insert(0) += n;
        }
    }

    Ok(materialise_rows(family, counts))
}

/// Inventory rows from a Firefox `formhistory.sqlite` path.
pub fn read_firefox_inventory(db_path: &Path) -> Result<Vec<AutofillInventoryRow>, AutofillError> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    read_firefox_inventory_from_conn(&conn)
}

pub fn read_firefox_inventory_from_conn(
    conn: &Connection,
) -> Result<Vec<AutofillInventoryRow>, AutofillError> {
    let mut counts: HashMap<PiiCategory, i64> = HashMap::new();
    if table_exists(conn, "moz_formhistory")? {
        let mut stmt = conn.prepare("SELECT DISTINCT fieldname FROM moz_formhistory")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for r in rows {
            *counts.entry(classify_field(&r?)).or_insert(0) += 1;
        }
    }
    Ok(materialise_rows(BrowserFamily::Firefox, counts))
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool, AutofillError> {
    let mut stmt =
        conn.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ? LIMIT 1")?;
    let n: i64 = stmt.query_row([name], |row| row.get(0)).unwrap_or(0);
    Ok(n == 1)
}

fn materialise_rows(
    family: BrowserFamily,
    counts: HashMap<PiiCategory, i64>,
) -> Vec<AutofillInventoryRow> {
    let mut out: Vec<AutofillInventoryRow> = counts
        .into_iter()
        .map(|(category, count)| AutofillInventoryRow {
            family,
            category,
            count,
        })
        .collect();
    out.sort_by_key(|r| r.category.as_str());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    #[test]
    fn classify_field_buckets_each_category() {
        assert_eq!(classify_field("email"), PiiCategory::Email);
        assert_eq!(classify_field("user-email"), PiiCategory::Email);
        assert_eq!(classify_field("phoneNumber"), PiiCategory::Phone);
        assert_eq!(classify_field("cc-number"), PiiCategory::Card);
        assert_eq!(classify_field("ccnum"), PiiCategory::Card);
        assert_eq!(classify_field("cvv"), PiiCategory::Card);
        assert_eq!(classify_field("street1"), PiiCategory::Address);
        assert_eq!(classify_field("postalCode"), PiiCategory::Address);
        assert_eq!(classify_field("firstName"), PiiCategory::Name);
        assert_eq!(classify_field("zzzz"), PiiCategory::Other);
    }

    fn make_chromium_schema(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE autofill (
                name VARCHAR,
                value VARCHAR
            );
            CREATE TABLE autofill_profiles (
                guid VARCHAR PRIMARY KEY,
                use_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE credit_cards (
                guid VARCHAR PRIMARY KEY,
                name_on_card VARCHAR
            );",
        )
        .unwrap();
    }

    #[test]
    fn chromium_inventory_collapses_by_category() {
        let conn = Connection::open_in_memory().unwrap();
        make_chromium_schema(&conn);
        for n in ["email", "user_email", "phone", "firstName"] {
            conn.execute(
                "INSERT INTO autofill (name, value) VALUES (?, '')",
                params![n],
            )
            .unwrap();
        }
        conn.execute("INSERT INTO autofill_profiles (guid) VALUES ('a')", [])
            .unwrap();
        conn.execute("INSERT INTO autofill_profiles (guid) VALUES ('b')", [])
            .unwrap();
        conn.execute(
            "INSERT INTO credit_cards (guid, name_on_card) VALUES ('c', 'x')",
            [],
        )
        .unwrap();

        let rows = read_chromium_inventory_from_conn(&conn, BrowserFamily::Chrome).unwrap();
        let lookup: HashMap<PiiCategory, i64> =
            rows.iter().map(|r| (r.category, r.count)).collect();
        // 2 emails, 1 phone, 1 name (autofill table) + 2 addresses
        // (autofill_profiles) + 1 card (credit_cards).
        assert_eq!(lookup.get(&PiiCategory::Email).copied(), Some(2));
        assert_eq!(lookup.get(&PiiCategory::Phone).copied(), Some(1));
        assert_eq!(lookup.get(&PiiCategory::Name).copied(), Some(1));
        assert_eq!(lookup.get(&PiiCategory::Address).copied(), Some(2));
        assert_eq!(lookup.get(&PiiCategory::Card).copied(), Some(1));
    }

    #[test]
    fn firefox_inventory_counts_distinct_fieldnames() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE moz_formhistory (
                id INTEGER PRIMARY KEY,
                fieldname TEXT NOT NULL,
                value TEXT NOT NULL
            )",
            [],
        )
        .unwrap();
        for (n, v) in [
            ("email", "a"),
            ("email", "b"), // dupe field name
            ("phone", "c"),
            ("address", "d"),
            ("address", "e"),
            ("address", "f"),
            ("favorite_color", "purple"),
        ] {
            conn.execute(
                "INSERT INTO moz_formhistory (fieldname, value) VALUES (?, ?)",
                params![n, v],
            )
            .unwrap();
        }
        let rows = read_firefox_inventory_from_conn(&conn).unwrap();
        let lookup: HashMap<PiiCategory, i64> =
            rows.iter().map(|r| (r.category, r.count)).collect();
        // DISTINCT collapses to 4 fieldnames: email, phone, address,
        // favorite_color.
        assert_eq!(lookup.get(&PiiCategory::Email).copied(), Some(1));
        assert_eq!(lookup.get(&PiiCategory::Phone).copied(), Some(1));
        assert_eq!(lookup.get(&PiiCategory::Address).copied(), Some(1));
        assert_eq!(lookup.get(&PiiCategory::Other).copied(), Some(1));
    }

    #[test]
    fn missing_tables_produce_empty_inventory() {
        let conn = Connection::open_in_memory().unwrap();
        let rows = read_chromium_inventory_from_conn(&conn, BrowserFamily::Chrome).unwrap();
        assert!(rows.is_empty());
        let rows = read_firefox_inventory_from_conn(&conn).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn rows_carry_family_label() {
        let conn = Connection::open_in_memory().unwrap();
        make_chromium_schema(&conn);
        conn.execute(
            "INSERT INTO credit_cards (guid, name_on_card) VALUES ('c', 'x')",
            [],
        )
        .unwrap();
        let rows = read_chromium_inventory_from_conn(&conn, BrowserFamily::Edge).unwrap();
        assert!(rows.iter().all(|r| r.family == BrowserFamily::Edge));
    }
}
