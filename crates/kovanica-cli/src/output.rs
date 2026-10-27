//! Human-readable (table) and JSON output helpers.
//!
//! Every command accepts a global `--json` flag; when set, results are emitted
//! as pretty-printed JSON. Otherwise a compact, column-aligned table is printed.

use anyhow::Result;
use serde_json::Value;

/// Print a value as pretty JSON (used when `--json` is set).
pub fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Print a simple two-column key/value table.
pub fn print_kv(rows: &[(&str, String)]) {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (key, value) in rows {
        println!("{key:<width$}  {value}");
    }
}

/// Print a table with a header row and pre-formatted string cells.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let columns = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(columns) {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let render = |cells: &[String]| {
        let mut line = String::new();
        for (i, width) in widths.iter().enumerate() {
            let cell = cells.get(i).map(String::as_str).unwrap_or("");
            if i + 1 == columns {
                line.push_str(&format!("{cell:<width$}"));
            } else {
                line.push_str(&format!("{cell:<width$}  "));
            }
        }
        line.trim_end().to_string()
    };

    let header: Vec<String> = headers.iter().map(|h| (*h).to_string()).collect();
    println!("{}", render(&header));
    let separator: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", render(&separator));
    for row in rows {
        println!("{}", render(row));
    }
}
