//! Inventory assertions and saved queries (AE-IOT-0011 user-defined
//! checks over the inventory evaluated continuously; AE-IOT-0014 presets
//! / saved views; ZTE-IOT section 105 Search And Reporting).
//!
//! A small, bounded expression language over asset fields:
//!
//! ```text
//! category == "industrial_control" and (firmware < "2.9.7" or risk_score >= 70)
//! vendor ~ "siemens" and not tags in ["lab", "spare"]
//! serial exists and lifecycle != "decommissioned"
//! ```
//!
//! Operators: `== != < <= > >=` (numbers numerically, `firmware`/`*_version`
//! fields version-aware, strings case-insensitively), `~` (contains),
//! `in [..]`, `exists`; `and`, `or`, `not`, parentheses. Expressions are
//! limited to 2000 characters, 64 comparisons and nesting depth 16.

use crate::vuln::cmp_version;
use serde_json::Value;
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Num(f64),
    Op(String),
    LParen,
    RParen,
    LBrack,
    RBrack,
    Comma,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Cmp(String, String, Value),
    In(String, Vec<Value>),
    Exists(String),
}

pub const MAX_LEN: usize = 2000;
const MAX_TERMS: usize = 64;
const MAX_DEPTH: usize = 16;

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    if s.len() > MAX_LEN {
        return Err("expression too long".into());
    }
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = vec![];
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch == '(' {
            out.push(Tok::LParen);
            i += 1;
        } else if ch == ')' {
            out.push(Tok::RParen);
            i += 1;
        } else if ch == '[' {
            out.push(Tok::LBrack);
            i += 1;
        } else if ch == ']' {
            out.push(Tok::RBrack);
            i += 1;
        } else if ch == ',' {
            out.push(Tok::Comma);
            i += 1;
        } else if ch == '"' {
            let mut v = String::new();
            i += 1;
            while i < c.len() && c[i] != '"' {
                if c[i] == '\\' && i + 1 < c.len() {
                    i += 1;
                }
                v.push(c[i]);
                i += 1;
            }
            if i >= c.len() {
                return Err("unterminated string".into());
            }
            i += 1;
            out.push(Tok::Str(v));
        } else if "=!<>~".contains(ch) {
            let two: String = c[i..(i + 2).min(c.len())].iter().collect();
            if ["==", "!=", "<=", ">="].contains(&two.as_str()) {
                out.push(Tok::Op(two));
                i += 2;
            } else if ch == '<' || ch == '>' || ch == '~' {
                out.push(Tok::Op(ch.to_string()));
                i += 1;
            } else {
                return Err(format!("unexpected '{ch}'"));
            }
        } else if ch.is_ascii_digit() || (ch == '-' && c.get(i + 1).map(|d| d.is_ascii_digit()).unwrap_or(false)) {
            let st = i;
            i += 1;
            while i < c.len() && (c[i].is_ascii_digit() || c[i] == '.') {
                i += 1;
            }
            let n: String = c[st..i].iter().collect();
            out.push(Tok::Num(n.parse().map_err(|_| format!("bad number {n}"))?));
        } else if ch.is_ascii_alphabetic() || ch == '_' {
            let st = i;
            while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_' || c[i] == '.') {
                i += 1;
            }
            out.push(Tok::Ident(c[st..i].iter().collect()));
        } else {
            return Err(format!("unexpected '{ch}'"));
        }
    }
    Ok(out)
}

struct P {
    t: Vec<Tok>,
    i: usize,
    terms: usize,
}

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }
    fn kw(&self, k: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(x)) if x.eq_ignore_ascii_case(k))
    }
    fn or(&mut self, d: usize) -> Result<Expr, String> {
        if d > MAX_DEPTH {
            return Err("expression nested too deeply".into());
        }
        let mut v = vec![self.and(d)?];
        while self.kw("or") {
            self.i += 1;
            v.push(self.and(d)?);
        }
        Ok(if v.len() == 1 { v.pop().unwrap_or(Expr::And(vec![])) } else { Expr::Or(v) })
    }
    fn and(&mut self, d: usize) -> Result<Expr, String> {
        let mut v = vec![self.not(d)?];
        while self.kw("and") {
            self.i += 1;
            v.push(self.not(d)?);
        }
        Ok(if v.len() == 1 { v.pop().unwrap_or(Expr::And(vec![])) } else { Expr::And(v) })
    }
    fn not(&mut self, d: usize) -> Result<Expr, String> {
        if self.kw("not") {
            self.i += 1;
            return Ok(Expr::Not(Box::new(self.not(d + 1)?)));
        }
        self.primary(d)
    }
    fn value(&mut self) -> Result<Value, String> {
        let v = match self.peek().cloned() {
            Some(Tok::Str(s)) => Value::String(s),
            Some(Tok::Num(n)) => serde_json::json!(n),
            Some(Tok::Ident(x)) if x == "true" || x == "false" => Value::Bool(x == "true"),
            other => return Err(format!("expected a value, found {other:?}")),
        };
        self.i += 1;
        Ok(v)
    }
    fn primary(&mut self, d: usize) -> Result<Expr, String> {
        match self.peek().cloned() {
            Some(Tok::LParen) => {
                self.i += 1;
                let e = self.or(d + 1)?;
                if self.peek() != Some(&Tok::RParen) {
                    return Err("missing ')'".into());
                }
                self.i += 1;
                Ok(e)
            }
            Some(Tok::Ident(field)) => {
                self.i += 1;
                self.terms += 1;
                if self.terms > MAX_TERMS {
                    return Err("too many comparisons".into());
                }
                if self.kw("exists") {
                    self.i += 1;
                    return Ok(Expr::Exists(field));
                }
                if self.kw("in") {
                    self.i += 1;
                    if self.peek() != Some(&Tok::LBrack) {
                        return Err("expected '['".into());
                    }
                    self.i += 1;
                    let mut vals = vec![];
                    loop {
                        vals.push(self.value()?);
                        match self.peek() {
                            Some(Tok::Comma) => self.i += 1,
                            Some(Tok::RBrack) => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err("expected ',' or ']'".into()),
                        }
                        if vals.len() > 64 {
                            return Err("too many values".into());
                        }
                    }
                    return Ok(Expr::In(field, vals));
                }
                let op = match self.peek().cloned() {
                    Some(Tok::Op(o)) => o,
                    other => return Err(format!("expected an operator after {field}, found {other:?}")),
                };
                self.i += 1;
                let v = self.value()?;
                Ok(Expr::Cmp(field, op, v))
            }
            other => Err(format!("unexpected {other:?}")),
        }
    }
}

pub fn parse(s: &str) -> Result<Expr, String> {
    let t = lex(s)?;
    if t.is_empty() {
        return Err("empty expression".into());
    }
    let mut p = P { t, i: 0, terms: 0 };
    let e = p.or(0)?;
    if p.i != p.t.len() {
        return Err(format!("unexpected trailing input at token {}", p.i));
    }
    Ok(e)
}

fn get<'a>(obj: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = obj;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    (!cur.is_null()).then_some(cur)
}

fn cmp_values(field: &str, a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64()?.partial_cmp(&y.as_f64()?),
        (Value::String(x), Value::String(y)) if field.ends_with("firmware") || field.ends_with("version") => Some(cmp_version(x, y)),
        (Value::String(x), Value::String(y)) => Some(x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase())),
        (Value::Bool(x), Value::Bool(y)) => Some(x.cmp(y)),
        (Value::String(x), Value::Number(y)) => x.parse::<f64>().ok()?.partial_cmp(&y.as_f64()?),
        _ => None,
    }
}

fn elem_eq(field: &str, a: &Value, b: &Value) -> bool {
    match a {
        Value::Array(items) => items.iter().any(|i| cmp_values(field, i, b) == Some(Ordering::Equal)),
        _ => cmp_values(field, a, b) == Some(Ordering::Equal),
    }
}

pub fn eval(e: &Expr, obj: &Value) -> bool {
    match e {
        Expr::And(v) => v.iter().all(|x| eval(x, obj)),
        Expr::Or(v) => v.iter().any(|x| eval(x, obj)),
        Expr::Not(x) => !eval(x, obj),
        Expr::Exists(f) => {
            get(obj, f).map(|v| !(v.is_string() && v.as_str() == Some("")) && !(v.is_array() && v.as_array().map(|a| a.is_empty()).unwrap_or(false))).unwrap_or(false)
        }
        Expr::In(f, vals) => get(obj, f).map(|a| vals.iter().any(|b| elem_eq(f, a, b))).unwrap_or(false),
        Expr::Cmp(f, op, b) => {
            let Some(a) = get(obj, f) else { return op == "!=" };
            match op.as_str() {
                "==" => elem_eq(f, a, b),
                "!=" => !elem_eq(f, a, b),
                "~" => match (a, b) {
                    (Value::String(x), Value::String(y)) => x.to_ascii_lowercase().contains(&y.to_ascii_lowercase()),
                    (Value::Array(items), Value::String(y)) => items.iter().any(|i| i.as_str().map(|s| s.to_ascii_lowercase().contains(&y.to_ascii_lowercase())).unwrap_or(false)),
                    _ => false,
                },
                "<" => cmp_values(f, a, b) == Some(Ordering::Less),
                "<=" => matches!(cmp_values(f, a, b), Some(Ordering::Less | Ordering::Equal)),
                ">" => cmp_values(f, a, b) == Some(Ordering::Greater),
                ">=" => matches!(cmp_values(f, a, b), Some(Ordering::Greater | Ordering::Equal)),
                _ => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn evaluates_expressions() {
        let a = json!({"category": "industrial_control", "firmware": "2.9.4", "risk_score": 72, "vendor": "Siemens", "tags": ["line-3", "critical"], "lifecycle": "active", "classification": {"tier": "high"}});
        let ok = |s: &str| eval(&parse(s).unwrap(), &a);
        assert!(ok(r#"category == "industrial_control" and firmware < "2.9.7""#));
        assert!(!ok(r#"firmware < "2.9.4""#));
        assert!(ok(r#"firmware < "2.10""#), "version-aware");
        assert!(ok("risk_score >= 70 and risk_score < 80"));
        assert!(ok(r#"vendor ~ "siem" and tags in ["critical", "lab"]"#));
        assert!(ok(r#"not tags in ["lab"]"#));
        assert!(ok(r#"classification.tier == "high""#));
        assert!(ok("vendor exists and not serial exists"));
        assert!(ok(r#"(lifecycle == "decommissioned" or risk_score > 50) and category != "printer""#));
        assert!(ok(r#"serial != "x""#), "missing field differs from any value");
    }

    #[test]
    fn rejects_bad_and_unbounded_input() {
        for bad in ["", "category ==", "category == \"x", "(a == 1", "a == 1 b", "a in [1,", "a $ 1"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let deep = format!("{}a == 1{}", "(".repeat(40), ")".repeat(40));
        assert!(parse(&deep).is_err());
        let many = (0..70).map(|i| format!("f{i} == 1")).collect::<Vec<_>>().join(" and ");
        assert!(parse(&many).is_err());
        assert!(parse(&"a".repeat(MAX_LEN + 1)).is_err());
    }
}
