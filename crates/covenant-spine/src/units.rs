//! Exact-precision value types: integer cents and scaled ratios. The engine
//! has no floats anywhere — money is i128 cents and ratios are integers
//! scaled by millionths, so every comparison and sum is exactly
//! reproducible.

use core::fmt;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Add, Mul, Sub};

/// Money in integer cents (i128). Serializes as a JSON string so values
/// beyond JSON's 2^53 exact-integer ceiling survive round-trips untouched.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cents(i128);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid cents value {0:?}: expected an integer string like \"-1234500\"")]
pub struct CentsParseError(String);

impl Cents {
    pub fn from_cents(value: i128) -> Self {
        Self(value)
    }

    pub fn get(self) -> i128 {
        self.0
    }

    pub fn from_decimal_str(raw: &str) -> Result<Self, CentsParseError> {
        let s = raw.trim();
        let (sign, digits) = match s.strip_prefix('-') {
            Some(rest) => (-1i128, rest),
            None => (1i128, s.strip_prefix('+').unwrap_or(s)),
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CentsParseError(raw.to_string()));
        }
        let value = digits
            .parse::<i128>()
            .map_err(|_| CentsParseError(raw.to_string()))?;
        Ok(Self(sign * value))
    }
}

impl fmt::Display for Cents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for Cents {
    type Output = Cents;
    fn add(self, rhs: Cents) -> Cents {
        Self(self.0 + rhs.0)
    }
}

impl Sub for Cents {
    type Output = Cents;
    fn sub(self, rhs: Cents) -> Cents {
        Self(self.0 - rhs.0)
    }
}

impl Serialize for Cents {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Cents {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CentsVisitor;

        impl de::Visitor<'_> for CentsVisitor {
            type Value = Cents;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an integer-cent string like \"-1234500\"")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Cents, E> {
                Cents::from_decimal_str(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(CentsVisitor)
    }
}

/// Scale for [`Ratio`]: ratios are stored in millionths, so
/// `Ratio::from_scaled(3_500_000)` reads 3.5x.
pub const RATIO_SCALE: i128 = 1_000_000;

const RATIO_SCALE_U128: u128 = RATIO_SCALE as u128;

/// A ratio in scaled integer units (millionths). Thresholds, measured
/// ratios, headroom, and trend slopes are all [`Ratio`] — no floats.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ratio(i128);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid ratio {0:?}: expected a decimal string with at most 6 fractional digits, like \"3.50\"")]
pub struct RatioParseError(String);

impl Ratio {
    pub fn from_scaled(value: i128) -> Self {
        Self(value)
    }

    pub fn scaled(self) -> i128 {
        self.0
    }

    /// Parse an exact decimal string ("3.50", ".5", "-0.903175"). More than
    /// six fractional digits would lose precision, so it is refused.
    pub fn from_decimal_str(raw: &str) -> Result<Self, RatioParseError> {
        let s = raw.trim();
        let (sign, rest) = match s.strip_prefix('-') {
            Some(r) => (-1i128, r),
            None => (1i128, s.strip_prefix('+').unwrap_or(s)),
        };
        if rest.is_empty() || rest.ends_with('.') {
            return Err(RatioParseError(raw.to_string()));
        }
        let (int_part, frac_part) = match rest.split_once('.') {
            Some((i, f)) => (i, f),
            None => (rest, ""),
        };
        let digits_ok = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
        if (!int_part.is_empty() && !digits_ok(int_part))
            || !digits_ok(frac_part)
            || frac_part.len() > 6
        {
            return Err(RatioParseError(raw.to_string()));
        }
        let int_val = if int_part.is_empty() {
            0
        } else {
            int_part
                .parse::<i128>()
                .map_err(|_| RatioParseError(raw.to_string()))?
        };
        let mut frac = frac_part.to_string();
        while frac.len() < 6 {
            frac.push('0');
        }
        let frac_val = frac
            .parse::<i128>()
            .map_err(|_| RatioParseError(raw.to_string()))?;
        Ok(Self(sign * (int_val * RATIO_SCALE + frac_val)))
    }

    /// Exact decimal rendering, trailing zeros trimmed: `Ratio(3_500_000)`
    /// is "3.5", `Ratio(-600_000)` is "-0.6", `Ratio(1)` is "0.000001".
    pub fn to_decimal_string(self) -> String {
        let abs = self.0.unsigned_abs();
        let sign = if self.0 < 0 { "-" } else { "" };
        let int = abs / RATIO_SCALE_U128;
        let frac = abs % RATIO_SCALE_U128;
        if frac == 0 {
            format!("{sign}{int}")
        } else {
            let mut frac = format!("{frac:06}");
            while frac.ends_with('0') {
                frac.pop();
            }
            format!("{sign}{int}.{frac}")
        }
    }

    /// num/den in scaled ratio units. `None` only when `den` is zero;
    /// callers check denominator sign against covenant semantics first and
    /// treat this arm as fail-closed rather than reachable.
    pub fn scaled_div(num: i128, den: i128) -> Option<Self> {
        if den == 0 {
            None
        } else {
            Some(Self(num * RATIO_SCALE / den))
        }
    }
}

impl fmt::Display for Ratio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_decimal_string())
    }
}

impl Add for Ratio {
    type Output = Ratio;
    fn add(self, rhs: Ratio) -> Ratio {
        Self(self.0 + rhs.0)
    }
}

impl Sub for Ratio {
    type Output = Ratio;
    fn sub(self, rhs: Ratio) -> Ratio {
        Self(self.0 - rhs.0)
    }
}

impl Mul<i128> for Ratio {
    type Output = Ratio;
    fn mul(self, rhs: i128) -> Ratio {
        Self(self.0 * rhs)
    }
}

impl Serialize for Ratio {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_decimal_string())
    }
}

impl<'de> Deserialize<'de> for Ratio {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RatioVisitor;

        impl de::Visitor<'_> for RatioVisitor {
            type Value = Ratio;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a decimal ratio string with at most 6 fractional digits, like \"3.50\"",
                )
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Ratio, E> {
                Ratio::from_decimal_str(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(RatioVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cents_parse_rejects_non_integer_strings() {
        assert!(Cents::from_decimal_str("1234500").is_ok());
        assert!(Cents::from_decimal_str("-1234500").is_ok());
        assert!(Cents::from_decimal_str("12.5").is_err());
        assert!(Cents::from_decimal_str("").is_err());
        assert!(Cents::from_decimal_str("12a").is_err());
        assert!(Cents::from_decimal_str("1 2").is_err());
    }

    #[test]
    fn ratio_parses_exact_decimals_and_bounds_fraction_digits() {
        assert_eq!(Ratio::from_decimal_str("3.50").unwrap().scaled(), 3_500_000);
        assert_eq!(Ratio::from_decimal_str("0.000001").unwrap().scaled(), 1);
        assert_eq!(
            Ratio::from_decimal_str("0.903175").unwrap().scaled(),
            903_175
        );
        assert_eq!(Ratio::from_decimal_str("-0.5").unwrap().scaled(), -500_000);
        assert_eq!(Ratio::from_decimal_str(".5").unwrap().scaled(), 500_000);
        assert_eq!(Ratio::from_decimal_str("4").unwrap().scaled(), 4_000_000);
        // Seven fractional digits would lose precision — refused.
        assert!(Ratio::from_decimal_str("3.5045671").is_err());
        assert!(Ratio::from_decimal_str("3.").is_err());
        assert!(Ratio::from_decimal_str(".").is_err());
        assert!(Ratio::from_decimal_str("").is_err());
        assert!(Ratio::from_decimal_str("abc").is_err());
    }

    #[test]
    fn ratio_decimal_string_roundtrips() {
        for raw in ["3.5", "-0.6", "0.000001", "0", "14", "0.903175"] {
            let r = Ratio::from_decimal_str(raw).unwrap();
            assert_eq!(r.to_decimal_string(), raw, "roundtrip {raw}");
        }
    }

    #[test]
    fn cents_and_ratio_serialize_as_strings() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Row {
            amount: Cents,
            ratio: Ratio,
        }
        let row = Row {
            amount: Cents::from_cents(-1_234_500),
            ratio: Ratio::from_scaled(3_500_000),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert_eq!(json, r#"{"amount":"-1234500","ratio":"3.5"}"#);
        let back: Row = serde_json::from_str(&json).unwrap();
        assert_eq!(back, row);
        // Bare JSON numbers are refused — the schema is strings-only, so no
        // float value can enter the engine through JSON parsing.
        assert!(serde_json::from_str::<Row>(r#"{"amount":123,"ratio":"3.5"}"#).is_err());
    }
}
