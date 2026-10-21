//! ACARS, VDL2 and HFDL messages as a batch carries them (RFC-0187 §3): one observation of format
//! [`crate::batch::format::ACARS_JSON`] a message, its data one line of JSON in one fixed, flat
//! schema, the [`project`]ion of what its decoder wrote. This is the one rule of what such a line
//! is: the feeder projects a decoder's line before it signs it, and a relay's `--acars-out` and the
//! map image's collector take only a line the schema writes byte for byte ([`line`]), so none of
//! them trusts another's shape.
//!
//! A line is one ACARS message and nothing else, each field only if its decoder gave it:
//!
//! | key        | what                                             |
//! | ---------- | ------------------------------------------------ |
//! | `t`        | when it was received, Unix seconds, whole        |
//! | `kind`     | `acars` (VHF ACARS), `vdl2` or `hfdl`: its link  |
//! | `icao`     | the aircraft's 24-bit address (not on HFDL)      |
//! | `reg`      | its registration                                 |
//! | `flight`   | the flight                                       |
//! | `gs`       | the ground station's address (VDL2) or id (HFDL) |
//! | `label`    | the message's label                              |
//! | `sublabel` | its sublabel, read from the text                 |
//! | `block`    | its block id                                     |
//! | `msgnum`   | its message number and sequence letter           |
//! | `mode`     | its mode character                               |
//! | `ack`      | its acknowledgement (`!` a NAK, `^` an ACK)      |
//! | `text`     | its text                                         |
//!
//! Nothing of a decoder's own trees is published: not the AVLC, LPDU or SPDU frame, not libacars'
//! decode of the text, not a field a decoder version adds or a configuration turns on. Those trees
//! differ by decoder, version and setting, so two receivers' copies of one message would differ by
//! them. A flat schema written once, each field spelled as libacars spells it whichever decoder
//! wrote it (a registration without its padding dots or a dash, a sublabel and MFI left in the
//! text, an ACK as `^`), makes every receiver's copy of a message the same line but for its time,
//! so the map's collector merges copies by plain equality ([`copy_key`]). HFDL carries no aircraft
//! address: dumphfdl takes it from its own cache of logons, not from the message. A frame that
//! carries no ACARS message (a VDL2 XID, X.25 or CPDLC without ACARS, an HFDL logon, performance
//! report or ground station's SPDU, acarsdec's route summary) is not published
//! ([`Refused::NotAcars`]), nor one its decoder says is damaged or holds only in part, a block
//! with more of its message to follow among them ([`Refused::Damaged`]). The broadcast address,
//! `FFFFFF`, is no aircraft's or station's, and is not published. Nothing of the receiver is published (RFC-0187 §3): not its station
//! name, signal, noise, frequency or channel, nor its decoder's error counts, and its time is cut
//! to the second, as a client form drops a BEAST frame's counter.
//!
//! A line is written canonically: keys in the order above sorted, no space anywhere, every string
//! escaped one way (only where JSON must, and U+0085, U+2028 and U+2029, which some readers take
//! for a line's end). A line that names one key twice, at any depth, is refused: two readers could
//! take different ones.

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// The longest line a batch carries: far past an ordinary message (a few hundred bytes; ACARS
/// text is at most 220 characters a block, and a reassembled message a few KiB), and a quarter of
/// one Noise message, so one line never fills a batch.
pub const MAX_LINE: usize = 16 * 1024;

/// Why a decoder's line is not published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A well-formed frame of one of the shapes that carries no ACARS message.
    NotAcars,
    /// A message its decoder says is damaged (libacars' `err`, or `crc_ok` false), a block of one
    /// it is still reassembling or could not place (acarsdec's `assstat`), or a block with more of
    /// its message to follow (libacars' `more`, acarsdec's and vdlm2dec's `end`): a part, never
    /// the message.
    Damaged,
    /// Not one of the shapes, a key twice, no usable time, or past [`MAX_LINE`] once projected.
    Malformed,
}

/// One message in the published schema (the module's table).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Message {
    t: u64,
    kind: &'static str,
    icao: Option<String>,
    reg: Option<String>,
    flight: Option<String>,
    gs: Option<String>,
    label: Option<String>,
    sublabel: Option<String>,
    block: Option<String>,
    msgnum: Option<String>,
    mode: Option<String>,
    ack: Option<String>,
    text: Option<String>,
}

/// The ACARS fields of one decoder's message object, by their names there.
struct Names {
    reg: &'static str,
    block: &'static str,
    msgnum: &'static [&'static str],
    text: &'static str,
    /// True on a block with more of its message to follow.
    more: &'static str,
}

/// acarsdec's and vdlm2dec's top-level message (acarsdec's `output.c`, `buildjson`; vdlm2dec's
/// `outacars.c`, `addacarsjson`): `tail`, `flight`, `label`, `sublabel` and `mfi` (acarsdec built
/// with libacars, which took them off the text), `block_id`, `msgno` (number and sequence letter
/// in one), `mode`, `ack` (acarsdec's NAK `false`, vdlm2dec's `!`, either's ACK its byte), `end`
/// (true when the block ends in ETB: more follow), `text`, acarsdec's `assstat`, and vdlm2dec's
/// `icao`, `toaddr` and `fromaddr` (numbers).
const ACARSDEC: Names = Names {
    reg: "tail",
    block: "block_id",
    msgnum: &["msgno"],
    text: "text",
    more: "end",
};

/// libacars' ACARS object, as dumpvdl2 and dumphfdl write it (libacars' `acars.c`,
/// `la_acars_format_json`): `err`, `crc_ok`, `reg`, `flight`, `label`, `sublabel` and `mfi` (taken
/// off the text), `blk_id`, `msg_num` and `msg_num_seq`, `mode`, `ack` (`!` a NAK, `^` an ACK),
/// `more`, `msg_text`.
const LIBACARS: Names = Names {
    reg: "reg",
    block: "blk_id",
    msgnum: &["msg_num", "msg_num_seq"],
    text: "msg_text",
    more: "more",
};

/// What is published of a decoder's line, as one line ([`line`] takes it), or why nothing is.
pub fn publish(input: &str) -> Result<String, Refused> {
    let value = parse(input).ok_or(Refused::Malformed)?;
    let top = value.as_object().ok_or(Refused::Malformed)?;
    let message = if let Some(vdl2) = top.get("vdl2") {
        from_vdl2(vdl2.as_object().ok_or(Refused::Malformed)?)?
    } else if let Some(hfdl) = top.get("hfdl") {
        from_hfdl(hfdl.as_object().ok_or(Refused::Malformed)?)?
    } else {
        from_acarsdec(top)?
    };
    let line = message.spelled().write();
    well_formed(line.as_bytes()).ok_or(Refused::Malformed)?;
    Ok(line)
}

/// `input` as JSON, if it is, and no object in it names a key twice.
fn parse(input: &str) -> Option<Value> {
    serde_json::from_str::<Unique>(input).ok()?;
    serde_json::from_str(input).ok()
}

/// [`publish`], as an option.
pub fn project(input: &str) -> Option<String> {
    publish(input).ok()
}

/// dumpvdl2's `vdl2` object (dumpvdl2's `output-json.c` and `avlc.c`): its time `t.sec`, and the
/// AVLC frame's `src` and `dst` (each an `addr` in hex and a `type`, `Aircraft` or `Ground
/// station`), carrying ACARS as `avlc.acars`.
fn from_vdl2(vdl2: &Map<String, Value>) -> Result<Message, Refused> {
    let avlc = vdl2.get("avlc").and_then(Value::as_object);
    let acars = avlc
        .and_then(|avlc| avlc.get("acars"))
        .and_then(Value::as_object)
        .ok_or(Refused::NotAcars)?;
    let mut message = from_acars("vdl2", acars, &LIBACARS, seconds(vdl2)?)?;
    let ends = avlc
        .into_iter()
        .flat_map(|avlc| ["src", "dst"].map(|end| avlc.get(end)));
    for end in ends.flatten() {
        let address = end.get("addr").and_then(hex_address);
        match end.get("type").and_then(Value::as_str) {
            Some("Aircraft") => message.icao = message.icao.take().or(address),
            Some("Ground station") => message.gs = message.gs.take().or(address),
            _ => {}
        }
    }
    Ok(message)
}

/// dumphfdl's `hfdl` object (dumphfdl's `output-json.c`, `lpdu.c` and `hfnpdu.c`): its time
/// `t.sec`, and the LPDU's `src` and `dst` (each a `type`, a ground station's `id`), carrying ACARS
/// as `lpdu.hfnpdu.acars`. An SPDU carries none. An aircraft's `ac_info.icao` is not the message's:
/// dumphfdl fills it from its own cache of the logons it heard (`util.c`, `lpdu.c`), so two
/// receivers' copies of one message differ by it.
fn from_hfdl(hfdl: &Map<String, Value>) -> Result<Message, Refused> {
    let lpdu = hfdl.get("lpdu").and_then(Value::as_object);
    let acars = lpdu
        .and_then(|lpdu| lpdu.get("hfnpdu"))
        .and_then(|hfnpdu| hfnpdu.get("acars"))
        .and_then(Value::as_object)
        .ok_or(Refused::NotAcars)?;
    let mut message = from_acars("hfdl", acars, &LIBACARS, seconds(hfdl)?)?;
    let ends = lpdu
        .into_iter()
        .flat_map(|lpdu| ["src", "dst"].map(|end| lpdu.get(end)));
    for end in ends.flatten() {
        if end.get("type").and_then(Value::as_str) == Some("Ground station") {
            let id = end
                .get("id")
                .and_then(Value::as_u64)
                .map(|id| id.to_string());
            message.gs = message.gs.take().or(id);
        }
    }
    Ok(message)
}

/// acarsdec's or vdlm2dec's message, with its time `timestamp` (seconds, with a fraction).
/// vdlm2dec's is VDL2 (its `app.name`, or the ground station's address it alone writes).
fn from_acarsdec(top: &Map<String, Value>) -> Result<Message, Refused> {
    let timestamp = top
        .get("timestamp")
        .and_then(Value::as_f64)
        .ok_or(Refused::Malformed)?
        .floor();
    if !(timestamp.is_finite() && (0.0..9_007_199_254_740_992.0).contains(&timestamp)) {
        return Err(Refused::Malformed);
    }
    // acarsdec's reassembly (`la_reasm_status_name_get`): a block of a message still being
    // reassembled, or one it could not place, is not the message.
    if let Some(status) = top.get("assstat")
        && !matches!(status.as_str(), Some("complete" | "skipped"))
    {
        return Err(Refused::Damaged);
    }
    let addresses = ["toaddr", "fromaddr"].map(|key| top.get(key).and_then(hex_address));
    let vdlm2dec = addresses.iter().any(Option::is_some)
        || top
            .get("app")
            .and_then(|app| app.get("name"))
            .and_then(Value::as_str)
            == Some("vdlm2dec");
    let kind = if vdlm2dec { "vdl2" } else { "acars" };
    let mut message = from_acars(kind, top, &ACARSDEC, timestamp as u64)?;
    message.icao = top.get("icao").and_then(hex_address);
    let [to, from] = addresses;
    message.gs = to.or(from);
    Ok(message)
}

/// A line already in the published schema, read back field by field ([`line`] alone reads one):
/// anything else in it is dropped, so [`line`] refuses it.
fn from_published(top: &Map<String, Value>) -> Option<Message> {
    let kind = match top.get("kind")?.as_str()? {
        "acars" => "acars",
        "vdl2" => "vdl2",
        "hfdl" => "hfdl",
        _ => return None,
    };
    let string = |key: &str| text(top.get(key));
    let message = Message {
        t: top.get("t")?.as_u64()?,
        kind,
        icao: top.get("icao").and_then(hex_address),
        reg: string("reg"),
        flight: string("flight"),
        gs: string("gs"),
        label: Some(string("label")?),
        sublabel: string("sublabel"),
        block: string("block"),
        msgnum: string("msgnum"),
        mode: string("mode"),
        ack: string("ack"),
        text: string("text"),
    };
    Some(message)
}

/// The ACARS fields of `object`, by `names`. A message has a label; an object with none carries
/// no ACARS message. One its decoder says is damaged (libacars' `err`, or `crc_ok` false) is not
/// published, nor a block with more to follow: a decoder that reassembles writes the message
/// whole on its last block (libacars' `acars.c`, `la_acars_parse`; acarsdec's `output.c`).
fn from_acars(
    kind: &'static str,
    object: &Map<String, Value>,
    names: &Names,
    t: u64,
) -> Result<Message, Refused> {
    let flag = |key: &str| object.get(key).and_then(Value::as_bool);
    if flag("err") == Some(true) || flag("crc_ok") == Some(false) || flag(names.more) == Some(true)
    {
        return Err(Refused::Damaged);
    }
    let string = |key: &str| text(object.get(key));
    let label = string("label").ok_or(Refused::NotAcars)?;
    let block = string(names.block);
    let msgnum: String = names
        .msgnum
        .iter()
        .filter_map(|key| object.get(*key).and_then(Value::as_str))
        .collect();
    let mut body = string(names.text).unwrap_or_default();
    // libacars takes an H1 message's sublabel and MFI off its text
    // (`la_acars_extract_sublabel_and_mfi`); they are put back as it found them, so a copy from a
    // decoder that left them on is the same text.
    if let (Some(sublabel), "H1") = (string("sublabel"), label.as_str()) {
        let mut head = if downlink(block.as_deref()) {
            format!("#{sublabel}B")
        } else {
            format!("- #{sublabel}")
        };
        if let Some(mfi) = string("mfi") {
            head.push_str(&format!("/{mfi} "));
        }
        body.insert_str(0, &head);
    }
    Ok(Message {
        t,
        kind,
        reg: string(names.reg),
        flight: string("flight"),
        label: Some(label),
        block,
        msgnum: (!msgnum.is_empty()).then_some(msgnum),
        mode: string("mode"),
        // acarsdec writes a NAK as `false` (`output.c`); vdlm2dec makes it `!` before it tests
        // for the byte (`outacars.c`), so writes `!`.
        ack: match object.get("ack") {
            Some(Value::Bool(false)) => Some("!".to_owned()),
            ack => text(ack),
        },
        text: (!body.is_empty()).then_some(body),
        ..Message::default()
    })
}

/// Whether a block id is a downlink's, an aircraft's to the ground (libacars' and acarsdec's
/// `IS_DOWNLINK_BLK`).
fn downlink(block: Option<&str>) -> bool {
    matches!(block, Some(block) if block.len() == 1 && block.as_bytes()[0].is_ascii_digit())
}

/// A dumpvdl2 or dumphfdl object's `t.sec`.
fn seconds(object: &Map<String, Value>) -> Result<u64, Refused> {
    object
        .get("t")
        .and_then(|t| t.get("sec"))
        .and_then(Value::as_u64)
        .ok_or(Refused::Malformed)
}

/// A string that says something.
fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// A 24-bit address, given as hex text (`"A1B2C3"`) or a number, as six upper-case hex digits;
/// not the broadcast address, `FFFFFF`, which names every aircraft or ground station at once
/// (vdlm2dec writes it as a broadcast's `toaddr` or `icao`, dumpvdl2 as its `dst`).
fn hex_address(value: &Value) -> Option<String> {
    let address = match value {
        Value::String(hex) if (1..=6).contains(&hex.len()) => u32::from_str_radix(hex, 16).ok()?,
        Value::Number(number) => u32::try_from(number.as_u64()?).ok()?,
        _ => return None,
    };
    (address < 0x00ff_ffff).then(|| format!("{address:06X}"))
}

impl Message {
    /// The message with each field spelled as libacars spells it, whichever decoder wrote it, and
    /// nothing a receiver's own state decides: every path to a line ends here, so [`line`] refuses
    /// a published line spelled another way.
    fn spelled(mut self) -> Message {
        // ACARS pads a registration to seven characters with dots (`.N842UA`), and vdlm2dec puts a
        // dash after a country's prefix (`fixreg`).
        self.reg = self
            .reg
            .map(|reg| reg.replace(['.', '-'], ""))
            .filter(|reg| !reg.is_empty());
        // libacars' printable NAK and ACK; acarsdec and vdlm2dec write an ACK as its byte.
        self.ack = self.ack.map(|ack| match ack.as_str() {
            "\u{15}" => "!".to_owned(),
            "\u{6}" => "^".to_owned(),
            _ => ack,
        });
        // A message number and flight are read from a downlink's text alone (libacars'
        // `la_acars_parse`); vdlm2dec reads them from a block id below `0` too, and they go back.
        if !downlink(self.block.as_deref()) {
            let head: String = [self.msgnum.take(), self.flight.take()]
                .into_iter()
                .flatten()
                .collect();
            if !head.is_empty() {
                self.text = Some(head + self.text.as_deref().unwrap_or_default());
            }
        }
        self.sublabel = self.read_sublabel();
        if self.kind == "hfdl" {
            self.icao = None;
        }
        self
    }

    /// An H1 message's sublabel, read from its text by libacars' one rule
    /// (`la_acars_extract_sublabel_and_mfi`): a downlink's text starts `#` with `B` fourth, an
    /// uplink's `- #`, the two characters after the `#`.
    fn read_sublabel(&self) -> Option<String> {
        let text = self.text.as_deref()?;
        if self.label.as_deref() != Some("H1") {
            return None;
        }
        let bytes = text.as_bytes();
        let sublabel = if downlink(self.block.as_deref()) {
            (bytes.len() >= 4 && bytes[0] == b'#' && bytes[3] == b'B').then(|| text.get(1..3))
        } else {
            (bytes.len() >= 5 && text.starts_with("- #")).then(|| text.get(3..5))
        };
        sublabel.flatten().map(str::to_owned)
    }

    /// Its line, canonically: keys sorted, no space, strings escaped one way.
    fn write(&self) -> String {
        self.write_fields(true)
    }

    fn write_fields(&self, with_time: bool) -> String {
        let t = self.t.to_string();
        let fields: [(&str, Option<&str>, bool); 13] = [
            ("ack", self.ack.as_deref(), true),
            ("block", self.block.as_deref(), true),
            ("flight", self.flight.as_deref(), true),
            ("gs", self.gs.as_deref(), true),
            ("icao", self.icao.as_deref(), true),
            ("kind", Some(self.kind), true),
            ("label", self.label.as_deref(), true),
            ("mode", self.mode.as_deref(), true),
            ("msgnum", self.msgnum.as_deref(), true),
            ("reg", self.reg.as_deref(), true),
            ("sublabel", self.sublabel.as_deref(), true),
            ("t", with_time.then_some(t.as_str()), false),
            ("text", self.text.as_deref(), true),
        ];
        let mut out = String::with_capacity(64 + self.text.as_ref().map_or(0, String::len));
        out.push('{');
        for (key, value, quoted) in fields {
            let Some(value) = value else { continue };
            if out.len() > 1 {
                out.push(',');
            }
            write_string(key, &mut out);
            out.push(':');
            if quoted {
                write_string(value, &mut out);
            } else {
                out.push_str(value);
            }
        }
        out.push('}');
        out
    }
}

fn write_string(text: &str, out: &mut String) {
    use std::fmt::Write as _;
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            character
                if u32::from(character) < 0x20
                    || matches!(character, '\u{85}' | '\u{2028}' | '\u{2029}') =>
            {
                let _ = write!(out, "\\u{:04x}", u32::from(character));
            }
            character => out.push(character),
        }
    }
    out.push('"');
}

/// A published line read back, if it is one.
fn read(line: &str) -> Option<Message> {
    from_published(parse(self::line(line.as_bytes())?)?.as_object()?)
}

/// What every copy of `line`'s message has alike, whoever heard it: the whole line but its time
/// (`t`, each receiver's clock). Lines with one key are copies of one message. `None` for what is
/// not a published line.
pub fn copy_key(line: &str) -> Option<String> {
    Some(read(line)?.write_fields(false))
}

/// `line` with its time set to `second`.
pub fn at_second(line: &str, second: u64) -> Option<String> {
    let mut message = read(line)?;
    message.t = second;
    Some(message.write())
}

/// When a published line's message was received, in Unix seconds.
pub fn second(line: &str) -> Option<u64> {
    Some(read(line)?.t)
}

/// When a published line's message was received, in Unix microseconds (a whole second).
pub fn time_us(line: &str) -> Option<u64> {
    second(line)?.checked_mul(1_000_000)
}

/// `data` as one published line, if it is one: well formed (UTF-8, at most [`MAX_LINE`] bytes, no
/// control character and none of the characters some readers take for a line's end: U+0085,
/// U+2028, U+2029), and exactly what it reads as in the schema, written again, byte for byte. A
/// reader that writes it with a newline after it writes one line of one message, with nothing of
/// the receiver in it. Only here is a line read as the schema: [`publish`] takes a decoder's.
pub fn line(data: &[u8]) -> Option<&str> {
    let text = well_formed(data)?;
    let message = from_published(parse(text)?.as_object()?)?;
    (message.spelled().write() == text).then_some(text)
}

fn well_formed(data: &[u8]) -> Option<&str> {
    if data.len() > MAX_LINE || data.iter().any(|byte| *byte < 0x20) {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    (!text.contains(['\u{85}', '\u{2028}', '\u{2029}'])).then_some(text)
}

/// Any JSON value in which no object names a key twice.
struct Unique;

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON value with no key twice in an object")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_str<E>(self, _: &str) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_unit<E>(self) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
        while seq.next_element::<Unique>()?.is_some() {}
        Ok(Unique)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom("a key named twice"));
            }
            map.next_value::<Unique>()?;
        }
        Ok(Unique)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"{"kind":"acars","label":"H1","t":1,"text":"x"}"#;

    /// A published line is one JSON object's text, no longer than the cap, with nothing that could
    /// end it or hide a second message after it, and nothing the projection would change.
    #[test]
    fn a_line_is_its_own_projection_and_one_line() {
        assert_eq!(line(OK.as_bytes()), Some(OK));
        let text = |n: usize| {
            format!(
                r#"{{"kind":"acars","label":"H1","t":1,"text":"{}"}}"#,
                "x".repeat(n)
            )
        };
        let longest = text(MAX_LINE - 45);
        assert_eq!(longest.len(), MAX_LINE);
        assert!(line(longest.as_bytes()).is_some());
        let over = text(MAX_LINE - 44);
        for refused in [
            over.as_bytes(),
            b"",
            b"[1]",
            b"\"text\"",
            br#"{"kind":"acars","label":"H1","t":1}{"kind":"acars","label":"H2","t":1}"#,
            b"{\"kind\":\"acars\",\"label\":\"H1\",\"t\":1}\n{\"b\":2}",
            br#"{"kind":"acars","label":"H1","t":1"#,
            b"{\"kind\":\"acars\",\"label\":\"H1\",\"t\":1,\"text\":\"\r\"}",
            b"{\"kind\":\"acars\",\"label\":\"H1\",\"t\":1,\"text\":\"\xff\"}",
            "{\"kind\":\"acars\",\"label\":\"H1\",\"t\":1,\"text\":\"\u{85}\"}".as_bytes(),
            "{\"kind\":\"acars\",\"label\":\"H1\",\"t\":1,\"text\":\"\u{2028}\"}".as_bytes(),
            "{\"kind\":\"acars\",\"label\":\"H1\",\"t\":1,\"text\":\"\u{2029}\"}".as_bytes(),
            // Not its projection: a field not in the schema, a fraction of a second, keys out of
            // order, a space, an escape of its own, a value spelled another way, a kind not one of
            // the three, a field of the wrong type, no label.
            br#"{"kind":"acars","label":"H1","level":-20,"t":1}"#,
            br#"{"kind":"acars","label":"H1","t":1.5}"#,
            br#"{"label":"H1","kind":"acars","t":1}"#,
            br#"{"kind":"acars", "label":"H1","t":1}"#,
            br#"{"kind":"acars","label":"\u0048\u0031","t":1}"#,
            br#"{"icao":"a1b2c3","kind":"vdl2","label":"H1","t":1}"#,
            br#"{"kind":"acars","label":"H1","reg":".N1","t":1}"#,
            br#"{"kind":"satcom","label":"H1","t":1}"#,
            br#"{"kind":"acars","label":"H1","more":false,"t":1}"#,
            br#"{"icao":"FFFFFF","kind":"vdl2","label":"H1","t":1}"#,
            br#"{"kind":"acars","t":1,"text":"x"}"#,
            // Not spelled as libacars spells it: a dash in a registration, an ACK as its byte, a
            // sublabel the text does not start with, a flight on an uplink, an HFDL address.
            br#"{"kind":"acars","label":"H1","reg":"C-FKDN","t":1}"#,
            br#"{"ack":"\u0006","kind":"acars","label":"H1","t":1}"#,
            br#"{"block":"3","kind":"acars","label":"H1","sublabel":"DF","t":1,"text":"x"}"#,
            br#"{"block":"A","flight":"UA1","kind":"acars","label":"H1","t":1}"#,
            br#"{"icao":"A9CFF8","kind":"hfdl","label":"H1","t":1}"#,
            // A key twice.
            br#"{"kind":"acars","label":"H1","t":1,"t":2}"#,
        ] {
            assert_eq!(line(refused), None, "{}", String::from_utf8_lossy(refused));
        }
        // Escaped, as JSON writes them, they are text and end nothing.
        assert!(
            line(br#"{"kind":"acars","label":"H1","t":1,"text":"one\r\ntwo\u2028\u0085"}"#)
                .is_some()
        );
    }

    /// Each decoder's message maps to the one schema, its own fields renamed, and nothing else.
    #[test]
    fn every_decoder_maps_to_the_one_schema() {
        // acarsdec, as its README's example writes a message's last block, with a receiver's fields
        // and libacars' decode beside it.
        assert_eq!(
            publish(
                r##"{"timestamp":1516206744.98,"station_id":"XX","channel":2,"freq":130.025,"level":-22,"error":0,"mode":"2","label":"H1","block_id":"6","ack":false,"tail":".N842UA","flight":"UA1412","msgno":"D04G","text":"#DFB","assstat":"complete","libacars":{"a":1}}"##
            ),
            Ok(r##"{"ack":"!","block":"6","flight":"UA1412","kind":"acars","label":"H1","mode":"2","msgnum":"D04G","reg":"N842UA","sublabel":"DF","t":1516206744,"text":"#DFB"}"##.to_owned())
        );
        // vdlm2dec's numbers for the aircraft's and the ground station's addresses, and its NAK.
        assert_eq!(
            publish(
                r#"{"timestamp":1.5,"station_id":"XX","freq":136.975,"hex":"A69AA8","icao":10918568,"toaddr":1131690,"is_response":0,"is_onground":0,"mode":"2","label":"_d","block_id":"4","ack":"!","tail":"N512UA","flight":"UA0001","msgno":"S01A","app":{"name":"vdlm2dec","ver":"2.3"}}"#
            ),
            Ok(
                r#"{"ack":"!","block":"4","flight":"UA0001","gs":"1144AA","icao":"A69AA8","kind":"vdl2","label":"_d","mode":"2","msgnum":"S01A","reg":"N512UA","t":1}"#
                    .to_owned()
            )
        );
        // The broadcast address is no aircraft's or station's: an uplink to every aircraft.
        assert_eq!(
            publish(
                r#"{"timestamp":1,"fromaddr":1131690,"icao":16777215,"hex":"FFFFFF","mode":"2","label":"SQ","block_id":"A","ack":"!","tail":"","text":"x","app":{"name":"vdlm2dec"}}"#
            ),
            Ok(r#"{"ack":"!","block":"A","gs":"1144AA","kind":"vdl2","label":"SQ","mode":"2","t":1,"text":"x"}"#.to_owned())
        );
        // dumpvdl2: the frame's two ends, and libacars' ACARS object with the sublabel it took off
        // the text put back.
        assert_eq!(
            publish(
                r#"{"vdl2":{"app":{"name":"dumpvdl2"},"station":"XX","t":{"sec":1769990648,"usec":949234},"sig_level":-16.6,"avlc":{"cr":"Command","dst":{"addr":"1144AA","type":"Ground station"},"src":{"addr":"ABFDAF","status":"Airborne","type":"Aircraft"},"rseq":5,"acars":{"err":false,"crc_ok":true,"more":false,"reg":".N8719Q","mode":"2","label":"H1","blk_id":"3","ack":"!","flight":"WN2340","msg_num":"D09","msg_num_seq":"A","sublabel":"DF","msg_text":"ABS\r\n","arinc622":{"x":1}}}}}"#
            ),
            Ok(r##"{"ack":"!","block":"3","flight":"WN2340","gs":"1144AA","icao":"ABFDAF","kind":"vdl2","label":"H1","mode":"2","msgnum":"D09A","reg":"N8719Q","sublabel":"DF","t":1769990648,"text":"#DFBABS\r\n"}"##.to_owned())
        );
        // dumphfdl: a ground station's id, and not the address dumphfdl remembers of the aircraft.
        assert_eq!(
            publish(
                r#"{"hfdl":{"t":{"sec":1769991943,"usec":852110},"freq":17919000,"lpdu":{"err":false,"dst":{"type":"Aircraft","id":223,"ac_info":{"icao":"A9CFF8"}},"src":{"type":"Ground station","id":1,"name":"San Francisco, California"},"hfnpdu":{"err":false,"acars":{"err":false,"crc_ok":true,"more":false,"reg":".N731NK","mode":"2","label":"_d","blk_id":"D","ack":"3","msg_text":""}}}}}"#
            ),
            Ok(r#"{"ack":"3","block":"D","gs":"1","kind":"hfdl","label":"_d","mode":"2","reg":"N731NK","t":1769991943}"#.to_owned())
        );
    }

    /// A frame with no ACARS message is not published, and is told from what is not a frame.
    #[test]
    fn a_frame_without_acars_is_not_published() {
        for frame in [
            // dumpvdl2: a ground station's XID, and X.25 with no ACARS.
            r#"{"vdl2":{"t":{"sec":1},"avlc":{"src":{"addr":"281658","type":"Ground station"},"xid":{"type":"GSIF"}}}}"#,
            r#"{"vdl2":{"t":{"sec":1},"avlc":{"x25":{"clnp":{}}}}}"#,
            // dumphfdl: a ground station's SPDU, a logon with performance data.
            r#"{"hfdl":{"t":{"sec":1},"spdu":{"src":{"type":"Ground station","id":1}}}}"#,
            r#"{"hfdl":{"t":{"sec":1},"lpdu":{"ac_info":{"icao":"06A129"},"hfnpdu":{"type":{"name":"Frequency data"}}}}}"#,
            // acarsdec's route summary, and a libacars object with no label.
            r#"{"timestamp":1543677178.96,"flight":"BA750P","depa":"EGLL","dsta":"LFSB"}"#,
            r#"{"vdl2":{"t":{"sec":1},"avlc":{"acars":{"msg_text":"x"}}}}"#,
        ] {
            assert_eq!(publish(frame), Err(Refused::NotAcars), "{frame}");
        }
        for malformed in [
            "not json",
            "[1]",
            r#"{"vdl2":"x"}"#,
            // No usable time.
            r#"{"label":"H1","text":"x"}"#,
            r#"{"timestamp":-1,"label":"H1"}"#,
            r#"{"timestamp":"soon","label":"H1"}"#,
            r#"{"vdl2":{"avlc":{"acars":{"label":"H1"}}}}"#,
            r#"{"hfdl":{"t":{"sec":"soon"},"lpdu":{"hfnpdu":{"acars":{"label":"H1"}}}}}"#,
            // A key twice, however deep.
            r#"{"timestamp":1,"label":"H1","label":"H2"}"#,
            r#"{"vdl2":{"t":{"sec":1},"avlc":{"src":{"a":1,"a":2},"acars":{"label":"H1"}}}}"#,
        ] {
            assert_eq!(publish(malformed), Err(Refused::Malformed), "{malformed}");
        }
    }

    /// However a decoder spaced, ordered or escaped its JSON, the line is the same; a published
    /// line is read as one, and is no decoder's.
    #[test]
    fn a_projection_is_canonical_however_the_decoder_wrote_it() {
        let ways = [
            "{\"timestamp\":7.9,\"label\":\"H1\",\"text\":\"\\u00e9\\/\\u2028\\t\"}",
            "{ \"text\" :\t\"é/\\u2028\\u0009\",\n\"label\" : \"\\u0048\\u0031\" , \"timestamp\":7 }",
        ];
        let canonical = r#"{"kind":"acars","label":"H1","t":7,"text":"é/\u2028\t"}"#;
        for way in ways {
            assert_eq!(project(way).as_deref(), Some(canonical), "{way}");
        }
        assert_eq!(line(canonical.as_bytes()), Some(canonical));
        assert_eq!(publish(canonical), Err(Refused::Malformed));
    }

    /// Copies of one message, whichever receiver, clock, decoder or decoder version they came
    /// from, are one line but for their time; any other difference is another message.
    #[test]
    fn copies_are_one_line_but_their_time() {
        let older = project(
            r#"{"vdl2":{"t":{"sec":10,"usec":1},"avlc":{"src":{"addr":"0000A1","type":"Aircraft"},"acars":{"label":"H1","msg_text":"HI","reg":".N1"}}}}"#,
        );
        let newer = project(
            r#"{"vdl2":{"t":{"sec":12},"station":"YY","avlc":{"src":{"addr":"0000A1","type":"Aircraft","status":"Airborne"},"acars":{"label":"H1","msg_text":"HI","reg":"N1","crc_ok":true,"arinc622":{}}}}}"#,
        );
        let (Some(older), Some(newer)) = (older, newer) else {
            panic!("a copy was refused");
        };
        assert_ne!(older, newer);
        assert_eq!(copy_key(&older), copy_key(&newer));
        assert!(copy_key(&older).is_some_and(|key| !key.contains("\"t\"")));
        assert_eq!(at_second(&older, 12).as_deref(), Some(newer.as_str()));
        assert_eq!(
            (second(&older), time_us(&newer)),
            (Some(10), Some(12_000_000))
        );
        // Another text, another aircraft, another link: another message.
        for other in [
            r#"{"icao":"0000A1","kind":"vdl2","label":"H1","reg":"N1","t":10,"text":"BYE"}"#,
            r#"{"icao":"0000A2","kind":"vdl2","label":"H1","reg":"N1","t":10,"text":"HI"}"#,
            r#"{"icao":"0000A1","kind":"acars","label":"H1","reg":"N1","t":10,"text":"HI"}"#,
        ] {
            assert!(line(other.as_bytes()).is_some(), "{other}");
            assert_ne!(copy_key(&older), copy_key(other), "{other}");
        }
        // What is not a published line has no key.
        assert_eq!(copy_key(r#"{"timestamp":1,"label":"H1"}"#), None);
    }

    /// One frame as vdlm2dec and dumpvdl2 write it (vdlm2dec's `out.c` and `outacars.c`; libacars'
    /// `la_acars_format_json`, which takes the sublabel and MFI off the text and spells an ACK `^`)
    /// is one message; so is an H1 message from acarsdec with and without libacars, either way.
    #[test]
    fn every_decoder_writes_one_frame_as_one_message() {
        let dumpvdl2 = r#"{"vdl2":{"app":{"name":"dumpvdl2","ver":"2.4.0"},"t":{"sec":1769990648,"usec":949234},"freq":136975000,"sig_level":-16.6,"avlc":{"src":{"addr":"C0FFEE","type":"Aircraft","status":"Airborne"},"dst":{"addr":"1144AA","type":"Ground station"},"cr":"Command","acars":{"err":false,"crc_ok":true,"more":false,"reg":".C-FKDN","mode":"2","label":"H1","blk_id":"5","ack":"^","flight":"AC0123","msg_num":"M01","msg_num_seq":"A","sublabel":"DF","mfi":"FA","msg_text":"ROUTE"}}}}"#;
        let vdlm2dec = r##"{"timestamp":1769990650.2,"station_id":"YY","freq":136.975,"icao":12648430,"toaddr":1131690,"is_response":0,"mode":"2","label":"H1","block_id":"5","ack":"\u0006","tail":"C-FKDN","flight":"AC0123","msgno":"M01A","text":"#DFB/FA ROUTE","app":{"name":"vdlm2dec","ver":"2.3"}}"##;
        let key = r##"{"ack":"^","block":"5","flight":"AC0123","gs":"1144AA","icao":"C0FFEE","kind":"vdl2","label":"H1","mode":"2","msgnum":"M01A","reg":"CFKDN","sublabel":"DF","text":"#DFB/FA ROUTE"}"##;
        for decoder in [dumpvdl2, vdlm2dec] {
            let line = project(decoder).unwrap_or_else(|| panic!("refused: {decoder}"));
            assert_eq!(copy_key(&line).as_deref(), Some(key), "{decoder}");
        }
        // An uplink's sublabel starts `- #`; acarsdec with libacars took it off, without did not.
        let with = r#"{"timestamp":1,"mode":"2","label":"H1","block_id":"A","ack":"!","tail":".N1","text":"POS","sublabel":"M1","mfi":"AB","assstat":"skipped"}"#;
        let without = r#"{"timestamp":1,"mode":"2","label":"H1","block_id":"A","ack":false,"tail":".N1","text":"- #M1/AB POS"}"#;
        let line = r#"{"ack":"!","block":"A","kind":"acars","label":"H1","mode":"2","reg":"N1","sublabel":"M1","t":1,"text":"- #M1/AB POS"}"#;
        assert_eq!(project(with).as_deref(), Some(line));
        assert_eq!(project(without).as_deref(), Some(line));
    }

    /// A message its decoder says is damaged, or holds only in part, is not published.
    #[test]
    fn a_damaged_or_partial_message_is_not_published() {
        for damaged in [
            r#"{"vdl2":{"t":{"sec":1},"avlc":{"acars":{"err":false,"crc_ok":false,"label":"H1"}}}}"#,
            r#"{"hfdl":{"t":{"sec":1},"lpdu":{"hfnpdu":{"acars":{"err":true}}}}}"#,
            r#"{"timestamp":1,"label":"H1","block_id":"1","text":"x","end":true,"assstat":"in progress"}"#,
            r#"{"timestamp":1,"label":"H1","block_id":"2","text":"x","assstat":"out of sequence"}"#,
            r#"{"timestamp":1,"label":"H1","block_id":"2","text":"x","assstat":"duplicate"}"#,
            // A block with more to follow: libacars', acarsdec's and vdlm2dec's.
            r#"{"vdl2":{"t":{"sec":1},"avlc":{"acars":{"err":false,"crc_ok":true,"more":true,"label":"H1","blk_id":"6","msg_text":"x"}}}}"#,
            r#"{"hfdl":{"t":{"sec":1},"lpdu":{"hfnpdu":{"acars":{"err":false,"crc_ok":true,"more":true,"label":"H1"}}}}}"#,
            r#"{"timestamp":1,"label":"H1","block_id":"1","text":"x","end":true}"#,
            r#"{"timestamp":1,"toaddr":1131690,"label":"H1","block_id":"1","text":"x","end":true}"#,
        ] {
            assert_eq!(publish(damaged), Err(Refused::Damaged), "{damaged}");
        }
        assert!(
            project(
                r#"{"timestamp":1,"label":"H1","block_id":"2","text":"xy","assstat":"complete"}"#
            )
            .is_some()
        );
    }
}
