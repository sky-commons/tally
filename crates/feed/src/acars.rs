//! Reading ACARS, VDL2 and HFDL messages from acars_router (RFC-0187 §3).
//!
//! acarsdec and vdlm2dec (VHF ACARS), dumpvdl2 (VDL Mode 2) and dumphfdl (HFDL) write one JSON
//! object a message, but none serves it on a port to connect to: acarsdec sends it over UDP,
//! dumpvdl2 and dumphfdl over UDP or ZeroMQ, each to an address it is given. acars_router
//! (github.com/sdr-enthusiasts/acars_router), which most stations run in front of them, takes them
//! in and serves each kind over TCP, one message a line (`AR_SERVE_TCP_ACARS` 15550,
//! `AR_SERVE_TCP_VDLM2` 15555, `AR_SERVE_TCP_HFDL` 15556; at commit 63d8d288, its
//! `rust/libraries/acars_connection_manager/src/tcp_services.rs`, `forward_to_peer`, writes each
//! message as `to_string_newline`). That is what `--acars` reads, one port each. The three shapes:
//!
//! ```text
//! {"timestamp":1516206744.1849549,"station_id":"XX","channel":2,"freq":130.025,"level":-22,...}
//! {"vdl2":{"app":{...},"station":"XX","t":{"sec":1645287903,"usec":757630},"sig_level":-20.8,
//!   ...,"avlc":{...}}}
//! {"hfdl":{"app":{...},"station":"XX","t":{"sec":1769991933,"usec":817375},"sig_level":-9.2,
//!   ...,"lpdu":{...}}}
//! ```
//!
//! Only the message is published, as [`acars::publish`] maps it into the one flat schema (the one
//! rule, which the relay and the map's collector hold every line to): the aircraft, the ground
//! station, the message's own fields and text, and its time to the second. Nothing of a decoder's
//! frame trees, nothing of the receiver; a frame that carries no ACARS message is counted and not
//! published.

use tally_wire::Observation;
use tally_wire::acars::{self, Refused};
use tally_wire::batch::format;

use crate::lines::{Line, TIMESTAMP_MODULUS};

/// The longest line read: the wire's cap ([`acars::MAX_LINE`]). Only what is allowed of a
/// message is published, so a longer line can still be published; a line past four times the cap
/// is not a message.
pub const MAX_LINE: usize = 4 * acars::MAX_LINE;

/// One line, without its newline. A message that states no usable time of its own is not
/// published: the feeder's clock would say when this receiver heard it, to the microsecond.
pub fn parse_line(line: &str) -> Line {
    let line = line.trim();
    if line.is_empty() {
        return Line::Ignored;
    }
    let text = match acars::publish(line) {
        Ok(text) => text,
        Err(Refused::NotAcars | Refused::Damaged) => return Line::NotPublished,
        Err(Refused::Malformed) => return Line::Bad,
    };
    let Some(timestamp) = acars::time_us(&text) else {
        return Line::Bad;
    };
    Line::Reception(Observation {
        format: format::ACARS_JSON,
        timestamp: timestamp % TIMESTAMP_MODULUS,
        signal: 0,
        data: text.into_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Real lines, as each decoder wrote them, through acars_router where noted:
    ///
    /// - acarsdec: the first three are its README's JSON examples (github.com/TLeconte/acarsdec,
    ///   README.md, "-o 4" and "-o 5"); the fourth is acars_router's test fixture
    ///   (github.com/sdr-enthusiasts/acars_router at 63d8d288,
    ///   `rust/libraries/acars_connection_manager/tests/fixtures/acars.jsonl`, line 1); the fifth
    ///   and sixth are acarsdec 4.4.1 through acars_router 1.3.1, from ACARS Hub's test fixtures
    ///   (github.com/sdr-enthusiasts/docker-acarshub at 862da2a6,
    ///   `acarshub-react/tests/fixtures/raw-acars-messages.jsonl`, lines 5 and 9).
    /// - dumpvdl2: acars_router's `tests/fixtures/vdlm2.jsonl` line 1 (dumpvdl2 2.1.1, a ground
    ///   station's XID), then ACARS Hub's `raw-vdlm2-messages.jsonl` (dumpvdl2 2.5.1 through
    ///   acars_router): an aircraft's ACARS, and line 509, a block with more to follow.
    /// - dumphfdl: ACARS Hub's `raw-hfdl-messages.jsonl` (dumphfdl 1.7.0 through acars_router), a
    ///   ground station's SPDU, an aircraft's LPDU, and one carrying ACARS.
    const ACARSDEC: &str = include_str!("../testdata/acarsdec.jsonl");
    const DUMPVDL2: &str = include_str!("../testdata/dumpvdl2.jsonl");
    const DUMPHFDL: &str = include_str!("../testdata/dumphfdl.jsonl");

    /// The schema's keys (`tally_wire::acars`).
    const SCHEMA: &[&str] = &[
        "ack", "block", "flight", "gs", "icao", "kind", "label", "mode", "msgnum", "reg",
        "sublabel", "t", "text",
    ];

    fn published(line: &str) -> Result<(String, u64), String> {
        let Line::Reception(observation) = parse_line(line) else {
            return Err(format!("not published: {line}"));
        };
        assert_eq!(
            (observation.format, observation.signal),
            (format::ACARS_JSON, 0)
        );
        let text = String::from_utf8(observation.data).map_err(|error| error.to_string())?;
        assert!(acars::line(text.as_bytes()).is_some(), "{text}");
        let value: Value = serde_json::from_str(&text).map_err(|error| error.to_string())?;
        for key in value
            .as_object()
            .into_iter()
            .flat_map(|object| object.keys())
        {
            assert!(SCHEMA.contains(&key.as_str()), "{key} was published");
        }
        Ok((text, observation.timestamp))
    }

    /// Each decoder's real messages, as published: the schema's fields and nothing else; and each
    /// frame that carries no ACARS message, counted and not published.
    #[test]
    fn each_decoders_messages_are_published_in_the_one_schema() -> Result<(), String> {
        let lines: Vec<&str> = ACARSDEC.lines().collect();
        // A block with more of its message to follow (`end`) is not the message: both README
        // examples are.
        assert_eq!(parse_line(lines[0]), Line::NotPublished);
        assert_eq!(parse_line(lines[1]), Line::NotPublished);
        // The route summary acarsdec writes with "-o 5" is no message.
        assert_eq!(parse_line(lines[2]), Line::NotPublished);
        published(lines[3])?;
        // A block of a message acarsdec is still reassembling is not the message; the message it
        // reassembled is.
        assert_eq!(parse_line(lines[4]), Line::NotPublished);
        let (whole, timestamp) = published(lines[5])?;
        assert_eq!(
            whole,
            "{\"ack\":\"!\",\"block\":\"3\",\"flight\":\"WN4899\",\"kind\":\"acars\",\"label\":\"H1\",\
             \"mode\":\"2\",\"msgnum\":\"D50B\",\"reg\":\"N8560Z\",\"t\":1769990359,\
             \"text\":\"7T217,8560,B737-800,260201,WN4899,KPHX,KSTL,0994,SW2501\\r\\n23.58.47,CR,\
             1899,37026,255.0,.788,-57.5,-30.8,N3421.9,W10912.9,153920\\r\\n\\r\\nOATTO,LPACKCL,\
             LMIN,LMAX,RPACKCL,RMIN,RMAX\\r\\n   81,    558, 558, 558,    456, 456, 456\\r\\n\"}"
        );
        // To the second, never finer: a receiver's clock reading.
        assert_eq!(timestamp, (1_769_990_359 * 1_000_000) % TIMESTAMP_MODULUS);

        let lines: Vec<&str> = DUMPVDL2.lines().collect();
        // A ground station's XID carries no ACARS.
        assert_eq!(parse_line(lines[0]), Line::NotPublished);
        assert_eq!(
            published(lines[1])?.0,
            "{\"ack\":\"!\",\"block\":\"3\",\"flight\":\"WN2340\",\"gs\":\"1144AA\",\
             \"icao\":\"ABFDAF\",\"kind\":\"vdl2\",\"label\":\"H1\",\"mode\":\"2\",\
             \"msgnum\":\"D09A\",\"reg\":\"N8719Q\",\"sublabel\":\"DF\",\"t\":1769990648,\
             \"text\":\"#DFBABS001DA_N8719Q  KMDWKPHX287\\r\\n 35322-1078960003037993-585264034X20W/\
             X0100150000--\\r\\n\"}"
        );
        // A block libacars has more of to come is a part, never the message.
        assert_eq!(parse_line(lines[2]), Line::NotPublished);

        let lines: Vec<&str> = DUMPHFDL.lines().collect();
        // A ground station's SPDU and a logon's frequency data carry no ACARS.
        assert_eq!(parse_line(lines[0]), Line::NotPublished);
        assert_eq!(parse_line(lines[1]), Line::NotPublished);
        assert_eq!(
            published(lines[2])?.0,
            "{\"ack\":\"3\",\"block\":\"D\",\"gs\":\"1\",\"kind\":\"hfdl\",\"label\":\"_d\",\"mode\":\"2\",\"reg\":\"N731NK\",\"t\":1769991943}"
        );
        Ok(())
    }

    /// A field no decoder writes today, or a decoder's own tree, is never published.
    #[test]
    fn a_field_a_later_decoder_adds_is_dropped() -> Result<(), String> {
        let (text, _) = published(
            r#"{"timestamp":1.5,"label":"H1","text":"x","receiver_lat":51.5,"rx":{"gain":40},"libacars":{"a":1}}"#,
        )?;
        assert_eq!(text, r#"{"kind":"acars","label":"H1","t":1,"text":"x"}"#);
        let (text, _) = published(
            r#"{"vdl2":{"t":{"sec":1},"antenna":"roof","avlc":{"src":{"addr":"A1B2C3","type":"Aircraft","status":"Airborne"},"acars":{"label":"H1","crc_ok":true,"arinc622":{"cpdlc":{}}}}}}"#,
        )?;
        assert_eq!(
            text,
            r#"{"icao":"A1B2C3","kind":"vdl2","label":"H1","t":1}"#
        );
        Ok(())
    }

    /// Strings carry what the decoder said, escaped one way, not the decoder's way.
    #[test]
    fn content_is_as_it_came() -> Result<(), String> {
        let line = "{ \"timestamp\" : 1516206744.1849549, \"label\":\"H1\", \"block_id\":\"2\", \
                    \"msgno\":\"D04G\", \"text\":\"line one\\r\\nline two \\u00e9 é\" }\r";
        assert_eq!(
            published(line)?.0,
            "{\"block\":\"2\",\"kind\":\"acars\",\"label\":\"H1\",\"msgnum\":\"D04G\",\
             \"t\":1516206744,\"text\":\"line one\\r\\nline two é é\"}"
        );
        Ok(())
    }

    /// The feeder's own clock would time the message to this receiver: one with no usable time
    /// of its own is skipped.
    #[test]
    fn without_a_usable_time_a_message_is_skipped() {
        for line in [
            r#"{"vdl2":{"t":{"sec":"soon"},"avlc":{"acars":{"label":"H1"}}}}"#,
            r#"{"hfdl":{"lpdu":{"hfnpdu":{"acars":{"label":"H1"}}}}}"#,
            r#"{"timestamp":-1,"label":"H1"}"#,
            r#"{"channel":2,"freq":130.025,"mode":"2","label":"H1","block_id":"6","text":"x"}"#,
        ] {
            assert_eq!(parse_line(line), Line::Bad, "{line}");
        }
    }

    #[test]
    fn what_is_not_an_acars_family_message_is_skipped() {
        for line in [
            "not json",
            "[1,2]",
            r#""text""#,
            r#"{"text":"no time, no link"}"#,
            r#"{"vdl2":"not an object"}"#,
            r#"{"timestamp":1.0"#,
            r#"{"timestamp":1.0,"label":"H1"}{"timestamp":2.0,"label":"H1"}"#,
        ] {
            assert_eq!(parse_line(line), Line::Bad, "{line}");
        }
        // Well formed, but nothing of a message once the receiver's fields are gone.
        for line in [
            r#"{"timestamp":1.0,"station_id":"XX","level":-20}"#,
            r#"{"vdl2":{"t":{"sec":1},"sig_level":-20}}"#,
        ] {
            assert_eq!(parse_line(line), Line::NotPublished, "{line}");
        }
        assert_eq!(parse_line(""), Line::Ignored);
        assert_eq!(parse_line(" \r"), Line::Ignored);
    }

    /// A message that would pass the wire's cap once written back is skipped, not cut; one that
    /// fits once its receiver's fields are gone is published.
    #[test]
    fn a_message_past_the_cap_is_skipped() {
        let text = "x".repeat(acars::MAX_LINE);
        let line = format!(r#"{{"timestamp":1.5,"label":"H1","text":"{text}"}}"#);
        assert_eq!(parse_line(&line), Line::Bad);
        let noise = "x".repeat(acars::MAX_LINE);
        let line =
            format!(r#"{{"timestamp":1.5,"label":"H1","text":"short","station_id":"{noise}"}}"#);
        assert!(matches!(parse_line(&line), Line::Reception(_)));
    }
}
