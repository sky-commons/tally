//! The probe's held read (RFC-0198 Appendix C, the held-read prototype): the indexes a `Reader`
//! makes of a window's receptions (each message's receptions, each second's messages, each
//! aircraft's positions and NACp by second), kept between refits and changed reception by
//! reception, and a block's events found from them as `Reader::events` finds them. A message's
//! place in byte order (`Reader::rank`) is its bytes compared; a clock's, its key's place
//! (`order`). Nothing here is read by a release.

use super::*;
use crate::arrived::proto::FxMap;

/// One reception as the held read keeps it: its clock (the prototype's number), linear count,
/// wall clock and message (the gather's number).
#[derive(Clone, Copy)]
pub(crate) struct HeldRx {
    pub(crate) clock: u32,
    pub(crate) linear: i64,
    pub(crate) wall: u64,
    pub(crate) message: u32,
}

struct HeldMessage {
    data: Box<[u8]>,
    parsed: Parsed,
    /// Its receptions, by slot.
    rxs: Vec<u32>,
}

/// The held read of one area.
#[derive(Default)]
pub(crate) struct HeldRead {
    messages: FxMap<u32, HeldMessage>,
    slots: Vec<Option<HeldRx>>,
    free: Vec<u32>,
    /// Each second's messages, with how many of their receptions are in it.
    by_second: BTreeMap<u64, FxMap<u32, u32>>,
    /// Each aircraft's position and NACp receptions, by second.
    positions: FxMap<(u32, u64), Vec<u32>>,
    nacp: FxMap<(u32, u64), Vec<u32>>,
}

/// A block's sync event as the held read finds it: its aircraft and hearers (slot, range).
pub(crate) struct HeldEvent {
    pub(crate) address: u32,
    pub(crate) hearers: Vec<(u32, f64)>,
}

fn remove_one(list: &mut Vec<u32>, slot: u32) {
    if let Some(at) = list.iter().position(|one| *one == slot) {
        list.swap_remove(at);
    }
}

impl HeldRead {
    /// Bytes it holds, roughly.
    pub(crate) fn bytes(&self) -> usize {
        self.messages
            .values()
            .map(|held| 120 + held.data.len() + held.rxs.capacity() * 4)
            .sum::<usize>()
            + self.slots.capacity() * size_of::<Option<HeldRx>>()
            + self
                .by_second
                .values()
                .map(|map| 48 + map.capacity() * 16)
                .sum::<usize>()
            + self
                .positions
                .values()
                .chain(self.nacp.values())
                .map(|list| 48 + list.capacity() * 4)
                .sum::<usize>()
    }

    /// The reception at `slot`.
    pub(crate) fn rx(&self, slot: u32) -> Option<&HeldRx> {
        self.slots.get(slot as usize)?.as_ref()
    }

    /// Keeps `rx` (its message's bytes `data`), returning its slot.
    pub(crate) fn add(&mut self, rx: HeldRx, data: &[u8]) -> u32 {
        let slot = match self.free.pop() {
            Some(slot) => {
                self.slots[slot as usize] = Some(rx);
                slot
            }
            None => {
                self.slots.push(Some(rx));
                (self.slots.len() - 1) as u32
            }
        };
        let held = self
            .messages
            .entry(rx.message)
            .or_insert_with(|| HeldMessage {
                data: data.into(),
                parsed: Parsed::of(data),
                rxs: Vec::new(),
            });
        held.rxs.push(slot);
        let (address, position, nacp) = (
            held.parsed.address,
            held.parsed.position.is_some(),
            held.parsed.nacp.is_some(),
        );
        let second = rx.wall / 1000;
        *self
            .by_second
            .entry(second)
            .or_default()
            .entry(rx.message)
            .or_insert(0) += 1;
        if let Some(address) = address {
            if position {
                self.positions
                    .entry((address, second))
                    .or_default()
                    .push(slot);
            }
            if nacp {
                self.nacp.entry((address, second)).or_default().push(slot);
            }
        }
        slot
    }

    /// Lets go of the reception at `slot`.
    pub(crate) fn remove(&mut self, slot: u32) {
        let Some(rx) = self.slots.get_mut(slot as usize).and_then(Option::take) else {
            return;
        };
        self.free.push(slot);
        let second = rx.wall / 1000;
        if let Some(map) = self.by_second.get_mut(&second) {
            if let Some(count) = map.get_mut(&rx.message) {
                *count -= 1;
                if *count == 0 {
                    map.remove(&rx.message);
                }
            }
            if map.is_empty() {
                self.by_second.remove(&second);
            }
        }
        let Some(held) = self.messages.get_mut(&rx.message) else {
            return;
        };
        remove_one(&mut held.rxs, slot);
        let (address, position, nacp) = (
            held.parsed.address,
            held.parsed.position.is_some(),
            held.parsed.nacp.is_some(),
        );
        if held.rxs.is_empty() {
            self.messages.remove(&rx.message);
        }
        if let Some(address) = address {
            for (wanted, table) in [(position, &mut self.positions), (nacp, &mut self.nacp)] {
                if !wanted {
                    continue;
                }
                if let Some(list) = table.get_mut(&(address, second)) {
                    remove_one(list, slot);
                    if list.is_empty() {
                        table.remove(&(address, second));
                    }
                }
            }
        }
    }

    fn data(&self, message: u32) -> &[u8] {
        self.messages.get(&message).map_or(&[], |held| &held.data)
    }

    /// The CPR reference of `address` for the block of `second` (`Reader::reference`), clocks
    /// in key order by `order`, their pair windows `windows`.
    fn reference(
        &mut self,
        address: u32,
        second: u64,
        order: &[u32],
        windows: &[i64],
    ) -> Option<modes::LatLon> {
        let (from, to) = Reader::read_span(second);
        // (clock's place, linear, message, odd, wall), sorted as `Reader::positions` is.
        let mut heard: Vec<(u32, i64, u32, bool, u64)> = Vec::new();
        for at in from / 1000..to / 1000 {
            for slot in self
                .positions
                .get(&(address, at))
                .map_or(&[][..], Vec::as_slice)
            {
                let Some(rx) = self.slots[*slot as usize] else {
                    continue;
                };
                if !(from..to).contains(&rx.wall) {
                    continue;
                }
                let odd = self
                    .messages
                    .get(&rx.message)
                    .and_then(|held| held.parsed.position)
                    .is_some_and(|position| position.odd);
                heard.push((
                    order[rx.clock as usize],
                    rx.linear,
                    rx.message,
                    odd,
                    rx.wall,
                ));
            }
        }
        heard.sort_unstable_by(|a, b| {
            (a.0, a.1)
                .cmp(&(b.0, b.1))
                .then_with(|| self.data(a.2).cmp(self.data(b.2)))
                .then((a.3, a.4).cmp(&(b.3, b.4)))
        });
        // As `cpr_reference`, a message's rank its bytes.
        let mut evens: Vec<u32> = heard
            .iter()
            .filter(|(_, _, _, odd, _)| !odd)
            .map(|(_, _, message, _, _)| *message)
            .collect();
        evens.sort_unstable_by(|a, b| self.data(*a).cmp(self.data(*b)));
        evens.dedup();
        let mut candidates: Vec<(u32, bool)> = Vec::new();
        for even in evens {
            candidates.clear();
            for (at, (clock, time, message, odd, _)) in heard.iter().enumerate() {
                if *odd || *message != even {
                    continue;
                }
                let window = windows[*clock as usize];
                let low = heard[..at]
                    .partition_point(|(c, t, _, _, _)| *c < *clock || *t < time - window);
                for (_, odd_time, odd_message, is_odd, _) in heard[low..]
                    .iter()
                    .take_while(|(c, t, _, _, _)| *c == *clock && *t <= time + window)
                {
                    if *is_odd {
                        candidates.push((*odd_message, odd_time > time));
                    }
                }
            }
            candidates
                .sort_unstable_by(|a, b| self.data(a.0).cmp(self.data(b.0)).then(a.1.cmp(&b.1)));
            candidates.dedup();
            let Some(even_position) = self
                .messages
                .get(&even)
                .and_then(|held| held.parsed.position)
            else {
                continue;
            };
            for (odd, odd_latest) in &candidates {
                let Some(odd_position) =
                    self.messages.get(odd).and_then(|held| held.parsed.position)
                else {
                    continue;
                };
                if let Some(position) = modes::cpr_global(
                    (even_position.lat_cpr, even_position.lon_cpr),
                    (odd_position.lat_cpr, odd_position.lon_cpr),
                    *odd_latest,
                ) {
                    return Some(position);
                }
            }
        }
        None
    }

    /// The NACp in force at an event of `address` in the block of `second`, its receptions
    /// `slots` (`Reader::nacp_at`).
    fn nacp_at(
        &self,
        address: u32,
        second: u64,
        slots: &[u32],
        timebase_of: &dyn Fn(u32) -> Timebase,
    ) -> Option<u8> {
        let (from, to) = Reader::read_span(second);
        let mut best: Option<(bool, i128, u8)> = None;
        for slot in slots {
            let Some(rx) = self.slots[*slot as usize] else {
                continue;
            };
            let mut before: Option<(i64, u8)> = None;
            let mut after: Option<(i64, u8)> = None;
            for at in from / 1000..to / 1000 {
                for one in self.nacp.get(&(address, at)).map_or(&[][..], Vec::as_slice) {
                    let Some(other) = self.slots[*one as usize] else {
                        continue;
                    };
                    if other.clock != rx.clock || !(from..to).contains(&other.wall) {
                        continue;
                    }
                    let Some(value) = self
                        .messages
                        .get(&other.message)
                        .and_then(|held| held.parsed.nacp)
                    else {
                        continue;
                    };
                    // As the sorted run's scan: the latest at or before, of equals the lower
                    // value; the earliest after, of equals the lower value.
                    if other.linear <= rx.linear {
                        if before.is_none_or(|(held, held_value)| {
                            other.linear > held || (other.linear == held && value < held_value)
                        }) {
                            before = Some((other.linear, value));
                        }
                    } else if after.is_none_or(|(held, held_value)| {
                        other.linear < held || (other.linear == held && value < held_value)
                    }) {
                        after = Some((other.linear, value));
                    }
                }
            }
            let timebase = timebase_of(rx.clock);
            let candidates = [
                before.map(|(linear, value)| {
                    (
                        false,
                        timebase.elapsed_ps(i128::from(rx.linear) - i128::from(linear)),
                        value,
                    )
                }),
                after.map(|(linear, value)| {
                    (
                        true,
                        timebase.elapsed_ps(i128::from(linear) - i128::from(rx.linear)),
                        value,
                    )
                }),
            ];
            for candidate in candidates.into_iter().flatten() {
                if best.is_none_or(|known| candidate < known) {
                    best = Some(candidate);
                }
            }
        }
        best.map(|(_, _, value)| value)
    }

    /// The sync events of the block of `second` (`Reader::events`), in byte order of their
    /// messages; clocks by the prototype's numbering: `order` their key order, `sites` theirs.
    pub(crate) fn events(
        &mut self,
        second: u64,
        order: &[u32],
        sites: &[SiteInfo],
    ) -> Vec<HeldEvent> {
        let Some(map) = self.by_second.get(&second) else {
            return Vec::new();
        };
        let mut messages: Vec<u32> = map.keys().copied().collect();
        messages.sort_unstable_by(|a, b| self.data(*a).cmp(self.data(*b)));
        let windows: Vec<i64> = sites
            .iter()
            .map(|site| site.timebase.pair_counts())
            .collect();
        // `windows` by clock place: the reference's heard list is by place.
        let mut by_place: Vec<i64> = vec![0; order.len()];
        for (clock, place) in order.iter().enumerate() {
            if let Some(slot) = by_place.get_mut(*place as usize) {
                *slot = windows[clock];
            }
        }
        let (look_from, _) = Reader::read_span(second);
        let (own_from, own_to) = (second * 1000, (second + 1 + SPAN_AFTER_S) * 1000);
        let mut references: FxMap<u32, Option<modes::LatLon>> = FxMap::default();
        let mut events = Vec::new();
        let mut indices: Vec<u32> = Vec::new();
        for message in messages {
            let Some(held) = self.messages.get(&message) else {
                continue;
            };
            if held.rxs.iter().any(|slot| {
                self.slots[*slot as usize]
                    .is_some_and(|rx| rx.wall >= look_from && rx.wall < own_from)
            }) {
                continue;
            }
            indices.clear();
            indices.extend(held.rxs.iter().copied().filter(|slot| {
                self.slots[*slot as usize].is_some_and(|rx| (own_from..own_to).contains(&rx.wall))
            }));
            let parsed = held.parsed;
            let (Some(address), Some(position)) = (parsed.address, parsed.position) else {
                continue;
            };
            if position.altitude.is_none() {
                continue;
            }
            let reference = match references.get(&address) {
                Some(found) => *found,
                None => {
                    let found = self.reference(address, second, order, &by_place);
                    references.insert(address, found);
                    found
                }
            };
            let Some(reference) = reference else {
                continue;
            };
            let Some(decoded) = self
                .messages
                .get_mut(&message)
                .and_then(|held| held.parsed.decode(reference))
            else {
                continue;
            };
            if !decoded.near {
                continue;
            }
            let timebase_of = |clock: u32| sites[clock as usize].timebase;
            let declared = self
                .nacp_at(address, second, &indices, &timebase_of)
                .and_then(modes::epu_m)
                .or_else(|| modes::containment_m(position.type_code));
            let Some(declared) = declared else {
                continue;
            };
            let sigma_h = (declared / R95).max(MIN_PRIOR_SIGMA_M);
            if sigma_h > MAX_PRIOR_SIGMA_M {
                continue;
            }
            // A clock that heard the message twice in the event's span is left out of it.
            let mut by_clock: Vec<(u32, u32, u32)> = indices
                .iter()
                .filter_map(|slot| {
                    let rx = self.slots[*slot as usize]?;
                    Some((order[rx.clock as usize], rx.clock, *slot))
                })
                .collect();
            by_clock.sort_unstable();
            let mut hearers = Vec::new();
            for (at, (place, clock, slot)) in by_clock.iter().enumerate() {
                let twice = (at > 0 && by_clock[at - 1].0 == *place)
                    || by_clock.get(at + 1).is_some_and(|next| next.0 == *place);
                if twice {
                    continue;
                }
                let range_m = linalg::norm(linalg::sub(decoded.prior, sites[*clock as usize].ecef));
                if range_m <= MAX_RANGE_M {
                    hearers.push((*slot, range_m));
                }
            }
            if hearers.len() < 2 {
                continue;
            }
            events.push(HeldEvent { address, hearers });
        }
        events
    }
}
