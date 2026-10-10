//! One budget of threads for a host's MLAT work (RFC-0181 §10, "MLAT in the cores"). A relay
//! hosting MLAT runs three kinds of work apart (seals, window steps and provisional steps), each
//! spreading over threads of its own; were each given the plan's threads, the three together would
//! run three times them, more cores than the plan gave MLAT. So a host makes one [`Gate`] of the
//! plan's threads, and every thread doing MLAT work holds one of its permits while it works: the
//! thread a step starts on ([`enter`]), and every thread a step spreads its work over
//! ([`on_threads`], which every parallel pass of the solver and the engine goes through). A thread
//! waiting on its own workers lends its permit to them while it waits ([`lend`]), so no thread
//! holds one idle. Provisional work is let in first, and never waits on background work for its
//! first permit: of a gate of two or more permits, background work holds all but one at most
//! ([`Gate::reserved`]), so a provisional step that arrives while seals and window steps hold every
//! permit they may takes the one left at once, and runs on it however long their items are.
//! Before, every permit could be background's, and a provisional step waited for one until a
//! [`checkpoint`], which only the window's fits had: a seal or a scope pass held it up whole). A
//! gate of one permit cannot spare one, so there background work gives its permit up between two
//! items of its work whenever a provisional thread waits ([`checkpoint`], in every pass of the
//! seals, the scope and the window, each item a receiver, a message run, an address or a tile),
//! and a waiting [`Urgency::Prompt`] thread takes the next permit freed: a provisional step then
//! waits one item at most. Beyond its first, a provisional step's threads take the permits
//! background gives up at its checkpoints.
//!
//! Work run on no gate (an engine driven in line, a test, a relay's standing) is not bounded here:
//! every call is then a no-op. Which thread runs what, and when, never changes what is computed.

use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// How soon a gate's work is needed: provisional work before background (seals, window steps,
/// forgetting receivers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Urgency {
    Prompt,
    Background,
}

/// The permits, the threads waiting for one by urgency, and the most ever held at once.
#[derive(Debug, Default)]
struct State {
    free: usize,
    prompt_waiting: usize,
    held: usize,
    peak: usize,
}

/// A host's threads for MLAT work (module docs): `permits` of them working at once, at most.
#[derive(Debug)]
pub struct Gate {
    state: Mutex<State>,
    freed: Condvar,
    /// Permits background work never takes (`reserved`).
    reserve: usize,
    /// `State::prompt_waiting`, readable without the lock: what a checkpoint asks.
    prompt_waiting: AtomicUsize,
}

impl Gate {
    /// A gate of `permits` threads, at least one, one of them kept for provisional work when there
    /// are two or more ([`Gate::reserved`]).
    pub fn new(permits: usize) -> Arc<Self> {
        let permits = permits.max(1);
        Arc::new(Self {
            state: Mutex::new(State {
                free: permits,
                ..State::default()
            }),
            freed: Condvar::new(),
            reserve: Self::reserved(permits),
            prompt_waiting: AtomicUsize::new(0),
        })
    }

    /// Of a gate of `permits`, the permits background work never holds: one when there are two or
    /// more, so provisional work always finds one free at once (module docs); none of one, which
    /// background work could not do without.
    pub const fn reserved(permits: usize) -> usize {
        if permits >= 2 { 1 } else { 0 }
    }

    /// The most threads that ever held a permit at once.
    pub fn peak(&self) -> usize {
        self.lock().peak
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn acquire(&self, urgency: Urgency) {
        let mut state = self.lock();
        match urgency {
            Urgency::Prompt => {
                state.prompt_waiting += 1;
                self.prompt_waiting
                    .store(state.prompt_waiting, Ordering::Release);
                while state.free == 0 {
                    state = self
                        .freed
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                state.prompt_waiting -= 1;
                self.prompt_waiting
                    .store(state.prompt_waiting, Ordering::Release);
            }
            Urgency::Background => {
                while state.free <= self.reserve || state.prompt_waiting > 0 {
                    state = self
                        .freed
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            }
        }
        state.free -= 1;
        state.held += 1;
        state.peak = state.peak.max(state.held);
    }

    fn release(&self) {
        let mut state = self.lock();
        state.free += 1;
        state.held -= 1;
        drop(state);
        self.freed.notify_all();
    }

    /// Whether a prompt thread waits for a permit: without the lock, so a checkpoint costs a load.
    pub(crate) fn prompt_waits(&self) -> bool {
        self.prompt_waiting.load(Ordering::Acquire) > 0
    }
}

/// The gate this thread works under, its urgency, and whether it holds a permit now.
struct Here {
    gate: Arc<Gate>,
    urgency: Urgency,
    holding: bool,
}

thread_local! {
    static HERE: RefCell<Option<Here>> = const { RefCell::new(None) };
}

/// Runs `work` on this thread as one of `gate`'s at `urgency`: it waits for a permit, holds it
/// while `work` runs (lending it while `work` waits on its own workers, [`lend`]), and gives it back
/// after.
pub fn enter<R>(gate: &Arc<Gate>, urgency: Urgency, work: impl FnOnce() -> R) -> R {
    gate.acquire(urgency);
    let before = HERE.with(|here| {
        here.borrow_mut().replace(Here {
            gate: Arc::clone(gate),
            urgency,
            holding: true,
        })
    });
    struct Leave(Option<Here>);
    impl Drop for Leave {
        fn drop(&mut self) {
            let left = HERE.with(|here| std::mem::replace(&mut *here.borrow_mut(), self.0.take()));
            if let Some(left) = left
                && left.holding
            {
                left.gate.release();
            }
        }
    }
    let _leave = Leave(before);
    work()
}

/// What a thread spawned from this one works under: the same gate at the same urgency, if any.
#[derive(Clone)]
pub struct Inherited(Option<(Arc<Gate>, Urgency)>);

/// This thread's gate and urgency, for the threads it spawns.
pub fn inherited() -> Inherited {
    Inherited(HERE.with(|here| {
        here.borrow()
            .as_ref()
            .map(|here| (Arc::clone(&here.gate), here.urgency))
    }))
}

impl Inherited {
    /// Runs `work` here under the inherited gate, if any: holding one of its permits.
    pub fn run<R>(&self, work: impl FnOnce() -> R) -> R {
        match &self.0 {
            Some((gate, urgency)) => enter(gate, *urgency, work),
            None => work(),
        }
    }
}

/// Runs `wait`, in which this thread only waits on threads of its own, with its permit lent out
/// meanwhile, and takes one again after.
pub fn lend<R>(wait: impl FnOnce() -> R) -> R {
    let lent = HERE.with(|here| {
        let mut here = here.borrow_mut();
        match here.as_mut() {
            Some(here) if here.holding => {
                here.holding = false;
                here.gate.release();
                Some((Arc::clone(&here.gate), here.urgency))
            }
            _ => None,
        }
    });
    struct Back(Option<(Arc<Gate>, Urgency)>);
    impl Drop for Back {
        fn drop(&mut self) {
            if let Some((gate, urgency)) = self.0.take() {
                gate.acquire(urgency);
                HERE.with(|here| {
                    if let Some(here) = here.borrow_mut().as_mut() {
                        here.holding = true;
                    }
                });
            }
        }
    }
    let _back = Back(lent);
    wait()
}

/// Between two items of a thread's work: background work whose gate has a prompt thread waiting
/// gives its permit up, and takes one again once the prompt work has its. Cheap (a thread-local
/// read and an atomic load), so every pass of background work calls it between its items.
pub fn checkpoint() {
    PASSED.with(|passed| passed.set(passed.get() + 1));
    let yielding = HERE.with(|here| {
        here.borrow().as_ref().and_then(|here| {
            (here.holding && here.urgency == Urgency::Background && here.gate.prompt_waits())
                .then(|| Arc::clone(&here.gate))
        })
    });
    if let Some(gate) = yielding {
        gate.release();
        gate.acquire(Urgency::Background);
    }
}

/// Runs `work` on each of `inputs` on at most `threads` threads under this thread's gate (here,
/// item by item, when one would do), this thread's permit lent to them while it waits, and returns
/// the results in the inputs' order. The threads pull the inputs one at a time from one shared
/// index (work stealing), checkpointing between two, so the pass ends about when its work over
/// the permits it actually holds is done, whatever the permit count: of a gate of `N` permits,
/// background work holds `N - 1` at most ([`Gate::reserved`]), and a pass cut into `N` fixed
/// shares left its last share to start only once another had ended, taking about twice as long
/// (a ten-second window step took twenty on eight threads, past the models' ripening).
/// A thread that gets its permit late finds what is left, or nothing. Which thread runs which
/// input never changes the results. A worker's panic is this thread's: the workers are plain
/// scoped threads, joined here, each panic raised again on this thread.
pub fn on_threads<I: Send, R: Send>(
    threads: usize,
    inputs: Vec<I>,
    work: impl Fn(I) -> R + Sync,
) -> Vec<R> {
    let workers = threads.clamp(1, inputs.len().max(1));
    if workers <= 1 {
        return inputs
            .into_iter()
            .map(|input| {
                checkpoint();
                work(input)
            })
            .collect();
    }
    let count = inputs.len();
    let slots: Vec<Mutex<Option<I>>> = inputs
        .into_iter()
        .map(|input| Mutex::new(Some(input)))
        .collect();
    let next = AtomicUsize::new(0);
    let (work, slots, next) = (&work, &slots, &next);
    let inherited = inherited();
    let pulled: Vec<Vec<(usize, R)>> = lend(|| {
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    let inherited = inherited.clone();
                    scope.spawn(move || {
                        inherited.run(|| {
                            let mut done = Vec::new();
                            loop {
                                let at = next.fetch_add(1, Ordering::Relaxed);
                                if at >= count {
                                    return done;
                                }
                                checkpoint();
                                let input = slots[at]
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .take();
                                if let Some(input) = input {
                                    done.push((at, work(input)));
                                }
                            }
                        })
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| match handle.join() {
                    Ok(done) => done,
                    Err(panic) => std::panic::resume_unwind(panic),
                })
                .collect()
        })
    });
    let mut results: Vec<Option<R>> = (0..count).map(|_| None).collect();
    for (at, result) in pulled.into_iter().flatten() {
        results[at] = Some(result);
    }
    results.into_iter().flatten().collect()
}

/// Inputs per item a pass over `len` cheap inputs on `threads` threads hands its workers at a time
/// ([`on_threads`] of chunks this long): about `PIECES_PER_THREAD` pieces a thread, so a thread
/// that comes late, or one whose pieces run long, costs the pass one piece at most.
pub fn piece(len: usize, threads: usize) -> usize {
    len.div_ceil(threads.max(1) * PIECES_PER_THREAD).max(1)
}

/// Pieces a pass of cheap inputs is cut into per thread (`piece`).
pub const PIECES_PER_THREAD: usize = 16;

/// Checkpoints this thread has passed: what a test reads to hold a pass to its items.
pub fn checkpoints_here() -> u64 {
    PASSED.with(std::cell::Cell::get)
}

thread_local! {
    static PASSED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Work spread over many threads under a gate of two never runs on more than two at once,
    /// whatever it nests, and computes what it computes on no gate.
    #[test]
    fn work_under_a_gate_runs_on_its_permits_at_most() {
        let gate = Gate::new(2);
        let running = AtomicUsize::new(0);
        let most = AtomicUsize::new(0);
        let item = |n: usize| {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            most.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(2));
            running.fetch_sub(1, Ordering::SeqCst);
            n * 2
        };
        let gated = enter(&gate, Urgency::Background, || {
            on_threads(8, (0..8).collect(), |n: usize| {
                on_threads(2, vec![n, n + 100], item)
                    .into_iter()
                    .sum::<usize>()
            })
        });
        assert!(most.load(Ordering::SeqCst) <= 2, "{most:?}");
        assert!(gate.peak() <= 2, "{}", gate.peak());
        let free: Vec<usize> = on_threads(8, (0..8).collect(), |n: usize| {
            on_threads(2, vec![n, n + 100], item)
                .into_iter()
                .sum::<usize>()
        });
        assert_eq!(gated, free);
    }

    /// Background work never holds a gate's every permit when it has two or more, so
    /// a provisional step arriving while background work holds all it may starts at once, however
    /// long the background items run and with no checkpoint among them. Before, a background step
    /// spread over the gate's every permit held a provisional one up until an item ended. Judged
    /// by order, not by a clock: the background items end only once the prompt
    /// work has run (or after a minute, so a failure ends), and the prompt work must have run while
    /// none had ended.
    #[test]
    fn prompt_work_finds_a_permit_free_at_once_while_background_holds_all_it_may() {
        for permits in [2, 3, 8] {
            let gate = Gate::new(permits);
            let let_go = Arc::new(AtomicUsize::new(0));
            let running = Arc::new(AtomicUsize::new(0));
            let ended = Arc::new(AtomicUsize::new(0));
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            std::thread::scope(|scope| {
                let (gate_b, let_go_b, running_b, ended_b) = (
                    Arc::clone(&gate),
                    Arc::clone(&let_go),
                    Arc::clone(&running),
                    Arc::clone(&ended),
                );
                scope.spawn(move || {
                    enter(&gate_b, Urgency::Background, || {
                        // Every item waits, with no checkpoint, until the prompt work has run.
                        on_threads(permits * 2, (0..permits * 2).collect(), |_: usize| {
                            running_b.fetch_add(1, Ordering::SeqCst);
                            let started = std::time::Instant::now();
                            while let_go_b.load(Ordering::SeqCst) == 0
                                && started.elapsed() < Duration::from_secs(60)
                            {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            ended_b.fetch_add(1, Ordering::SeqCst);
                        });
                    });
                });
                // Background holds every permit it may.
                let held = permits - Gate::reserved(permits);
                while running.load(Ordering::SeqCst) < held {
                    std::thread::sleep(Duration::from_millis(1));
                }
                let (gate_p, ended_p) = (Arc::clone(&gate), Arc::clone(&ended));
                scope.spawn(move || {
                    enter(&gate_p, Urgency::Prompt, || {
                        let _ = entered_tx.send(ended_p.load(Ordering::SeqCst));
                    });
                });
                let ended_before = entered_rx.recv();
                let_go.store(1, Ordering::SeqCst);
                assert_eq!(
                    ended_before,
                    Ok(0),
                    "the prompt work waited for background work to end an item, of {permits}"
                );
            });
            assert!(gate.peak() <= permits, "{} of {permits}", gate.peak());
        }
    }

    /// A background pass under a gate of `N` permits, which may hold `N - 1` of them,
    /// ends in the rounds its work takes over `N - 1` threads, not in twice them. Counted in
    /// rounds, not time: every item waits until `N - 1` items are in its round (or a long while,
    /// which only a starved round ever waits out), so the rounds a pass takes are its schedule's.
    /// Cut into `N` fixed shares, `N - 1` shares ran in `N - 1` full rounds, and the last share
    /// started only after, one item a round: `2 (N - 1)` rounds. Pulled from one index, the
    /// `N (N - 1)` items take `N` full rounds.
    #[test]
    fn a_background_pass_on_n_permits_takes_its_work_over_the_permits_it_holds() {
        for permits in [2, 3, 4, 8] {
            let gate = Gate::new(permits);
            let width = permits - Gate::reserved(permits);
            let items = permits * width;
            let rounds = Mutex::new((0usize, 0usize));
            let advanced = Condvar::new();
            let full = AtomicUsize::new(0);
            enter(&gate, Urgency::Background, || {
                on_threads(permits, (0..items).collect(), |_: usize| {
                    let mut state = rounds
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let mine = state.0;
                    state.1 += 1;
                    if state.1 == width {
                        full.fetch_add(1, Ordering::SeqCst);
                        *state = (mine + 1, 0);
                        advanced.notify_all();
                        return;
                    }
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    while state.0 == mine {
                        let left = deadline.saturating_duration_since(std::time::Instant::now());
                        if left.is_zero() {
                            // A starved round: it ends short.
                            *state = (mine + 1, 0);
                            advanced.notify_all();
                            break;
                        }
                        state = advanced
                            .wait_timeout(state, left)
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .0;
                    }
                });
            });
            let (taken, _) = *rounds
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(
                (taken, full.load(Ordering::SeqCst)),
                (items / width, items / width),
                "rounds taken and full of {items} items on {permits} permits"
            );
        }
    }

    /// A prompt thread waiting for a permit is let in at the next checkpoint of background work
    /// holding every permit.
    #[test]
    fn prompt_work_is_let_in_between_two_items_of_background_work() {
        let gate = Gate::new(1);
        let started = Arc::new(std::sync::Barrier::new(2));
        let done = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            let (gate_b, started_b, done_b) = (Arc::clone(&gate), Arc::clone(&started), &done);
            scope.spawn(move || {
                enter(&gate_b, Urgency::Background, || {
                    started_b.wait();
                    // Items until the prompt work has run: it gets in at a checkpoint.
                    while done_b.load(Ordering::SeqCst) == 0 {
                        std::thread::sleep(Duration::from_millis(1));
                        checkpoint();
                    }
                });
            });
            started.wait();
            enter(&gate, Urgency::Prompt, || done.store(1, Ordering::SeqCst));
        });
        assert_eq!(gate.peak(), 1);
    }
}
