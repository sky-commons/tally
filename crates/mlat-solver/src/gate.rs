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
//! permit they may takes the one left at once, and runs on it however long their items are (sweep 5,
//! N6: before, every permit could be background's, and a provisional step waited for one until a
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

/// Runs `work` on each of `inputs`, each on a thread of its own under this thread's gate (here when
/// there is only one), this thread's permit lent to them while it waits, and returns the results in
/// the inputs' order. A worker's panic is this thread's.
pub fn on_threads<I: Send, R: Send>(inputs: Vec<I>, work: impl Fn(I) -> R + Sync) -> Vec<R> {
    if inputs.len() <= 1 {
        return inputs.into_iter().map(work).collect();
    }
    let work = &work;
    let inherited = inherited();
    lend(|| {
        std::thread::scope(|scope| {
            let handles: Vec<_> = inputs
                .into_iter()
                .map(|input| {
                    let inherited = inherited.clone();
                    scope.spawn(move || inherited.run(|| work(input)))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| match handle.join() {
                    Ok(result) => result,
                    Err(panic) => std::panic::resume_unwind(panic),
                })
                .collect()
        })
    })
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
            on_threads((0..8).collect(), |n: usize| {
                on_threads(vec![n, n + 100], item)
                    .into_iter()
                    .sum::<usize>()
            })
        });
        assert!(most.load(Ordering::SeqCst) <= 2, "{most:?}");
        assert!(gate.peak() <= 2, "{}", gate.peak());
        let free: Vec<usize> = on_threads((0..8).collect(), |n: usize| {
            on_threads(vec![n, n + 100], item)
                .into_iter()
                .sum::<usize>()
        });
        assert_eq!(gated, free);
    }

    /// Sweep 5, N6: background work never holds a gate's every permit when it has two or more, so
    /// a provisional step arriving while background work holds all it may starts at once, however
    /// long the background items run and with no checkpoint among them. Before, a background step
    /// spread over the gate's every permit held a provisional one up until an item ended.
    #[test]
    fn prompt_work_finds_a_permit_free_at_once_while_background_holds_all_it_may() {
        for permits in [2, 3, 8] {
            let gate = Gate::new(permits);
            let let_go = Arc::new(AtomicUsize::new(0));
            let running = Arc::new(AtomicUsize::new(0));
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            std::thread::scope(|scope| {
                let (gate_b, let_go_b, running_b) =
                    (Arc::clone(&gate), Arc::clone(&let_go), Arc::clone(&running));
                scope.spawn(move || {
                    enter(&gate_b, Urgency::Background, || {
                        // Every item waits, with no checkpoint, until the prompt work has run (or
                        // ten seconds, so a failure ends).
                        on_threads((0..permits * 2).collect(), |_: usize| {
                            running_b.fetch_add(1, Ordering::SeqCst);
                            let started = std::time::Instant::now();
                            while let_go_b.load(Ordering::SeqCst) == 0
                                && started.elapsed() < Duration::from_secs(10)
                            {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                        });
                    });
                });
                // Background holds every permit it may.
                let held = permits - Gate::reserved(permits);
                while running.load(Ordering::SeqCst) < held {
                    std::thread::sleep(Duration::from_millis(1));
                }
                let asked = std::time::Instant::now();
                let gate_p = Arc::clone(&gate);
                scope.spawn(move || {
                    enter(&gate_p, Urgency::Prompt, || {
                        let _ = entered_tx.send(asked.elapsed());
                    });
                });
                let waited = entered_rx.recv_timeout(Duration::from_secs(5));
                let_go.store(1, Ordering::SeqCst);
                assert!(
                    waited.is_ok_and(|waited| waited < Duration::from_secs(1)),
                    "the prompt work waited for background work: {waited:?} of {permits}"
                );
            });
            assert!(gate.peak() <= permits, "{} of {permits}", gate.peak());
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
