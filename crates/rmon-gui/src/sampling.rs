//! The background sampling thread, and the policy that decides how often
//! it runs.
//!
//! # Why a thread
//!
//! A tick is not cheap and its cost is not under rMon's control. The bulk
//! of it is one `NtQuerySystemInformation(SystemProcessInformation)` call,
//! which asks the kernel for every process *and every thread* on the
//! machine. Measured on the box that prompted this — 1,352 processes and
//! 25,300 threads — that single call takes 85-100ms and returns 2.9MB, of
//! which roughly 1.6MB is per-thread records rMon reads none of. There is
//! no cheaper information class: the thread-free alternatives either do
//! not exist (classes 88 and 148 return `STATUS_INVALID_INFO_CLASS` /
//! `STATUS_NOT_IMPLEMENTED`) or cost more (class 57, 4.3MB in 91ms).
//!
//! Running that from `App::ui` — as rMon did — stalls the UI thread for a
//! tenth of a second every second, which is exactly the "keep sampling
//! work off rendering/input paths when it can block" rule in AGENTS.md.
//! So the `Sampler` lives here instead, on one dedicated thread it is
//! created on and never leaves (its WMI/COM state is thread-affine).
//!
//! # Why the interval moves
//!
//! Sampling cost scales with how loaded the machine is, so a fixed 1s tick
//! quietly turns a monitor into a load source on exactly the machines
//! someone opened a monitor to investigate. Instead the interval is
//! derived from the measured cost of the last sample, so rMon spends at
//! most [`MAX_DUTY`] of one core on sampling whatever it is running on.
//! Ordinary machines (a sample costs a few ms) are unaffected and keep
//! ticking at [`MIN_INTERVAL`]; pathological ones back off on their own.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rmon_core::{PortEntry, Sampler, Snapshot, list_all_ports};

/// Fastest rMon will sample. Faster than this buys nothing: CPU
/// percentages are deltas over the interval, and sub-second deltas are
/// mostly scheduler noise.
pub const MIN_INTERVAL: Duration = Duration::from_millis(1000);
/// Slowest the automatic back-off will go while the window is visible.
pub const MAX_INTERVAL: Duration = Duration::from_secs(10);
/// Share of one core rMon budgets for sampling before it starts sampling
/// less often. 5% is low enough not to show up in its own process list.
pub const MAX_DUTY: f64 = 0.05;
/// Interval used while the window is hidden or minimized.
///
/// Not "paused": the accumulated-usage ranking and the leak/idle trends
/// are the reason people leave rMon in the tray, and both integrate
/// `cpu_percent` over elapsed time, so a slower cadence still totals
/// correctly — a percentage measured over 10s *is* the average over those
/// 10s. 10s specifically because `RollingHistory` clamps a single tick's
/// contribution at 10s, so anything longer would silently under-count.
pub const HIDDEN_INTERVAL: Duration = Duration::from_secs(10);

/// How long the thread naps before re-reading the shared knobs, so a
/// change to the interval or to window visibility takes effect promptly
/// instead of at the end of a possibly-10s sleep.
const POLL_SLICE: Duration = Duration::from_millis(200);

/// One tick's worth of work, handed to the UI thread.
pub struct Tick {
    pub snapshot: Snapshot,
    /// Collected here rather than on the UI thread because it is the same
    /// cadence and the same kind of system-wide table walk.
    pub ports: Vec<PortEntry>,
    /// What this sample cost, which is what drives the next interval.
    pub cost: Duration,
    /// How long the thread will wait before the next sample.
    pub interval: Duration,
}

/// A user override for the sampling interval, or automatic.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IntervalChoice {
    /// Derive it from measured cost — see [`MAX_DUTY`].
    Auto,
    Fixed(Duration),
}

impl IntervalChoice {
    pub const ALL: [IntervalChoice; 5] = [
        IntervalChoice::Auto,
        IntervalChoice::Fixed(Duration::from_secs(1)),
        IntervalChoice::Fixed(Duration::from_secs(2)),
        IntervalChoice::Fixed(Duration::from_secs(5)),
        IntervalChoice::Fixed(Duration::from_secs(10)),
    ];

    pub fn label(self) -> String {
        match self {
            IntervalChoice::Auto => "automatic".to_string(),
            IntervalChoice::Fixed(d) => format!("every {}s", d.as_secs()),
        }
    }

    fn as_millis(self) -> u64 {
        match self {
            IntervalChoice::Auto => 0,
            IntervalChoice::Fixed(d) => d.as_millis() as u64,
        }
    }

    fn from_millis(ms: u64) -> Self {
        match ms {
            0 => IntervalChoice::Auto,
            ms => IntervalChoice::Fixed(Duration::from_millis(ms)),
        }
    }
}

/// Handle to the sampling thread. Dropping it drops the receiver, which is
/// how the thread learns the app is gone and exits.
pub struct BackgroundSampler {
    rx: mpsc::Receiver<Tick>,
    /// 0 means automatic; see [`IntervalChoice`].
    override_ms: Arc<AtomicU64>,
    hidden: Arc<AtomicBool>,
    has_gpu_source: bool,
    /// Cost and interval of the most recent tick, for the settings tab.
    last_cost: Option<Duration>,
    interval: Duration,
}

impl BackgroundSampler {
    /// Starts the thread and blocks until the `Sampler` has been built and
    /// warmed up, which is what the caller used to do inline anyway. After
    /// this returns, nothing about sampling touches the calling thread.
    pub fn start() -> Self {
        let (tx, rx) = mpsc::channel();
        let (init_tx, init_rx) = mpsc::channel();
        let override_ms = Arc::new(AtomicU64::new(0));
        let hidden = Arc::new(AtomicBool::new(false));

        let thread_override = Arc::clone(&override_ms);
        let thread_hidden = Arc::clone(&hidden);
        std::thread::Builder::new()
            .name("rmon-sampler".to_string())
            .spawn(move || run(tx, init_tx, thread_override, thread_hidden))
            .expect("failed to spawn the sampling thread");

        // If the thread died during construction there is nothing to
        // monitor with; `false` just means "no GPU column".
        let has_gpu_source = init_rx.recv().unwrap_or(false);
        Self {
            rx,
            override_ms,
            hidden,
            has_gpu_source,
            last_cost: None,
            interval: MIN_INTERVAL,
        }
    }

    /// The newest tick, if one has arrived since the last call. Older
    /// queued ticks are discarded rather than replayed: a UI that fell
    /// behind should catch up to *now*, not crawl through history.
    pub fn newest(&mut self) -> Option<Tick> {
        let mut newest = None;
        while let Ok(tick) = self.rx.try_recv() {
            self.last_cost = Some(tick.cost);
            self.interval = tick.interval;
            newest = Some(tick);
        }
        newest
    }

    pub fn has_gpu_source(&self) -> bool {
        self.has_gpu_source
    }

    /// What the last sample cost, once one has completed.
    pub fn last_cost(&self) -> Option<Duration> {
        self.last_cost
    }

    /// The interval currently in effect.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn choice(&self) -> IntervalChoice {
        IntervalChoice::from_millis(self.override_ms.load(Ordering::Relaxed))
    }

    pub fn set_choice(&self, choice: IntervalChoice) {
        self.override_ms
            .store(choice.as_millis(), Ordering::Relaxed);
    }

    /// Tells the thread whether anyone can currently see the window.
    pub fn set_hidden(&self, hidden: bool) {
        self.hidden.store(hidden, Ordering::Relaxed);
    }
}

/// The interval a sample costing `cost` earns, before the hidden-window
/// and user-override rules are applied.
pub fn auto_interval(cost: Duration) -> Duration {
    let budgeted = Duration::from_secs_f64(cost.as_secs_f64() / MAX_DUTY);
    budgeted.clamp(MIN_INTERVAL, MAX_INTERVAL)
}

fn run(
    tx: mpsc::Sender<Tick>,
    init_tx: mpsc::Sender<bool>,
    override_ms: Arc<AtomicU64>,
    hidden: Arc<AtomicBool>,
) {
    let mut sampler = Sampler::new();
    if init_tx.send(sampler.has_gpu_source()).is_err() {
        return;
    }
    sampler.sample(); // warm-up: CPU percentages are deltas, so discard it.

    let mut was_hidden = false;
    let mut interval = MIN_INTERVAL;
    loop {
        // Re-read the knobs in slices so a change lands within POLL_SLICE
        // rather than at the end of the current wait.
        let deadline = Instant::now() + interval;
        while Instant::now() < deadline {
            std::thread::sleep(POLL_SLICE.min(deadline - Instant::now()));
            if hidden.load(Ordering::Relaxed) != was_hidden {
                break; // visibility flipped: re-evaluate the cadence now
            }
        }

        let now_hidden = hidden.load(Ordering::Relaxed);
        if now_hidden != was_hidden {
            was_hidden = now_hidden;
            if !now_hidden {
                // Coming back into view after a slow stretch: re-baseline
                // so the first visible reading is a fresh delta rather
                // than an average over however long the window was away.
                sampler.sample();
            }
        }

        let started = Instant::now();
        let snapshot = sampler.sample();
        let ports = list_all_ports().unwrap_or_default();
        let cost = started.elapsed();

        interval = match IntervalChoice::from_millis(override_ms.load(Ordering::Relaxed)) {
            IntervalChoice::Auto => auto_interval(cost),
            IntervalChoice::Fixed(d) => d,
        };
        if now_hidden {
            interval = interval.max(HIDDEN_INTERVAL);
        }

        if tx
            .send(Tick {
                snapshot,
                ports,
                cost,
                interval,
            })
            .is_err()
        {
            return; // the app is gone
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of the duty budget: a machine where sampling is cheap
    /// keeps the fast tick, and one where it is expensive pays no more
    /// than MAX_DUTY of a core for it.
    #[test]
    fn interval_holds_the_duty_budget() {
        assert_eq!(auto_interval(Duration::from_millis(3)), MIN_INTERVAL);
        assert_eq!(auto_interval(Duration::from_millis(50)), MIN_INTERVAL);

        // The measured cost on the 1,352-process box this was written for.
        let busy = auto_interval(Duration::from_millis(95));
        assert!(busy > MIN_INTERVAL, "{busy:?} should have backed off");
        let duty = 0.095 / busy.as_secs_f64();
        assert!(duty <= MAX_DUTY + f64::EPSILON, "duty {duty} over budget");

        // Absurd costs are capped rather than extrapolated: a monitor that
        // updates once a minute has stopped being a monitor.
        assert_eq!(auto_interval(Duration::from_secs(5)), MAX_INTERVAL);
    }

    #[test]
    fn hidden_interval_matches_the_history_clamp() {
        // RollingHistory clamps one tick's contribution to the accumulated
        // totals at 10s. Sampling slower than that would under-count.
        assert!(HIDDEN_INTERVAL <= Duration::from_secs(10));
    }

    #[test]
    fn choices_round_trip() {
        for choice in IntervalChoice::ALL {
            assert!(IntervalChoice::from_millis(choice.as_millis()) == choice);
            assert!(!choice.label().is_empty());
        }
    }
}
