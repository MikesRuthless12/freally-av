// FirstRun page (TASK-046, extended Phase 7B).
//
// Four-step welcome flow shown on first launch:
//   1. Welcome — what Mythodikal is, what it isn't (no telemetry, no
//      cloud, no kernel driver).
//   2. Defaults — Shields ON, abuse.ch feed, quarantine vault under
//      the user data dir; user confirms (no decisions to make).
//   3. Whitelist (NSRL) — opt-in choice for the NSRL clean-file
//      database. Defaults to "per-OS slice (~1.7 GB)" but the user
//      can skip entirely or upgrade to the full union (~3.4 GB).
//   4. Ready — "Start your first scan" CTA that flips the persisted
//      flag and routes to /scan.
//
// We intentionally do NOT collect a username, email, or any opt-in for
// telemetry: the project ships with zero telemetry by design, so there
// is nothing to consent to.

import { For, Show, createSignal, type Component } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { markFirstRunComplete } from "@/stores/firstRun";
import { nsrlPreference, setNsrlPreference, type NsrlPreference } from "@/stores/nsrlPreference";

type Step = 1 | 2 | 3 | 4;

const FirstRun: Component = () => {
  const [step, setStep] = createSignal<Step>(1);
  const navigate = useNavigate();

  // Seed the local choice from the existing store (handles cases where
  // the user backtracks through the wizard mid-session). Default the
  // NSRL choice to "per_os_slice" since that's the recommended balance
  // of disk-space vs scan-speed payoff for single-OS end users.
  const initialChoice: NsrlPreference =
    nsrlPreference() === "unset" ? "per_os_slice" : nsrlPreference();
  const [nsrlChoice, setNsrlChoice] = createSignal<NsrlPreference>(initialChoice);

  const finish = () => {
    if (nsrlChoice() !== "unset") {
      setNsrlPreference(nsrlChoice());
    }
    markFirstRunComplete();
    navigate("/scan", { replace: true });
  };

  return (
    <div class="flex h-screen items-center justify-center bg-myth-bg-0 p-8">
      <div class="w-full max-w-xl rounded-lg border border-myth-line bg-myth-bg-1 p-8">
        <header class="mb-6 flex items-center justify-between">
          <h1 class="font-display text-2xl font-semibold tracking-tight text-myth-text-hi">
            Welcome to Mythodikal
          </h1>
          <span class="font-mono text-xs uppercase tracking-wide text-myth-text-lo">
            Step {step()} of 4
          </span>
        </header>

        <Show when={step() === 1}>
          <section class="space-y-4 text-sm text-myth-text-md">
            <p>
              Mythodikal is an open-source anti-virus that runs entirely on
              your machine. Threat feeds are fetched from public sources
              (abuse.ch, NSRL); detections happen locally; quarantine stays
              on your disk.
            </p>
            <ul class="space-y-2 pl-4 [&_li]:list-disc">
              <li>
                <strong class="text-myth-text-hi">No telemetry.</strong>{" "}
                Nothing leaves your computer unless you copy it there
                yourself.
              </li>
              <li>
                <strong class="text-myth-text-hi">No kernel driver.</strong>{" "}
                Mythodikal is a user-mode process — it does not require
                Windows-kernel signing or root.
              </li>
              <li>
                <strong class="text-myth-text-hi">No cost.</strong> The
                engine, the UI, and the threat feeds are all free for any
                use, commercial or personal.
              </li>
            </ul>
          </section>
        </Show>

        <Show when={step() === 2}>
          <section class="space-y-4 text-sm text-myth-text-md">
            <p>
              Mythodikal ships with safe defaults; you can change any of
              them later under Settings.
            </p>
            <dl class="grid grid-cols-[10rem_1fr] gap-y-2 text-xs">
              <DefaultRow
                label="Real-time shields"
                value="ON (pause from the badge in the sidebar)"
              />
              <DefaultRow
                label="Threat feeds"
                value="abuse.ch (refreshed daily); NSRL whitelist opt-in next step"
              />
              <DefaultRow
                label="SHA-256 hashing"
                value="Enabled (required for feed matching)"
              />
              <DefaultRow
                label="Symlinks"
                value="Not followed (prevents loops + scope creep)"
              />
              <DefaultRow
                label="Quarantine vault"
                value="Inside your user data dir, XOR-keyed via OS keyring"
              />
            </dl>
          </section>
        </Show>

        <Show when={step() === 3}>
          <section class="space-y-4 text-sm text-myth-text-md">
            <p>
              Optional: download the NSRL clean-file database. NSRL is
              the US government's reference set of known-good OS and
              app file hashes — when the scanner sees a file already
              on this list, it short-circuits the analysis. On a typical
              full-disk scan that's roughly 5–10× faster.
            </p>
            <fieldset class="space-y-2">
              <legend class="sr-only">NSRL download choice</legend>
              <For
                each={
                  [
                    {
                      value: "per_os_slice" as const,
                      label: "Download per-OS slice",
                      size: "~1.7 GB",
                      note: "Recommended. Only the hashes for your current operating system. Halves disk + bandwidth vs the full set.",
                    },
                    {
                      value: "full" as const,
                      label: "Download full union",
                      size: "~3.4 GB",
                      note: "All OSes. Use this for forensics machines or multi-boot systems.",
                    },
                    {
                      value: "skipped" as const,
                      label: "Skip for now",
                      size: "0 GB",
                      note: "Blacklist scanning still works. You can opt in later from Settings → Feeds.",
                    },
                  ] satisfies Array<{
                    value: NsrlPreference;
                    label: string;
                    size: string;
                    note: string;
                  }>
                }
              >
                {(opt) => (
                  <label class="flex cursor-pointer items-start gap-3 rounded-sm border border-myth-line bg-myth-bg-0 p-3 hover:border-myth-accent">
                    <input
                      type="radio"
                      name="nsrl-choice"
                      class="mt-0.5"
                      checked={nsrlChoice() === opt.value}
                      onChange={() => setNsrlChoice(opt.value)}
                    />
                    <span class="flex-1">
                      <span class="flex items-baseline justify-between">
                        <span class="text-myth-text-hi">{opt.label}</span>
                        <span class="font-mono text-xs text-myth-text-lo">
                          {opt.size}
                        </span>
                      </span>
                      <span class="block text-xs text-myth-text-md">
                        {opt.note}
                      </span>
                    </span>
                  </label>
                )}
              </For>
            </fieldset>
            <p class="text-xs text-myth-text-lo">
              The download happens in the background after this wizard
              closes; the first scan can start immediately. NSRL is
              public-domain data (NIST, 17 U.S.C. § 105).
            </p>
          </section>
        </Show>

        <Show when={step() === 4}>
          <section class="space-y-4 text-sm text-myth-text-md">
            <p>
              You're ready to scan. Pick any folder you'd like to inspect
              — your Downloads, an external drive, or an entire user
              profile.
            </p>
            <p class="text-myth-text-lo">
              The first scan calibrates the throughput meter; subsequent
              scans share that calibration so ETAs are accurate within a
              few seconds.
            </p>
          </section>
        </Show>

        <footer class="mt-8 flex items-center justify-between">
          <div class="flex items-center gap-3">
            <button
              type="button"
              class="rounded-sm px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-lo hover:text-myth-text-md disabled:cursor-not-allowed disabled:opacity-30"
              disabled={step() === 1}
              onClick={() => setStep((s) => (s > 1 ? ((s - 1) as Step) : s))}
            >
              ← Back
            </button>
            <button
              type="button"
              class="rounded-sm px-3 py-1 font-mono text-xs uppercase tracking-wide text-myth-text-lo hover:text-myth-text-md"
              onClick={finish}
              title="Skip the welcome flow. The persisted flag stops this from showing again on subsequent launches."
            >
              Skip
            </button>
          </div>
          <Show
            when={step() < 4}
            fallback={
              <button
                type="button"
                class="rounded-sm border border-myth-accent bg-myth-accent px-4 py-1.5 font-mono text-sm font-medium uppercase tracking-wide text-white hover:bg-myth-accent/90"
                onClick={finish}
              >
                Start your first scan →
              </button>
            }
          >
            <button
              type="button"
              class="rounded-sm border border-myth-line bg-myth-bg-0 px-4 py-1.5 font-mono text-sm uppercase tracking-wide text-myth-text-hi hover:border-myth-accent"
              onClick={() => setStep((s) => ((s + 1) as Step))}
            >
              Continue →
            </button>
          </Show>
        </footer>
      </div>
    </div>
  );
};

const DefaultRow: Component<{ label: string; value: string }> = (props) => (
  <>
    <dt class="font-mono uppercase tracking-wide text-myth-text-lo">
      {props.label}
    </dt>
    <dd class="text-myth-text-hi">{props.value}</dd>
  </>
);

export default FirstRun;
