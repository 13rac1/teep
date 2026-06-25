# teep brand

The mark is a **held prompt**: your prompt (the chevron) cradled inside teep's
guards. It says, in one glyph, what teep is — a protective wrapper that keeps the
one thing you can't afford to expose sealed, even while it sits in someone
else's hardware. teep is a guard, not a gate.

| Asset | File | Use |
|-------|------|-----|
| Mark | [`teep-mark.svg`](teep-mark.svg) | favicon, app icon, square avatar |
| Logo lockup (dark) | [`teep-logo.svg`](teep-logo.svg) | dark backgrounds — light wordmark |
| Logo lockup (light) | [`teep-logo-light.svg`](teep-logo-light.svg) | light backgrounds — dark wordmark, deeper teal guards |

The lockup is dark-first, so on a light background the near-white wordmark
disappears. Pick the variant by background, and on surfaces that switch themes
(like a GitHub README) serve both with `<picture>`:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/teep-logo.svg">
  <img alt="teep" src="docs/brand/teep-logo-light.svg" width="200">
</picture>
```

The same mark renders live in the dashboard hero, where a ring around the cradle
fills with the verification factors that passed and changes color with the
current posture — sealed, partial, broken, or idle. The logo is the product's
status light.

## Construction

- **Guards** — two rounded brackets that *cradle*, not clamp. Rounded corners
  read as cupped hands; the form stays legible as `[ › ]`, code-native. Drawn in
  the `--seal` mint: the guards are teep.
- **Prompt** — a single chevron, the glyph of a chat/CLI prompt. This is the
  thing being protected, so it carries its own color: light `--ink` on dark
  surfaces (swap to `#080B0F` on light ones). The prompt is *yours*; the guards
  are teep wrapped around it.
- Two colors, one job each. Never fill the guards — the cradle is an embrace,
  not a box. On the dashboard the guards take the posture color while the prompt
  stays neutral, so "your prompt" reads as constant no matter the state.

## Color

The palette is a cool "enclave graphite" — deliberately not the default
near-black-plus-blue of most developer dashboards.

| Token | Hex | Role |
|-------|-----|------|
| `--bg` | `#080B0F` | page background |
| `--surface` | `#0F141A` | cards, panels |
| `--surface-2` | `#141B23` | raised chips, inputs |
| `--line` | `#202A35` | borders |
| `--ink` | `#E8EEF4` | primary text |
| `--dim` | `#8493A3` | secondary text |
| `--faint` | `#4A5663` | labels, idle state |
| `--seal` | `#4FE3C1` | **signature** — attested / sealed |
| `--crypt` | `#5BB8FF` | end-to-end encryption |
| `--warn` | `#E8B24A` | partial / non-critical failures |
| `--alert` | `#FF6B7D` | blocked / enforced failure |

`--seal` is the one accent that carries the brand; the others are reserved for
status. Keep amber and coral for things that are actually wrong.

## Type

teep is terminal-native, so the identity is monospace. The wordmark is set in a
monospace face (`JetBrains Mono` → `SF Mono` → `ui-monospace`), lowercase, tight
tracking. Body copy and data use the system sans for legibility, always with
tabular numerals so live counters don't jitter.

The wordmark is always lowercase: `teep`, never `Teep` or `TEEP`.
