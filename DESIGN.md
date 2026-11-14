---
name: Phylax
description: Dark olive command-post dashboard for passive IT/OT security triage at TNI AD sites.
colors:
  ink-black: "#070806"
  card: "#0e100b"
  card-raised: "#13150f"
  hairline: "#22261a"
  text: "#eef0e6"
  text-muted: "#9a9d88"
  olive: "#556b2f"
  olive-hover: "#61793a"
  olive-soft: "#a3b35c"
  link-olive: "#c2cf8a"
  gold: "#c9a646"
  signal-red: "#e5534b"
  signal-amber: "#e39b3a"
  signal-blue: "#5aa9d6"
  ok-olive: "#8fa84a"
typography:
  display:
    fontFamily: "Segoe UI Variable Display, Segoe UI, Inter, Helvetica, Arial, sans-serif"
    fontSize: "28px"
    fontWeight: 600
    lineHeight: 1.15
    letterSpacing: "-0.01em"
  kpi:
    fontFamily: "Segoe UI Variable Display, Segoe UI, Inter, Helvetica, Arial, sans-serif"
    fontSize: "38px"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "-0.02em"
  title:
    fontFamily: "Segoe UI Variable Text, Segoe UI, Inter, Helvetica, Arial, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: 1.3
  body:
    fontFamily: "Segoe UI Variable Text, Segoe UI, Inter, Helvetica, Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Segoe UI Variable Text, Segoe UI, Inter, Helvetica, Arial, sans-serif"
    fontSize: "12px"
    fontWeight: 600
    letterSpacing: "0.05em"
  mono:
    fontFamily: "IBM Plex Mono, ui-monospace, Consolas, Liberation Mono, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.5
rounded:
  sm: "8px"
  md: "10px"
  lg: "14px"
  xl: "16px"
  pill: "999px"
spacing:
  xs: "6px"
  sm: "10px"
  md: "16px"
  lg: "26px"
  page: "34px"
components:
  button-primary:
    backgroundColor: "{colors.olive}"
    textColor: "{colors.text}"
    rounded: "{rounded.md}"
    padding: "8px 16px"
  button-primary-hover:
    backgroundColor: "{colors.olive-hover}"
  button-default:
    backgroundColor: "{colors.card-raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.md}"
    padding: "8px 16px"
  input:
    backgroundColor: "{colors.ink-black}"
    textColor: "{colors.text}"
    rounded: "{rounded.md}"
    padding: "8px 12px"
  kpi-card:
    backgroundColor: "{colors.card-raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.xl}"
    padding: "18px"
  chip:
    textColor: "{colors.olive-soft}"
    rounded: "{rounded.pill}"
    padding: "0 8px"
---

# Design System: Phylax

## Overview

**Creative North Star: "The Night-Watch Console"**

Phylax looks like the screen of a command post at night: near-black olive surfaces, one army-green voice, and signal colours that appear only when something needs attention. The layout is a CyFocus-style dashboard: a floating left rail, a page header, a row of KPI cards, then two-column cards for ranked lists and feeds. It is dense but calm, built to be read in a dim ops room and from the back of a demo hall.

Colour is doctrine, not decoration. TNI olive carries brand and action. Gold marks only the current place and tiny accents. Red, amber and blue appear solely to say how urgent or informative something is, and always beside a text label. The surface is flat and tonal: depth comes from slightly lighter olive-black cards on an olive-black page, not from glow.

The system is final. New screens extend it; they do not restyle it.

**Key Characteristics:**
- Olive-black tonal layers, hairline borders, rounded cards (14–16px).
- One brand colour (olive #556b2f), one rare accent (gold).
- Severity = signal colour + label + square marker, never colour alone.
- System font stack only (offline, CSP blocks web fonts); mono for IDs, IPs, counts.

## Colors

A near-monochrome olive palette with three meaning-only signal hues.

### Primary
- **Army Olive** (#556b2f): primary buttons, the "add" action in the rail, avatar. Hover is Parade Olive (#61793a).
- **Sage Highlight** (#a3b35c): active nav icon, chips, sparkline and progress fills, the shield mark. Text-on-dark use is via Moss Link (#c2cf8a).

### Secondary
- **Brass Gold** (#c9a646): small marks only: active-nav bar, active secondary-tab underline, focus ring, notice left rule, empty-state globe nodes, "maximum" dashed outlines.

### Tertiary (signal, meaning only)
- **Signal Red** (#e5534b): critical, confirmed, error.
- **Signal Amber** (#e39b3a): high, potential, warning.
- **Signal Blue** (#5aa9d6): informational, needs review.
- **Field Green** (#8fa84a): ok, resolved.

### Neutral
- **Ink Black** (#070806): page and input background.
- **Card** (#0e100b) / **Raised Card** (#13150f): panel and card surfaces.
- **Hairline** (#22261a): borders and dividers (also white at 8% as `line-2`).
- **Bone Text** (#eef0e6): primary text. **Lichen Muted** (#9a9d88): secondary text.

### Named Rules
**The Meaning-Only Rule.** Red, amber and blue never decorate. If it is not a severity or state, it is olive or neutral.
**The Gold Crumb Rule.** Gold is a crumb, not a fill. It never backs a button, card or heading.
**The Label Beside Colour Rule.** Every signal colour ships with a word and a marker shape.

## Typography

**Display Font:** Segoe UI Variable Display (with Segoe UI, Inter, Helvetica, Arial)
**Body Font:** Segoe UI Variable Text (same fallbacks)
**Label/Mono Font:** IBM Plex Mono if installed, else system monospace (Consolas)

**Character:** Plain, system-native, utilitarian. No web fonts by constraint; hierarchy comes from weight, size and mono for machine values.

### Hierarchy
- **Display** (600, 28px, 1.15): page h1.
- **KPI** (700, 38px, 1): big numbers on KPI cards.
- **Title** (600, 15–16px, 1.3): card and section h2 (sentence case, no rule line).
- **Body** (400, 14px, 1.55): all running text; keep prose to ~65–78ch.
- **Label** (600, 12px, +0.05em, uppercase): table headers.
- **Mono** (12–13px): IPs, IDs, hashes, counts, evidence.

### Named Rules
**The Machine Values Are Mono Rule.** Anything copied from a log or inventory is monospace.

## Layout

Two-column shell: sticky floating rail (248px) plus a main column capped at ~1380px with 34px side padding. Inside: KPI grid (auto-fit, min 220px, 16px gap), then 2-column `cards`, ranked lists, feeds, and tables in panels. Spacing rhythm is 6 / 10 / 16 / 26px. Under 900px the rail collapses into a header with a disclosure menu, columns stack, touch targets reach 44px and form text 16px. Tables scroll inside their panel; nothing causes page-level horizontal scroll.

## Elevation & Depth

Tonal layering with a hairline, not glow. Cards sit one step lighter than the page; the rail and KPI cards carry a soft drop shadow (e.g. `0 10px 30px #00000059`) purely to separate from the background. The page and cards use very subtle olive vertical gradients and a faint olive corner wash on the body.

### Named Rules
**The No-Glow Rule.** No coloured glows, neon edges or gradient text. Shadows are black and only for separation.
**The Tonal Step Rule.** Depth is one surface step lighter, never a stack of shadows.

## Shapes

Soft-rectangular. 10px controls, 14–16px cards and panels, 18px rail, pill (999px) chips and status pills, 2px bars. Signal markers are small squares (8px) so severity reads by shape as well as colour. Borders are 1px hairline; the only thick strokes are 3px left rules on notices and headlines.

## Components

### Buttons
- **Shape:** 10px radius, 8px 16px padding.
- **Primary:** Army Olive fill, light text, 700 weight; hover Parade Olive.
- **Default:** Raised Card fill with a control-line border; hover a step lighter.
- **Focus:** 2px gold outline, 2px offset (all focusable elements).

### Chips / Status pills
Pill-shaped, tint at ~10% of the signal colour with the same-hue text; status pills lead with an 8px square marker.

### Cards / Containers
KPI card (16px radius, 18px padding, label row with chip, 38px number, optional ring or sparkline); content card (`cardx`, header with h2 and aux action); panel for tables (14px radius). Alert board columns hold draggable alert cards.

### Inputs / Fields
Ink Black fill, 1px control-line border, 10px radius; labels above at 13px; invalid state uses Signal Red border and message.

### Navigation
Floating rail with line icons (18px, 1.6 stroke), muted text, active item on a faint olive tint with a gold left bar; primary "add" action as an olive block at the top. Secondary views are an underlined tab row with a gold underline on the active tab.

### Evidence / Topology views
SVG network map with plates on Raised Card, zone strokes and dashed support links in the signal palette.

## Do's and Don'ts

### Do:
- **Do** use olive (#556b2f) for the one primary action per view.
- **Do** pair every severity colour with a text label and a square marker.
- **Do** keep text on dark at strong contrast (#eef0e6 on #0e100b); muted text only for secondary info, never for critical data.
- **Do** put every new string in `phylax/locales/id.json` and every style in `phylax/theme.py`.
- **Do** keep scripts served from the app itself.

### Don't:
- **Don't** use gradient text, glows, neon, or rainbow palettes.
- **Don't** use gold for fills, buttons or headings.
- **Don't** use red, amber or blue for decoration.
- **Don't** load web fonts or external assets (CSP blocks them).
- **Don't** redesign the layout; refine within it.
