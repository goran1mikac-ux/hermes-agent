#!/usr/bin/env python3
"""Generate hermes_cli/skins_reference.html from the built-in skin catalog.

A hand-maintained markdown list of skins drifts the moment someone adds a skin
(the old docs listed 4 of the 9 that actually ship). This renders a visual,
self-contained HTML reference straight from ``_BUILTIN_SKINS`` so the palette,
spinner faces, and branding always match the code.

Run from the repo root:

    python scripts/gen_skins_reference.py

It writes ``hermes_cli/skins_reference.html`` (open it in a browser). Re-run it
whenever ``hermes_cli/skin_engine.py`` changes.
"""
from __future__ import annotations

import html
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hermes_cli.skin_engine import _BUILTIN_SKINS  # noqa: E402

OUTPUT = REPO_ROOT / "hermes_cli" / "skins_reference.html"

# Color keys we surface as labelled swatches, in a sensible reading order.
# Any other keys a skin defines are appended after these so nothing is dropped.
_PREFERRED_ORDER = [
    "banner_border", "banner_title", "banner_accent", "banner_dim", "banner_text",
    "response_border", "ui_accent", "ui_label", "ui_ok", "ui_warn", "ui_error",
    "prompt", "input_rule", "session_label", "session_border",
    "status_bar_bg", "status_bar_text", "status_bar_strong", "status_bar_dim",
    "status_bar_good", "status_bar_warn", "status_bar_bad", "status_bar_critical",
]


def _ordered_color_items(colors: dict) -> list[tuple[str, str]]:
    seen = set()
    items: list[tuple[str, str]] = []
    for key in _PREFERRED_ORDER:
        if key in colors:
            items.append((key, colors[key]))
            seen.add(key)
    for key, val in colors.items():
        if key not in seen:
            items.append((key, val))
    return items


def _swatch(key: str, value: str) -> str:
    safe_val = html.escape(str(value))
    safe_key = html.escape(key)
    return (
        '<div class="swatch">'
        f'<span class="chip" style="background:{safe_val}"></span>'
        f'<span class="meta"><code>{safe_key}</code><span class="hex">{safe_val}</span></span>'
        "</div>"
    )


def _skin_card(name: str, data: dict) -> str:
    colors = data.get("colors", {})
    branding = data.get("branding", {})
    spinner = data.get("spinner", {})
    tool_prefix = data.get("tool_prefix", "")

    border = colors.get("banner_border", "#888")
    title_c = colors.get("banner_title", "#fff")
    text_c = colors.get("banner_text", "#ccc")
    accent_c = colors.get("banner_accent", title_c)
    bg = colors.get("status_bar_bg", "#111")

    agent_name = html.escape(str(branding.get("agent_name", name)))
    resp_label = html.escape(str(branding.get("response_label", "")).strip())
    prompt_symbol = html.escape(str(branding.get("prompt_symbol", "")))

    # Live preview strip painted with the skin's own colors.
    preview = (
        f'<div class="preview" style="background:{bg};border-color:{border}">'
        f'<div class="preview-title" style="color:{title_c}">{agent_name}</div>'
        f'<div class="preview-line" style="color:{text_c}">'
        f'<span style="color:{accent_c}">{html.escape(tool_prefix)}</span> '
        f'preview &mdash; <span style="color:{accent_c}">{resp_label or "&nbsp;"}</span>'
        f' <span style="color:{title_c}">{prompt_symbol}</span></div>'
        "</div>"
    )

    swatches = "".join(_swatch(k, v) for k, v in _ordered_color_items(colors))

    spinner_html = ""
    faces = spinner.get("thinking_faces") or spinner.get("waiting_faces")
    if faces:
        chips = "".join(f'<span class="face">{html.escape(f)}</span>' for f in faces)
        spinner_html += f'<div class="row"><span class="row-label">spinner</span><span class="faces">{chips}</span></div>'
    verbs = spinner.get("thinking_verbs")
    if verbs:
        verb_txt = html.escape(", ".join(verbs))
        spinner_html += f'<div class="row"><span class="row-label">verbs</span><span class="verbs">{verb_txt}</span></div>'

    brand_bits = []
    if resp_label:
        brand_bits.append(f'label <code>{resp_label}</code>')
    if prompt_symbol:
        brand_bits.append(f'prompt <code>{prompt_symbol}</code>')
    if tool_prefix:
        brand_bits.append(f'tool&nbsp;prefix <code>{html.escape(tool_prefix)}</code>')
    brand_html = ""
    if brand_bits:
        brand_html = f'<div class="row"><span class="row-label">branding</span><span>{" &middot; ".join(brand_bits)}</span></div>'

    return (
        '<section class="card">'
        f'<header><h2>{html.escape(name)}</h2>'
        f'<p class="desc">{html.escape(str(data.get("description", "")))}</p></header>'
        f'{preview}'
        f'<div class="swatches">{swatches}</div>'
        f'{spinner_html}{brand_html}'
        "</section>"
    )


def build_html() -> str:
    cards = "\n".join(_skin_card(name, data) for name, data in _BUILTIN_SKINS.items())
    count = len(_BUILTIN_SKINS)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hermes Agent &mdash; Skin Reference</title>
<style>
  :root {{
    --bg: #f6f7f9; --fg: #1a1a1e; --muted: #6b7280; --card: #ffffff;
    --line: #e5e7eb; --code-bg: #f0f1f4;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg: #0f1115; --fg: #e6e7ea; --muted: #9aa1ac; --card: #171a21;
             --line: #262b34; --code-bg: #21262f; }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--fg);
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }}
  h1 {{ font-size: 1.7rem; margin: 0 0 4px; }}
  .lede {{ color: var(--muted); margin: 0 0 8px; }}
  .note {{ color: var(--muted); font-size: 0.85rem; margin: 0 0 28px;
    border-left: 3px solid var(--line); padding-left: 12px; }}
  code {{ background: var(--code-bg); padding: 1px 5px; border-radius: 4px;
    font: 0.85em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 20px; }}
  .card {{ background: var(--card); border: 1px solid var(--line); border-radius: 12px;
    padding: 18px; overflow: hidden; }}
  .card header {{ margin-bottom: 12px; }}
  .card h2 {{ margin: 0; font-size: 1.15rem; font-family: ui-monospace, Menlo, monospace; }}
  .desc {{ margin: 2px 0 0; color: var(--muted); font-size: 0.9rem; }}
  .preview {{ border: 1px solid; border-radius: 8px; padding: 12px 14px; margin-bottom: 14px; }}
  .preview-title {{ font-weight: 700; letter-spacing: 0.02em; }}
  .preview-line {{ font-family: ui-monospace, Menlo, monospace; font-size: 0.85rem; margin-top: 4px; }}
  .swatches {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; }}
  .swatch {{ display: flex; align-items: center; gap: 8px; min-width: 0; }}
  .chip {{ width: 22px; height: 22px; border-radius: 5px; flex: none;
    border: 1px solid rgba(128,128,128,.35); }}
  .meta {{ display: flex; flex-direction: column; min-width: 0; }}
  .meta code {{ background: none; padding: 0; font-size: 0.75rem; overflow: hidden; text-overflow: ellipsis; }}
  .hex {{ color: var(--muted); font-size: 0.72rem; font-family: ui-monospace, Menlo, monospace; }}
  .row {{ display: flex; gap: 10px; margin-top: 12px; font-size: 0.85rem; align-items: baseline; }}
  .row-label {{ color: var(--muted); flex: none; width: 68px; text-transform: uppercase;
    font-size: 0.7rem; letter-spacing: 0.05em; padding-top: 2px; }}
  .faces {{ display: flex; flex-wrap: wrap; gap: 6px; }}
  .face {{ font-family: ui-monospace, Menlo, monospace; background: var(--code-bg);
    padding: 1px 6px; border-radius: 4px; }}
  .verbs {{ color: var(--muted); }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Hermes Agent &mdash; Skin Reference</h1>
  <p class="lede">{count} built-in CLI skins, shown with their actual palette, spinner, and branding.</p>
  <p class="note">Generated from <code>hermes_cli/skin_engine.py</code> (<code>_BUILTIN_SKINS</code>)
    by <code>scripts/gen_skins_reference.py</code> &mdash; do not edit by hand; re-run the script
    after changing a skin. Activate a skin with <code>/skin &lt;name&gt;</code> or
    <code>display.skin: &lt;name&gt;</code> in <code>config.yaml</code>.</p>
  <div class="grid">
{cards}
  </div>
</div>
</body>
</html>
"""


def main() -> None:
    OUTPUT.write_text(build_html(), encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(REPO_ROOT)} ({len(_BUILTIN_SKINS)} skins)")


if __name__ == "__main__":
    main()
