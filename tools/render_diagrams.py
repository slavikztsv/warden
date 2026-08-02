"""Generate the README's architecture diagrams as SVG, on an exact grid.

Why not Mermaid. These three were Mermaid flowcharts for a while and could
not be made to look drawn rather than emitted. Measured on the real diagrams,
across every d3 curve option Mermaid exposes:

    curve     orthogonal   arrow distortion   needless jogs   backtracking
    basis           32%                  23               2              6
    linear          43%                   0               2              6
    step           100%                  11               2              6

The jog and backtrack counts are IDENTICAL in all three, because they come
from dagre's layout rather than from the curve function -- so no curve
setting removes them. Each setting only trades one defect for another:
`linear` lands arrowheads correctly but routes on diagonals that kink at
every dagre waypoint, while `step` is fully orthogonal but leaves final
segments shorter than the arrowhead itself, which is what makes arrows look
distorted and land on the wrong part of a shape.

So these are placed by hand. Every box sits on a grid, every edge is
orthogonal by construction, an edge between boxes sharing a centre line is a
single straight segment, and every arrowhead meets its target square on
because the anchor IS the midpoint of that side.

Hand placement earns its own failure mode -- boxes that overlap, a label
chip landing on a box, a connector crossing a box it has nothing to do
with -- so `check()` looks for exactly those and `main()` refuses to write a
diagram that fails. Every defect it names was one this file actually shipped
before the check existed.

    python -m tools.render_diagrams        writes docs/assets/*.svg

The palette matches the README's: red for untrusted input and paths that
must not exist, violet for warden and its actions, indigo for the policy
core, gold for the control plane, green for protected systems, slate for
durable stores. Every fill carries its own text colour, because GitHub
serves one SVG to light and dark readers alike.
"""

from __future__ import annotations

from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "docs" / "assets"

PALETTE = {
    "untrusted": ("#B23A34", "#8B2A25", "#FFFFFF"),
    "enforce": ("#6D4FD6", "#5340AE", "#FFFFFF"),
    "core": ("#4527A0", "#341E7A", "#FFFFFF"),
    "control": ("#976D19", "#795714", "#FFFFFF"),
    "target": ("#2E7D5B", "#226046", "#FFFFFF"),
    "store": ("#37474F", "#263238", "#FFFFFF"),
    "plumbing": ("#7760DB", "#5D41D4", "#FFFFFF"),
}
ZONE = {
    "untrusted": ("#FBEAE8", "#B23A34", "#7A241F"),
    "enforce": ("#EEE9FC", "#6D4FD6", "#3F2E8C"),
    "control": ("#FAF1DF", "#976D19", "#6B4C0F"),
    "target": ("#E3F2EB", "#2E7D5B", "#1D4E39"),
    "plumbing": ("#F4F1FD", "#7760DB", "#3F2E8C"),
}
LINE = "#8B85A6"
FORBIDDEN = "#B23A34"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

ZONE_PAD = 16          # gap between a zone's border and its boxes
ZONE_LABEL_H = 28      # headroom reserved for the zone's own label

# Type sizes. These are deliberately large relative to the canvas: GitHub
# renders the diagram at its container width, so a label's readability is set
# by its size AS A FRACTION of the viewBox, not by the export scale. Doubling
# the raster only makes small text smoothly small.
FS_TITLE = 14          # a box's first line
FS_SUB = 12            # its remaining lines
FS_CHIP = 11           # an edge label
FS_ZONE = 11.5         # a zone title
TEXT_PAD = 14          # minimum breathing room each side of a box's text

# Advance width per character for a monospace face, as a fraction of font
# size. 0.6 is the usual figure for SF Mono / Menlo / Consolas. Estimating
# with the MONO ratio is the conservative choice even though cairosvg falls
# back to a proportional sans (~0.55), because whatever fits the wider of the
# two fits both.
MONO_RATIO = 0.6


def text_width(text, size):
    return len(text) * size * MONO_RATIO


def esc(t):
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Box:
    def __init__(self, x, y, w, h, lines, kind, shape="rect"):
        self.x, self.y, self.w, self.h = float(x), float(y), float(w), float(h)
        self.lines, self.kind, self.shape = lines, kind, shape

    cx = property(lambda s: s.x + s.w / 2)
    cy = property(lambda s: s.y + s.h / 2)
    right = property(lambda s: s.x + s.w)
    bottom = property(lambda s: s.y + s.h)

    def at(self, side, t=0.5):
        """Midpoint of a side, or a fraction `t` along it.

        The fraction is what keeps parallel feeds straight: two boxes above a
        wider one can each drop a single vertical segment into their own
        share of its top edge, instead of both aiming at one point and
        bending to get there.
        """
        return {
            "top": (self.x + self.w * t, self.y),
            "bottom": (self.x + self.w * t, self.bottom),
            "left": (self.x, self.y + self.h * t),
            "right": (self.right, self.y + self.h * t),
        }[side]

    def rect(self):
        return (self.x, self.y, self.right, self.bottom)


class Zone:
    def __init__(self, label, kind, boxes, pad=ZONE_PAD):
        xs = [b.x for b in boxes] + [b.right for b in boxes]
        ys = [b.y for b in boxes] + [b.bottom for b in boxes]
        self.x, self.right = min(xs) - pad, max(xs) + pad
        self.y = min(ys) - pad - ZONE_LABEL_H
        self.bottom = max(ys) + pad
        self.label, self.kind = label, kind

    w = property(lambda s: s.right - s.x)
    h = property(lambda s: s.bottom - s.y)


class Diagram:
    def __init__(self, width, height, title):
        self.w, self.h, self.title = width, height, title
        self.boxes, self.zones, self.edges, self.notes = [], [], [], []

    def box(self, *a, **k):
        b = Box(*a, **k)
        self.boxes.append(b)
        return b

    def zone(self, label, kind, boxes, pad=ZONE_PAD):
        z = Zone(label, kind, boxes, pad)
        self.zones.append(z)
        return z

    def note(self, x, y, text, colour, anchor="middle", size=10.5):
        self.notes.append((x, y, text, colour, anchor, size))

    def fit(self, margin=20):
        """Size the canvas to its contents.

        Hand-placed diagrams grow downward as boxes are added, and a hardcoded
        height silently clips whatever ran past it -- which is exactly how the
        protected-systems row got cut off the first time.
        """
        xs = [b.right for b in self.boxes] + [z.right for z in self.zones]
        ys = [b.bottom for b in self.boxes] + [z.bottom for z in self.zones]
        ys += [y + 6 for _, y, *_ in self.notes]
        for e in self.edges:
            xs += [p[0] for p in e["pts"]]
            ys += [p[1] for p in e["pts"]]
        self.w = max(self.w, max(xs) + margin)
        self.h = max(ys) + margin

    def edge(self, a, b, *, src=None, dst=None, label=None, bend=None, kind="solid",
             label_t=0.5):
        """Orthogonal polyline from anchor a to anchor b.

        Collinear anchors give ONE straight segment. Otherwise the turn sits
        on the midline, so routing is symmetric and both ends meet their box
        edge square on. `bend="h"` turns horizontally first, a number pins the
        crossing coordinate.
        """
        (x1, y1), (x2, y2) = a, b
        if abs(x1 - x2) < 0.5 or abs(y1 - y2) < 0.5:
            pts = [(x1, y1), (x2, y2)]
        elif bend == "h":
            mx = (x1 + x2) / 2
            pts = [(x1, y1), (mx, y1), (mx, y2), (x2, y2)]
        elif isinstance(bend, (int, float)):
            pts = [(x1, y1), (x1, bend), (x2, bend), (x2, y2)]
        else:
            my = (y1 + y2) / 2
            pts = [(x1, y1), (x1, my), (x2, my), (x2, y2)]
        self.edges.append({"pts": pts, "label": label, "kind": kind,
                           "src": src, "dst": dst, "label_t": label_t})

    def route(self, pts, *, src=None, dst=None, label=None, kind="solid", label_t=0.5):
        """An explicit waypoint list, for the few edges that must go around."""
        self.edges.append({"pts": [tuple(p) for p in pts], "label": label,
                           "kind": kind, "src": src, "dst": dst, "label_t": label_t})

    # ---------------- validation ----------------

    @staticmethod
    def _overlap(a, b, slack=0.0):
        ax1, ay1, ax2, ay2 = a
        bx1, by1, bx2, by2 = b
        return (ax1 < bx2 - slack and bx1 < ax2 - slack
                and ay1 < by2 - slack and by1 < ay2 - slack)

    def _chip(self, e):
        if not e["label"]:
            return None
        best, blen = None, -1
        for i in range(len(e["pts"]) - 1):
            (ax, ay), (bx, by) = e["pts"][i], e["pts"][i + 1]
            seg = abs(bx - ax) + abs(by - ay)
            if seg > blen:
                blen, best = seg, (e["pts"][i], e["pts"][i + 1])
        (ax, ay), (bx, by) = best
        t = e.get("label_t", 0.5)
        cx, cy = ax + (bx - ax) * t, ay + (by - ay) * t
        w = text_width(e["label"], FS_CHIP) + 18
        return (cx - w / 2, cy - 9, cx + w / 2, cy + 9)

    def check(self):
        bad = []
        for i, a in enumerate(self.boxes):
            for b in self.boxes[i + 1:]:
                if self._overlap(a.rect(), b.rect()):
                    bad.append(f"boxes overlap: {a.lines[0]!r} / {b.lines[0]!r}")

        for b in self.boxes:
            need = max(text_width(t, FS_TITLE if i == 0 else FS_SUB)
                       for i, t in enumerate(b.lines)) + 2 * TEXT_PAD
            if need > b.w + 0.5:
                bad.append(f"text overflows {b.lines[0]!r}: needs {need:.0f}px, box is {b.w:.0f}px")

        for e in self.edges:
            ends = {e["src"], e["dst"]}
            for k in range(len(e["pts"]) - 1):
                (ax, ay), (bx, by) = e["pts"][k], e["pts"][k + 1]
                seg = (min(ax, bx), min(ay, by), max(ax, bx), max(ay, by))
                for b in self.boxes:
                    if b in ends:
                        continue
                    if self._overlap(seg, b.rect(), slack=1.0):
                        bad.append(
                            f"edge crosses {b.lines[0]!r}"
                            + (f" (label {e['label']!r})" if e["label"] else "")
                        )
            chip = self._chip(e)
            if chip:
                for b in self.boxes:
                    if self._overlap(chip, b.rect(), slack=1.0):
                        bad.append(f"label {e['label']!r} lands on {b.lines[0]!r}")

        for z in self.zones:
            label_box = (z.x + 7, z.y + 4,
                         z.x + 23 + text_width(z.label, FS_ZONE) + len(z.label) * 0.9,
                         z.y + 26)
            for e in self.edges:
                chip = self._chip(e)
                if chip and self._overlap(chip, label_box, 1.0):
                    bad.append(f"label {e['label']!r} lands on zone title {z.label!r}")
            for b in self.boxes:
                inside_x = z.x <= b.x and b.right <= z.right
                inside_y = z.y <= b.y and b.bottom <= z.bottom
                straddles = self._overlap((z.x, z.y, z.right, z.bottom), b.rect(), 1.0)
                if straddles and not (inside_x and inside_y):
                    bad.append(f"{b.lines[0]!r} straddles zone {z.label!r}")
        return sorted(set(bad))

    # ---------------- rendering ----------------

    def _draw_box(self, b):
        fill, stroke, colour = PALETTE[b.kind]
        out = []
        if b.shape == "stadium":
            out.append(f'<rect x="{b.x}" y="{b.y}" width="{b.w}" height="{b.h}" '
                       f'rx="{b.h/2}" fill="{fill}" stroke="{stroke}"/>')
        elif b.shape == "hex":
            k = 12
            pts = (f"{b.x+k},{b.y} {b.right-k},{b.y} {b.right},{b.cy} "
                   f"{b.right-k},{b.bottom} {b.x+k},{b.bottom} {b.x},{b.cy}")
            out.append(f'<polygon points="{pts}" fill="{fill}" stroke="{stroke}"/>')
        elif b.shape == "store":
            e = 6
            out.append(
                f'<path d="M{b.x},{b.y+e} A{b.w/2},{e} 0 0 1 {b.right},{b.y+e} '
                f'L{b.right},{b.bottom-e} A{b.w/2},{e} 0 0 1 {b.x},{b.bottom-e} Z" '
                f'fill="{fill}" stroke="{stroke}"/>'
                f'<path d="M{b.x},{b.y+e} A{b.w/2},{e} 0 0 0 {b.right},{b.y+e}" '
                f'fill="none" stroke="{stroke}"/>')
        else:
            out.append(f'<rect x="{b.x}" y="{b.y}" width="{b.w}" height="{b.h}" '
                       f'rx="5" fill="{fill}" stroke="{stroke}"/>')
        first = b.cy - (len(b.lines) - 1) * 7
        for i, line in enumerate(b.lines):
            out.append(
                f'<text x="{b.cx}" y="{first + i*14}" fill="{colour}" font-family="{MONO}" '
                f'font-size="{FS_TITLE if i == 0 else FS_SUB}" '
                f'font-weight="{600 if i == 0 else 400}" '
                f'text-anchor="middle" dominant-baseline="central">{esc(line)}</text>')
        return "".join(out)

    def _draw_zone(self, z):
        fill, stroke, _ = ZONE[z.kind]
        return (f'<rect x="{z.x}" y="{z.y}" width="{z.w}" height="{z.h}" rx="7" '
                f'fill="{fill}" stroke="{stroke}"/>')

    def _draw_zone_label(self, z):
        """Drawn last, over a chip of the zone's own fill.

        A connector running down the middle of a zone otherwise strikes
        straight through its title, because edges are painted after the zone
        rectangle. Painting the title last, on an opaque chip, means the
        label always wins.
        """
        fill, _, colour = ZONE[z.kind]
        w = 16 + text_width(z.label, FS_ZONE) + len(z.label) * 0.9
        return (f'<rect x="{z.x+7}" y="{z.y+5}" width="{w:.1f}" height="19" rx="4" '
                f'fill="{fill}"/>'
                f'<text x="{z.x+13}" y="{z.y+17}" fill="{colour}" font-family="{MONO}" '
                f'font-size="{FS_ZONE}" font-weight="600" letter-spacing="0.9">{esc(z.label)}</text>')

    def _draw_edge(self, e):
        stroke = FORBIDDEN if e["kind"] == "forbidden" else LINE
        dash = ' stroke-dasharray="6 4"' if e["kind"] == "forbidden" else ""
        marker = "arrowbad" if e["kind"] == "forbidden" else "arrow"
        d = "M" + " L".join(f"{x},{y}" for x, y in e["pts"])
        out = [f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="1.6"{dash} '
               f'marker-end="url(#{marker})"/>']
        chip = self._chip(e)
        if chip:
            x1, y1, x2, y2 = chip
            fill, stroke_c, colour = ZONE["untrusted" if e["kind"] == "forbidden" else "enforce"]
            out.append(
                f'<rect x="{x1:.1f}" y="{y1:.1f}" width="{x2-x1:.1f}" height="18" rx="9" '
                f'fill="{fill}" stroke="{stroke_c}" stroke-width="0.8"/>'
                f'<text x="{(x1+x2)/2:.1f}" y="{(y1+y2)/2:.1f}" fill="{colour}" '
                f'font-family="{MONO}" font-size="{FS_CHIP}" text-anchor="middle" '
                f'dominant-baseline="central">{esc(e["label"])}</text>')
        return "".join(out)

    def svg(self):
        body = [self._draw_zone(z) for z in self.zones]
        body += [self._draw_edge(e) for e in self.edges]
        body += [self._draw_box(b) for b in self.boxes]
        body += [self._draw_zone_label(z) for z in self.zones]
        for x, y, text, colour, anchor, size in self.notes:
            body.append(f'<text x="{x}" y="{y}" fill="{colour}" font-family="{MONO}" '
                        f'font-size="{size}" text-anchor="{anchor}">{esc(text)}</text>')
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" '
            f'width="{self.w}" height="{self.h}" role="img" aria-label="{esc(self.title)}">'
            f"<title>{esc(self.title)}</title><defs>"
            f'<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            f'markerHeight="7" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="{LINE}"/></marker>'
            f'<marker id="arrowbad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            f'markerHeight="7" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="{FORBIDDEN}"/>'
            f"</marker></defs>" + "".join(body) + "</svg>\n")


# --------------------------------------------------------------------------


def architecture():
    d = Diagram(1040, 780, "warden architecture: the request pipeline")
    CX, bw, bh = 500, 250, 46

    ctl = d.box(30, 44, 190, 46, ["broker-control", "control_main.py"], "control")
    client = d.box(CX - bw / 2, 44, bw, 46, ["Agent runtime · untrusted"], "untrusted", "stadium")

    stages = [
        (["Tool API  :8080", "app.py"], "enforce"),
        (["1 · Verify token", "identity.py"], "plumbing"),
        (["2 · Snapshot task state", "taint.py"], "plumbing"),
        (["3 · Validate + describe", "config/catalog.py"], "plumbing"),
        (["4 · Decide", "pdp.py"], "plumbing"),
    ]
    pipe, y = [], 170
    for lines, kind in stages:
        pipe.append(d.box(CX - bw / 2, y, bw, bh, lines, kind))
        y += bh + 32
    aud = d.box(CX - bw / 2, y, bw, 52, ["5 · Record", "audit.py"], "store", "store")
    api, ident, taint, cat, pdp = pipe

    proxy = d.box(770, 170, 230, bh, ["Egress proxy  :3128", "proxy.py"], "enforce")
    opa = d.box(770, pdp.cy - 27, 230, 54, ["OPA 1.19.0  :8181", "authz.rego + data.json"],
                "core", "hex")

    d.zone("WARDEN BROKER — ONE PROCESS, ONE WORKER", "enforce", [*pipe, aud])

    ay = aud.bottom + 74
    names = ["docstore", "sql", "mail", "http"]
    targets = ["docstore.internal", "customers.db", "mailer.internal", "Allowlisted hosts"]
    cw, gap = 178, 20
    total = len(names) * cw + (len(names) - 1) * gap
    x0 = CX - total / 2
    ad = [d.box(x0 + i * (cw + gap), ay, cw, 40, [n], "plumbing") for i, n in enumerate(names)]
    tg = [d.box(x0 + i * (cw + gap), ay + 120, cw, 42, [t], "target",
                "store" if t == "customers.db" else "rect")
          for i, t in enumerate(targets)]
    d.zone("6 · EXECUTE — broker/adapters/", "plumbing", ad)
    d.zone("PROTECTED SYSTEMS", "target", tg)

    d.edge(ctl.at("right"), client.at("left"), src=ctl, dst=client, label="Ed25519 task token")
    d.edge(client.at("bottom"), api.at("top"), src=client, dst=api, label="Bearer",
           label_t=0.28)
    for a, b in zip(pipe, pipe[1:]):
        d.edge(a.at("bottom"), b.at("top"), src=a, dst=b)
    d.edge(pdp.at("bottom"), aud.at("top"), src=pdp, dst=aud, label="allow")
    d.edge(client.at("right"), proxy.at("left"), src=client, dst=proxy,
           bend="h", label="CONNECT", label_t=0.25)
    d.edge(proxy.at("bottom"), opa.at("top"), src=proxy, dst=opa)
    d.edge(pdp.at("right"), opa.at("left"), src=pdp, dst=opa, label="input · decision")
    d.edge(aud.at("bottom"), (CX, ad[0].y - ZONE_PAD), src=aud,
           label="written before execution")
    for a, t in zip(ad, tg):
        d.edge(a.at("bottom"), t.at("top"), src=a, dst=t)
    ext = tg[3]
    d.route([proxy.at("right"), (1020, proxy.cy), (1020, ext.cy), (ext.right, ext.cy)],
            src=proxy, dst=ext)
    d.fit()
    return d


def trust():
    d = Diagram(1000, 560, "warden trust boundaries")
    poison = d.box(40, 76, 148, 44, ["Poisoned", "document"], "untrusted")
    reply = d.box(202, 76, 148, 44, ["Model", "response"], "untrusted")
    agent = d.box(40, 186, 310, 46, ["Agent runtime"], "untrusted", "stadium")
    d.zone("UNTRUSTED — agent-net, internal: true", "untrusted", [poison, reply, agent])

    # A boundary diagram, not a component diagram -- the architecture picture
    # already breaks the broker open. Here it is one box, because what matters
    # is that everything crosses it.
    broker = d.box(468, 76, 332, 46, ["Tool API · egress proxy"], "enforce")
    pdp = d.box(468, 152, 332, 44, ["Policy decision"], "core", "hex")
    aud = d.box(468, 226, 332, 46, ["Hash-chained audit"], "store", "store")
    d.zone("TRUSTED ENFORCEMENT — warden broker", "enforce", [broker, pdp, aud])

    mint = d.box(468, 400, 332, 44, ["broker-control · private key"], "control")
    d.zone("CONTROL PLANE — backend-net only", "control", [mint])

    db = d.box(880, 76, 142, 44, ["customers.db"], "target", "store")
    intern = d.box(880, 146, 142, 44, ["docstore", "mailer"], "target")
    ext = d.box(880, 216, 142, 44, ["Allowlisted", "hosts"], "target")
    d.zone("PROTECTED SYSTEMS", "target", [db, intern, ext])

    # Two straight drops into the agent, one into each half of its top edge.
    d.edge(poison.at("bottom"), agent.at("top", 0.239), src=poison, dst=agent)
    d.edge(reply.at("bottom"), agent.at("top", 0.761), src=reply, dst=agent)
    d.edge(broker.at("bottom"), pdp.at("top"), src=broker, dst=pdp)
    d.edge(pdp.at("bottom"), aud.at("top"), src=pdp, dst=aud)

    d.route([agent.at("right"), (390, agent.cy), (390, broker.cy), (broker.x, broker.cy)],
            src=agent, dst=broker, label="Bearer · CONNECT")
    # Three straight exits, each from its own share of the broker's right edge.
    for i, target in enumerate((db, intern, ext)):
        t = 0.25 + i * 0.25
        # 18px apart, not 6 -- three corridors that close together read as
        # one frayed line rather than three routes.
        corridor = 826 + i * 18
        d.route([broker.at("right", t), (corridor, broker.y + broker.h * t),
                 (corridor, target.cy), (target.x, target.cy)],
                src=broker, dst=target)
    d.route([mint.at("left"), (420, mint.cy), (420, agent.bottom + 46),
             (agent.cx, agent.bottom + 46), (agent.cx, agent.bottom)],
            src=mint, dst=agent, label="5-minute task token", label_t=0.85)
    d.route([(agent.right - 46, agent.bottom), (agent.right - 46, 350), (mint.x - 30, 350)],
            src=agent, kind="forbidden")
    d.note(agent.right - 38, 338, "no route to the minter", FORBIDDEN, anchor="start")
    d.fit()
    return d


def integration():
    d = Diagram(1000, 330, "integrating warden with an existing agent")
    loop = d.box(40, 78, 252, 44, ["Agent loop"], "untrusted", "stadium")
    sdk = d.box(40, 156, 252, 44, ["Model SDK · client · curl"], "untrusted", "stadium")
    d.zone("YOUR AGENT — CODE UNCHANGED", "untrusted", [loop, sdk])

    api = d.box(390, 78, 150, 44, ["Tool API", ":8080"], "enforce")
    px = d.box(390, 156, 150, 44, ["Egress proxy", ":3128"], "enforce")
    gate = d.box(576, 100, 132, 78, ["policy", "taint", "audit"], "core", "hex")
    d.zone("WARDEN", "enforce", [api, px, gate])

    sysb = d.box(790, 78, 178, 44, ["Databases · APIs", "mail"], "target")
    net = d.box(790, 156, 178, 44, ["Allowlisted hosts"], "target")
    d.zone("YOUR SYSTEMS", "target", [sysb, net])

    d.edge(loop.at("right"), api.at("left"), src=loop, dst=api, label="BROKER_URL")
    d.edge(sdk.at("right"), px.at("left"), src=sdk, dst=px, label="HTTP_PROXY")
    d.edge(api.at("right"), gate.at("left"), src=api, dst=gate, bend="h")
    d.edge(px.at("right"), gate.at("left"), src=px, dst=gate, bend="h")
    d.route([gate.at("right"), (740, gate.cy), (740, sysb.cy), (sysb.x, sysb.cy)],
            src=gate, dst=sysb, label="allow")
    d.route([gate.at("right"), (740, gate.cy), (740, net.cy), (net.x, net.cy)],
            src=gate, dst=net, label="allow")
    d.note(500, 262, "deny → 403 + X-Warden-Rule, and the decision is recorded either way",
           FORBIDDEN)
    d.fit()
    return d


def export_png(svg_path, scale=3):
    """Optional PNG beside the SVG, for readers whose viewer will not render
    SVG. Transparent background on purpose: the diagrams put nothing behind
    their zones, so the page's own colour shows through and one file serves
    light and dark alike. Needs cairosvg (`pip install cairosvg`); skipped
    with a note when it is absent, because the SVGs are the source of truth
    and generating them must not require it.
    """
    try:
        import cairosvg
    except ImportError:
        return None
    png = svg_path.with_suffix(".png")
    cairosvg.svg2png(url=str(svg_path), write_to=str(png), scale=scale,
                     background_color=None)
    return png


# --------------------------------------------------------------------------
# Scenario strips — one per row of the README's "What it stops" table.
#
# Four beats, always the same shape, so the three read as a set: who is
# asking, what they asked for, the rule that answered, what they actually
# got. Deliberately iconographic rather than architectural -- this is the
# picture for someone who has not read anything else yet.
# --------------------------------------------------------------------------

ICON = 44


def _icon(kind, x, y, colour):
    """A 44x44 glyph, drawn from primitives so there is nothing to embed."""
    cx, cy = x + ICON / 2, y + ICON / 2
    st = f'fill="none" stroke="{colour}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"'
    if kind == "agent":
        return (f'<rect x="{x+7}" y="{y+12}" width="{ICON-14}" height="22" rx="6" {st}/>'
                f'<path d="M{cx},{y+6} L{cx},{y+12}" {st}/>'
                f'<circle cx="{cx}" cy="{y+5}" r="2.6" fill="{colour}"/>'
                f'<circle cx="{cx-6}" cy="{y+22}" r="2.4" fill="{colour}"/>'
                f'<circle cx="{cx+6}" cy="{y+22}" r="2.4" fill="{colour}"/>'
                f'<path d="M{cx-5},{y+29} L{cx+5},{y+29}" {st}/>')
    if kind == "records":
        top, bot, r = y + 8, y + 34, 14
        return (f'<ellipse cx="{cx}" cy="{top}" rx="{r}" ry="4.6" {st}/>'
                f'<path d="M{cx-r},{top} V{bot}" {st}/>'
                f'<path d="M{cx+r},{top} V{bot}" {st}/>'
                f'<path d="M{cx-r},{bot} a{r},4.6 0 0 0 {2*r},0" {st}/>'
                f'<path d="M{cx-r},{top+9} a{r},4.6 0 0 0 {2*r},0" {st}/>'
                f'<path d="M{cx-r},{top+18} a{r},4.6 0 0 0 {2*r},0" {st}/>')
    if kind == "person":
        return (f'<circle cx="{cx}" cy="{y+14}" r="6.5" {st}/>'
                f'<path d="M{cx-11},{y+34} a11,11 0 0 1 22,0" {st}/>')
    if kind == "server":
        return (f'<rect x="{x+6}" y="{y+9}" width="{ICON-12}" height="12" rx="3" {st}/>'
                f'<rect x="{x+6}" y="{y+25}" width="{ICON-12}" height="12" rx="3" {st}/>'
                f'<circle cx="{x+13}" cy="{y+15}" r="1.9" fill="{colour}"/>'
                f'<circle cx="{x+13}" cy="{y+31}" r="1.9" fill="{colour}"/>')
    if kind == "shield":
        return (f'<path d="M{cx},{y+5} L{x+35},{y+12} V{y+24} '
                f'C{x+35},{y+32} {cx+5},{y+37} {cx},{y+39} '
                f'C{cx-5},{y+37} {x+9},{y+32} {x+9},{y+24} V{y+12} Z" {st}/>')
    if kind == "blocked":
        return (f'<circle cx="{cx}" cy="{cy}" r="15" {st}/>'
                f'<path d="M{cx-10},{cy+10} L{cx+10},{cy-10}" {st}/>')
    raise KeyError(kind)


CARD_TEXT_X = 14 + ICON + 13     # icon inset + icon + gap
CARD_PAD_R = 14


def _card(x, y, w, h, kind, icon, head, sub, tone):
    """One beat: an icon on the left, two lines of text beside it.

    Refuses to draw text it would clip. The first version of these strips
    silently cut "a subject the token never declared" off the right edge of
    its card -- the same class of bug the box diagrams have a check for, so
    it gets the same treatment here.
    """
    room = w - CARD_TEXT_X - CARD_PAD_R
    for text, size in ((head, 15), (sub, 12.5)):
        need = text_width(text, size)
        if need > room:
            raise ValueError(
                f"{text!r} needs {need:.0f}px, card gives {room:.0f}px")
    fill, stroke, colour = (ZONE[tone] if tone in ZONE else (None, None, None))
    body = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" '
            f'stroke="{stroke}"/>']
    ix = x + 14
    body.append(_icon(icon, ix, y + (h - ICON) / 2, colour))
    tx = ix + ICON + 13
    body.append(f'<text x="{tx}" y="{y + h/2 - 8}" fill="{colour}" font-family="{MONO}" '
                f'font-size="15" font-weight="600">{esc(head)}</text>')
    body.append(f'<text x="{tx}" y="{y + h/2 + 12}" fill="{colour}" font-family="{MONO}" '
                f'font-size="12.5">{esc(sub)}</text>')
    return "".join(body)


TITLE_CHIP = ("#EDEAF4", "#B9B2CC", "#2A2440")


def _chip(x_centre, y, text, size, tone, anchor_left=False):
    """Text on an opaque pill.

    Everything outside a card sits on whatever colour the page happens to be,
    and NO single ink clears 4.5:1 against both white and GitHub's #0d1117 --
    the two requirements are arithmetically incompatible (luminance <= 0.183
    for one, >= 0.200 for the other). The rule name used to be bare text at
    1.79:1 on dark. A pill sidesteps the whole problem.
    """
    fill, stroke, colour = tone
    w = text_width(text, size) + 22
    x = x_centre if anchor_left else x_centre - w / 2
    h = size + 11
    return (f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{h/2:.1f}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="0.8"/>'
            f'<text x="{x + w/2:.1f}" y="{y + h/2:.1f}" fill="{colour}" font-family="{MONO}" '
            f'font-size="{size}" font-weight="600" text-anchor="middle" '
            f'dominant-baseline="central">{esc(text)}</text>')


def _strip(title, rule, ask_icon, ask_head, ask_sub, got_head, got_sub, note):
    W, H = 1080, 186
    ch, top = 88, 44           # card height, and where the cards begin
    gate_x = 706
    body = []

    body.append(_chip(0, 4, title, 13.5, TITLE_CHIP, anchor_left=True))

    body.append(_card(0, top, 250, ch, None, "agent", "the agent", "one task token", "untrusted"))
    body.append(_card(310, top, 340, ch, None, ask_icon, ask_head, ask_sub, "untrusted"))
    body.append(_card(800, top, 280, ch, None, "shield", got_head, got_sub, "target"))

    fill, stroke, _ = PALETTE["enforce"]
    body.append(f'<rect x="{gate_x}" y="{top - 6}" width="14" height="{ch + 12}" rx="5" '
                f'fill="{fill}" stroke="{stroke}"/>')

    mid = top + ch / 2
    for x1, x2 in ((250, 310), (650, gate_x), (gate_x + 14, 800)):
        body.append(f'<path d="M{x1+8},{mid} L{x2-6},{mid}" fill="none" stroke="{LINE}" '
                    f'stroke-width="2" marker-end="url(#arrow)"/>')

    # The rule travels with its explanation, in one pill, rather than floating
    # above the gate where it was unreadable on a dark page.
    body.append(_chip(W / 2, top + ch + 14, f"{rule} · {note}", 12, ZONE["enforce"]))

    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" '
            f'height="{H}" role="img" aria-label="{esc(title)}: {esc(ask_head)}, '
            f'{esc(ask_sub)}; {esc(rule)} gives {esc(got_head)}, {esc(got_sub)}">'
            f'<title>{esc(title)}</title><defs>'
            f'<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            f'markerHeight="7" orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="{LINE}"/></marker>'
            f'</defs>' + "".join(body) + '</svg>\n')


SCENARIOS = {
    "stop-report": dict(
        title="report · bulk extraction",
        rule="rows.bounded",
        ask_icon="records", ask_head="read the whole table", ask_sub="20,651 customer records",
        got_head="1 record", got_sub="the one the task named",
        note="splitting the read into thirds changed nothing"),
    "stop-crosscheck": dict(
        title="crosscheck · out-of-scope read",
        rule="rows.scope",
        ask_icon="person", ask_head="read another customer", ask_sub="one row, inside the budget",
        got_head="refused", got_sub="an undeclared subject",
        note="wrong subject, not too many rows"),
    "stop-share": dict(
        title="share · data reaching an unapproved sink",
        rule="egress.pii_sink",
        ask_icon="server", ask_head="POST to an internal host", ask_sub="docstore.internal, allowlisted",
        got_head="0 bytes", got_sub="the task was holding PII",
        note="refused for what it carried, not where it went"),
}


def illustrations():
    written = []
    for name, spec in SCENARIOS.items():
        path = OUT / f"{name}.svg"
        path.write_text(_strip(**spec), encoding="utf-8")
        png = export_png(path)
        written.append(f"{name}.svg" + (f" +{png.name}" if png else ""))
    return written


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    failed = False
    for name, fn in (("architecture", architecture), ("trust-boundaries", trust),
                     ("integration", integration)):
        d = fn()
        problems = d.check()
        if problems:
            failed = True
            print(f"{name}: REFUSED — {len(problems)} layout problem(s)")
            for p in problems:
                print(f"    {p}")
            continue
        path = OUT / f"{name}.svg"
        path.write_text(d.svg(), encoding="utf-8")
        note = f"{len(d.boxes)} boxes, {len(d.edges)} edges, layout clean"
        png = export_png(path)
        if png:
            note += f", +{png.name}"
        print(f"wrote {path.relative_to(OUT.parent.parent)}  ({note})")
    for line in illustrations():
        print(f"wrote docs/assets/{line}")
    if not failed and export_png(OUT / "architecture.svg") is None:
        print("note: cairosvg not installed, so no PNGs were written")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
