"""Convert the designer's dc-runtime template (design/console/Interlock
Console.dc.html) into React TSX, one file per screen/overlay, binding every
{{ path }} to a typed view-model `v` (web/src/vals.ts). Mechanical on purpose:
the markup and inline styles are the design, so nothing here re-interprets
them.

The one exception is PATCHES: places where the designer's markup hard-codes a
value from their mock data (a receipt number, a file path, an unlock code). The
console shows real data only, so each becomes a binding here - listed in one
place, each required to match exactly once, so a new design drop that moves
one fails loudly instead of quietly shipping a mock value.

Usage: python3 scripts/console_design/convert.py \
         "design/console/Interlock Console.dc.html" web/src/design
"""
import json
import re
import sys
from html.parser import HTMLParser

VOID = {"input", "br", "hr", "img", "meta", "link"}
ATTR_CASE = {
    "onclick": "onClick", "onchange": "onChange", "onmouseenter": "onMouseEnter",
    "onmouseleave": "onMouseLeave", "onfocus": "onFocus", "viewbox": "viewBox",
    "tabindex": "tabIndex", "spellcheck": "spellCheck", "class": "className", "for": "htmlFor",
    "stroke-width": "strokeWidth", "stroke-linecap": "strokeLinecap",
    "stroke-linejoin": "strokeLinejoin", "stroke-dasharray": "strokeDasharray",
    "stroke-dashoffset": "strokeDashoffset", "readonly": "readOnly", "maxlength": "maxLength",
    "autocomplete": "autoComplete", "autofocus": "autoFocus",
}
BIND = re.compile(r"\{\{\s*(.*?)\s*\}\}")


#: (design markup, replacement). Mock literals -> bindings; stale notes removed.
PATCHES = [
    # Sidebar: the real quarantined-rule and detector counts.
    ("color:var(--il-rewrite)\">~1</span>", "color:var(--il-rewrite)\">~{{ quarCount }}</span>"),
    ("color:var(--il-dim)\">115</span", "color:var(--il-dim)\">{{ detCount }}</span"),
    # Audit: the broken-chain banner names the real receipt and problem.
    (">Chain broken at receipt #1,191</strong>", ">Chain broken at receipt #{{ chain.brokenAt }}</strong>"),
    (">mac mismatch: the receipt's signature doesn't match its contents or the one before it.</span>",
     ">{{ chain.problem }}</span>"),
    (">Show receipt #1,191</button>", ">Show receipt #{{ chain.brokenAt }}</button>"),
    # Policy: the real file and what it extends.
    (">~/.interlock/policy.json</span></span>", ">{{ pol.path }}</span></span>"),
    ("cursor:pointer\">builtin:coding-agent</button>", "cursor:pointer\">{{ pol.extendsLabel }}</button>"),
    ("font-size:10.5px\">policy.json</span>", "font-size:10.5px\">{{ pol.fileName }}</span>"),
    ("font-size:11px\">builtin:coding-agent</code>. Locked rules",
     "font-size:11px\">{{ pol.extendsLabel }}</code>. Locked rules"),
    ("font-size:11px\">~/.interlock/policy.json</code>. Hooks read", "font-size:11px\">{{ pol.path }}</code>. Hooks read"),
    # Unlock: this console's own address; never a code (only the terminal has it).
    ("$ python3 -m interlock.console --receipts ~/.interlock/receipts.jsonl\ninterlock console on http://127.0.0.1:8787 (read-only)\nunlock writes: http://127.0.0.1:8787/#/unlock/<span style=\"color:var(--il-acc)\">k7Qm-2fXa-9RtL</span>",
     "$ {{ unlockCmd }}\ninterlock console on {{ baseUrl }} (read-only)\nunlock writes: {{ baseUrl }}/#/unlock/<span style=\"color:var(--il-acc)\">xxxx-xxxx-xxxx</span>"),
    # Reviews: four-eyes is a console setting, not a per-rule one.
    ("Four-eyes is on for this rule,", "Four-eyes is on for this console,"),
    # Activity: the bucketed report API this note asked for now exists.
    (" Time buckets above need the proposed bucketed report API.<", "<"),
    # Ops: open the real MCP starter rule as an unsaved draft in the editor.
    ("<a href=\"#/policy\" style=\"font-size:12.5px;font-weight:500;padding:6px 11px;border-radius:7px;border:1px solid var(--il-rule2);color:var(--il-fg);text-decoration:none\">Review starter policy</a>",
     "<a href=\"#/policy/starter\" style=\"font-size:12.5px;font-weight:500;padding:6px 11px;border-radius:7px;border:1px solid var(--il-rule2);color:var(--il-fg);text-decoration:none\">Review starter policy</a>"),
]


def apply_patches(html):
    for old, new in PATCHES:
        count = html.count(old)
        if count != 1:
            raise SystemExit("patch matched {} times (want 1): {!r}".format(count, old[:80]))
        html = html.replace(old, new)
    return html


class Node:
    def __init__(self, tag, attrs):
        self.tag, self.attrs, self.children = tag, attrs, []


class Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root", [])
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = Node(tag, attrs)
        self.stack[-1].children.append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.stack[-1].children.append(Node(tag, attrs))

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                return
        raise SystemExit("unbalanced </{}>".format(tag))

    def handle_data(self, data):
        self.stack[-1].children.append(data)


class Emitter:
    def __init__(self):
        self.hover = {}  # css text -> class name

    # --- expressions ---------------------------------------------------------
    @staticmethod
    def loop_name(var):
        """Loop variables get a prefix so none can shadow the view-model ``v``."""
        return "it_" + var

    def expr(self, path, scope):
        if path in ("true", "false"):
            return path
        head, _, rest = path.partition(".")
        if head in scope:
            return self.loop_name(head) + ("." + rest if rest else "")
        return "v." + path

    def interp(self, text, scope):
        """A string with {{ }} parts -> a JS expression."""
        parts = BIND.split(text)
        if len(parts) == 3 and parts[0] == "" and parts[2] == "":
            return self.expr(parts[1], scope)
        out = []
        for i, p in enumerate(parts):
            if i % 2:
                out.append("${" + self.expr(p, scope) + "}")
            else:
                out.append(p.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${"))
        return "`" + "".join(out) + "`"

    # --- style ---------------------------------------------------------------
    @staticmethod
    def split_decls(css):
        decls, depth, quote, cur = [], 0, None, ""
        for ch in css:
            if quote:
                cur += ch
                if ch == quote:
                    quote = None
                continue
            if ch in "'\"":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == ";" and depth == 0:
                if cur.strip():
                    decls.append(cur.strip())
                cur = ""
                continue
            cur += ch
        if cur.strip():
            decls.append(cur.strip())
        out = []
        for d in decls:
            k, _, val = d.partition(":")
            out.append((k.strip(), val.strip()))
        return out

    @staticmethod
    def camel(prop):
        if prop.startswith("--"):
            return json.dumps(prop)
        if prop.startswith("-webkit-"):
            prop = "Webkit-" + prop[len("-webkit-"):]
        parts = prop.split("-")
        name = parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])
        return name

    def style(self, css, scope):
        items = []
        decls = self.split_decls(css)
        # A later declaration of the same property wins in CSS; keep only it.
        last = {k: i for i, (k, _) in enumerate(decls)}
        decls = [d for i, d in enumerate(decls) if last[d[0]] == i]
        for k, val in decls:
            if BIND.search(val):
                items.append("{}: {}".format(self.camel(k), self.interp(val, scope)))
            else:
                items.append("{}: {}".format(self.camel(k), json.dumps(val, ensure_ascii=False)))
        return "{{ " + ", ".join(items) + " }}"

    def hover_class(self, css):
        if css not in self.hover:
            self.hover[css] = "ilh-{}".format(len(self.hover) + 1)
        return self.hover[css]

    # --- nodes ---------------------------------------------------------------
    def attrs(self, node, scope):
        out, classes = [], []
        for name, value in node.attrs:
            if name.startswith("hint-"):
                continue
            value = "" if value is None else value
            if name == "style":
                out.append("style={}".format(self.style(value, scope)))
                continue
            if name == "style-hover":
                classes.append(self.hover_class(value))
                continue
            jsx = ATTR_CASE.get(name, name)
            if BIND.search(value):
                out.append("{}={{{}}}".format(jsx, self.interp(value, scope)))
            elif name in ("spellcheck",):
                out.append("{}={{{}}}".format(jsx, value))
            elif name in ("tabindex", "rows", "cols", "colspan", "rowspan") and re.fullmatch(r"-?\d+", value):
                out.append("{}={{{}}}".format(jsx, value))
            elif name in ("disabled",) and value in ("", "disabled", "true"):
                out.append(jsx)
            elif '"' in value or "\\" in value:
                out.append("{}={{{}}}".format(jsx, json.dumps(value, ensure_ascii=False)))
            else:
                # JSX attribute strings take no escapes: keep characters as-is.
                out.append('{}="{}"'.format(jsx, value))
        if classes:
            out.append('className="{}"'.format(" ".join(classes)))
        return out

    def text(self, data, pre):
        if pre:
            segs = data
        else:
            segs = re.sub(r"\s+", " ", data)
        return segs

    @staticmethod
    def ignores_ws(container):
        """True when whitespace-only text between children renders nothing:
        flex/grid containers drop it, and so does the component root."""
        if container is None or container.tag == "#root":
            return True
        style = dict(container.attrs).get("style") or ""
        m = re.search(r"(?:^|;)\s*display\s*:\s*([a-z-]+)", style)
        return bool(m) and m.group(1) in ("flex", "grid", "inline-flex", "inline-grid")

    BLOCKS = {"div", "section", "aside", "header", "main", "nav", "p", "h1", "h2", "h3",
              "ul", "ol", "li", "dl", "dt", "dd", "form", "table", "tr", "td", "th", "pre"}

    def children(self, node, scope, pre, ind, container=None):
        lines = []
        real = node if node.tag not in ("sc-if", "sc-for") else container
        kids = node.children
        for pos, child in enumerate(kids):
            if isinstance(child, str):
                t = self.text(child, pre)
                if not t:
                    continue
                if not pre and t == " ":
                    edge = pos == 0 or pos == len(kids) - 1
                    if self.ignores_ws(real) or (edge and real is not None and real.tag in self.BLOCKS
                                                 and node is real):
                        continue
                    lines.append(ind + '{" "}')
                    continue
                parts = BIND.split(t)
                for i, p in enumerate(parts):
                    if i % 2:
                        # The design runtime renders each text binding in its own
                        # inline span; in a flex row that makes it its own item,
                        # so the gaps around it depend on the wrapper.
                        lines.append(ind + '<span className="sc-interp">{' + self.expr(p, scope) + "}</span>")
                    elif p:
                        if not pre and re.fullmatch(r"[^{}<>&\s](?:[^{}<>&]*[^{}<>&\s])?", p) and "  " not in p:
                            lines.append(ind + p)
                        else:
                            lines.append(ind + "{" + json.dumps(p, ensure_ascii=False) + "}")
            else:
                lines.extend(self.node(child, scope, pre, ind, real))
        return lines

    def node(self, node, scope, pre, ind, container=None):
        a = dict(node.attrs)
        if node.tag == "sc-if":
            cond = self.interp(a["value"], scope)
            body = self.children(node, scope, pre, ind + "    ", container)
            return [ind + "{" + cond + " ? (", ind + "  <>"] + body + [ind + "  </>", ind + ") : null}"]
        if node.tag == "sc-for":
            lst = self.interp(a["list"], scope)
            var = a["as"]
            idx = "i_" + var
            inner = scope | {var}
            body = self.children(node, inner, pre, ind + "    ", container)
            # Typed as an element of its list, so every property the markup
            # reads is checked against the view-model.
            elem = "(typeof " + lst + ")[number]"
            return ([ind + "{" + lst + ".map((" + self.loop_name(var) + ": " + elem + ", " + idx + ": number) => (",
                     ind + "  <Fragment key={" + idx + "}>"] + body +
                    [ind + "  </Fragment>", ind + "))}"])
        if node.tag in ("sc-component",):
            raise SystemExit("unhandled " + node.tag)
        style = a.get("style") or ""
        child_pre = pre or node.tag in ("pre", "textarea") or "white-space:pre" in style
        attrs = self.attrs(node, scope)
        open_ = "<" + node.tag + ("" if not attrs else " " + " ".join(attrs))
        if node.tag in VOID or (node.tag == "textarea"):
            # textarea content is bound through value=, never children
            return [ind + open_ + " />"]
        body = self.children(node, scope, child_pre, ind + "  ")
        if not body:
            return [ind + open_ + "></" + node.tag + ">"]
        return [ind + open_ + ">"] + body + [ind + "</" + node.tag + ">"]


def find(node, pred, out):
    for c in node.children:
        if isinstance(c, Node):
            if pred(c):
                out.append(c)
            else:
                find(c, pred, out)
    return out


def main():
    src, out_dir = sys.argv[1], sys.argv[2]
    html = apply_patches(open(src, encoding="utf-8").read())
    body = html[html.index("</helmet>") + len("</helmet>"):]
    body = body[:body.index("<script type=\"text/x-dc\"")]
    body = body.replace("</x-dc>", "").replace("</body>", "").replace("</html>", "")
    p = Parser()
    p.feed(body)
    em = Emitter()
    screens = {}
    is_cond = re.compile(r"^\{\{ (is\.[a-z]+|navOpen|unlockOpen|keysOpen|saveOpen) \}\}$")

    def detach(node):
        """Replace each screen/overlay sc-if with a placeholder and collect it."""
        for i, c in enumerate(node.children):
            if isinstance(c, Node):
                if c.tag == "sc-if" and is_cond.match(dict(c.attrs).get("value", "")):
                    key = is_cond.match(dict(c.attrs)["value"]).group(1)  # type: ignore[union-attr]
                    screens[key] = c
                    node.children[i] = Node("slot-" + key.replace(".", "-"), [])
                else:
                    detach(c)
    detach(p.root)

    import os
    os.makedirs(out_dir, exist_ok=True)
    names = {}
    for key, node in screens.items():
        comp = "".join(w.capitalize() for w in re.split(r"[.]", key)[-1:])
        comp = {"is.activity": "ActivityScreen", "is.reviews": "ReviewsScreen", "is.audit": "AuditScreen",
                "is.policy": "PolicyScreen", "is.playground": "PlaygroundScreen", "is.catalog": "CatalogScreen",
                "is.inspector": "InspectorScreen", "is.ops": "OpsScreen", "is.notfound": "NotFoundScreen",
                "navOpen": "NavDrawer", "unlockOpen": "UnlockDialog", "keysOpen": "KeysDialog",
                "saveOpen": "SaveDialog"}[key]
        names[key] = comp
        body_lines = em.children(node, set(), False, "      ")
        src_lines = [
            "// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.",
            "// Edit the view-model, not this markup: regenerate instead.",
            "import { Fragment } from \"react\";",
            "import type { Vals } from \"../vals\";",
            "",
            "export function {}({{ v }}: {{ v: Vals }}) {{".format(comp),
            "  return (",
            "    <>",
        ] + body_lines + ["    </>", "  );", "}", ""]
        if not any("<Fragment" in ln for ln in body_lines):
            src_lines.remove("import { Fragment } from \"react\";")
        with open(os.path.join(out_dir, comp + ".tsx"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(src_lines))
    shell_lines = em.children(p.root, set(), False, "    ")
    out = []
    for ln in shell_lines:
        m = re.match(r"^(\s*)<slot-([A-Za-z-]+)></slot-[A-Za-z-]+>$", ln.strip() and ln)
        if m:
            key = m.group(2).replace("-", ".", 1) if m.group(2).startswith("is-") else m.group(2)
            key = {"navopen": "navOpen", "unlockopen": "unlockOpen", "keysopen": "keysOpen",
                   "saveopen": "saveOpen"}.get(key.lower(), key)
            comp = names[key]
            cond = "v." + key
            out.append(m.group(1) + "{" + cond + " ? <" + comp + " v={v} /> : null}")
        else:
            out.append(ln)
    imports = "\n".join("import {{ {0} }} from \"./{0}\";".format(c) for c in sorted(names.values()))
    shell = [
        "// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.",
        "// Edit the view-model, not this markup: regenerate instead.",
        "import { Fragment } from \"react\";",
        "import type { Vals } from \"../vals\";",
        imports,
        "",
        "export function Shell({ v }: { v: Vals }) {",
        "  return (",
        "    <>",
    ] + out + ["    </>", "  );", "}", ""]
    if not any("<Fragment" in ln for ln in out):
        shell.remove("import { Fragment } from \"react\";")
    with open(os.path.join(out_dir, "Shell.tsx"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(shell))
    css = ["/* GENERATED: the template's style-hover rules. Inline styles win over a",
           "   plain class rule, so each hover declaration is !important. */"]
    for text, cls in em.hover.items():
        decls = "; ".join("{}: {} !important".format(k, val) for k, val in Emitter.split_decls(text))
        css.append(".{}:hover {{ {} }}".format(cls, decls))
    with open(os.path.join(out_dir, "hover.css"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(css) + "\n")
    print("screens:", sorted(names.values()), "hover rules:", len(em.hover))


if __name__ == "__main__":
    main()
