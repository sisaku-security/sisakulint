"use strict";
// The script of a report view: it draws the data of the page
// (reportview.Page). Text goes into the page by textContent and attributes
// only, never as HTML: the data has the text of workflows, which an
// attacker may write.

// addedText says which added attackers (--add-attacker) a finding or an
// inconclusive place (what) needs, as the field added_attackers of the
// report means: one attacker alone, or each of several alone.
function addedText(vs, what) {
  if (vs.length === 1) {
    return "Added attacker: " + vs[0] + ". A run that adds this attacker reports this " + what + ", and a run that adds no attacker does not report this " + what + " (--add-attacker).";
  }
  return "Added attackers: " + vs.join(", ") + ". A run that adds any one of these attackers alone reports this " + what + ", and a run that adds no attacker does not report this " + what + " (--add-attacker).";
}

// evaluate is the truth of the condition c, given the truth of each leaf by
// its id, in Kleene's logic, as lint.Eval: all is false when a part is,
// any is true when a part is, and either is unknown when a part is and
// nothing decides.
function evaluate(c, truths) {
  if (c.op === "leaf") return truths[c.id];
  const stop = c.op === "all" ? "false" : "true";
  let out = c.op === "all" ? "true" : "false";
  for (const p of c.parts || []) {
    const v = evaluate(p, truths);
    if (v === stop) return stop;
    if (v === "unknown") out = "unknown";
  }
  return out;
}

// qualityGroupText says what the group of the quality rules is.
const qualityGroupText = "When the workflow has no other flaw, an attacker gets nothing from a flaw that a quality rule finds. The flaw that a quality rule finds can only make an attack through another flaw worse, such as an attack through a flaw that a rule in the groups above finds. A finding of a quality rule does not change the exit code, so a CI step that runs the linter does not fail because of a finding of a quality rule. No quality rule has a value of weakness or of any other axis that the group by buttons choose. Whichever group by button is pressed, the quality rules group is the last group of the list.";

// groupRules is the table of contents of rules (the catalog's rules) as
// the axis facet (an element of the catalog's facets) groups it: a group
// of each value some rule has, in the order of facet's values, with the
// rules that have it, each with the other values of facet it has. With no
// facet, one group of every rule in their order. The quality rules are not
// in those groups: they are last, in a group of their own, in their order.
function groupRules(all, facet) {
  const rules = all.filter((r) => !r.quality);
  const quality = all.filter((r) => r.quality);
  const out = [];
  if (!facet) {
    if (rules.length) out.push({ value: null, description: "", rules: rules.map((rule) => ({ rule, also: [] })) });
  } else {
    const values = (r) => ((r.meta && r.meta.facets) || {})[facet.key] || [];
    for (const v of facet.values) {
      const rs = rules.filter((r) => values(r).includes(v.value));
      if (rs.length) out.push({ value: v.value, description: v.description, rules: rs.map((rule) => ({ rule, also: values(rule).filter((x) => x !== v.value) })) });
    }
  }
  if (quality.length) out.push({ value: "quality rules", description: qualityGroupText, rules: quality.map((rule) => ({ rule, also: [] })) });
  return out;
}

// groupOf is the value group of terms (the catalog's terms) whose ID is id,
// or null.
function groupOf(terms, id) {
  return terms.definitions.value_groups.find((g) => g.id === id) || null;
}

// itemNameAt is what the key at path (a registry path, the keys from the
// meta of a rule joined by dots) means, by terms: {name, text} of its item
// name, or the heading and the description of the value group whose axis
// it is; null when it has neither.
function itemNameAt(terms, path) {
  const n = terms.paths.item_names[path];
  if (n) return terms.definitions.item_names.find((d) => d.name === n) || null;
  const g = terms.paths.axes[path] ? groupOf(terms, terms.paths.axes[path]) : null;
  return g ? { name: g.heading, text: g.description } : null;
}

// valueAt is what value, a value at path, means, by terms: {name, text} of
// the value in the value group of the path, or of metric for the value of
// a CVSS metric; null when it is in none.
function valueAt(terms, path, value, metric) {
  const p = terms.paths;
  const id = metric ? p.metrics[metric] : p.values[path] || p.axes[path];
  const g = id ? groupOf(terms, id) : null;
  return (g && g.values.find((v) => v.name === value)) || null;
}

// refRoot is the registry path under which the page draws what a key of a
// finding kind refers to (a precondition, an incident, a fix), or null for
// a key that refers to nothing.
function refRoot(key) {
  return { preconditions: "threat.preconditions", incidents: "threat.incidents", fixes: "fix_kinds" }[key] || null;
}

// withArguments is a copy of the Meta m of a rule whose finding kinds have
// their arguments (CatalogRule.arguments, which args gives by the ID of
// each kind), m as it was.
function withArguments(m, args) {
  if (!m || !args) return m;
  return { ...m, finding_kinds: (m.finding_kinds || []).map((k) => (args[k.id] ? { ...k, arguments: args[k.id] } : k)) };
}

// plural is k and the noun one, in the plural unless k is 1.
const plural = (k, one) => k + " " + one + (k === 1 ? "" : "s");

// countText names a count of findings and a count of quality findings, for
// people: each left out when zero, and both named as absent when both are.
function countText(findings, quality) {
  const parts = [];
  if (findings) parts.push(plural(findings, "finding"));
  if (quality) parts.push(plural(quality, "quality finding"));
  return parts.length ? parts.join(", ") : "no findings and no quality findings";
}

// rowClass is the class of a row of a file whose marks are m: finding,
// quality and inconclusive, the places on the row of findings whose
// certainty is confirmed or conditional, of quality findings and of findings
// whose certainty is inconclusive. A place of a finding comes first, then
// one of a quality finding, then one of an inconclusive finding; a row of
// evidence or related places alone, of a finding or of a quality finding,
// is the evidence color.
function rowClass(m) {
  return m.finding ? "row-finding" : m.quality ? "row-quality" : m.inconclusive ? "row-inconclusive" : "row-evidence";
}

// summaryText is the summary of a report's page: the findings, of which
// inconclusive are the findings whose certainty is inconclusive and accepted
// those of them that an entry of --accept matched, and the quality findings,
// which the findings do not include and which do not change the exit code.
function summaryText(findings, inconclusive, accepted, quality) {
  let s = plural(findings, "finding");
  if (inconclusive) s += " (" + inconclusive + " of the findings inconclusive" + (accepted ? ", and " + accepted + " of the inconclusive findings accepted by --accept" : "") + ")";
  if (quality) {
    s += ", " + plural(quality, "quality finding") + ". The " + plural(findings, "finding") + (findings === 1 ? " does" : " do") + " not include the " + plural(quality, "quality finding") + ". Quality findings do not change the exit code, so a CI step that runs the linter does not fail because of quality findings.";
  }
  return s;
}

if (typeof module !== "undefined") module.exports = { evaluate, groupRules, itemNameAt, valueAt, refRoot, withArguments, countText, summaryText, rowClass };

if (typeof document !== "undefined") {
  const app = document.getElementById("app");
  const SVG = "http://www.w3.org/2000/svg";
  const status = { true: "holds", unknown: "holds if its condition does", false: "does not hold" };
  const titles = { event: "Event", evidence: "Through", finding: "Here", related: "Related" };

  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  };

  const fileOf = (n) => (n.input ? n.input : n.query ? JSON.stringify(n.query) : "");
  const fileLine = (n) => fileOf(n) + (n.line ? ":" + n.line : "");
  const where = (n) => [fileLine(n), n.job ? "job " + n.job : "", n.step ? "step " + n.step : ""].filter(Boolean).join(" › ");
  const at = (n) => fileOf(n) + (n.line ? ":" + n.line + ":" + n.column : "") + (n.via ? " (through an alias)" : "");

  function box(n, title) {
    const b = el("div", "node node-" + n.role);
    b.appendChild(el("div", "node-title", title || titles[n.role]));
    if (n.role === "event") {
      b.appendChild(el("div", "node-where", "An attacker triggers " + n.events.join(", ")));
      return b;
    }
    const w = where(n);
    if (w) b.appendChild(el("div", "node-where", w));
    if (n.snippet) b.appendChild(snippet(n.snippet));
    else if (n.source) b.appendChild(el("pre", "node-source", n.source.trim()));
    if (n.note) b.appendChild(el("div", "node-note", n.note));
    if (n.column || n.via) b.appendChild(el("div", "node-at audit", (n.column ? "column " + n.column : "") + (n.via ? " (through an alias)" : "")));
    if (n.key_path) b.appendChild(el("code", "node-key audit", n.key_path));
    return b;
  }

  // snippet is the lines of a step, without their common indent, the line
  // of the place marked, and an ellipsis where lines are left out.
  function snippet(lines) {
    const indent = Math.min(...lines.filter((x) => x.text.trim()).map((x) => x.text.length - x.text.trimStart().length));
    const pre = el("pre", "node-source");
    let prev = 0;
    for (const x of lines) {
      if (prev && x.line > prev + 1) pre.appendChild(el("span", "gap", "…"));
      pre.appendChild(el("span", x.at ? "here" : "line", x.text.slice(Number.isFinite(indent) ? indent : 0) || " "));
      prev = x.line;
    }
    return pre;
  }

  function arrow() {
    const s = document.createElementNS(SVG, "svg");
    s.setAttribute("class", "arrow");
    s.setAttribute("viewBox", "0 0 20 28");
    s.setAttribute("width", "20");
    s.setAttribute("height", "28");
    const line = document.createElementNS(SVG, "line");
    line.setAttribute("x1", "10");
    line.setAttribute("y1", "0");
    line.setAttribute("x2", "10");
    line.setAttribute("y2", "20");
    const head = document.createElementNS(SVG, "polygon");
    head.setAttribute("points", "4,18 16,18 10,28");
    s.append(line, head);
    return s;
  }

  function leaves(c, out) {
    if (c.op === "leaf") out[c.id] = c.truth;
    for (const p of c.parts || []) leaves(p, out);
    return out;
  }

  function conditionList(c, truths, changed) {
    const li = el("li");
    if (c.op === "leaf") {
      li.appendChild(el("code", "leaf", c.text));
      if (c.assumed) li.appendChild(el("span", "assumed", "assumed"));
      for (const v of ["true", "false", "unknown"]) {
        const b = el("button", "truth", v);
        b.type = "button";
        b.setAttribute("aria-pressed", String(truths[c.id] === v));
        b.addEventListener("click", () => {
          truths[c.id] = v;
          changed();
        });
        li.appendChild(b);
      }
      return li;
    }
    li.appendChild(el("span", "op", c.op === "all" ? "all of" : "any of"));
    const ul = el("ul");
    for (const p of c.parts || []) ul.appendChild(conditionList(p, truths, changed));
    li.appendChild(ul);
    return li;
  }

  // fixView is the fix of a finding, or its reason for none: null when
  // the finding has neither.
  function fixView(f) {
    const d = el("div", "fix");
    if (f.fix) {
      d.appendChild(el("h3", null, "Fix (" + f.fix.safety + ")"));
      d.appendChild(el("p", "fix-title", f.fix.title));
      if (f.fix.side_effects.length) {
        const ul = el("ul", "side-effects");
        for (const x of f.fix.side_effects) ul.appendChild(el("li", null, x.text));
        d.appendChild(ul);
      }
      for (const e of f.fix.edits) {
        const pre = el("pre", "fix-diff");
        pre.appendChild(el("span", "diff-at", "line " + e.line));
        for (const l of e.old) pre.appendChild(el("span", "del", "- " + l));
        for (const l of e.new) pre.appendChild(el("span", "add", "+ " + l));
        d.appendChild(pre);
      }
      return d;
    }
    if (f.no_fix) {
      d.appendChild(el("h3", null, "No fix (" + f.no_fix.reason + ")"));
      d.appendChild(el("p", "fix-note", f.no_fix.note));
      return d;
    }
    return null;
  }

  // findingView is the card of f, a finding or a quality finding (f.quality):
  // a quality finding has the mark quality in place of a severity, and no fix.
  function findingView(f) {
    const s = el("section", f.quality ? "finding quality" : "finding sev-" + f.severity);
    const inconclusive = f.certainty === "inconclusive";
    const h = el("h2");
    h.append(el("span", "severity", f.quality ? "quality" : f.severity));
    if (inconclusive) h.append(el("span", "mark-inconclusive", "inconclusive"));
    h.append(el("span", "detected", f.detected));
    s.appendChild(h);
    s.appendChild(el("div", "kind audit", f.kind_id));
    const st = el("div", "status");
    s.appendChild(st);
    const flow = el("div", "flow");
    const chain = el("div", "chain");
    let after = false; // a place of the evidence after the finding's runs later
    f.path.forEach((n, i) => {
      if (i > 0) chain.appendChild(arrow());
      chain.appendChild(box(n, after && n.role === "evidence" ? "Then" : titles[n.role]));
      if (n.role === "finding") after = true;
    });
    flow.appendChild(chain);
    if (f.related.length) {
      const side = el("div", "side");
      for (const n of f.related) side.appendChild(box(n));
      flow.appendChild(side);
    }
    s.appendChild(flow);
    s.appendChild(el("p", "remedy", f.remedy));
    const fx = f.quality ? null : fixView(f);
    if (fx) s.appendChild(fx);
    s.appendChild(el("p", "consequence audit", f.consequence));
    // the declaration of the inconclusive kind: what places of the kind the rule cannot decide on
    if (inconclusive && f.kind_text) s.appendChild(el("p", "place-kind", "Inconclusive kind (the same text for every finding of this inconclusive kind): " + f.kind_text));
    if (f.acceptance) s.appendChild(el("p", "accepted", "Accepted by an entry of the file given to --accept. The reason that the person who added the entry wrote: " + f.acceptance));
    if (f.added_attackers) s.appendChild(el("p", "added", addedText(f.added_attackers, "finding")));
    const cond = el("div", "condition audit");
    s.appendChild(cond);
    const truths = f.condition ? leaves(f.condition, {}) : null;
    const render = () => {
      const t = f.condition ? evaluate(f.condition, truths) : "true";
      if (inconclusive) {
        st.className = "status status-inconclusive";
        st.textContent = "This finding is inconclusive: the rule could not decide whether the place of the finding has the problem that the rule of the finding looks for. A person decides: read the workflow at the place.";
        return;
      }
      st.className = "status status-" + t;
      st.textContent = (f.quality ? "This quality finding " : "This finding ") + status[t] + ".";
      cond.replaceChildren();
      if (!f.condition) return;
      cond.appendChild(el("h3", null, "Condition"));
      const ul = el("ul", "cond");
      ul.appendChild(conditionList(f.condition, truths, render));
      cond.appendChild(ul);
    };
    render();
    const dl = el("dl", "details audit");
    for (const [k, v] of [["args", JSON.stringify(f.args)], ["certainty in the report", f.certainty], ["fingerprint", f.fingerprint]]) {
      dl.append(el("dt", null, k), el("dd", null, v));
    }
    s.appendChild(dl);
    return s;
  }

  // The page: a header, then a report's page (mount), or a catalog of the
  // examples whose entries each mount a page.
  let current = null; // what is mounted: its draw, for the mode and resizing
  const header = el("header");
  header.appendChild(el("h1", null, document.getElementById("catalog-data") ? "sisakulint examples" : "sisakulint report"));
  const modes = el("div", "mode");
  const setMode = (m) => {
    document.body.dataset.mode = m;
    for (const b of modes.children) b.setAttribute("aria-pressed", String(b.dataset.mode === m));
    if (current) current.draw();
  };
  for (const m of ["plain", "audit"]) {
    const b = el("button", null, m);
    b.type = "button";
    b.dataset.mode = m;
    b.addEventListener("click", () => setMode(m));
    modes.appendChild(b);
  }
  header.appendChild(modes);
  app.appendChild(header);

  // mount draws data, a report's page, in root: the file on the left, the
  // cards on the right, and the path of a finding chosen over the file. The
  // findings and then the quality findings are one list (items), each
  // quality finding marked quality.
  function mount(data, root) {
    const quality = data.quality_findings || [];
    const items = data.findings.map((f) => ({ ...f, quality: false })).concat(quality.map((f) => ({ ...f, quality: true })));
    const inconclusive = data.findings.filter((f) => f.certainty === "inconclusive");
    const accepted = inconclusive.filter((g) => g.acceptance).length;
    root.appendChild(el("p", "summary", summaryText(data.findings.length, inconclusive.length, accepted, quality.length)));

    const layout = el("div", "layout");
    const left = el("div", "files");
    const tabs = el("div", "tabs");
    const code = el("div", "code");
    left.append(tabs, code);
    const right = el("div", "list");
    const scope = el("div", "scope");
    const cards = el("div", "cards");
    right.append(scope, cards);
    layout.append(left, right);
    root.appendChild(layout);

    const files = new Map(data.files.map((f) => [f.input, f]));
    const sections = items.map((f) => findingView(f));
    const inFile = (n, name) => n.input === name && n.line > 0;
    const nodesOf = (f) => f.path.filter((n) => n.role !== "event").concat(f.related);
    // line: the row the list is narrowed to, or 0
    const state = { file: null, chosen: -1, all: false, line: 0 };

    // onLine are the findings with a place on line of the file name, those
    // found there first.
    const onLine = (name, line) => {
      const at = (f, role) => nodesOf(f).some((n) => inFile(n, name) && n.line === line && (!role || n.role === role));
      const ids = items.map((_, i) => i).filter((i) => at(items[i]));
      return ids.filter((i) => at(items[i], "finding")).concat(ids.filter((i) => !at(items[i], "finding")));
    };

    // segments are the steps of f's path, in order, between two places of
    // files: the line from a to b, or a jump when b is in another file.
    function segments(f) {
      const ns = f.path.filter((n) => n.role !== "event" && n.input && n.line > 0);
      const out = [];
      for (let i = 1; i < ns.length; i++) {
        const a = ns[i - 1], b = ns[i];
        if (a.input === b.input && a.line === b.line) continue;
        out.push({ a, b });
      }
      return out;
    }

    function showFile(name) {
      state.file = name;
      state.line = 0;
      for (const b of tabs.children) b.setAttribute("aria-pressed", String(b.dataset.file === name));
      code.replaceChildren();
      const f = files.get(name);
      if (!f) {
        code.appendChild(el("p", "empty", countText(0, 0)));
        return;
      }
      // line -> {finding, quality, inconclusive: the places of findings
      // whose certainty is confirmed or conditional, of quality findings
      // and of findings whose certainty is inconclusive; texts: the kinds
      // and texts}
      const marks = new Map();
      const markOf = (line) => marks.get(line) || { finding: 0, quality: 0, inconclusive: 0, texts: [] };
      items.forEach((x) => {
        for (const n of nodesOf(x)) {
          if (!inFile(n, name)) continue;
          const m = markOf(n.line);
          if (n.role === "finding") m[x.quality ? "quality" : x.certainty === "inconclusive" ? "inconclusive" : "finding"]++;
          const t = (n.role === "finding" ? "" : "(" + n.role + ") ") + (x.quality ? "quality finding " : x.certainty === "inconclusive" ? "inconclusive finding " : "") + x.kind_id + ": " + x.detected;
          if (!m.texts.includes(t)) m.texts.push(t);
          marks.set(n.line, m);
        }
      });
      f.lines.forEach((text, i) => {
        const line = i + 1;
        const row = el("div", "row");
        row.dataset.line = String(line);
        const m = marks.get(line);
        if (m) row.classList.add(rowClass(m));
        row.appendChild(el("span", "num", String(line)));
        row.appendChild(el("span", "text", text || " "));
        if (m && m.finding + m.inconclusive + m.quality > 1) row.appendChild(el("span", "count", countText(m.finding + m.inconclusive, m.quality)));
        if (m) {
          row.title = m.texts.join("\n");
          row.classList.add("marked");
          row.addEventListener("click", () => {
            state.line = line;
            state.all = false;
            all.setAttribute("aria-pressed", "false");
            listCards();
            choose(onLine(name, line)[0], false);
          });
        }
        code.appendChild(row);
      });
      listCards();
      draw();
    }

    function listCards() {
      cards.replaceChildren();
      if (state.line) {
        const ids = onLine(state.file, state.line);
        for (const i of ids) cards.appendChild(sections[i]);
        const q = ids.filter((i) => items[i].quality).length;
        lineChip.textContent = "line " + state.line + ": " + countText(ids.length - q, q) + " ✕";
        lineChip.hidden = false;
        return;
      }
      lineChip.hidden = true;
      items.forEach((f, i) => {
        if (state.all || nodesOf(f).some((n) => n.input === state.file)) cards.appendChild(sections[i]);
      });
      if (!cards.children.length) cards.appendChild(el("p", "empty", countText(0, 0) + " in this file"));
    }

    // choose chooses the finding i. From a card (follow), it shows the
    // file of the finding's first place and brings that line into view; from
    // a row of the file, the row is in view already, and it brings the card
    // into view.
    function choose(i, follow) {
      state.chosen = i;
      sections.forEach((s, j) => s.classList.toggle("chosen", j === i));
      if (i < 0) return draw();
      const f = items[i];
      if (!follow) {
        if (sections[i].isConnected) sections[i].scrollIntoView({ block: "nearest" });
        return draw();
      }
      const first = f.path.find((n) => n.input && n.line > 0 && files.has(n.input));
      if (first && first.input !== state.file) showFile(first.input);
      else draw();
      const here = f.path.find((n) => inFile(n, state.file));
      if (here) reveal(here.line);
    }

    // reveal brings the row of line into view: inside the file's pane when
    // it scrolls by itself (a wide window), or in the window.
    function reveal(line) {
      const row = code.querySelector('.row[data-line="' + line + '"]');
      if (!row) return;
      if (getComputedStyle(left).position !== "sticky") return row.scrollIntoView({ block: "center" });
      let box = left.getBoundingClientRect();
      if (box.top < 0 || box.bottom > innerHeight) {
        scrollBy(0, box.top); // the pane runs past the window: bring it in, where it sticks
        box = left.getBoundingClientRect();
      }
      const top = Math.max(box.top, 0), shown = Math.min(box.bottom, innerHeight) - top;
      left.scrollTop = box.top + code.offsetTop + row.offsetTop + row.offsetHeight / 2 - top - shown / 2;
    }

    // draw lays the path of the chosen finding over the file: lines in the
    // gutter between the rows of its places, and jumps to other files.
    function draw() {
      for (const old of code.querySelectorAll(".lines, .jump")) old.remove();
      for (const r of code.querySelectorAll(".row-chosen")) r.classList.remove("row-chosen");
      const rowOf = (n) => code.querySelector('.row[data-line="' + n.line + '"]');
      if (state.chosen < 0 || !files.has(state.file)) return;
      const f = items[state.chosen];
      for (const n of f.path) if (inFile(n, state.file)) rowOf(n).classList.add("row-chosen");
      const svg = document.createElementNS(SVG, "svg");
      svg.setAttribute("class", "lines");
      svg.setAttribute("width", "28");
      svg.setAttribute("height", String(code.scrollHeight));
      const mid = (r) => r.offsetTop + r.offsetHeight / 2;
      let depth = 0;
      for (const { a, b } of segments(f)) {
        const ra = inFile(a, state.file) ? rowOf(a) : null;
        const rb = inFile(b, state.file) ? rowOf(b) : null;
        if (ra && rb) {
          const x = 22 - 6 * (depth++ % 3), y1 = mid(ra), y2 = mid(rb);
          const path = document.createElementNS(SVG, "path");
          path.setAttribute("d", "M 26 " + y1 + " H " + x + " V " + y2 + " H 24");
          const head = document.createElementNS(SVG, "polygon");
          head.setAttribute("points", "28," + y2 + " 22," + (y2 - 4) + " 22," + (y2 + 4));
          svg.append(path, head);
        } else if (ra) {
          jump(ra, "→ " + b.input + ":" + b.line, b.input, b.line);
        } else if (rb) {
          jump(rb, "← " + a.input + ":" + a.line, a.input, a.line);
        }
      }
      code.appendChild(svg);
    }

    function jump(row, text, file, line) {
      const b = el("button", "jump", text);
      b.type = "button";
      if (files.has(file)) b.addEventListener("click", (e) => {
        e.stopPropagation();
        showFile(file);
        reveal(line);
      });
      else b.disabled = true;
      row.appendChild(b);
    }

    for (const f of data.files) {
      const b = el("button", null, f.input);
      b.type = "button";
      b.dataset.file = f.input;
      b.addEventListener("click", () => showFile(f.input));
      tabs.appendChild(b);
    }
    const all = el("button", null, "all files");
    all.type = "button";
    all.addEventListener("click", () => {
      state.line = 0;
      state.all = !state.all;
      all.setAttribute("aria-pressed", String(state.all));
      listCards();
    });
    scope.appendChild(all);
    const lineChip = el("button", "chip");
    lineChip.type = "button";
    lineChip.hidden = true;
    lineChip.addEventListener("click", () => {
      state.line = 0;
      listCards();
    });
    scope.appendChild(lineChip);
    sections.forEach((s, i) =>
      s.addEventListener("click", (e) => {
        if (e.target.closest("button")) return;
        choose(i, true);
      })
    );

    // the file shown first: that of the first finding
    const first = items.length ? items[0].path.find((n) => n.input && files.has(n.input)) : null;
    const start = first || null;
    showFile(start ? start.input : data.files.length ? data.files[0].input : null);
    if (items.length) choose(0, false);
    return { draw };
  }

  // The Meta of a rule (CatalogRule.meta: the registry's JSON of the rule,
  // without its examples). fields draws an object by the keys it names, in
  // their order, and then each key it does not name as its JSON, so that a
  // field the script does not know yet is still shown. Given the registry
  // path of the object, fields adds to each key the definition of its item
  // name, and to each value the definition of its value (terms: the
  // catalog's terms); a function that draws a key is given the path of the
  // key.
  let terms = null;
  const join = (v) => (typeof v === "string" ? v : Array.isArray(v) && v.every((x) => typeof x === "string") ? v.join(", ") : JSON.stringify(v));
  const child = (p, k) => (p ? p + "." + k : k);
  // frag is the strings and elements xs (nested), in a span.
  const frag = (...xs) => {
    const s = el("span");
    s.append(...xs.flat(Infinity));
    return s;
  };
  // definitionToggle makes b open and close the definition d (an item name
  // or a value: {name, text}) in a new element tag, which place puts in the
  // page.
  function definitionToggle(b, d, place, tag) {
    const text = d.name + ": " + d.text;
    b.title = text;
    b.setAttribute("aria-expanded", "false");
    let shown = null;
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      if (shown) {
        shown.remove();
        shown = null;
      } else {
        shown = el(tag, "term-def", text);
        place(shown);
      }
      b.setAttribute("aria-expanded", String(!!shown));
    });
  }
  // valueEl is the value x at the path p, a button that opens its definition
  // when it has one (of metric for the value of a CVSS metric), else text.
  function valueEl(p, x, metric) {
    const d = terms && p !== undefined && typeof x === "string" ? valueAt(terms, p, x, metric) : null;
    if (!d) return document.createTextNode(typeof x === "string" ? x : join(x));
    const b = el("button", "term-value", x);
    b.type = "button";
    definitionToggle(b, d, (x) => (b.closest("li, dd") || b.parentNode).append(x), "div");
    return b;
  }
  // valuesEl is v, a string or strings at the path p, each that has a
  // definition a button; null when none has one.
  function valuesEl(p, v) {
    const xs = Array.isArray(v) ? v : [v];
    if (!terms || p === undefined || !xs.every((x) => typeof x === "string") || !xs.some((x) => valueAt(terms, p, x))) return null;
    return frag(xs.map((x, i) => [i ? ", " : "", valueEl(p, x)]));
  }
  function cite(u) {
    if (typeof u !== "string" || !u.startsWith("https://")) return el("span", null, join(u));
    const a = el("a", null, u);
    a.href = u;
    a.rel = "noreferrer";
    return a;
  }
  function listOf(xs, f) {
    const ul = el("ul", "meta-list");
    for (const x of xs) {
      const li = el("li");
      li.append(f(x));
      ul.appendChild(li);
    }
    return ul;
  }
  const cites = (us) => listOf(us, cite);
  // fields draws o; path is its registry path, undefined for an object
  // that is no part of the meta of a rule (a row of the boundary).
  function fields(o, show, path) {
    const dl = el("dl", "meta");
    const put = (k, v) => {
      const p = path === undefined ? undefined : child(path, k);
      const dt = el("dt", null, k);
      const dd = el("dd");
      dd.append(v instanceof Node ? v : valuesEl(p, v) || join(v));
      dl.append(dt, dd);
      const d = terms && p !== undefined ? itemNameAt(terms, p) : null;
      if (!d) return;
      const b = el("button", "term-open", "?");
      b.type = "button";
      b.setAttribute("aria-label", "show or hide the definition of " + d.name);
      definitionToggle(b, d, (x) => dd.after(x), "dd");
      dt.title = d.name + ": " + d.text;
      dt.append(" ", b);
    };
    for (const [k, f] of Object.entries(show)) {
      const v = o[k];
      if (v === undefined || v === null || v === "" || (Array.isArray(v) && !v.length)) continue;
      put(k, f ? f(v, path === undefined ? undefined : child(path, k)) : v);
    }
    for (const k of Object.keys(o)) if (!Object.hasOwn(show, k)) put(k, JSON.stringify(o[k]));
    return dl;
  }
  const byID = (xs, id) => (xs || []).find((x) => x.id === id);
  const disposition = { disposition: null, rule: null, decided_by: null, needs: null };
  const score = (s, p) => frag(s.score + " (", valueEl(child(p, "rating"), s.rating), ")");
  const metric = (x, p) => fields(x, { metric: null, value: (v, q) => valueEl(q, v, x.metric), reason: null, cites }, p);
  const cvss = (c, p) => fields(c, { vector: null, b: score, bt: score, metrics: (ms, q) => listOf(ms, (x) => metric(x, q)) }, p);
  const basis = (b, p) => fields(b, { impact: (i, q) => fields(i, { level: null, from: null }, q), likelihood: (l, q) => fields(l, { level: null, from: null, lowered_by: null }, q) }, p);
  const precondition = (x, p) => fields(x, { id: null, text: null, observed: (os, q) => listOf(os, (o) => fields(o, { date: null, runner: null, what: null }, q)), cites }, p);
  // starters are the run starters of an actor at the path p: each event and
  // who starts its runs
  const starters = (rs, p) => frag(rs.map((x, i) => [i ? ", " : "", x.event + ": ", valueEl(child(p, "run_starter"), x.run_starter), x.run_starter === "other" ? " (started by others)" : ""]));
  const actor = (a, p) => fields(a, { attacker: null, via: null, events: null, run_starters: starters, gains: null }, p);
  const incident = (x, p) => fields(x, { id: null, date: null, cve: null, summary: null, advisory: cite, compromised: null, downstream: null }, p);
  const fixKind = (f, p) => fields(f, { id: null, title: null, safety: null, fact_kinds: null, possible_side_effects: (es) => listOf(es, (e) => e.id + ": " + e.text) }, p);
  const factKinds = (ks, p) => listOf(ks, (k) => frag(valueEl(child(p, "kind"), k.kind), " (" + k.provider + ")"));
  // form is an undetected form or an inconclusive kind at the path p.
  const form = (f, p) => fields(f, { id: null, text: null, ...disposition }, p);
  // kind is a kind of finding at the path p; deep, its preconditions,
  // incidents and fixes drawn from m, not their IDs alone, each at the path
  // of what it refers to.
  function kind(k, m, deep, p) {
    // a reference with no root (refRoot gives null) is drawn without
    // definitions, not under the path of the rule
    const ref = (list, draw, key) => (ids) => listOf(ids, (id) => (byID(list, id) ? draw(byID(list, id), refRoot(key) || undefined) : el("span", null, id)));
    return fields(k, {
      id: null, detected: null,
      arguments: (as) => listOf(as, (a) => "{" + a.name + "}: " + a.text + (a.in_detected ? "" : " (not in the text of detected)")),
      consequence: null, remedy: null, severity: null, severity_basis: basis, cvss, attackers: null,
      preconditions: deep ? ref(m.threat && m.threat.preconditions, precondition, "preconditions") : null,
      incidents: deep ? ref(m.threat && m.threat.incidents, incident, "incidents") : null,
      fixes: deep ? ref(m.fix_kinds, fixKind, "fixes") : null,
      fact_kinds: null,
    }, p);
  }
  // falsePositive is a false positive form at the path p; deep, its kinds
  // with what each detects.
  function falsePositive(f, m, deep, p) {
    return fields(f, {
      id: null, text: null,
      finding_kinds: deep ? (ids) => listOf(ids, (id) => id + (byID(m.finding_kinds, id) ? ": " + byID(m.finding_kinds, id).detected : "")) : null,
      ...disposition, fact_kinds: factKinds,
    }, p);
  }
  const threat = (t, p) => fields(t, { preconditions: (ps, q) => listOf(ps, (x) => precondition(x, q)), actors: (as, q) => listOf(as, (a) => actor(a, q)), incidents: (xs, q) => listOf(xs, (x) => incident(x, q)) }, p);
  // ruleMeta is all of m, the Meta of a rule or of a quality rule
  // (quality), in the order of --explain.
  function ruleMeta(m, quality) {
    const v = el("div", "meta-rule");
    const h = el("h2", null, quality ? "quality rule " : "rule ");
    h.appendChild(el("code", null, m.id));
    v.appendChild(h);
    v.appendChild(fields(m, {
      id: null, problem: null, expected: null,
      facets: (f, p) => fields(f, Object.fromEntries(Object.keys(f).map((k) => [k, null])), p),
      severity: null, targets: null, default_run: null, default_run_fact_kinds: null,
      finding_kinds: (ks, p) => listOf(ks, (k) => kind(k, m, false, p)),
      fix_kinds: (fs, p) => listOf(fs, (f) => fixKind(f, p)),
      undetected_forms: (fs, p) => listOf(fs, (f) => form(f, p)),
      inconclusive_kinds: (fs, p) => listOf(fs, (f) => form(f, p)),
      false_positive_forms: (fs, p) => listOf(fs, (f) => falsePositive(f, m, false, p)),
      threat, citations: cites,
    }, ""));
    return v;
  }
  // declaration is what m says of the declaration of the entry e, or null
  // when m has no such declaration.
  function declaration(e, m) {
    if (!m) return null;
    switch (e.what) {
      case "true-positive":
      case "true-negative": {
        const k = byID(m.finding_kinds, e.id);
        return k ? kind(k, m, true, "finding_kinds") : null;
      }
      case "false-positive": {
        const f = byID(m.false_positive_forms, e.id);
        return f ? falsePositive(f, m, true, "false_positive_forms") : null;
      }
      case "undetected": {
        const f = byID(m.undetected_forms, e.id);
        return f ? form(f, "undetected_forms") : null;
      }
      case "inconclusive": {
        const f = byID(m.inconclusive_kinds, e.id);
        return f ? form(f, "inconclusive_kinds") : null;
      }
    }
    return null;
  }
  // termsPage is the terms, with the headings and in the order of
  // --explain=terms.
  function termsPage() {
    const d = terms.definitions;
    const v = el("div", "terms");
    const list = (xs) => {
      const dl = el("dl", "term-list");
      for (const x of xs) {
        const dd = el("dd", null, x.text);
        // the items under the text (the symbols and the formulas of the
        // credential premise), one to an item of a list
        if (x.items && x.items.length) {
          const ul = el("ul", "term-items");
          for (const it of x.items) ul.append(el("li", null, it));
          dd.append(ul);
        }
        dl.append(el("dt", null, x.name), dd);
      }
      return dl;
    };
    v.append(el("h2", null, "item names"), el("p", null, d.item_names_description), list(d.item_names));
    v.append(el("h2", null, "words in the texts"), list(d.text_terms));
    v.append(el("h2", null, "values"));
    let cvssShown = false;
    for (const g of d.value_groups) {
      if (g.cvss) {
        if (!cvssShown) v.append(el("h3", null, "CVSS"));
        cvssShown = true;
        v.append(el("h4", null, g.heading + ": " + g.description));
      } else {
        v.append(el("h3", null, g.heading));
        if (g.description) v.append(el("p", null, g.description));
      }
      v.append(list(g.values));
    }
    return v;
  }

  // catalog lays out the examples of every rule: a table of contents of the
  // declarations on the left, and the page of the example chosen.
  function catalog(cat) {
    terms = cat.terms;
    const abbr = { "true-positive": "TP", "true-negative": "TN", "false-positive": "FP", undetected: "UD", inconclusive: "IC" };
    const wrap = el("div", "catalog");
    const toc = el("nav", "toc");
    const view = el("div", "entry");
    wrap.append(toc, view);
    app.appendChild(wrap);
    const failing = el("button", null, "✗ only");
    failing.type = "button";
    toc.appendChild(failing);
    const unseen = el("button", null, "unreviewed only");
    unseen.type = "button";
    toc.appendChild(unseen);
    // group by: the rules in their order, or grouped by an axis of the
    // facets (groupRules); layout draws them.
    const groupBox = el("div", "group-by");
    groupBox.appendChild(el("span", null, "group by"));
    const groupButtons = [];
    for (const f of [null, ...(cat.facets || [])]) {
      const name = f ? f.facet : "none";
      const gb = el("button", null, name);
      gb.type = "button";
      if (f) gb.title = f.description;
      gb.addEventListener("click", () => layout(name));
      groupBox.appendChild(gb);
      groupButtons.push({ gb, name });
    }
    toc.appendChild(groupBox);
    // The boundary: the facts the viewer chooses, shared by the explorer
    // and the boundary of each rule.
    const B = cat.boundary;
    const choice = {}; // fact kind → "t", "f" or "u"
    const keyOf = (cell) => cell.facts.map((k) => choice[k] || "u").join("");
    const valueOf = (cell) => (cell ? cell.values[keyOf(cell)] : null);
    const basisRank = { unverified: 0, documented: 1, observed: 2 };
    // refLabel is a run "<event> <head>" for people: the event alone when it
    // is of no pull request, and where the pull request comes from.
    const headLabels = { fork: " — PR from a fork", repository: " — PR from a branch of the repository", none: "" };
    const refLabel = (ref) => { const [e, h] = ref.split(" "); return e + (headLabels[h] || ""); };
    const weakest = (...bs) => bs.filter(Boolean).sort((a, b) => basisRank[a] - basisRank[b])[0] || "unverified";
    // pathwayAttackers are the attackers with no event, who reach a run
    // by a pathway (an artifact, a log, code a job runs, what a job sends)
    // and not by a channel.
    const pathwayAttackers = new Set(B.pathway_rows.map((r) => r.attacker));
    // crossing is what one of role gets of each gain in a run of ref when
    // they write what attacker writes, or take the pathway of attacker to
    // the run (way); through is whether they can.
    function crossing(attacker, role, ref) {
      const way = pathwayAttackers.has(attacker) ? "pathway" : "channel";
      const ch = valueOf((way === "pathway" ? B.pathway_cells : B.channel_cells)[attacker + " " + role]);
      const run = valueOf(B.runs[ref]);
      const held = valueOf(B.roles[role]);
      // the author of a pull request from a fork writes none from a branch
      const through = way === "channel" && B.unreachable.includes(attacker + " " + ref.split(" ")[1]) ? "false" : ch ? (way === "pathway" ? ch.usable : ch.writable) : "unknown";
      const out = { way, through, basis: weakest(ch && ch.basis, run ? run.basis : "unverified", held ? held.basis : "unverified"), gains: {} };
      for (const g of B.gains) {
        const v = run ? run.dims[g] : "unknown";
        const h = held ? held.dims[g] : "unknown";
        out.gains[g] = { run: v, held: h, crossing: B.crossings[v][h] };
      }
      return out;
    }
    // needs is what a run holds that the gain g needs, for people.
    const needs = (g) => B.holding_texts[B.gain_holdings[g]];
    const gainLabel = (g) => g + " — needs " + needs(g);
    const noChannelText = "in this table, one of this role cannot write what the attacker writes for the run to read (an issue, a comment, a pull request), so one of this role gains nothing by the channel";
    const noPathwayText = "in this table, one of this role cannot take the pathway of the attacker to the run (download an artifact of the run, view the log of the run, have code run in a job of the run, receive what a job of the run sends), so one of this role gains nothing by the pathway";
    // blocked is what a cell shows where one of the role cannot write what
    // the attacker writes, or cannot take the pathway of the attacker to the
    // run; blockedText says what it means.
    const blocked = (x) => (x.way === "pathway" ? "no pathway" : "no channel");
    // stateKey is the name, in the JSON of the state, of whether one of the
    // role can: writable of a channel, usable of a pathway, as the catalog
    // names them.
    const stateKey = (x) => (x.way === "pathway" ? "usable" : "writable");
    const blockedText = (x) => (x.way === "pathway" ? noPathwayText : noChannelText);
    // legend says what each crossing means and what to do of it, and what a
    // dotted line and no effect mean.
    function legend() {
      const dl = el("dl", "boundary-legend");
      for (const c of ["by-workflow", "by-baseline", "none", "unknown"]) dl.append(el("dt", "crossing-" + c, c), el("dd", null, B.crossing_texts[c]));
      dl.append(el("dt", "crossing-no-channel", "no channel"), el("dd", null, noChannelText));
      dl.append(el("dt", "crossing-no-pathway", "no pathway"), el("dd", null, noPathwayText));
      dl.append(el("dt", null, "a dotted line, no effect here"), el("dd", null, "that fact alone, the other facts staying, changes neither the row nor a cell of this page; it may when another fact changes with it"));
      return dl;
    }
    const letter = (k) => choice[k] || "u";
    const truthOf = { t: "true", f: "false", u: "unknown" };
    // tv is a truth, true, false or unknown, as a colored tag; kv, a name
    // and its truth.
    const tv = (v) => el("span", "tv tv-" + v, v);
    const kv = (k, v) => [k + ": ", tv(v)];
    // keyWith is the key of the facts fs as chosen, with the fact k as l.
    const keyWith = (fs, k, l) => fs.map((f) => (f === k ? l : letter(f))).join("");
    // rowTruth is whether the condition of the row r holds, as chosen.
    const rowTruth = (r) => r.holds[r.facts.map(letter).join("")];
    // effective is whether another truth of the fact k alone changes what
    // shown gives.
    function effective(k, shown) {
      const was = choice[k];
      const before = JSON.stringify(shown());
      let changes = false;
      for (const l of ["t", "f", "u"]) {
        if (l === (was || "u")) continue;
        choice[k] = l;
        if (JSON.stringify(shown()) !== before) changes = true;
      }
      if (was === undefined) delete choice[k];
      else choice[k] = was;
      return changes;
    }
    // cellClass is the class of a cell that shows s.
    const cellClass = (s) => "crossing-" + s.replace("?", "").replace(" ", "-");
    // later calls f once the graph is in the page, and again when the
    // window changes its size.
    let redraw = null;
    addEventListener("resize", () => redraw && redraw());
    const later = (f) => { redraw = f; requestAnimationFrame(f); };
    const starterLabel = (st) => (st === "none" ? "the attacker starts no run" : st === "other" ? "started by others: what the attacker writes reaches it" : st === "attacker" ? "started by the attacker" : "who starts it is not declared");
    // wayText is what an attacker with no event does to a run of the
    // workflow: the pathway of the attacker.
    const wayText = {
      "artifact-reader": (a) => a + " downloads an artifact of a run of the workflow",
      "log-reader": (a) => a + " views the log of a run of the workflow",
      "maintainer-of-called": (a) => a + " controls the code of an action or a reusable workflow that a job of a run of the workflow calls, and the job runs that code",
      "forker-of-called": (a) => a + " pushes a commit to a fork of the repository of an action, and a job of a run of the workflow runs that commit",
      "image-publisher": (a) => a + " pushes an image under the tag that a job of a run of the workflow names, and the job runs that image",
      "advisory-attacker": (a) => a + " exploits a vulnerability of an action that a job of a run of the workflow runs",
      "destination-holder": (a) => a + " runs a server that a job of a run of the workflow sends requests to, and receives what the job sends",
    };
    const noEventText = (a) => a + " starts no run. " + (wayText[a] ? wayText[a](a) : a + " takes another pathway to a run of the workflow") + ". The on key of the workflow decides which runs there are, so each table below is for one group of runs, and the runs in one group give the same things that the gains depend on (the repository's secrets, a GITHUB_TOKEN that may write, a cache of the default branch). Where a cell is by-workflow, one of that role gets what the finding of the rule says that the run gives." + (leftText[a] || "");
    // leftText is, of an attacker who reads what a run leaves, that the run
    // leaves less than the run holds.
    const leftText = {
      "artifact-reader": " An artifact holds only what the finding of the rule names, not everything that the run holds.",
      "log-reader": " A log holds only what the finding of the rule names, not everything that the run holds.",
    };
    // outsider is whether one of any role can use the pathway of a, whatever
    // the facts: one outside the repository. The attacker of an advisory,
    // whose rows are not known, is not one.
    const outsider = (a) => B.pathway_rows.filter((r) => r.attacker === a).every((r) => !r.facts.length && r.usable === "true");
    const outsiderText = (a) => "Usually " + a + " has no role in the repository whose files are given to the linter (the column none). A column of another role is for the case where " + a + " also has that role in that repository.";
    // holdingKey is the key of B.run_groups of the gains gs: the holdings
    // they need, each once, in the order of B.holding_order.
    const holdingKey = (gs) => B.holding_order.filter((h) => gs.some((g) => B.gain_holdings[g] === h)).join(",");
    const allFacts = [...new Set([...Object.values(B.runs), ...Object.values(B.roles), ...Object.values(B.channel_cells), ...Object.values(B.pathway_cells)].flatMap((c) => c.facts))].sort();
    // factPanel is the buttons of every fact, true, false or unknown; with
    // shown, a fact that alone changes nothing shown is marked no effect.
    function factPanel(changed, shown) {
      const ul = el("ul", "facts");
      for (const k of allFacts) {
        const idle = shown ? !effective(k, shown) : false;
        const li = el("li", idle ? "no-effect" : null);
        li.appendChild(el("code", null, k));
        for (const [l, name] of [["t", "true"], ["f", "false"], ["u", "unknown"]]) {
          const b = el("button", "truth", name);
          b.type = "button";
          b.setAttribute("aria-pressed", String(letter(k) === l));
          b.addEventListener("click", () => {
            choice[k] = l;
            changed();
          });
          li.appendChild(b);
        }
        if (idle) li.appendChild(el("span", "no-effect-note", "no effect here"));
        ul.appendChild(li);
      }
      return ul;
    }
    const noEffect = (shown) => allFacts.filter((k) => !effective(k, shown));
    // factState is every fact the tables read, with what the viewer chose.
    const factState = () => Object.fromEntries(allFacts.map((k) => [k, { t: "true", f: "false", u: "unknown" }[choice[k] || "u"]]));
    // copyButton copies what state gives, as JSON, for a report of a bug;
    // where the clipboard is refused, it shows the JSON to copy by hand.
    function copyButton(state) {
      const wrap = el("span", "boundary-copy");
      const b = el("button", null, "copy state as JSON");
      b.type = "button";
      b.addEventListener("click", async () => {
        const text = JSON.stringify(state(), null, 2);
        try {
          await navigator.clipboard.writeText(text);
          b.textContent = "copied";
          setTimeout(() => { b.textContent = "copy state as JSON"; }, 1500);
        } catch {
          const ta = el("textarea");
          ta.value = text;
          ta.readOnly = true;
          ta.rows = 12;
          wrap.replaceChildren(b, ta);
          ta.select();
        }
      });
      wrap.appendChild(b);
      return wrap;
    }
    // groundsShow draws the grounds of a row: fields draws a key it is not
    // given as JSON, so a row is drawn by one call with these keys too.
    const groundsShow = {
      basis: null, uncertainty: null,
      quotes: (qs) => listOf(qs, (q) => { const d = el("div"); d.append(el("q", null, q.text), " ", cite(q.citation), " (" + q.retrieved + ")"); return d; }),
      observed: (os) => listOf(os, (o) => [o.date, o.runner, o.what].filter(Boolean).join(" — ")),
    };
    const bare = ({ holds, ...r }) => r;
    const rowView = (r, show) => { const d = el("div", "boundary-row"); d.append(fields(bare(r), { ...show, ...groundsShow, facts: null })); return d; };
    // conditionText is a condition of a row (lint.Condition as JSON) for
    // people: and, or, a fact equal to a value, a fact absent; always for
    // the condition that always holds.
    function conditionText(c, nested) {
      if (c.all || c.any) {
        const parts = c.all || c.any;
        if (!parts.length) return c.all ? "always" : "never";
        const t = parts.map((p) => conditionText(p, true)).join(c.all ? " and " : " or ");
        return nested && parts.length > 1 ? "(" + t + ")" : t;
      }
      if (c.query) {
        const { kind, ...args } = c.query;
        const name = kind + (Object.keys(args).length ? "[" + Object.entries(args).map(([k, v]) => k + "=" + v).join(",") + "]" : "");
        return c.absent ? name + " is absent" : name + " = " + JSON.stringify(c.eq);
      }
      if (c.input) return "the input " + c.input + " is present";
      return JSON.stringify(c);
    }
    const headDesc = { fork: "a pull request from a fork", repository: "a pull request from a branch of the repository", none: "no pull request" };
    const grantShow = { event: null, head: (h) => headDesc[h] || h, condition: (c) => conditionText(c), token: null, cache: null, secrets: null };
    const baselineShow = { role: null, condition: (c) => conditionText(c), runs: (rs) => rs.map(refLabel).join(", "), self_hosted_runner: null };
    const channelShow = { attacker: null, role: null, condition: (c) => conditionText(c), writable: null };
    const pathwayShow = { attacker: null, role: null, condition: (c) => conditionText(c), usable: null };
    // throughLine is, of one of role and the attacker a, whether they can
    // write what a writes or take the pathway of a to the run, for people.
    const throughLine = (x, a) => (x.way === "pathway" ? "can take the pathway of " + a + " to the run: " : "can write what " + a + " writes: ") + x.through;
    // wayRows are the rows of a and role that say whether they can: channel
    // rows, or pathway rows for an attacker with no event.
    const wayRows = (a, role) => (pathwayAttackers.has(a) ? B.pathway_rows : B.channel_rows).filter((c) => c.attacker === a && c.role === role);
    // explorer is the page of one attacker, role, event and head.
    function explorer() {
      const v = el("div", "boundary");
      const attackers = [...new Set([...B.channel_rows, ...B.pathway_rows].map((c) => c.attacker))];
      const roles = B.role_order;
      const refs = Object.keys(B.runs).sort();
      const state = { attacker: attackers[0], role: roles[0], ref: refs[0] };
      const pick = (name, xs, k, label = (x) => x) => {
        const s = el("select");
        s.setAttribute("aria-label", name);
        for (const x of xs) {
          const o = el("option", null, label(x));
          o.value = x;
          o.selected = x === state[k];
          s.appendChild(o);
        }
        s.addEventListener("change", () => { state[k] = s.value; draw(); });
        const l = el("label", null, name + " ");
        l.appendChild(s);
        return l;
      };
      const out = el("div");
      let last = null;
      function draw() {
        out.replaceChildren();
        const shown = () => { const x = crossing(state.attacker, state.role, state.ref); return [x.through, B.gains.map((g) => x.gains[g].crossing)]; };
        out.appendChild(factPanel(draw, shown));
        out.appendChild(legend());
        const x = crossing(state.attacker, state.role, state.ref);
        const [ev, hd] = state.ref.split(" ");
        last = {
          page: "boundary", attacker: state.attacker, role: state.role, run: state.ref, run_label: refLabel(state.ref), facts: factState(), no_effect: noEffect(shown),
          way: x.way, [stateKey(x)]: x.through, basis: x.basis,
          gains: Object.fromEntries(B.gains.map((g) => [g, { ...x.gains[g], needs: B.gain_holdings[g], shown: x.through === "false" ? blocked(x) : x.gains[g].crossing }])),
          rows: {
            grants: B.grants.filter((g) => g.event === ev && g.head === hd).map(bare),
            baselines: B.baselines.filter((r) => r.role === state.role).map(bare),
            [x.way === "pathway" ? "pathways" : "channels"]: wayRows(state.attacker, state.role).map(bare),
          },
          graph: null,
        };
        out.appendChild(el("p", "boundary-channel", throughLine(x, state.attacker) + " · basis: " + x.basis + " · the token is the most a workflow may ask for (permissions:), and a role holds what it holds with no branch protection, ruleset or environment reviewers (write and above may hold less)"));
        // the table is always drawn: when the role cannot write what the
        // attacker writes, or take the pathway of the attacker to the run,
        // every gain is no channel or no pathway, and the line says why
        if (x.through === "false") out.appendChild(el("p", "boundary-outside", x.way === "pathway" ? "In the run " + refLabel(state.ref) + ", one of this role cannot take the pathway of " + state.attacker + " to the run, so one of this role gains nothing by the pathway: every gain is no pathway." : "In the run " + refLabel(state.ref) + ", one of this role cannot write what " + state.attacker + " writes, so one of this role gains nothing by the channel: every gain is no channel."));
        const tb = el("table", "boundary-table");
        const hr = el("tr");
        for (const h of ["gain", "the run holds it", "one of the role holds it", "crossing"]) hr.appendChild(el("th", null, h));
        tb.appendChild(hr);
        for (const g of B.gains) {
          const tr = el("tr");
          const c = x.gains[g];
          const cr = x.through === "false" ? blocked(x) : c.crossing;
          for (const t of [gainLabel(g), c.run, c.held, cr]) tr.appendChild(el("td", null, t));
          tr.lastChild.className = cellClass(cr);
          tb.appendChild(tr);
        }
        out.appendChild(tb);
        const gr = graph(state.attacker, state.role, state.ref, B.gains);
        out.appendChild(gr.el);
        last.graph = gr.state;
        later(gr.draw);
        const sec = (title, rows, show) => { const d = el("details"); d.append(el("summary", null, title + " (" + rows.length + ")"), ...rows.map((r) => rowView(r, show))); out.appendChild(d); };
        sec("run grants of " + refLabel(state.ref), B.grants.filter((g) => g.event === ev && g.head === hd), grantShow);
        sec("baselines of " + state.role, B.baselines.filter((b) => b.role === state.role), baselineShow);
        if (x.way === "pathway") sec("pathways of " + state.attacker + " " + state.role, wayRows(state.attacker, state.role), pathwayShow);
        else sec("channels of " + state.attacker + " " + state.role, wayRows(state.attacker, state.role), channelShow);
      }
      v.append(el("h2", null, "boundary"), copyButton(() => last), pick("attacker", attackers, "attacker"), pick("role", roles, "role"), pick("run", refs, "ref", refLabel), out);
      draw();
      return v;
    }
    // rowsPage is every row, filtered by basis.
    function rowsPage() {
      const v = el("div", "boundary");
      let only = "";
      const out = el("div");
      function draw() {
        out.replaceChildren();
        const keep = (r) => !only || r.basis === only;
        for (const [title, rows, show] of [["run grants", B.grants, grantShow], ["baselines", B.baselines, baselineShow], ["channels", B.channel_rows, channelShow], ["pathways", B.pathway_rows, pathwayShow]]) {
          out.appendChild(el("h3", null, title));
          for (const r of rows.filter(keep)) out.appendChild(rowView(r, show));
        }
      }
      const bar = el("div");
      for (const b of ["", "unverified", "documented", "observed"]) {
        const x = el("button", null, b || "all");
        x.type = "button";
        x.addEventListener("click", () => { only = b; draw(); });
        bar.appendChild(x);
      }
      v.append(el("h2", null, "boundary rows"), bar, out);
      draw();
      return v;
    }
    // graph draws, for one of role who writes what attacker writes, in a
    // run of ref, how the facts decide the gains gs, in four columns: the
    // facts as chosen; the rows whose conditions read them, with their
    // truth; what the run and the role hold and whether the role can write
    // it; and each gain, what it needs, and its crossing. A line from a
    // fact is dotted where that fact alone, the other facts staying, does
    // not change the row. draw lays the lines; it is called once the graph
    // is in the page.
    // othersText names the other runs of a group, with the basis of each.
    const othersText = (others) => (others.length ? "these runs give the same things that the gains depend on: " + others.map((o) => refLabel(o) + " (basis " + ((valueOf(B.runs[o]) || {}).basis || "unverified") + ")").join(", ") : "");
    // For a table of a group of runs, others are the other runs of the
    // group: the graph draws ref, the first, and names them.
    function graph(attacker, role, ref, gs, others = []) {
      const [event, head] = ref.split(" ");
      const rows = [
        ...B.grants.filter((g) => g.event === event && g.head === head).map((r) => ({ r, to: "run", title: "run grant", text: "token " + r.token + ", cache " + r.cache + ", secrets " + r.secrets })),
        ...B.baselines.filter((b) => b.role === role).map((r) => ({ r, to: "role", title: "baseline of " + role, text: "own runs: " + (r.runs.map(refLabel).join(", ") || "none"), more: kv("self-hosted runner", r.self_hosted_runner) })),
        ...wayRows(attacker, role).map((r) => (pathwayAttackers.has(attacker) ? { r, to: "channel", title: "pathway", text: "", more: kv("usable", r.usable) } : { r, to: "channel", title: "channel", text: "", more: kv("can write", String(r.writable)) })),
      ];
      // the runs of their own that one of role holds things in: the role
      // holds what the grants of these runs give
      const own = [...new Set(B.baselines.filter((b) => b.role === role).flatMap((b) => b.runs))];
      for (const o of own) {
        const [e, h] = o.split(" ");
        for (const r of B.grants.filter((g) => g.event === e && g.head === h)) rows.push({ r, to: "role", title: "run grant of their own run, " + refLabel(o), text: "token " + r.token + ", cache " + r.cache + ", secrets " + r.secrets });
      }
      const x = crossing(attacker, role, ref);
      const run = valueOf(B.runs[ref]);
      const held = valueOf(B.roles[role]);
      const scroll = el("div", "graph-scroll");
      const wrap = el("div", "graph");
      scroll.appendChild(wrap);
      const cols = [0, 1, 2, 3].map(() => el("div", "graph-col"));
      wrap.append(...cols);
      // a title or a line is a string, or a list of strings and elements
      const line = (cls, l) => { const d = el("div", cls); d.append(...(Array.isArray(l) ? l : [l])); return d; };
      const node = (col, cls, title, lines) => {
        const n = el("div", "graph-node" + (cls ? " " + cls : ""));
        n.appendChild(line("node-title", title));
        for (const l of lines) if (l !== "") n.appendChild(line(null, l));
        cols[col].appendChild(n);
        return n;
      };
      const state = { attacker, role, run: ref, facts: {}, rows: [], run_has: run ? { ran: run.ran, ...run.has } : null, role_has: held ? { ...held.has } : null, way: x.way, [stateKey(x)]: x.through, others, gains: {} };
      const factNode = {};
      for (const k of [...new Set(rows.flatMap(({ r }) => r.facts))].sort()) {
        state.facts[k] = truthOf[letter(k)];
        factNode[k] = node(0, null, "fact", [[k + " = ", tv(state.facts[k])]]);
      }
      const sinks = {
        run: node(2, null, "the run: " + refLabel(ref), run ? [kv("runs", run.ran), kv("write-token", run.has["write-token"]), kv("secrets", run.has.secrets), kv("write-cache", run.has["write-cache"]), othersText(others)] : [["no run grant ", tv("unknown")]]),
        role: node(2, null, "one of " + role + ", in runs of their own", held ? [kv("write-token", held.has["write-token"]), kv("secrets", held.has.secrets), kv("write-cache", held.has["write-cache"]), kv("self-hosted-runner", held.has["self-hosted-runner"]), ...own.filter((o) => B.runs[o]).map((o) => { const v = valueOf(B.runs[o]); return [refLabel(o) + " — ", ...kv("write-token", v.has["write-token"]), ", ", ...kv("secrets", v.has.secrets), ", ", ...kv("write-cache", v.has["write-cache"])]; })] : [["no baseline ", tv("unknown")]]),
        channel: node(2, null, x.way === "pathway" ? "can take the pathway of " + attacker + " to the run" : "can write what " + attacker + " writes", [[tv(x.through)]]),
      };
      const edges = [];
      for (const { r, to, title, text, more } of rows) {
        const truth = rowTruth(r);
        const n = node(1, "row-" + truth, [title + " — ", tv(truth)], [text, more || "", "if " + conditionText(r.condition)]);
        state.rows.push({ row: title, text: [text, more ? more[0] + more[1].textContent : ""].filter(Boolean).join(" "), condition: conditionText(r.condition), holds: truth });
        for (const k of r.facts) {
          const now = r.holds[keyWith(r.facts, k, letter(k))];
          const dead = ["t", "f", "u"].every((l) => r.holds[keyWith(r.facts, k, l)] === now);
          edges.push({ a: factNode[k], b: n, dead });
        }
        if (truth !== "false") edges.push({ a: n, b: sinks[to] });
      }
      for (const g of gs) {
        const c = x.gains[g];
        const shown = x.through === "false" ? blocked(x) : c.crossing;
        const words = x.through === "false" ? blockedText(x) : B.crossing_texts[c.crossing];
        const n = node(3, cellClass(shown), g, ["needs " + needs(g), kv("the run holds it", c.run), kv("one of " + role + " holds it", c.held), shown + (x.through === "unknown" ? "?" : "") + ": " + words]);
        state.gains[g] = { needs: B.gain_holdings[g], run: c.run, held: c.held, shown };
        edges.push({ a: sinks.run, b: n }, { a: sinks.role, b: n }, { a: sinks.channel, b: n });
      }
      function draw() {
        for (const old of wrap.querySelectorAll(".graph-lines")) old.remove();
        const svg = document.createElementNS(SVG, "svg");
        svg.setAttribute("class", "graph-lines");
        svg.setAttribute("width", String(wrap.scrollWidth));
        svg.setAttribute("height", String(wrap.scrollHeight));
        for (const { a, b, dead } of edges) {
          const x1 = a.offsetLeft + a.offsetWidth, y1 = a.offsetTop + a.offsetHeight / 2;
          const x2 = b.offsetLeft, y2 = b.offsetTop + b.offsetHeight / 2;
          const mx = (x1 + x2) / 2;
          const p = document.createElementNS(SVG, "path");
          p.setAttribute("d", "M " + x1 + " " + y1 + " C " + mx + " " + y1 + ", " + mx + " " + y2 + ", " + x2 + " " + y2);
          if (dead) p.setAttribute("class", "dead");
          svg.appendChild(p);
        }
        wrap.appendChild(svg);
      }
      return { el: scroll, state, draw };
    }
    // ruleTables is the boundary of the rule m as the page shows it: in
    // the order of its actors and events, a table of each run an actor's
    // event starts or reaches, and a line where there is none.
    // cellsOf are the cells of a table of the actor a in a run of ref, the
    // weakest basis of runs too: the runs of a group hold alike what the
    // gains need, so their crossings are those of ref.
    function cellsOf(a, ref, runs = [ref]) {
      const cells = {};
      for (const g of a.gains.filter((g) => B.gains.includes(g))) {
        cells[g] = {};
        for (const role of B.role_order) {
          const x = crossing(a.attacker, role, ref);
          // a cell whose channel or pathway is not known shows what one
          // gets if they can, marked with ?
          const c = x.through === "false" ? blocked(x) : x.gains[g].crossing;
          const basis = weakest(x.basis, ...runs.map((r) => (valueOf(B.runs[r]) || {}).basis || "unverified"));
          cells[g][role] = { shown: c + (x.through === "unknown" ? "?" : ""), way: x.way, [stateKey(x)]: x.through, run: x.gains[g].run, held: x.gains[g].held, crossing: x.gains[g].crossing, basis };
        }
      }
      return cells;
    }
    function ruleTables(m) {
      const items = [];
      for (const a of (m.threat && m.threat.actors) || []) {
        if (!a.events || !a.events.length) {
          const key = holdingKey(a.gains);
          if (!key) {
            items.push({ line: a.attacker + ": " + a.gains.join(", ") + " — the tables have no row for this gain: the gain is an account of a registry, and the attacker uses the account outside any run of the workflow" });
            continue;
          }
          items.push({ line: noEventText(a.attacker) });
          if (outsider(a.attacker)) items.push({ line: outsiderText(a.attacker) });
          for (const runs of B.run_groups[key] || []) {
            items.push({ table: { attacker: a.attacker, run: runs[0], runs, run_label: runs.map(refLabel).join(", "), run_starter: "none", cells: cellsOf(a, runs[0], runs) } });
          }
          continue;
        }
        for (const e of a.events) {
          for (const ref of Object.keys(B.runs).filter((r) => r.split(" ")[0] === e)) {
            if (B.unreachable.includes(a.attacker + " " + ref.split(" ")[1])) {
              // a table of no channel in every cell says nothing: one line
              items.push({ line: a.attacker + " · " + refLabel(ref) + ": " + a.attacker + " does not write this (no channel for any role)" });
              continue;
            }
            // who starts the run: the attacker, or another or a schedule,
            // which what the attacker writes reaches
            const st = ((a.run_starters || []).find((x) => x.event === e) || {}).run_starter || "unknown";
            items.push({ table: { attacker: a.attacker, run: ref, run_label: refLabel(ref), run_starter: st, cells: cellsOf(a, ref) } });
          }
          if (!Object.keys(B.runs).some((r) => r.split(" ")[0] === e)) items.push({ line: a.attacker + " · " + e + ": no run grant (unverified)" });
        }
      }
      return items;
    }
    // shownOf is what every cell of the items shows.
    const shownOf = (items) => items.filter((i) => i.table).map((i) => Object.values(i.table.cells).map((rs) => Object.values(rs).map((c) => c.shown)));
    // ruleBoundary is the boundary of each actor of the rule m.
    function ruleBoundary(m) {
      const v = el("section", "boundary");
      v.appendChild(el("h2", null, "boundary"));
      v.appendChild(copyButton(() => last));
      v.appendChild(el("p", "boundary-note", "One table for each actor of the rule, each event that the actor acts on, and, for a pull request event, each place the pull request comes from (a fork, a branch of the repository). An actor with no event has one table for each group of runs of the workflow; the runs in one group give the same things that the gains of the actor depend on. An event with no run grant has no table, and a line names the event. A cell is no channel where one of that role cannot write what the actor writes for the run to read (an issue, a comment, a pull request), and no pathway where one of that role cannot take the pathway of the actor to the run (download an artifact of the run, view the log of the run, have code run in a job of the run). A cell ends with ? (for example, by-workflow?) where whether one of that role can write or take the pathway is not known; the cell then shows the crossing for the case where one of that role can. Choose a cell, or a role, to see below the table how the facts decide the cell."));
      v.appendChild(el("p", "boundary-note", "The token is the most a workflow may ask for (permissions:). A role holds what it holds with no branch protection, ruleset or environment reviewers: where they are, write and above may hold less, and by-baseline may be by-workflow."));
      const out = el("div");
      let last = null;
      // sel is the cell chosen: an attacker, a run, a role, and a gain, or
      // no gain when the role is chosen; it stays when a fact changes
      const sel = { attacker: null, run: null, role: null, gain: null };
      const pick = (t, role, g, text) => {
        const b = el("button", "pick", text);
        b.type = "button";
        b.setAttribute("aria-pressed", String(sel.attacker === t.attacker && sel.run === t.run && sel.role === role && sel.gain === g));
        b.addEventListener("click", () => { Object.assign(sel, { attacker: t.attacker, run: t.run, role, gain: g }); draw(); });
        return b;
      };
      function draw() {
        out.replaceChildren();
        const shown = () => shownOf(ruleTables(m));
        out.appendChild(factPanel(draw, shown));
        out.appendChild(legend());
        last = { page: "rule boundary", rule: m.id, facts: factState(), no_effect: noEffect(shown), selected: sel.attacker ? { ...sel } : null, tables: [], lines: [], graph: null };
        for (const it of ruleTables(m)) {
          if (it.line) {
            out.appendChild(el("p", "boundary-outside", it.line));
            last.lines.push(it.line);
            continue;
          }
          const t = it.table;
          last.tables.push(t);
          out.appendChild(el("h3", null, t.attacker + " · " + t.run_label + " — " + starterLabel(t.run_starter)));
          const tb = el("table", "boundary-table");
          const hr = el("tr");
          hr.appendChild(el("th", null, "gain"));
          for (const role of B.role_order) {
            const th = el("th");
            th.appendChild(pick(t, role, null, role));
            hr.appendChild(th);
          }
          tb.appendChild(hr);
          for (const [g, byRole] of Object.entries(t.cells)) {
            const tr = el("tr");
            tr.appendChild(el("td", null, gainLabel(g)));
            for (const role of B.role_order) {
              const c = byRole[role];
              const td = el("td", cellClass(c.shown));
              const b = pick(t, role, g, c.shown);
              b.title = "basis: " + c.basis + (c[stateKey(c)] === "unknown" ? (c.way === "pathway" ? " · whether one of this role can take the pathway of " + t.attacker + " to the run is not known" : " · whether this role can write what " + t.attacker + " writes is not known") : "");
              td.appendChild(b);
              tr.appendChild(td);
            }
            tb.appendChild(tr);
          }
          out.appendChild(tb);
          if (sel.attacker === t.attacker && sel.run === t.run) {
            const gr = graph(t.attacker, sel.role, t.run, sel.gain ? [sel.gain] : Object.keys(t.cells), (t.runs || []).slice(1));
            out.appendChild(gr.el);
            last.graph = gr.state;
            later(gr.draw);
          }
        }
      }
      v.appendChild(out);
      draw();
      return v;
    }
    // advisoriesPage is the index of the advisories (the catalog's
    // advisories): for each page of an advisory, the examples whose form
    // is the form of the advisory; a button opens the example.
    function advisoriesPage() {
      const v = el("div", "advisories");
      v.appendChild(el("h2", null, "advisories"));
      v.appendChild(el("p", "boundary-note", "Each row is the page of an advisory, and the examples that reproduce the steps of the workflow of the advisory. An example has only the steps on which the harm of the advisory depends: a row shows what each rule reports on those steps, not on the whole workflow."));
      const tb = el("table", "advisory-table");
      for (const a of cat.advisories || []) {
        const tr = el("tr");
        const th = el("th");
        const link = el("a", null, a.id);
        link.href = a.url;
        link.rel = "noreferrer";
        th.appendChild(link);
        const td = el("td");
        for (const x of a.entries) {
          const b = el("button", "toc-entry " + (x.holds ? "holds" : "fails"));
          b.type = "button";
          b.append(el("span", "what what-" + x.what, abbr[x.what]), el("span", "toc-id", x.rule + " " + x.id), el("span", "mark", x.holds ? "✓" : "✗"), el("span", "kind", x.example));
          b.addEventListener("click", () => {
            const r = (cat.rules || []).find((y) => y.rule === x.rule);
            const it = r && items.find((i) => i.e === r.entries[x.entry]);
            if (it) {
              it.d.open = true;
              open(it.e, it.b, 0, it.m);
            }
          });
          td.appendChild(b);
        }
        tr.append(th, td);
        tb.appendChild(tr);
      }
      v.appendChild(tb);
      return v;
    }
    for (const [label, page] of [["boundary", explorer], ["boundary rows", rowsPage], ...(terms ? [["terms", termsPage]] : []), ...((cat.advisories || []).length ? [["advisories", advisoriesPage]] : [])]) {
      const b = el("button", "toc-entry toc-meta");
      b.type = "button";
      b.append(el("span", "what", "C"), el("span", "toc-id", label));
      b.addEventListener("click", () => {
        for (const x of toc.querySelectorAll(".toc-entry")) x.setAttribute("aria-current", String(x === b));
        view.replaceChildren(page());
        current = null;
      });
      toc.appendChild(b);
    }
    const items = [];
    // open shows the entry e of the button b, its run k; all, the page of
    // every rule on the example instead of its rule's.
    function open(e, b, k, m, all) {
      for (const x of toc.querySelectorAll(".toc-entry")) x.setAttribute("aria-current", String(x === b));
      view.replaceChildren();
      view.appendChild(el("h2", null, abbr[e.what] + " " + e.id + (e.holds ? " ✓" : " ✗")));
      view.appendChild(el("p", "decl", e.text));
      const d = declaration(e, m);
      if (d) {
        const det = el("details", "meta-decl");
        det.append(el("summary", null, "declaration"), d);
        view.appendChild(det);
      }
      const notes = el("dl", "notes");
      for (const [k, v] of [["Situation", e.situation], ["Why", e.reason], ["Rule's cause", e.cause]]) {
        if (v) notes.append(el("dt", null, k), el("dd", null, v));
      }
      if (e.advisories && e.advisories.length) {
        const dd = el("dd");
        e.advisories.forEach((u, i) => dd.append(i ? ", " : "", cite(u)));
        notes.append(el("dt", null, "Advisories"), dd);
      }
      if (e.sources && e.sources.length) {
        const dd = el("dd");
        e.sources.forEach((u, i) => dd.append(i ? ", " : "", cite(u)));
        notes.append(el("dt", null, "Sources"), dd);
      }
      view.appendChild(notes);
      if (e.attack || e.attack_carrier) {
        const atk = el("dl", "notes attack");
        if (e.attack) atk.append(el("dt", null, "Attack"), el("dd", null, e.attack));
        if (e.attack_carrier) {
          const dd = el("dd");
          dd.append(el("p", null, "into " + e.attack_carrier), el("pre", "node-source", e.attack_value));
          atk.append(el("dt", null, "Attack"), dd);
        }
        if (e.substitutions && e.substitutions.length) {
          const dd = el("dd");
          for (const s of e.substitutions) dd.append(el("p", null, s.file + ": " + s.where), el("pre", "node-source", s.text));
          atk.append(el("dt", null, "After substitution"), dd);
        }
        if (e.attack_run_behavior) atk.append(el("dt", null, "What the run does"), el("dd", null, e.attack_run_behavior));
        view.appendChild(atk);
        if (e.checked) view.appendChild(el("p", "checked", e.checked));
      }
      view.appendChild(el("p", e.reviewed ? "seen" : "unseen", e.reviewed ? "✔ reviewed" : "unreviewed"));
      view.appendChild(el("p", "kind", e.example));
      if (!e.holds) view.appendChild(el("p", "why", e.why));
      const runs = el("div", "runs");
      if (e.runs.length > 1) {
        e.runs.forEach((r, j) => {
          const rb = el("button", null, r.facts);
          rb.type = "button";
          rb.setAttribute("aria-pressed", String(j === k));
          rb.addEventListener("click", () => open(e, b, j, m, all));
          runs.appendChild(rb);
        });
      } else if (e.runs.length) {
        view.appendChild(el("p", "kind", "facts: " + e.runs[0].facts));
      }
      if (e.runs.length) {
        const p = e.runs[k].all_rules;
        const rule = m && m.id;
        const n = [...(p.findings || []), ...(p.quality_findings || [])].filter((x) => x.rule !== rule).length;
        const ob = el("button", "others", "other rules (" + n + ")");
        ob.type = "button";
        ob.setAttribute("aria-pressed", String(!!all));
        ob.addEventListener("click", () => open(e, b, k, m, !all));
        runs.appendChild(ob);
        view.appendChild(runs);
        // the facts the rule asked (every rule, with all) and the answers
        const lines = all ? e.runs[k].all_fact_lines : e.runs[k].fact_lines;
        view.appendChild(lines.length ? el("pre", "node-source facts", lines.join("\n")) : el("p", "kind", all ? "No rule asked a fact." : "The rule asked no fact."));
      }
      const root = el("div");
      view.appendChild(root);
      current = e.runs.length ? mount(all ? e.runs[k].all_rules : e.runs[k].page, root) : null;
    }
    // openRule shows the Meta of the rule m, and its boundary; of a quality
    // rule, which has no threat, the Meta alone.
    function openRule(m, b, quality) {
      for (const x of toc.querySelectorAll(".toc-entry")) x.setAttribute("aria-current", String(x === b));
      if (quality) view.replaceChildren(ruleMeta(m, true));
      else view.replaceChildren(ruleMeta(m), ruleBoundary(m));
      current = null;
    }
    // The rules, below the boundary: layout draws them into rulesBox.
    const rulesBox = el("div", "toc-rules");
    toc.appendChild(rulesBox);
    // ruleDetails is the rule r and its entries in the table of contents;
    // also, the other values it has of the axis the rules are grouped by.
    function ruleDetails(r, also) {
      const m = withArguments(r.meta, r.arguments);
      const d = el("details", "toc-rule");
      const fails = r.entries.filter((e) => !e.holds).length;
      const s = el("summary", null, r.rule + " (" + r.entries.length + (fails ? ", " + fails + " ✗" : "") + ")");
      if (also.length) s.appendChild(el("span", "facet-also", " also " + also.join(", ")));
      d.appendChild(s);
      const rb = el("button", "toc-entry toc-meta");
      rb.type = "button";
      rb.append(el("span", "what", r.quality ? "quality rule" : "rule"), el("span", "toc-id", r.rule), el("span", r.meta_reviewed ? "seen" : "unseen", r.meta_reviewed ? "✔ reviewed" : "unreviewed"));
      if (!r.reviewed) s.appendChild(el("span", "unseen", " not all reviewed"));
      rb.addEventListener("click", () => openRule(m, rb, r.quality));
      d.appendChild(rb);
      for (const e of r.entries) {
        const b = el("button", "toc-entry " + (e.holds ? "holds" : "fails"));
        b.type = "button";
        b.append(el("span", "what what-" + e.what, abbr[e.what]), el("span", "toc-id", e.id), el("span", "mark", e.holds ? "✓" : "✗"), el("span", e.reviewed ? "seen" : "unseen", e.reviewed ? "✔ reviewed" : "unreviewed"));
        b.addEventListener("click", () => open(e, b, 0, m));
        d.appendChild(b);
        items.push({ b, e, d, m });
      }
      return d;
    }
    let onlyFailing = false, onlyUnseen = false;
    const filter = () => {
      failing.setAttribute("aria-pressed", String(onlyFailing));
      unseen.setAttribute("aria-pressed", String(onlyUnseen));
      for (const x of items) x.b.hidden = (onlyFailing && x.e.holds) || (onlyUnseen && x.e.reviewed);
      for (const d of toc.querySelectorAll("details")) d.open = onlyFailing || onlyUnseen || d === toc.querySelector("details");
    };
    failing.addEventListener("click", () => { onlyFailing = !onlyFailing; filter(); });
    unseen.addEventListener("click", () => { onlyUnseen = !onlyUnseen; filter(); });
    // The axis chosen is kept in the viewer's browser; where storage is
    // refused (a private window, a file), the rules are in their order.
    const groupKey = "sisakulint.catalog.group-by";
    // layout draws the rules grouped by the axis named by, or in their
    // order for none or a name of no axis, and keeps the choice.
    function layout(by) {
      const f = (cat.facets || []).find((x) => x.facet === by) || null;
      const name = f ? f.facet : "none";
      try { localStorage.setItem(groupKey, name); } catch (_) { /* not kept */ }
      for (const x of groupButtons) x.gb.setAttribute("aria-pressed", String(x.name === name));
      items.length = 0;
      rulesBox.replaceChildren();
      for (const g of groupRules(cat.rules, f)) {
        let box = rulesBox;
        if (g.value !== null) {
          box = el("section", "toc-group");
          box.append(el("h3", null, g.value), el("p", "toc-group-text", g.description));
          rulesBox.appendChild(box);
        }
        for (const x of g.rules) box.appendChild(ruleDetails(x.rule, x.also));
      }
      filter();
    }
    let saved = "none";
    try { saved = localStorage.getItem(groupKey) || "none"; } catch (_) { /* in their order */ }
    layout(saved);
    // start at the first rule's Meta: what its examples are examples of
    const first = rulesBox.querySelector(".toc-meta");
    if (first) first.click();
  }

  addEventListener("resize", () => current && current.draw());
  setMode("plain");
  const cat = document.getElementById("catalog-data");
  if (cat) catalog(JSON.parse(cat.textContent));
  else current = mount(JSON.parse(document.getElementById("report-data").textContent), app);
}
