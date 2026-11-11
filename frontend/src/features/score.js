import { el, post, badge } from "./ui.js";
import { bindTool } from "./share.js";

export function renderScore(root, d) {
  root.replaceChildren(
    el("div", { class: "mm-score" },
      el("div", { class: `mm-grade mm-grade-${d.grade}` }, d.grade),
      el("div", {},
        el("h3", {}, d.domain),
        el("p", {}, `Score ${d.score}/100`),
        d.skipped.length ? el("p", { class: "mm-note" }, `Not scored: ${d.skipped.join(", ")}`) : null)),
    el("table", {},
      el("thead", {}, el("tr", {}, ["Check", "Result", "Points", "Details"].map((h) => el("th", {}, h)))),
      el("tbody", {}, d.checks.map((c) => el("tr", {},
        el("td", {}, c.label),
        el("td", {}, badge(c.status)),
        el("td", {}, c.status === "skip" ? "—" : `${c.points}/${c.max}`),
        el("td", {}, c.detail))))),
    d.fixes.length
      ? el("div", {}, el("h4", {}, "What to fix first"),
          el("ol", {}, d.fixes.map((f) => el("li", {}, el("strong", {}, `${f.check}: `), f.fix))))
      : el("p", {}, "Nothing to fix. Nice work.")
  );
}

export function initScore() {
  const domain = document.getElementById("scoreDomain");
  const selector = document.getElementById("scoreSelector");
  bindTool({
    button: document.getElementById("scoreButton"),
    enterOn: [domain, selector],
    out: document.getElementById("scoreResult"),
    actions: document.getElementById("scoreActions"),
    type: "score",
    busyMsg: "Running checks (can take up to ~15 seconds)…",
    request: async () => {
      const d = domain.value.trim();
      if (!d) throw new Error("Enter a domain name.");
      return post("/score", { domain: d, selector: selector.value.trim() || undefined });
    },
    render: renderScore
  });
}
