import { el, post, badge } from "./ui.js";
import { bindTool } from "./share.js";

export function renderBlacklist(root, data) {
  const s = data.summary;
  root.replaceChildren(
    el("h3", {}, `Results for ${data.target}`),
    el("p", {},
      badge(s.listed ? "listed" : "clean", s.listed ? `Listed on ${s.listed}` : "Not listed"),
      ` ${s.checked} checks: ${s.clean} clean, ${s.listed} listed, ${s.unknown} unknown`),
    ...data.entries.map((entry) => el("div", {},
      el("h4", {}, `${entry.type === "ip" ? "IP" : "Domain"}: ${entry.target}`),
      el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "List"), el("th", {}, "Status"), el("th", {}, "Details"))),
        el("tbody", {}, entry.results.map((r) => el("tr", {},
          el("td", {}, r.name),
          el("td", {}, badge(r.status)),
          el("td", {}, [r.returnCode, r.reason].filter(Boolean).join(" · ") || "—")))))
    )),
    s.unknown
      ? el("p", { class: "mm-note" }, "“Unknown” usually means the list refused the DNS resolver (common with public resolvers like 8.8.8.8).")
      : null
  );
}

export function initBlacklist() {
  const input = document.getElementById("blTarget");
  bindTool({
    button: document.getElementById("blButton"),
    enterOn: [input],
    out: document.getElementById("blResult"),
    actions: document.getElementById("blActions"),
    type: "blacklist",
    busyMsg: "Querying blacklists…",
    request: async () => {
      const target = input.value.trim();
      if (!target) throw new Error("Enter an IPv4 address or domain name.");
      return post("/blacklist", { target });
    },
    render: renderBlacklist
  });
}
