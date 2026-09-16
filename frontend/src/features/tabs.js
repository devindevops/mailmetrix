const PANELS = {
  smtp: "smtpTool",
  dns: "dnsTool",
  headers: "headersTool"
};

const FLOW_COPY = {
  smtp: {
    title: "SMTP delivery path",
    labels: [
      ["Frontend", "Browser"],
      ["Backend", "Node.js"],
      ["SMTP", "Authentication"],
      ["Email", "Sending"]
    ]
  },
  dns: {
    title: "DNS inspection path",
    labels: [
      ["Frontend", "Browser"],
      ["Backend", "Node.js"],
      ["DNS", "Resolution"],
      ["Records", "Analysis"]
    ]
  },
  headers: {
    title: "Header analysis path",
    labels: [
      ["Frontend", "Browser"],
      ["Backend", "Node.js"],
      ["Parser", "Analysis"],
      ["Findings", "Diagnostics"]
    ]
  }
};

function showPanel(tool) {
  Object.entries(PANELS).forEach(([name, id]) => {
    document.getElementById(id)?.classList.toggle("hidden", name !== tool);
  });

  document.querySelectorAll(".tab").forEach((tab) => {
    const active = tab.dataset.tool === tool;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });

  const copy = FLOW_COPY[tool];
  if (copy) {
    const title = document.getElementById("flowTitle");
    if (title) title.textContent = copy.title;

    ["flowFrontend", "flowBackend", "flowSMTP", "flowEmail"].forEach((id, index) => {
      const step = document.getElementById(id);
      if (!step || !copy.labels[index]) return;
      const [label, sublabel] = copy.labels[index];
      const strong = step.querySelector("strong");
      const small = step.querySelector("small");
      if (strong) strong.textContent = label;
      if (small) small.textContent = sublabel;
      step.classList.remove("active", "success", "error");
      if (index === 0) step.classList.add("active");
    });
  }
}

export function initTabs() {
  const tabs = document.querySelectorAll(".tab");
  if (!tabs.length) return;

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      if (PANELS[tab.dataset.tool]) showPanel(tab.dataset.tool);
    });
  });

  showPanel("smtp");
}
