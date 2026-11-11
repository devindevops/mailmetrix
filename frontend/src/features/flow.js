// Shared workflow-card controller used by every tool tab.
// Steps: flowFrontend -> flowBackend -> flowSMTP (tool step 3) -> flowEmail (tool step 4).
// tabs.js relabels the steps per tool; this module only drives their state.
import { $ } from "./utils.js";

const FLOW_IDS = ["flowFrontend", "flowBackend", "flowSMTP", "flowEmail"];

/* ---------- low-level helpers (used by dns.js, headers.js, generator.js) ---------- */

export function resetFlow() {
  FLOW_IDS.forEach((id) => {
    const element = $(id);
    element?.classList.remove("active", "success", "error");
  });
}

export function setFlowStep(id, state) {
  const element = $(id);
  if (!element) return;

  element.classList.remove("active", "success", "error");
  if (state) element.classList.add(state);
}

export function startFlow() {
  resetFlow();
  setFlowStep("flowFrontend", "active");
}

export function flowError(id) {
  setFlowStep(id, "error");
}

export function flowSuccess(id) {
  setFlowStep(id, "success");
}

export function flowActive(id) {
  setFlowStep(id, "active");
}

/* ---------- backend reachability (shared by every tool) ---------- */

export async function checkBackend() {
  try {
    const response = await fetch("/api/health");
    return response.ok;
  } catch {
    return false;
  }
}

/* ---------- high-level controller for the standard tool lifecycle ----------
   const flow = createFlow(document.getElementById("blacklistTool"));
   flow.start();                    // Frontend ✓, Backend …
   flow.backendOk();                // Backend ✓, step 3 …
   flow.done();                     // all ✓          flow.fail("flowSMTP")  // mark a step ✗
   Every method is a no-op while `panel` is hidden, so a slow request can't repaint
   the card after the user has switched to another tool. */
export function createFlow(panel) {
  const live = () => !panel || !panel.classList.contains("hidden");
  const run = (fn) => { if (live()) fn(); };

  return {
    start() {
      run(() => {
        resetFlow();
        flowSuccess("flowFrontend");
        flowActive("flowBackend");
      });
    },
    backendOk() {
      run(() => {
        flowSuccess("flowBackend");
        flowActive("flowSMTP");
      });
    },
    done() { run(() => FLOW_IDS.forEach(flowSuccess)); },
    fail(id) { run(() => flowError(id)); },
    set(id, state) { run(() => setFlowStep(id, state)); }
  };
}