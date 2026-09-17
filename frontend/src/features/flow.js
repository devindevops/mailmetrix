import { $ } from "./utils.js";

const FLOW_IDS = ["flowFrontend", "flowBackend", "flowSMTP", "flowEmail"];

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
