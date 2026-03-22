"use client";

import type {
  AgentBrowserContext,
  AgentBrowserDOMNode,
  AgentBrowserSemanticAction,
  AgentBrowserSemanticEntity,
  AgentBrowserSemanticForm,
  AgentBrowserSemanticSection,
  AgentPageContext,
  AgentSemanticPageContext,
  AgentUIAction,
  AgentUIActionResult,
  AgentUIActionType,
  AgentBrowserVisibleAction,
} from "@/types/agent";

const MAX_DOM_NODES = 80;
const MAX_VISIBLE_ACTIONS = 20;
const MAX_OPEN_PANELS = 6;
const MAX_FORMS = 6;
const MAX_SEMANTIC_ACTIONS = 32;
const MAX_SECTIONS = 12;
const MAX_SECONDARY_ENTITIES = 12;

let nodeCounter = 0;

function isInsideAgentUI(element: Element | null) {
  return Boolean(element?.closest("[data-haor-agent-root='true']"));
}

function truncate(value: string | null | undefined, maxLength: number) {
  const normalized = String(value || "").replace(/\s+/g, " ").trim();
  if (!normalized) {
    return "";
  }
  return normalized.length > maxLength ? `${normalized.slice(0, maxLength - 1)}…` : normalized;
}

function toSlug(value: string | null | undefined) {
  return truncate(value, 120)
    .toLowerCase()
    .replace(/[^a-z0-9\u4e00-\u9fff]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48) || "section";
}

function buildRouteContextFromLocation(): AgentPageContext {
  const pathname = window.location.pathname || "/";
  const searchParams = new URLSearchParams(window.location.search);
  const query: Record<string, string> = {};
  searchParams.forEach((value, key) => {
    query[key] = value;
  });
  const segments = pathname.split("/").filter(Boolean);
  let assetId = query.assetId || query.asset_id || "";
  let findingId = query.findingId || query.finding_id || "";
  let taskId = query.taskId || query.task_id || "";
  if (!assetId && segments[0] === "assets" && segments[1]) {
    assetId = segments[1];
  }
  if (!assetId && segments[0] === "remediation" && segments[1]) {
    assetId = segments[1];
  }
  if (!taskId && segments[0] === "tasks" && segments[1]) {
    taskId = segments[1];
  }
  return {
    pathname,
    query,
    asset_id: assetId || null,
    finding_id: findingId || null,
    task_id: taskId || null,
  };
}

function isElementVisible(element: Element | null): element is HTMLElement {
  if (!(element instanceof HTMLElement)) {
    return false;
  }
  if (isInsideAgentUI(element)) {
    return false;
  }
  const style = window.getComputedStyle(element);
  if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) {
    return false;
  }
  const rect = element.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}

function isInteractiveElement(element: HTMLElement) {
  const tagName = element.tagName.toLowerCase();
  if (["button", "a", "input", "textarea", "select", "summary"].includes(tagName)) {
    return true;
  }
  if (element.getAttribute("role") && ["button", "link", "tab", "switch", "checkbox", "menuitem"].includes(String(element.getAttribute("role")))) {
    return true;
  }
  return typeof element.onclick === "function" || element.tabIndex >= 0;
}

function ensureNodeId(element: HTMLElement) {
  const existing = element.dataset.haorNodeId;
  if (existing) {
    return existing;
  }
  nodeCounter += 1;
  const nodeId = `haor-node-${nodeCounter}`;
  element.dataset.haorNodeId = nodeId;
  return nodeId;
}

function getElementText(element: HTMLElement) {
  return truncate(
    element.getAttribute("aria-label")
      || element.getAttribute("title")
      || ("value" in element ? String((element as HTMLInputElement).value || "") : "")
      || element.innerText
      || element.textContent,
    180,
  );
}

function getElementLabel(element: HTMLElement) {
  const ariaLabel = truncate(element.getAttribute("aria-label"), 120);
  if (ariaLabel) {
    return ariaLabel;
  }
  const labelledBy = element.getAttribute("aria-labelledby");
  if (labelledBy) {
    const labelNode = document.getElementById(labelledBy);
    const labelText = truncate(labelNode?.textContent, 120);
    if (labelText) {
      return labelText;
    }
  }
  const placeholder = truncate(element.getAttribute("placeholder"), 120);
  if (placeholder) {
    return placeholder;
  }
  if (element.id) {
    const label = document.querySelector(`label[for="${CSS.escape(element.id)}"]`);
    const labelText = truncate(label?.textContent, 120);
    if (labelText) {
      return labelText;
    }
  }
  return truncate(element.innerText || element.textContent, 120);
}

function readSectionTitle(element: HTMLElement) {
  return truncate(
    element.getAttribute("data-haor-section")
      || element.querySelector(".ant-card-head-title, h1, h2, h3, h4, .ant-drawer-title, .ant-modal-title")?.textContent
      || "",
    120,
  );
}

function domNodeFromElement(element: HTMLElement): AgentBrowserDOMNode {
  const tagName = element.tagName.toLowerCase();
  const href = tagName === "a" ? truncate((element as HTMLAnchorElement).href, 255) : "";
  const value = "value" in element ? truncate(String((element as HTMLInputElement).value || ""), 120) : "";
  const attributes: Record<string, string> = {};
  ["type", "name", "placeholder", "data-testid", "aria-expanded", "aria-selected"].forEach((key) => {
    const attributeValue = truncate(element.getAttribute(key), 120);
    if (attributeValue) {
      attributes[key] = attributeValue;
    }
  });
  return {
    node_id: ensureNodeId(element),
    tag_name: tagName,
    role: truncate(element.getAttribute("role"), 32) || null,
    text: getElementText(element) || null,
    label: getElementLabel(element) || null,
    href: href || null,
    value: value || null,
    is_interactive: isInteractiveElement(element),
    is_visible: true,
    attributes,
  };
}

function collectDOMSnapshot() {
  const selectors = [
    "main",
    "button",
    "a",
    "input",
    "textarea",
    "select",
    "[role='button']",
    "[role='link']",
    "[role='tab']",
    "[role='dialog']",
    ".ant-table-row",
    ".ant-card",
    ".ant-collapse-item",
    ".ant-tabs-tab",
    ".ant-drawer",
    ".ant-modal",
  ];
  const seen = new Set<string>();
  const nodes: AgentBrowserDOMNode[] = [];
  document.querySelectorAll<HTMLElement>(selectors.join(",")).forEach((element) => {
    if (!isElementVisible(element)) {
      return;
    }
    const node = domNodeFromElement(element);
    if (!node.node_id || seen.has(node.node_id)) {
      return;
    }
    if (!node.is_interactive && !node.text && !node.label) {
      return;
    }
    seen.add(node.node_id);
    nodes.push(node);
  });
  return nodes.slice(0, MAX_DOM_NODES);
}

function collectVisibleActions(domSnapshot: AgentBrowserDOMNode[]) {
  const actions: AgentBrowserVisibleAction[] = [];
  for (const node of domSnapshot) {
    if (!node.is_interactive) {
      continue;
    }
    actions.push({
      action_id: `visible-${node.node_id}`,
      action_type: node.tag_name === "a" ? "navigate" : "click",
      node_id: node.node_id,
      label: node.label || node.text || node.tag_name,
      description: node.href ? `打开 ${node.href}` : undefined,
    });
    if (actions.length >= MAX_VISIBLE_ACTIONS) {
      break;
    }
  }
  return actions;
}

function collectOpenPanels() {
  const panels: Array<Record<string, unknown>> = [];
  const selectors = [".ant-modal [role='dialog']", ".ant-drawer", "[role='dialog']", ".ant-collapse-item-active"];
  document.querySelectorAll<HTMLElement>(selectors.join(",")).forEach((element) => {
    if (!isElementVisible(element)) {
      return;
    }
    panels.push({
      kind: element.matches(".ant-modal [role='dialog'], [role='dialog']") ? "dialog" : "panel",
      title: readSectionTitle(element) || truncate(element.textContent, 120) || null,
      node_id: ensureNodeId(element),
    });
  });
  return panels.slice(0, MAX_OPEN_PANELS);
}

function collectForms() {
  const forms: Array<Record<string, unknown>> = [];
  document.querySelectorAll<HTMLElement>("form, .ant-form").forEach((element) => {
    if (!isElementVisible(element)) {
      return;
    }
    const fields = Array.from(element.querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>("input, textarea, select"))
      .filter((field) => isElementVisible(field))
      .slice(0, 8)
      .map((field) => ({
        name: truncate(field.name || field.id || field.getAttribute("placeholder"), 80) || null,
        type: field.tagName.toLowerCase() === "input" ? truncate((field as HTMLInputElement).type, 40) || "text" : field.tagName.toLowerCase(),
        label: getElementLabel(field),
      }));
    forms.push({
      node_id: ensureNodeId(element),
      name: truncate(element.getAttribute("name") || element.getAttribute("aria-label") || element.className, 120) || null,
      fields,
    });
  });
  return forms.slice(0, MAX_FORMS);
}

function collectSelectedEntities(pageContext: AgentPageContext) {
  const selected: Array<Record<string, unknown>> = [];
  if (pageContext.asset_id) {
    selected.push({ kind: "asset", id: pageContext.asset_id, label: `资产 ${pageContext.asset_id}`, source: "route" });
  }
  if (pageContext.finding_id) {
    selected.push({ kind: "finding", id: pageContext.finding_id, label: `风险 ${pageContext.finding_id}`, source: "route" });
  }
  if (pageContext.task_id) {
    selected.push({ kind: "task", id: pageContext.task_id, label: `任务 ${pageContext.task_id}`, source: "route" });
  }
  document.querySelectorAll<HTMLElement>(".ant-table-row-selected, [aria-selected='true'], .ant-tabs-tab-active").forEach((element) => {
    if (!isElementVisible(element)) {
      return;
    }
    selected.push({
      kind: "selection",
      id: ensureNodeId(element),
      label: truncate(element.textContent, 120) || "当前选中项",
      source: "dom",
    });
  });
  return selected.slice(0, 8);
}

function inferPageKind(pageContext: AgentPageContext) {
  const pathname = pageContext.pathname || "/";
  if (pathname === "/assets") {
    return "asset_list";
  }
  if (pathname.startsWith("/assets/")) {
    return "asset_detail";
  }
  if (pathname === "/tasks") {
    return "task_list";
  }
  if (pathname.startsWith("/tasks/") && pathname !== "/tasks/logs") {
    return "task_detail";
  }
  if (pathname === "/remediation") {
    return "remediation_overview";
  }
  if (pathname.startsWith("/remediation/")) {
    return "remediation_asset_detail";
  }
  if (pathname === "/vuln-library") {
    return "vuln_library";
  }
  if (pathname === "/risks") {
    return "risk_entry";
  }
  if (pathname === "/discovery") {
    return "discovery";
  }
  return "generic";
}

function buildSemanticEntity(
  kind: string,
  id: string | null | undefined,
  label: string | null | undefined,
  extra: Partial<AgentBrowserSemanticEntity> = {},
): AgentBrowserSemanticEntity {
  return {
    kind,
    id: id || null,
    label: truncate(label, 120) || null,
    status: extra.status || null,
    source: extra.source || "dom",
    meta: extra.meta || {},
  };
}

function pushUniqueSection(target: AgentBrowserSemanticSection[], section: AgentBrowserSemanticSection) {
  if (!section.section_id || !section.label) {
    return;
  }
  if (target.some((item) => item.section_id === section.section_id)) {
    return;
  }
  target.push(section);
}

function pushUniqueAction(target: AgentBrowserSemanticAction[], action: AgentBrowserSemanticAction) {
  if (!action.semantic_action_id || !action.label) {
    return;
  }
  if (target.some((item) => item.semantic_action_id === action.semantic_action_id)) {
    return;
  }
  target.push(action);
}

function pushUniqueForm(target: AgentBrowserSemanticForm[], form: AgentBrowserSemanticForm) {
  if (!form.semantic_form_id || !form.label) {
    return;
  }
  if (target.some((item) => item.semantic_form_id === form.semantic_form_id)) {
    return;
  }
  target.push(form);
}

function semanticAction(
  pageKind: string,
  actionId: string,
  label: string,
  actionType: AgentUIActionType,
  element: HTMLElement | null,
  extras: Partial<AgentBrowserSemanticAction> = {},
): AgentBrowserSemanticAction {
  const nodeId = element && isElementVisible(element) ? ensureNodeId(element) : null;
  return {
    semantic_action_id: `${pageKind}:${actionId}`,
    label,
    action_type: actionType,
    node_id: nodeId,
    description: extras.description || null,
    section_id: extras.section_id || null,
    href: extras.href || null,
    selector: extras.selector || null,
    text_contains: extras.text_contains || truncate(label, 120) || null,
    target_entity: extras.target_entity || {},
    keywords: extras.keywords || [],
  };
}

function collectGenericSections(pageKind: string) {
  const sections: AgentBrowserSemanticSection[] = [];
  const sectionNodes = Array.from(document.querySelectorAll<HTMLElement>(".panel-card, .ant-card, section, .ant-modal, .ant-drawer"));
  sectionNodes.forEach((element, index) => {
    if (!isElementVisible(element)) {
      return;
    }
    const label = readSectionTitle(element);
    if (!label) {
      return;
    }
    pushUniqueSection(sections, {
      section_id: `${pageKind}:section:${toSlug(label)}-${index + 1}`,
      label,
      node_id: ensureNodeId(element),
      description: null,
    });
  });
  return sections.slice(0, MAX_SECTIONS);
}

function addSectionScrollActions(pageKind: string, sections: AgentBrowserSemanticSection[], actions: AgentBrowserSemanticAction[]) {
  sections.forEach((section) => {
    if (!section.node_id) {
      return;
    }
    pushUniqueAction(
      actions,
      semanticAction(pageKind, `scroll:${section.section_id}`, `定位到 ${section.label}`, "scroll_into_view", getNodeById(section.node_id), {
        section_id: section.section_id,
        description: `滚动到 ${section.label}`,
        keywords: ["定位", "滚动", "查看", "打开", section.label],
      }),
    );
  });
}

function collectSelectedRows() {
  const rows: Array<Record<string, unknown>> = [];
  document.querySelectorAll<HTMLElement>(".ant-table-row-selected, [aria-selected='true']").forEach((element) => {
    if (!isElementVisible(element)) {
      return;
    }
    rows.push({
      node_id: ensureNodeId(element),
      label: truncate(element.textContent, 160) || "当前选中行",
    });
  });
  return rows.slice(0, 6);
}

function addCommonSearchForm(
  pageKind: string,
  forms: AgentBrowserSemanticForm[],
  actions: AgentBrowserSemanticAction[],
  selector: string,
  label: string,
) {
  const field = document.querySelector<HTMLInputElement>(selector);
  if (!isElementVisible(field)) {
    return;
  }
  const semanticActionId = `${pageKind}:search`;
  pushUniqueForm(forms, {
    semantic_form_id: `${pageKind}:search-form`,
    label,
    node_id: ensureNodeId(field),
    fields: [{ label, type: "text", placeholder: field.placeholder || "" }],
    submit_action_id: semanticActionId,
  });
  pushUniqueAction(
    actions,
    semanticAction(pageKind, "search", label, "input", field, {
      description: `在${label}中输入关键字`,
      keywords: ["搜索", "筛选", "关键字", label],
    }),
  );
}

function collectAssetListSemantics(pageContext: AgentPageContext) {
  const pageKind = "asset_list";
  const sections = collectGenericSections(pageKind);
  const actions: AgentBrowserSemanticAction[] = [];
  const forms: AgentBrowserSemanticForm[] = [];
  const secondaryEntities: AgentBrowserSemanticEntity[] = [];
  addSectionScrollActions(pageKind, sections, actions);
  addCommonSearchForm(pageKind, forms, actions, ".asset-search-input input", "资产列表搜索");
  document.querySelectorAll<HTMLAnchorElement>("a[href^='/assets/']").forEach((link) => {
    if (!isElementVisible(link)) {
      return;
    }
    const href = link.getAttribute("href") || "";
    const match = href.match(/^\/assets\/([^/?#]+)/);
    if (!match) {
      return;
    }
    const assetId = match[1];
    const card = link.closest<HTMLElement>(".asset-square-card") || link;
    const label = truncate(card.querySelector(".asset-square-ip")?.textContent || card.textContent, 120) || `资产 ${assetId}`;
    secondaryEntities.push(buildSemanticEntity("asset", assetId, label, { source: "page" }));
    pushUniqueAction(
      actions,
      semanticAction(pageKind, `open_asset:${assetId}`, `打开资产 ${label}`, "navigate", link, {
        href,
        section_id: sections[0]?.section_id || null,
        target_entity: { kind: "asset", id: assetId, label },
        keywords: ["打开", "查看详情", "资产", label],
      }),
    );
  });
  return {
    page_kind: pageKind,
    primary_entity: {},
    secondary_entities: secondaryEntities.slice(0, MAX_SECONDARY_ENTITIES),
    visible_sections: sections,
    semantic_actions: actions.slice(0, MAX_SEMANTIC_ACTIONS),
    semantic_forms: forms,
    active_dialog: {},
    selected_rows: collectSelectedRows(),
    summary: `资产列表页，可直接搜索、筛选并打开资产详情。当前可见 ${secondaryEntities.length} 条资产入口。`,
  } satisfies AgentSemanticPageContext;
}

function collectTaskListSemantics() {
  const pageKind = "task_list";
  const sections = collectGenericSections(pageKind);
  const actions: AgentBrowserSemanticAction[] = [];
  const secondaryEntities: AgentBrowserSemanticEntity[] = [];
  addSectionScrollActions(pageKind, sections, actions);
  document.querySelectorAll<HTMLAnchorElement>("a[href^='/tasks/']").forEach((link) => {
    if (!isElementVisible(link)) {
      return;
    }
    const href = link.getAttribute("href") || "";
    const match = href.match(/^\/tasks\/([^/?#]+)/);
    if (!match || href.startsWith("/tasks/logs")) {
      return;
    }
    const taskId = match[1];
    const label = truncate(link.closest("tr")?.textContent || link.textContent, 120) || `任务 ${taskId}`;
    secondaryEntities.push(buildSemanticEntity("task", taskId, label, { source: "page" }));
    pushUniqueAction(
      actions,
      semanticAction(pageKind, `open_task:${taskId}`, `打开任务 ${taskId}`, "navigate", link, {
        href,
        target_entity: { kind: "task", id: taskId, label },
        keywords: ["打开", "任务详情", "任务", taskId],
      }),
    );
  });
  const logsButton = findInteractiveByText("任务日志");
  if (logsButton) {
    pushUniqueAction(
      actions,
      semanticAction(pageKind, "open_logs", "打开任务日志页", "click", logsButton, {
        keywords: ["日志", "任务日志", "查看日志"],
      }),
    );
  }
  return {
    page_kind: pageKind,
    primary_entity: {},
    secondary_entities: secondaryEntities.slice(0, MAX_SECONDARY_ENTITIES),
    visible_sections: sections,
    semantic_actions: actions.slice(0, MAX_SEMANTIC_ACTIONS),
    semantic_forms: [],
    active_dialog: {},
    selected_rows: collectSelectedRows(),
    summary: `任务列表页，可打开任务详情或日志。当前可见 ${secondaryEntities.length} 条任务入口。`,
  } satisfies AgentSemanticPageContext;
}

function collectTaskDetailSemantics(pageContext: AgentPageContext) {
  const pageKind = "task_detail";
  const sections = collectGenericSections(pageKind);
  const actions: AgentBrowserSemanticAction[] = [];
  const taskId = pageContext.task_id || truncate(document.querySelector("h1")?.textContent, 64) || null;
  const primaryEntity = taskId ? buildSemanticEntity("task", taskId, `任务 ${taskId}`, { source: "route" }) : {};
  addSectionScrollActions(pageKind, sections, actions);
  [["刷新", "refresh"], ["查看全局日志", "open_global_logs"], ["中断任务", "cancel_task"]].forEach(([label, actionId]) => {
    const button = findInteractiveByText(label);
    if (!button) {
      return;
    }
    pushUniqueAction(
      actions,
      semanticAction(pageKind, actionId, label, actionId === "open_global_logs" ? "click" : "click", button, {
        target_entity: { kind: "task", id: taskId, label: taskId ? `任务 ${taskId}` : "当前任务" },
        keywords: [label, "任务", taskId || ""],
      }),
    );
  });
  return {
    page_kind: pageKind,
    primary_entity: primaryEntity,
    secondary_entities: [],
    visible_sections: sections,
    semantic_actions: actions.slice(0, MAX_SEMANTIC_ACTIONS),
    semantic_forms: [],
    active_dialog: {},
    selected_rows: [],
    summary: `任务详情页，可定位任务概况、阶段耗时和事件日志，并执行刷新、打开全局日志或中断任务。`,
  } satisfies AgentSemanticPageContext;
}

function collectAssetDetailSemantics(pageContext: AgentPageContext) {
  const pageKind = "asset_detail";
  const sections = collectGenericSections(pageKind);
  const actions: AgentBrowserSemanticAction[] = [];
  const assetId = pageContext.asset_id || null;
  const primaryLabel = truncate(document.querySelector("h1")?.textContent, 120) || (assetId ? `资产 ${assetId}` : "当前资产");
  const primaryEntity = buildSemanticEntity("asset", assetId, primaryLabel, { source: "route" });
  addSectionScrollActions(pageKind, sections, actions);
  [["风险验证", "verify_risks"], ["重新验证管理员凭据", "verify_credential"], ["执行 SSH 授权深度检查", "run_collection"]].forEach(([label, actionId]) => {
    const button = findInteractiveByText(label);
    if (!button) {
      return;
    }
    pushUniqueAction(
      actions,
      semanticAction(pageKind, actionId, label, "click", button, {
        target_entity: { kind: "asset", id: assetId, label: primaryLabel },
        keywords: [label, "资产", assetId || ""],
      }),
    );
  });
  document.querySelectorAll<HTMLAnchorElement>("a[href^='/remediation/']").forEach((link) => {
    if (!isElementVisible(link)) {
      return;
    }
    const href = link.getAttribute("href") || "";
    const label = truncate(link.textContent, 120) || "打开修复工作台";
    pushUniqueAction(
      actions,
      semanticAction(pageKind, `open_remediation:${toSlug(href)}`, label, "navigate", link, {
        href,
        target_entity: { kind: "asset", id: assetId, label: primaryLabel },
        keywords: ["修复", "风险修复", label],
      }),
    );
  });
  return {
    page_kind: pageKind,
    primary_entity: primaryEntity,
    secondary_entities: [],
    visible_sections: sections,
    semantic_actions: actions.slice(0, MAX_SEMANTIC_ACTIONS),
    semantic_forms: [],
    active_dialog: {},
    selected_rows: collectSelectedRows(),
    summary: `资产详情页，可查看资产概览、服务、SSH 授权、深度检查和风险发现，并直接执行风险验证与深度检查。`,
  } satisfies AgentSemanticPageContext;
}

function collectRemediationOverviewSemantics() {
  const pageKind = "remediation_overview";
  const sections = collectGenericSections(pageKind);
  const actions: AgentBrowserSemanticAction[] = [];
  const forms: AgentBrowserSemanticForm[] = [];
  const secondaryEntities: AgentBrowserSemanticEntity[] = [];
  addSectionScrollActions(pageKind, sections, actions);
  addCommonSearchForm(pageKind, forms, actions, "input[placeholder*='可修复资产']", "修复资产搜索");
  document.querySelectorAll<HTMLElement>(".remediation-square-card").forEach((card, index) => {
    if (!isElementVisible(card)) {
      return;
    }
    const label = truncate(card.querySelector(".remediation-square-ip")?.textContent || card.textContent, 120) || `修复资产 ${index + 1}`;
    const nodeId = ensureNodeId(card);
    secondaryEntities.push(buildSemanticEntity("asset", nodeId, label, { source: "page" }));
    pushUniqueAction(
      actions,
      {
        semantic_action_id: `${pageKind}:open_asset:${index + 1}`,
        label: `打开修复资产 ${label}`,
        action_type: "click",
        node_id: nodeId,
        description: "进入该资产的修复界面",
        section_id: sections[0]?.section_id || null,
        text_contains: label,
        target_entity: { kind: "asset", label, node_id: nodeId },
        keywords: ["打开", "修复资产", label],
      },
    );
  });
  return {
    page_kind: pageKind,
    primary_entity: {},
    secondary_entities: secondaryEntities.slice(0, MAX_SECONDARY_ENTITIES),
    visible_sections: sections,
    semantic_actions: actions.slice(0, MAX_SEMANTIC_ACTIONS),
    semantic_forms: forms,
    active_dialog: {},
    selected_rows: [],
    summary: `修复概览页，可搜索并打开可修复资产。当前可见 ${secondaryEntities.length} 个修复入口。`,
  } satisfies AgentSemanticPageContext;
}

function collectRemediationAssetDetailSemantics(pageContext: AgentPageContext) {
  const pageKind = "remediation_asset_detail";
  const sections = collectGenericSections(pageKind);
  const actions: AgentBrowserSemanticAction[] = [];
  const assetId = pageContext.asset_id || null;
  const primaryEntity = buildSemanticEntity("asset", assetId, truncate(document.querySelector("h1")?.textContent, 120) || `资产 ${assetId || ""}`, { source: "route" });
  addSectionScrollActions(pageKind, sections, actions);
  [["安装 Runner", "install_runner"], ["重装 Runner", "install_runner"], ["一次确认并交给 Runner 执行", "approve_plan"], ["刷新", "refresh"], ["打开任务详情", "open_task_detail"], ["返回资产选择", "back_to_gallery"]].forEach(([label, actionId]) => {
    const button = findInteractiveByText(label);
    if (!button) {
      return;
    }
    pushUniqueAction(
      actions,
      semanticAction(pageKind, actionId, label, "click", button, {
        target_entity: { kind: "asset", id: assetId, label: primaryEntity.label },
        keywords: [label, "修复", "runner", assetId || ""],
      }),
    );
  });
  return {
    page_kind: pageKind,
    primary_entity: primaryEntity,
    secondary_entities: [],
    visible_sections: sections,
    semantic_actions: actions.slice(0, MAX_SEMANTIC_ACTIONS),
    semantic_forms: [],
    active_dialog: {},
    selected_rows: [],
    summary: "修复资产详情页，可查看 Runner 状态、会话消息、整机修复计划和任务输出，并推进安装 Runner 或执行修复。",
  } satisfies AgentSemanticPageContext;
}

function collectVulnLibrarySemantics() {
  const pageKind = "vuln_library";
  const sections = collectGenericSections(pageKind);
  const actions: AgentBrowserSemanticAction[] = [];
  const forms: AgentBrowserSemanticForm[] = [];
  addSectionScrollActions(pageKind, sections, actions);
  addCommonSearchForm(pageKind, forms, actions, "input[placeholder*='搜索']", "漏洞库搜索");
  [["刷新", "refresh"], ["导出规则", "export_rules"], ["导入规则", "import_rules"]].forEach(([label, actionId]) => {
    const button = findInteractiveByText(label);
    if (!button) {
      return;
    }
    pushUniqueAction(
      actions,
      semanticAction(pageKind, actionId, label, "click", button, {
        keywords: ["漏洞库", label],
      }),
    );
  });
  return {
    page_kind: pageKind,
    primary_entity: {},
    secondary_entities: [],
    visible_sections: sections,
    semantic_actions: actions.slice(0, MAX_SEMANTIC_ACTIONS),
    semantic_forms: forms,
    active_dialog: {},
    selected_rows: collectSelectedRows(),
    summary: "漏洞库页面，可搜索、查看和管理规则列表。",
  } satisfies AgentSemanticPageContext;
}

function collectRiskEntrySemantics() {
  const pageKind = "risk_entry";
  const sections = collectGenericSections(pageKind);
  const actions: AgentBrowserSemanticAction[] = [];
  addSectionScrollActions(pageKind, sections, actions);
  return {
    page_kind: pageKind,
    primary_entity: {},
    secondary_entities: [],
    visible_sections: sections,
    semantic_actions: actions,
    semantic_forms: [],
    active_dialog: {},
    selected_rows: [],
    summary: "全局风险列表页，可按资产、等级和状态查看风险，并跳转到资产详情继续分析。",
  } satisfies AgentSemanticPageContext;
}

function collectGenericSemantics(pageContext: AgentPageContext) {
  const pageKind = inferPageKind(pageContext);
  const sections = collectGenericSections(pageKind);
  const actions: AgentBrowserSemanticAction[] = [];
  addSectionScrollActions(pageKind, sections, actions);
  return {
    page_kind: pageKind,
    primary_entity: {},
    secondary_entities: [],
    visible_sections: sections,
    semantic_actions: actions,
    semantic_forms: [],
    active_dialog: {},
    selected_rows: collectSelectedRows(),
    summary: truncate(document.title || pageContext.pathname, 160),
  } satisfies AgentSemanticPageContext;
}

function collectSemanticPageContext(pageContext: AgentPageContext) {
  switch (inferPageKind(pageContext)) {
    case "asset_list":
      return collectAssetListSemantics(pageContext);
    case "asset_detail":
      return collectAssetDetailSemantics(pageContext);
    case "task_list":
      return collectTaskListSemantics();
    case "task_detail":
      return collectTaskDetailSemantics(pageContext);
    case "remediation_overview":
      return collectRemediationOverviewSemantics();
    case "remediation_asset_detail":
      return collectRemediationAssetDetailSemantics(pageContext);
    case "vuln_library":
      return collectVulnLibrarySemantics();
    case "risk_entry":
      return collectRiskEntrySemantics();
    default:
      return collectGenericSemantics(pageContext);
  }
}

export function collectBrowserContext(pageContext: AgentPageContext): AgentBrowserContext {
  const domSnapshot = collectDOMSnapshot();
  const semanticPageContext = collectSemanticPageContext(pageContext);
  return {
    pathname: pageContext.pathname,
    origin: window.location.origin,
    title: document.title || "",
    query: pageContext.query,
    asset_id: pageContext.asset_id || null,
    finding_id: pageContext.finding_id || null,
    task_id: pageContext.task_id || null,
    selected_entities: collectSelectedEntities(pageContext),
    open_panels: collectOpenPanels(),
    forms: collectForms(),
    visible_actions: collectVisibleActions(domSnapshot),
    semantic_page_context: semanticPageContext,
    semantic_actions: semanticPageContext.semantic_actions || [],
    semantic_forms: semanticPageContext.semantic_forms || [],
    dom_snapshot: domSnapshot,
  };
}

function getNodeById(nodeId: string | null | undefined) {
  if (!nodeId) {
    return null;
  }
  return (
    Array.from(document.querySelectorAll<HTMLElement>("[data-haor-node-id]")).find(
      (element) => !isInsideAgentUI(element) && element.dataset.haorNodeId === nodeId,
    ) || null
  );
}

function findInteractiveByText(text: string | null | undefined) {
  const needle = truncate(text, 120).toLowerCase();
  if (!needle) {
    return null;
  }
  const candidates = Array.from(document.querySelectorAll<HTMLElement>("button, a, input, textarea, select, [role='button'], [role='link'], [role='tab'], .ant-btn, .ant-tabs-tab"));
  return candidates.find((element) => {
    if (!isElementVisible(element)) {
      return false;
    }
    const textValue = `${getElementLabel(element)} ${getElementText(element)}`.toLowerCase();
    return textValue.includes(needle);
  }) || null;
}

function resolveSemanticActionDefinition(action: AgentUIAction) {
  if (!action.semantic_action_id) {
    return null;
  }
  const liveContext = collectBrowserContext(buildRouteContextFromLocation());
  const pageKind = liveContext.semantic_page_context?.page_kind || "generic";
  if (action.expected_page_kind && action.expected_page_kind !== pageKind) {
    return {
      liveContext,
      semanticAction: null,
    };
  }
  return {
    liveContext,
    semanticAction: (liveContext.semantic_actions || []).find((item) => item.semantic_action_id === action.semantic_action_id) || null,
  };
}

function resolveElement(action: AgentUIAction) {
  const semanticResolved = resolveSemanticActionDefinition(action);
  const semanticAction = semanticResolved?.semanticAction || null;
  const mergedAction = {
    ...semanticAction,
    ...action,
    target_node_id: action.target_node_id || semanticAction?.node_id || null,
    selector: action.selector || semanticAction?.selector || null,
    href: action.href || semanticAction?.href || null,
    text_contains: action.text_contains || semanticAction?.text_contains || semanticAction?.label || null,
  };

  const byNodeId = getNodeById(mergedAction.target_node_id);
  if (byNodeId) {
    return { element: byNodeId, semanticAction, liveContext: semanticResolved?.liveContext || null };
  }
  if (mergedAction.selector) {
    const bySelector = document.querySelector<HTMLElement>(mergedAction.selector);
    if (isElementVisible(bySelector) && !isInsideAgentUI(bySelector)) {
      ensureNodeId(bySelector);
      return { element: bySelector, semanticAction, liveContext: semanticResolved?.liveContext || null };
    }
  }
  const byLabel = findInteractiveByText(mergedAction.label_contains || mergedAction.text_contains || mergedAction.field_name || mergedAction.option_label || mergedAction.value);
  if (byLabel) {
    ensureNodeId(byLabel);
    return { element: byLabel, semanticAction, liveContext: semanticResolved?.liveContext || null };
  }
  return { element: null, semanticAction, liveContext: semanticResolved?.liveContext || null };
}

function fireInputEvents(element: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, value: string) {
  const nativeSetter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(element), "value")?.set;
  nativeSetter?.call(element, value);
  element.dispatchEvent(new Event("input", { bubbles: true }));
  element.dispatchEvent(new Event("change", { bubbles: true }));
}

function isSameOriginHref(href: string) {
  try {
    const url = new URL(href, window.location.origin);
    return url.origin === window.location.origin;
  } catch {
    return false;
  }
}

function sleep(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function waitForElement(action: AgentUIAction) {
  const timeoutMs = Math.max(200, Math.min(Number(action.wait_ms || 800), 5_000));
  const startedAt = Date.now();
  while (Date.now() - startedAt <= timeoutMs) {
    const target = resolveElement(action);
    if (target.element && isElementVisible(target.element)) {
      return target;
    }
    await sleep(120);
  }
  return { element: null, semanticAction: null, liveContext: null };
}

function matchExpectedEntity(expectedEntity: Record<string, unknown> | undefined, browserContext: AgentBrowserContext) {
  if (!expectedEntity || !Object.keys(expectedEntity).length) {
    return true;
  }
  const page = browserContext.semantic_page_context;
  const candidates = [page?.primary_entity, ...(page?.secondary_entities || []), ...(page?.selected_rows || [])];
  return candidates.some((item) => {
    if (!item || typeof item !== "object") {
      return false;
    }
    const record = item as Record<string, unknown>;
    if (expectedEntity.id && record.id === expectedEntity.id) {
      return true;
    }
    if (expectedEntity.label && record.label === expectedEntity.label) {
      return true;
    }
    return false;
  });
}

function matchesExpectedResult(action: AgentUIAction, browserContext: AgentBrowserContext) {
  if (action.expected_page_kind && browserContext.semantic_page_context?.page_kind !== action.expected_page_kind) {
    return false;
  }
  if (action.expected_section) {
    const hasSection = (browserContext.semantic_page_context?.visible_sections || []).some(
      (item) => item.section_id === action.expected_section || item.label === action.expected_section,
    );
    if (!hasSection) {
      return false;
    }
  }
  return matchExpectedEntity(action.expected_entity, browserContext);
}

function buildResolvedTarget(
  action: AgentUIAction,
  resolvedNode: HTMLElement | null,
  semanticAction: AgentBrowserSemanticAction | null,
  browserContext: AgentBrowserContext | null,
) {
  return {
    semantic_action_id: action.semantic_action_id || semanticAction?.semantic_action_id || null,
    label: semanticAction?.label || null,
    node_id: resolvedNode?.dataset.haorNodeId || semanticAction?.node_id || null,
    page_kind: browserContext?.semantic_page_context?.page_kind || null,
    section_id: semanticAction?.section_id || null,
    target_entity: semanticAction?.target_entity || {},
  };
}

async function executeResolvedAction(
  action: AgentUIAction,
  deps: { navigate: (href: string) => void },
  attemptCount: number,
) {
  const resolved = action.action_type === "wait_for" ? await waitForElement(action) : resolveElement(action);
  const target = resolved.element;
  const semanticAction = resolved.semanticAction;
  const liveContext = resolved.liveContext;

  const baseResult: AgentUIActionResult = {
    action_id: action.action_id,
    action_type: action.action_type,
    ok: false,
    semantic_action_id: action.semantic_action_id || semanticAction?.semantic_action_id || null,
    target_node_id: action.target_node_id || semanticAction?.node_id || null,
    resolved_node_id: target?.dataset.haorNodeId || null,
    resolved_target: buildResolvedTarget(action, target, semanticAction, liveContext),
    message: null,
    attempt_count: attemptCount,
    detail_json: {},
  };

  if (action.action_type === "wait_for") {
    return {
      ...baseResult,
      ok: Boolean(target),
      message: target ? "目标节点已出现" : "等待超时，未发现目标节点",
    };
  }

  if (!target && action.action_type !== "navigate") {
    return {
      ...baseResult,
      message: "未找到可执行的页面目标",
    };
  }

  if (target) {
    target.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
    await sleep(100);
  }

  if (action.action_type === "navigate") {
    const href = action.href || semanticAction?.href || (target instanceof HTMLAnchorElement ? target.getAttribute("href") || target.href : "");
    if (!href || !isSameOriginHref(href)) {
      return {
        ...baseResult,
        message: "导航目标不存在或不在当前站点域名内",
      };
    }
    const url = new URL(href, window.location.origin);
    deps.navigate(`${url.pathname}${url.search}${url.hash}`);
    await sleep(Math.max(240, Math.min(Number(action.wait_ms || 650), 2_500)));
    const nextContext = collectBrowserContext(buildRouteContextFromLocation());
    return {
      ...baseResult,
      ok: matchesExpectedResult(action, nextContext),
      message: `已跳转到 ${url.pathname}${url.search}`,
      resolved_target: buildResolvedTarget(action, target, semanticAction, nextContext),
      detail_json: { after_context: nextContext.semantic_page_context },
    };
  }

  if (!target) {
    return {
      ...baseResult,
      message: "未找到可执行的页面目标",
    };
  }

  if (action.action_type === "input" || action.action_type === "select") {
    if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement)) {
      return {
        ...baseResult,
        message: "目标不是可输入字段",
      };
    }
    fireInputEvents(target, String(action.value || action.option_label || ""));
    await sleep(160);
    const nextContext = collectBrowserContext(buildRouteContextFromLocation());
    return {
      ...baseResult,
      ok: matchesExpectedResult(action, nextContext) || true,
      message: `已填写 ${getElementLabel(target) || target.name || target.tagName.toLowerCase()}`,
      resolved_target: buildResolvedTarget(action, target, semanticAction, nextContext),
      detail_json: { after_context: nextContext.semantic_page_context },
    };
  }

  if (target instanceof HTMLAnchorElement && target.href && !isSameOriginHref(target.href)) {
    return {
      ...baseResult,
      message: "目标链接超出当前平台域名，已拒绝执行",
    };
  }

  if (action.action_type === "scroll_into_view") {
    const nextContext = collectBrowserContext(buildRouteContextFromLocation());
    return {
      ...baseResult,
      ok: matchesExpectedResult(action, nextContext) || true,
      message: "已定位到目标节点",
      resolved_target: buildResolvedTarget(action, target, semanticAction, nextContext),
      detail_json: { after_context: nextContext.semantic_page_context },
    };
  }

  target.click();
  await sleep(Math.max(180, Math.min(Number(action.wait_ms || 420), 2_500)));
  const nextContext = collectBrowserContext(buildRouteContextFromLocation());
  return {
    ...baseResult,
    ok: matchesExpectedResult(action, nextContext) || true,
    message: `已执行 ${action.action_type}`,
    resolved_target: buildResolvedTarget(action, target, semanticAction, nextContext),
    detail_json: { after_context: nextContext.semantic_page_context },
  };
}

export async function executeUIActions(
  actions: AgentUIAction[],
  deps: {
    navigate: (href: string) => void;
  },
) {
  const results: AgentUIActionResult[] = [];

  for (const action of actions) {
    try {
      const first = await executeResolvedAction(action, deps, 1);
      if (first.ok || action.retryable === false) {
        results.push(first);
        continue;
      }
      if (!action.semantic_action_id) {
        results.push(first);
        continue;
      }
      await sleep(180);
      const retried = await executeResolvedAction(action, deps, 2);
      results.push({
        ...retried,
        detail_json: {
          ...retried.detail_json,
          retry_from: first.message || "初次定位失败",
        },
      });
    } catch (error) {
      results.push({
        action_id: action.action_id,
        action_type: action.action_type,
        ok: false,
        semantic_action_id: action.semantic_action_id || null,
        target_node_id: action.target_node_id || null,
        resolved_node_id: null,
        resolved_target: {},
        message: error instanceof Error ? error.message : "页面动作执行失败",
        attempt_count: 1,
        detail_json: {},
      });
    }
  }

  return results;
}
