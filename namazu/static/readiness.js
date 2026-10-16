/* Offline preparation. Only explicit buttons call local planning APIs. */
(function (root) {
  'use strict';
  function reportSummary(value) {
    const plan = value && value.plan;
    const prepared = (plan && plan.baseline) || (value && value.prepared) || {};
    return {positive_control: value?.draft_dirty !== true && prepared.positive_control === true,
      missing_prerequisites: (plan && plan.missing_prerequisites) || prepared.missing_prerequisites || [],
      warnings: prepared.warnings || [], owner_request: prepared.owner_request || '',
      planned_requests: plan && plan.budget ? plan.budget.planned : 0,
      requests_sent: 0,
      note: 'Preparation and planning establish no completed test coverage.'};
  }

  function mount(container, options) {
    options = options || {};
    const doc = container.ownerDocument || document;
    const context = typeof options.context === 'function' ? options.context : () => options.context || {};
    let state = options.initial || {};
    let revision = 0;
    let assertionMode = 'advanced';
    function node(tag, text, className) {
      const item = doc.createElement(tag);
      if (text !== undefined) item.textContent = text;
      if (className) item.className = className;
      return item;
    }
    function field(label, value, type, parent = form) {
      const wrapper = node('label', undefined, 'readiness-field');
      wrapper.append(node('span', label));
      const input = node(type === 'textarea' ? 'textarea' : 'input');
      if (type !== 'textarea') input.type = type || 'text';
      input.value = value ?? '';
      if (type === 'textarea') input.rows = 5;
      wrapper.append(input); parent.append(wrapper); return input;
    }
    function advanced(label, description) {
      const details = node('details', undefined, 'disclosure readiness-advanced');
      const body = node('div', undefined, 'disclosure-body');
      details.append(node('summary', label), body);
      if (description) body.append(node('p', description));
      form.append(details); return body;
    }
    function choice(label, values, selected, parent) {
      const wrapper = node('label', undefined, 'readiness-field');
      const input = node('select');
      values.forEach(([value, title]) => {const option = node('option', title); option.value = value; input.append(option);});
      input.value = selected;
      wrapper.append(node('span', label), input); parent.append(wrapper); return input;
    }
    container.replaceChildren();
    const form = node('div', undefined, 'readiness-form');
    container.append(node('h3', 'Prepare successful baseline'),
      node('p', 'Import a known-good request, assign a local identity and define what successful resource content looks like. Preparation and plans send no target requests.'), form);
    const original = state.prepared || {};
    const request = field('Known-good request (JSON, one HAR entry, or raw HTTP)',
      original.request ? JSON.stringify(original.request, null, 2) : '', 'textarea');
    const file = field('Import a request file', '', 'file');
    file.accept = '.json,.har,.txt,.http';
    const identity = field('Local identity reference', original.identity_ref || '');
    const status = field('Expected successful HTTP status', original.expectation && original.expectation.status || '200');
    const negativeLabel = node('label');
    const negative = node('input'); negative.type = 'checkbox'; negative.checked = !!(original.expectation && original.expectation.negative);
    negativeLabel.append(negative, node('span', 'This is an expected denial (cannot unlock positive controls)')); form.append(negativeLabel);
    const assertionHelp = node('p', 'Define how the response identifies the requested resource and contains the expected business result. These assertions use response JSON pointers. A 2xx status alone does not establish either.');
    form.append(assertionHelp);
    const simple = {};
    const assertionRows = node('div', undefined, 'readiness-assertion-rows'); form.append(assertionRows);
    for (const [purpose, title, example] of [['resource', 'Identify the returned resource', '/document/id'], ['content', 'Check the expected content', '/summary']]) {
      const initial = (original.assertions || []).find(item => item.purpose === purpose && ['equals', 'contains'].includes(item.operator || 'equals')) || {};
      const group = node('fieldset', undefined, 'readiness-assertion'); group.append(node('legend', title));
      const path = field('Response field (JSON pointer)', initial.pointer || '', 'text', group); path.placeholder = 'For example: ' + example;
      const operator = choice('Comparison', [['equals', 'Equals this value'], ['contains', 'Contains this value']], initial.operator || 'equals', group);
      const type = choice('Value format', [['text', 'Text'], ['json', 'JSON number, boolean, array or object']], typeof initial.expected === 'string' || initial.expected === undefined ? 'text' : 'json', group);
      const expected = field('Expected value', initial.expected === undefined ? '' : typeof initial.expected === 'string' ? initial.expected : JSON.stringify(initial.expected), 'text', group);
      simple[purpose] = {path, operator, type, expected}; assertionRows.append(group);
    }
    const assertionAdvanced = advanced('Advanced response assertions', 'Add additional resource or content assertions, or edit their JSON directly. The simple controls update the first matching resource and content assertion; additional assertions are preserved.');
    const assertions = field('Business assertions (JSON array)', JSON.stringify(original.assertions || [], null, 2), 'textarea', assertionAdvanced);
    const recordedAdvanced = advanced('Use an exchange captured elsewhere', 'Leave empty to review the selected audit baseline. A successful response must retain its exact request, identity and full response. A response detached from its request cannot establish a control.');
    const recorded = field('Recorded successful exchange (optional JSON override)',
      original.recorded_response ? JSON.stringify(original.recorded_response, null, 2) : '', 'textarea', recordedAdvanced);
    recordedAdvanced.append(node('p', 'Include method, url, request_headers, request_body, identity_ref, status, response_headers and response_body. No exchange is replayed during review.'));
    const followup = advanced('Prepare deeper tests or retry incomplete cases', 'Define the permissions and constraints to test, then build a bounded plan. Planning does not authorize writes, change scope or execute requests.');
    const matrix = field('Permission matrix (JSON array; explicit allow or deny)',
      JSON.stringify(state.configuration && state.configuration.permission_matrix || [], null, 2), 'textarea', followup);
    followup.append(node('p', 'Rows name kind (entitlement, cache-isolation, persona-options), identity_ref, expect, resource/content assertions and identity_control with its recorded response. Use the same baseline request for entitlement and cache checks. Persona/options rows also need a boundary_definition and an explicit request. Cross-user access is not assumed forbidden.'));
    const constraints = field('Remaining numeric/string constraints (explicit JSON cases)',
      JSON.stringify(state.configuration && state.configuration.constraints || [], null, 2), 'textarea', followup);
    followup.append(node('p', 'Constraint cases name field_pointer, mutation, expected_handling (accept or reject), and the exact request. Scope, write permissions and budget come from the current run configuration. Timeout retries remain new attempts, not reproduced responses.'));
    const budget = field('Follow-up request budget (0 to 200)', String(state.configuration?.budget ?? context().budget ?? 10), 'number', followup); budget.min = '0'; budget.max = '200';
    const rate = field('Maximum requests per second (0.1 to 100)', String(state.configuration?.requests_per_second ?? context().requests_per_second ?? 1), 'number', followup); rate.min = '0.1'; rate.max = '100'; rate.step = '0.1';
    const buttons = node('div', undefined, 'readiness-actions');
    const prepareButton = node('button', 'Review baseline readiness'); prepareButton.type = 'button';
    const planButton = node('button', 'Build follow-up and incomplete-case plan'); planButton.type = 'button';
    const useButton = node('button', 'Use as saved baseline'); useButton.type = 'button';
    buttons.append(prepareButton, useButton); form.append(buttons); followup.append(planButton);
    useButton.disabled = !state.prepared || state.draft_dirty === true;
    const result = node('div', undefined, 'readiness-result'); container.append(result);

    function display() {
      result.replaceChildren();
      const summary = reportSummary(state);
      if (state.draft_dirty) {
        result.append(node('p', 'Inputs changed. Review baseline readiness again before saving this request or using its assertions as a control. No request was sent.')); return;
      }
      if (!state.prepared && !state.plan) {
        result.append(node('p', 'No successful business baseline has been prepared. The saved audit remains unchanged.')); return;
      }
      result.append(node('h4', summary.positive_control ? 'Business assertions passed for the recorded baseline' : 'Prerequisites remain unresolved'));
      const missing = node('ul');
      summary.missing_prerequisites.forEach(item => missing.append(node('li', item.detail + ' [' + item.code + ']')));
      if (missing.childNodes.length) result.append(missing);
      summary.warnings.forEach(item => result.append(node('p', item.pointer + ': ' + item.detail, 'readiness-warning')));
      const prepared = state.plan && state.plan.baseline || state.prepared;
      if (prepared && prepared.assertion_results && prepared.assertion_results.length) {
        const list = node('ul');
        prepared.assertion_results.forEach(item => list.append(node('li', item.purpose + ' ' + item.pointer + ': ' + (item.matched ? 'matched' : 'not established'))));
        result.append(list);
      }
      if (state.plan) {
        const plan = state.plan;
        result.append(node('p', plan.budget.planned + ' planned requests / budget ' + plan.budget.limit + '; ' + plan.summary.blocked + ' blocked cases; ' + plan.summary.budget_exhausted + ' beyond budget. Requests sent: 0.'));
        plan.cases.forEach(item => {
          const detail = node('details');
          detail.append(node('summary', item.kind + ' / ' + item.identity_ref + ': ' + item.status + ' (' + item.planned_request_count + ' requests)'));
          detail.append(node('p', item.prerequisite), node('p', (item.reason_codes || []).join(', ')), node('pre', JSON.stringify(item, null, 2)));
          result.append(detail);
        });
        plan.limitations.forEach(text => result.append(node('p', text)));
      }
      result.append(node('h4', 'Request to the API owner'), node('pre', summary.owner_request));
      result.append(node('p', 'Credentials in imported requests are redacted. Configure credentials on Auth before any separately initiated execution. Viewing, importing and exporting this plan never replays POST requests.'));
    }
    function save() { useButton.disabled = !state.prepared || state.draft_dirty === true; if (typeof options.onChange === 'function') options.onChange(state); display(); }
    function invalidate() {
      revision++;
      state = {...state, prepared: null, plan: null, draft_dirty: true};
      useButton.disabled = true;
      if (typeof options.onChange === 'function') options.onChange(state);
      display();
    }
    function simpleToJson() {
      const values = JSON.parse(assertions.value || '[]');
      if (!Array.isArray(values)) throw new Error('Business assertions must be a JSON array.');
      for (const [purpose, inputs] of Object.entries(simple)) {
        const index = values.findIndex(item => item.purpose === purpose && ['equals', 'contains'].includes(item.operator || 'equals'));
        if (!inputs.path.value.trim()) {if (index >= 0) values.splice(index, 1); continue;}
        const expected = inputs.type.value === 'json' ? JSON.parse(inputs.expected.value) : inputs.expected.value;
        const assertion = {purpose, pointer: inputs.path.value.trim(), operator: inputs.operator.value, expected};
        if (index >= 0) values[index] = assertion; else values.push(assertion);
      }
      assertions.value = JSON.stringify(values, null, 2);
    }
    function jsonToSimple() {
      const values = JSON.parse(assertions.value || '[]');
      if (!Array.isArray(values)) return;
      for (const [purpose, inputs] of Object.entries(simple)) {
        const assertion = values.find(item => item.purpose === purpose && ['equals', 'contains'].includes(item.operator || 'equals')) || {};
        inputs.path.value = assertion.pointer || '';
        inputs.operator.value = assertion.operator || 'equals';
        inputs.type.value = typeof assertion.expected === 'string' || assertion.expected === undefined ? 'text' : 'json';
        inputs.expected.value = assertion.expected === undefined ? '' : typeof assertion.expected === 'string' ? assertion.expected : JSON.stringify(assertion.expected);
      }
    }
    function input(current = context()) {
      if (assertionMode === 'simple') simpleToJson();
      return {request: request.value, base_url: current.base_url || '', operation: current.operation || '',
        credential_names: Array.isArray(current.credential_names) ? [...current.credential_names] : [],
        identity_ref: identity.value.trim(), expectation: {status: status.value.trim(), negative: negative.checked},
        assertions: JSON.parse(assertions.value || '[]'),
        recorded_response: recorded.value.trim() ? JSON.parse(recorded.value) : current.baseline_exchange || null};
    }
    async function review(makePlan) {
      prepareButton.disabled = planButton.disabled = true;
      useButton.disabled = true;
      const reviewedRevision = revision;
      try {
        const reviewedContextKey = JSON.stringify(context() || {});
        const reviewedContext = JSON.parse(reviewedContextKey);
        const stale = () => {
          if (revision !== reviewedRevision) {display(); return true;}
          if (JSON.stringify(context() || {}) !== reviewedContextKey) {
            invalidate();
            result.replaceChildren(node('p', 'The target, identity or test configuration changed during review. Review baseline readiness again before saving. No target request was sent.'));
            return true;
          }
          return false;
        };
        const configuration = {permission_matrix: JSON.parse(matrix.value || '[]'), constraints: JSON.parse(constraints.value || '[]'),
          budget: Number(budget.value), requests_per_second: Number(rate.value)};
        const prepared = await options.api('/api/readiness/prepare', {...input(reviewedContext), configuration});
        if (stale()) return;
        const next = {prepared, configuration: prepared.configuration || {}};
        // Replace pasted credentials immediately with the redacted saved template.
        request.value = JSON.stringify(prepared.request, null, 2);
        if (recorded.value.trim()) recorded.value = JSON.stringify(prepared.recorded_response, null, 2);
        if (makePlan) {
          next.plan = await options.api('/api/readiness/plan', {...reviewedContext, ...next.configuration,
            baseline_exchange: prepared.recorded_response, prepared});
          if (stale()) return;
          next.configuration = next.plan.configuration || {};
        }
        state = next;
        matrix.value = JSON.stringify(state.configuration.permission_matrix || [], null, 2);
        constraints.value = JSON.stringify(state.configuration.constraints || [], null, 2);
        save();
      } catch (error) {
        result.replaceChildren(node('p', String(error.message || error)));
      } finally { prepareButton.disabled = planButton.disabled = false; }
    }
    file.addEventListener('change', async () => {
      if (!file.files || !file.files[0]) return;
      if (file.files[0].size > 1048576) { result.replaceChildren(node('p', 'Keep the request file below 1 MiB.')); return; }
      request.value = await file.files[0].text();
      invalidate();
      result.replaceChildren(node('p', 'Request loaded locally. Review baseline readiness before saving it; no request was sent.'));
    });
    prepareButton.addEventListener('click', () => review(false));
    planButton.addEventListener('click', () => review(true));
    [request, identity, status, negative, assertions, recorded, matrix, constraints, budget, rate].forEach(input => {
      input.addEventListener('input', invalidate);
      input.addEventListener('change', invalidate);
    });
    Object.values(simple).flatMap(inputs => Object.values(inputs)).forEach(input => {
      const update = () => {assertionMode = 'simple'; invalidate(); try {simpleToJson();} catch (error) {result.replaceChildren(node('p', 'Check the assertion value: ' + error.message));}};
      input.addEventListener('input', update); input.addEventListener('change', update);
    });
    const editedJson = () => {assertionMode = 'advanced'; try {jsonToSimple();} catch { /* Keep invalid JSON visible for correction. */ }};
    assertions.addEventListener('input', editedJson); assertions.addEventListener('change', editedJson);
    useButton.addEventListener('click', () => {
      if (useButton.disabled || !state.prepared) { result.replaceChildren(node('p', 'Review the request and assertions first.')); return; }
      if (typeof options.onUseBaseline !== 'function') return;
      const prepared = state.prepared;
      const contentType = Object.entries(prepared.request.headers || {}).find(([name]) => name.toLowerCase() === 'content-type')?.[1];
      options.onUseBaseline({example: {url: prepared.request.url, headers: prepared.request.headers, body: prepared.request.body,
        ...(contentType ? {content_type: contentType} : {})},
        expectation: prepared.expectation, identity_ref: prepared.identity_ref, assertions: prepared.assertions});
    });
    display();
    return {getState: () => state};
  }
  const api = {mount, reportSummary};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.NamazuReadiness = api;
}(typeof globalThis !== 'undefined' ? globalThis : this));
