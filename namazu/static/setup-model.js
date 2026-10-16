/* Setup explains supplied evidence; it never makes requests or creates credentials. */
(function (root) {
  'use strict';
  const DENIAL_MESSAGE = 'The request was denied. Credentials, endpoint roles or resource permissions may be responsible. This response does not distinguish them.';
  const own = (value, key) => Object.prototype.hasOwnProperty.call(value || {}, key);
  const object = value => value && typeof value === 'object' && !Array.isArray(value);
  const requiredNames = schema => Array.isArray(schema.required) ? schema.required : [];
  const escape = value => String(value).replace(/~/g, '~0').replace(/\//g, '~1');
  const sensitive = name => /(?:authorization|cookie|password|passwd|secret|token|api[-_]?key|credential)/i.test(name);
  const identity = value => ({a: 'primary', 'identity a': 'primary', b: 'secondary', 'identity b': 'secondary'}[String(value || '').toLowerCase()] || String(value || '').trim());
  const PROFILES = [
    {id: 'passive', label: 'Start with a baseline', detail: 'One permitted baseline request per operation, then review its response and the specification. Inventory, if selected, is separate.', budget: 1, concurrency: 1},
    {id: 'readonly', label: 'Read-only checks', detail: 'Adds bounded input, access and HTTP checks where the method and available controls permit them. Does not authorize POST or other writes.', budget: 90, concurrency: 4},
    {id: 'thorough', label: 'Extended read-only checks', detail: 'Adds timing probes and a short rate-limit burst. Review possible load and generation costs before selecting it.', budget: 160, concurrency: 6},
    {id: 'writes', label: 'Checks that may write', detail: 'Permits selected write operations and request-body tests only with separate write authorization. Confirm costs, disposable resources and cleanup first.', budget: 220, concurrency: 4}
  ];

  function pointer(value, path) {
    if (path === '') return {present: value !== undefined, value};
    let current = value;
    for (const part of path.slice(1).split('/')) {
      const key = part.replace(/~1/g, '/').replace(/~0/g, '~');
      if (!object(current) && !Array.isArray(current) || !own(current, key)) return {present: false};
      current = current[key];
    }
    return {present: true, value: current};
  }
  function placeholder(value) {
    if (typeof value !== 'string') return false;
    const text = value.trim();
    return /^(?:string|example|example[-_ ]?(?:id|value)|your[-_ ].+|change[-_ ]?me|replace[-_ ].+|<[^>]+>|\{[^{}]+\})$/i.test(text)
      || /^0{8}-0{4}-[04]0{3}-[08]0{3}-0{12}$/i.test(text)
      || /^https?:\/\/(?:www\.)?example\.(?:com|org|net)(?:[/:?#]|$)/i.test(text);
  }
  function safeExample(value) {
    if (Array.isArray(value)) return value.map(safeExample);
    if (object(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sensitive(key) ? '<redacted>' : safeExample(item)]));
    if (typeof value === 'string') return value.replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+\/-]+=*/gi, '<redacted>');
    return value;
  }
  function requestFields(spec, operation, request) {
    spec = spec || {}; operation = operation || {}; request = request || {};
    const document = spec.document || spec;
    const warnings = [];
    const fields = new Map();
    const maximum = 400;
    function warn(code, detail, path) {
      if (!warnings.some(item => item.code === code && item.pointer === (path || ''))) warnings.push({code, detail, pointer: path || ''});
    }
    function resolve(source, seen) {
      if (!object(source)) return {};
      if (!source.$ref) return source;
      const ref = source.$ref;
      if (seen.includes(ref) || seen.length >= 20) {
        warn('recursive-schema', 'A recursive schema needs manual input review.', ref); return {};
      }
      if (!ref.startsWith('#/')) {
        warn('unresolved-schema', 'This schema reference is not bundled in the imported specification. Import a bundled specification to review its inputs.', ref); return {};
      }
      let path;
      try { path = decodeURIComponent(ref.slice(1)); } catch { path = ''; }
      const found = path && pointer(document, path);
      if (!found || !found.present || !object(found.value)) {
        warn('unresolved-schema', 'This schema reference could not be resolved in the imported specification.', ref); return {};
      }
      return {...resolve(found.value, [...seen, ref]), ...Object.fromEntries(Object.entries(source).filter(([key]) => key !== '$ref'))};
    }
    function merge(left, right) {
      const properties = {...left.properties};
      Object.entries(right.properties || {}).forEach(([key, value]) => {
        properties[key] = properties[key] ? {allOf: [properties[key], value]} : value;
      });
      return {...left, ...right, properties,
        required: [...new Set([...requiredNames(left), ...requiredNames(right)])],
        readOnly: left.readOnly === true || right.readOnly === true,
        writeOnly: left.writeOnly === true || right.writeOnly === true};
    }
    function variants(source, depth, seen) {
      if (depth > 20) { warn('schema-depth-limit', 'Deeply nested inputs need manual review.'); return [{}]; }
      const resolved = resolve(source, seen || []);
      const plain = Object.fromEntries(Object.entries(resolved).filter(([key]) => !['allOf', 'anyOf', 'oneOf'].includes(key)));
      let out = [plain];
      const intersect = parts => {
        const combined = [];
        for (const left of out) for (const right of parts) {
          if (combined.length >= 32) { warn('schema-variant-limit', 'Additional schema alternatives need manual review.'); break; }
          combined.push(merge(left, right));
        }
        out = combined;
      };
      (resolved.allOf || []).forEach(part => intersect(variants(part, depth + 1, source.$ref ? [...(seen || []), source.$ref] : seen)));
      for (const key of ['oneOf', 'anyOf']) if (Array.isArray(resolved[key]) && resolved[key].length) {
        intersect(resolved[key].flatMap(part => variants(part, depth + 1, seen)).slice(0, 32));
      }
      return out;
    }
    function examples(schema) {
      const choices = [];
      if (own(schema, 'example')) choices.push({value: schema.example, source: 'schema example'});
      if (Array.isArray(schema.examples)) schema.examples.forEach(value => choices.push({value, source: 'schema example'}));
      if (own(schema, 'default')) choices.push({value: schema.default, source: 'schema default'});
      if (own(schema, 'const')) choices.push({value: schema.const, source: 'declared constant'});
      if (Array.isArray(schema.enum)) schema.enum.slice(0, 5).forEach(value => choices.push({value, source: 'allowed value'}));
      return choices.filter((item, index) => choices.findIndex(other => JSON.stringify(other.value) === JSON.stringify(item.value)) === index).slice(0, 5);
    }
    function walk(schemas, location, path, needed, conditional, supplied, depth, description) {
      if (depth > 16 || fields.size >= maximum) { warn('input-review-limit', 'Additional nested request inputs need manual review.', path); return; }
      const alternatives = schemas.flatMap(schema => variants(schema, 0, []));
      const writable = alternatives.filter(schema => schema.readOnly !== true);
      if (!writable.length) return;
      const required = needed && writable.length === alternatives.length;
      const properties = [...new Set(writable.flatMap(schema => [...Object.keys(schema.properties || {}), ...requiredNames(schema)]))];
      const found = pointer(supplied, path);
      const privateField = sensitive(path) || writable.some(schema => schema.writeOnly === true);
      const choices = writable.flatMap(examples).filter((item, index, all) => all.findIndex(other => JSON.stringify(other.value) === JSON.stringify(item.value)) === index);
      const types = [...new Set(writable.flatMap(schema => Array.isArray(schema.type) ? schema.type : [schema.type || (Object.keys(schema.properties || {}).length ? 'object' : 'unspecified')]))];
      if (path || !properties.length) {
        const id = location + ':' + path;
        const probablePlaceholder = found.present && placeholder(found.value);
        const valueState = !found.present ? 'missing' : probablePlaceholder ? 'review-example' : 'provided';
        fields.set(id, {id, location, pointer: path, name: path.split('/').pop().replace(/~1/g, '/').replace(/~0/g, '~') || 'request body',
          type: types.join(' or '), required, conditional: !!conditional,
          description: description || writable.find(schema => schema.description)?.description || '',
          examples: privateField ? [] : choices.map(item => ({...item, value: safeExample(item.value), probable_placeholder: placeholder(item.value)})),
          example_redacted: privateField && choices.length > 0, sensitive: privateField,
          provided: found.present, value_state: valueState, probable_placeholder: probablePlaceholder,
          unresolved: (required && !conditional && !found.present) || probablePlaceholder,
          nullable: writable.some(schema => schema.nullable || schema.type === 'null' || Array.isArray(schema.type) && schema.type.includes('null'))});
      }
      properties.forEach(key => {
        const present = writable.filter(schema => own(schema.properties, key) || requiredNames(schema).includes(key));
        const childRequired = present.length === writable.length && present.every(schema => requiredNames(schema).includes(key));
        const sometimesRequired = present.some(schema => requiredNames(schema).includes(key)) && !childRequired;
        const parentOptional = conditional || (!required && !found.present);
        walk(present.map(schema => schema.properties?.[key] || {}), location, path + '/' + escape(key), childRequired,
          parentOptional || present.length !== writable.length || sometimesRequired, supplied, depth + 1);
      });
      const arrays = writable.filter(schema => schema.type === 'array' && object(schema.items));
      if (arrays.length) walk(arrays.map(schema => schema.items), location, path + '/0',
        arrays.every(schema => schema.minItems > 0), conditional || !found.present || !Array.isArray(found.value) || !found.value.length,
        supplied, depth + 1, 'First array item; the same schema applies to further items.');
    }
    let body = request.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch { /* Retain a non-JSON body as provided. */ } }
    const requestBody = resolve(operation.request_body || operation.requestBody, []);
    const mediaEntries = Object.entries(requestBody.content || {});
    const selectedMedia = mediaEntries.find(([name]) => name === request.content_type) || mediaEntries.find(([name]) => /json/i.test(name)) || mediaEntries[0];
    if (selectedMedia) {
      const media = selectedMedia[1];
      let schema = media.schema || {};
      if (own(media, 'example')) schema = {...schema, example: media.example};
      walk([schema], 'body', '', requestBody.required === true, false, body, 0, requestBody.description);
      const bodyExamples = [own(media, 'example') ? media.example : undefined,
        ...Object.values(media.examples || {}).filter(example => object(example) && own(example, 'value')).map(example => example.value),
        ...variants(schema, 0, []).flatMap(examples).map(example => example.value)].filter(object);
      bodyExamples.forEach(bodyExample => fields.forEach(field => {
        if (field.location !== 'body' || field.sensitive) return;
        const example = pointer(bodyExample, field.pointer);
        if (example.present && !field.examples.some(item => JSON.stringify(item.value) === JSON.stringify(example.value))) field.examples.unshift({value: safeExample(example.value), source: 'request example', probable_placeholder: placeholder(example.value)});
      }));
    }
    (operation.parameters || []).forEach(raw => {
      const parameter = resolve(raw, []);
      if (!parameter.name || !['path', 'query', 'header', 'cookie'].includes(parameter.in)) return;
      let schema = parameter.schema || Object.values(parameter.content || {})[0]?.schema || parameter;
      if (own(parameter, 'example')) schema = {...schema, example: parameter.example};
      const parameterExamples = Object.values(parameter.examples || {}).filter(example => object(example) && own(example, 'value')).map(example => example.value);
      if (parameterExamples.length) schema = {...schema, examples: [...parameterExamples, ...(schema.examples || [])]};
      const path = '/' + escape(parameter.name);
      const supplied = {};
      const key = parameter.in + '.' + parameter.name;
      if (own(request.parameters, key)) supplied[parameter.name] = request.parameters[key];
      else if (own(request.parameters?.[parameter.in], parameter.name)) supplied[parameter.name] = request.parameters[parameter.in][parameter.name];
      walk([schema], parameter.in, path, parameter.required === true || parameter.in === 'path', false, supplied, 0, parameter.description);
    });
    const output = [...fields.values()];
    return {fields: output, unresolved: output.filter(field => field.unresolved), warnings};
  }

  function authenticationState(authentication, baseline) {
    const value = authentication || {};
    const response = baseline?.exchange || baseline || {};
    if (Number(response.status) === 403) return {state: 'inconclusive', detail: DENIAL_MESSAGE};
    if (response.error && !Number(response.status)) return {state: 'inconclusive', detail: 'No response was received for the baseline. Authentication and resource access remain unknown.'};
    if (Number(response.status) === 401) return {state: 'unverified', detail: 'The request was not accepted as authenticated. Check the credential value, expiry, intended API and how it is attached.'};
    if (value.error || value.status === 'failed' || value.expired === true) return {state: 'unverified', detail: 'Token acquisition failed or the configured credential may have expired. No authenticated API access has been established.'};
    if (value.status === 'verified' && value.basis === 'identity-response' && value.identity_match === true && value.current_credentials_match === true
      && Number(value.response_status) >= 200 && Number(value.response_status) < 300) {
      return {state: 'verified', detail: 'An explicit identity response matched the active identity and current credentials. Resource permissions still need their own checks.'};
    }
    return {state: 'unverified', detail: 'Attaching credentials, decoding a token or obtaining one does not establish that this API accepts it or grants access to this resource.'};
  }
  function blockerAction(blocker) {
    const codes = [blocker?.code, blocker?.reason, ...(blocker?.reason_codes || [])].filter(Boolean).join(' ').toLowerCase();
    if (blocker?.state === 'not-applicable' || /method-not-applicable|requires-get|unsupported-method|no-applicable|no-request-body|no-input/.test(codes)) return {id: 'none', kind: 'not-applicable', label: 'Does not apply to this operation'};
    if (/second-identity|cross-identity|permission-matrix|explicit-permission|resource-and-content|boundary-definition/.test(codes)) return {id: 'permissions', kind: 'missing-setup', label: 'Configure a second identity and expected permissions'};
    if (/identity|credential|authentication|token/.test(codes)) return {id: 'identity', kind: 'missing-setup', label: 'Configure the active identity'};
    if (/assertion|positive-control|successful-business|successful-baseline/.test(codes)) return {id: 'baseline', kind: 'missing-setup', label: 'Supply a known-good request and define success assertions'};
    if (/example|input|data|parameter|request-required/.test(codes)) return {id: 'data', kind: 'missing-setup', label: 'Supply valid request data'};
    if (/timeout|execution-error|budget|incomplete/.test(codes)) return {id: 'replay', kind: 'incomplete', label: 'Prepare a bounded replay'};
    if (/write|mutating|scope|profile/.test(codes)) return {id: 'plan', kind: 'policy', label: 'Review the selected scope and traffic permissions'};
    return {id: 'evidence', kind: 'review', label: 'Inspect the recorded exchange'};
  }
  function deriveSetup(input) {
    input = input || {};
    const spec = input.spec;
    const operation = input.operation || spec?.operations?.[0] || {};
    const data = requestFields(spec, operation, input.request);
    const configured = input.credentials_configured === true;
    const servers = [...new Set([...(spec?.servers || []), ...(operation.servers || [])].map(server => typeof server === 'string' ? server : server.url).filter(Boolean))];
    const target = input.target_selected !== false && (servers.length <= 1 || input.target_selected === true)
      && /^https?:\/\//i.test(input.base_url || '') && (input.base_url !== spec?.source_url || input.target_selected === true);
    const prepared = input.prepared || {};
    const matchingIdentity = !!prepared.identity_ref && identity(prepared.identity_ref) === identity(input.identity_ref);
    const matchingOperation = !!operation.id && prepared.operation === operation.id;
    let matchingTarget = false;
    try {
      const selected = new URL(input.base_url);
      const recorded = new URL(prepared.request?.url);
      const prefix = selected.pathname.replace(/\/$/, '');
      matchingTarget = recorded.origin === selected.origin && (recorded.pathname === prefix || recorded.pathname.startsWith(prefix + '/'));
    } catch { /* A missing or invalid target cannot establish a matching control. */ }
    const positive = prepared.positive_control === true && prepared.expectation?.negative !== true
      && Number(prepared.recorded_response?.status) >= 200 && Number(prepared.recorded_response?.status) < 300
      && !(prepared.missing_prerequisites || []).length && matchingIdentity && matchingOperation && matchingTarget;
    const second = input.second_identity === true || typeof input.second_identity === 'string' && !!input.second_identity.trim() && identity(input.second_identity) !== identity(input.identity_ref);
    const rows = Array.isArray(input.permission_matrix) ? input.permission_matrix : [];
    const permissions = rows.length > 0 && rows.every(row => ['allow', 'deny'].includes(row.expect));
    const auth = authenticationState(input.authentication, input.baseline);
    const items = [
      {id: 'specification', label: 'Specification', state: spec ? 'loaded' : 'missing', detail: spec ? `${spec.title || 'Untitled API'}; ${(spec.operations || []).length} documented operations.` : 'Import an OpenAPI file, specification URL or supported documentation page.', action: 'api'},
      {id: 'target', label: 'API target', state: target ? 'selected' : 'missing', detail: target ? 'Requests use the selected API server. The documentation page is a separate source.' : 'Choose the API server explicitly before sending requests.', action: 'api'},
      {id: 'credentials', label: 'Credentials', state: configured ? 'configured' : 'missing', detail: configured ? `Credentials are attached for ${input.identity_ref || 'the active identity'}; acceptance is not yet implied.` : 'Configure how credentials are attached, or deliberately use an anonymous identity.', action: 'identity'},
      {id: 'authentication', label: 'Authentication', ...auth, action: 'identity'},
      {id: 'business-baseline', label: 'Successful business baseline', state: positive ? 'established' : 'missing', detail: positive ? 'The recorded request and its resource and content assertions established a positive control for that operation and identity.' : 'Supply valid data and define expected resource and content. A 2xx response alone or an expected denial is insufficient.', action: 'baseline'},
      {id: 'second-identity', label: 'Second identity', state: second ? 'configured' : 'missing', detail: second ? 'A distinct second identity is configured. It still needs its own successful resource control.' : 'A distinct second identity is needed for controlled access comparisons.', action: 'permissions'},
      {id: 'permissions', label: 'Permission expectations', state: permissions ? 'configured' : 'missing', detail: permissions ? 'Explicit allowed or denied outcomes are supplied. Review resource/content assertions and each identity control before executing a boundary plan.' : 'State which identity may access which resource. Cross-user access is not assumed forbidden.', action: 'permissions'}
    ];
    const method = String(operation.method || 'GET').toUpperCase();
    const mutating = !['GET', 'HEAD', 'OPTIONS'].includes(method);
    const canRun = spec ? ['Review specification declarations without sending requests.'] : [];
    const requires = [];
    if (spec && target && !mutating) canRun.push('Send a permitted baseline and review any received response; HTTP 200 is not required for response observations.');
    if (spec && target && mutating && input.profile === 'writes' && input.allow_writes === true) canRun.push('Send the selected write operation and bounded input cases within the reviewed scope and budget, even when the baseline is denied.');
    else if (mutating) requires.push('This operation may write or generate content. Select the writes profile and explicitly authorize the selected scope before any endpoint request.');
    if (!positive) requires.push('Success-dependent comparisons need a successful business baseline with resource and content assertions.');
    if (!second || !permissions) requires.push('Entitlement and cache-isolation comparisons need a second identity, expected permissions and successful controls for both identities.');
    if (data.unresolved.length) requires.push(`${data.unresolved.length} request input${data.unresolved.length === 1 ? '' : 's'} need values or example review; generated examples do not establish valid business data.`);
    const suggestion = positive && !mutating ? 'readonly' : 'passive';
    const ownerLines = ['Please provide test data and permissions for ' + (operation.id || `${method} ${operation.path || '(operation not selected)'}`) + '.',
      'I need a known-good request for an authorized test resource, the required endpoint roles and resource entitlements, and the expected successful response with meaningful resource/content assertions.'];
    if (data.unresolved.length) ownerLines.push('Inputs to confirm: ' + data.unresolved.map(field => field.location + ' ' + (field.pointer || '/') + ' (' + field.type + ')').join(', ') + '.');
    ownerLines.push('For access comparisons, provide a separate test identity and explicit allowed/denied permissions for that resource. Confirm generation costs, permitted writes and cleanup. Please share credentials through your approved secure channel.');
    return {...data, items, authentication: auth, suggested_profile: suggestion, profiles: PROFILES,
      profile_reason: suggestion === 'readonly' ? 'A recorded business baseline supports review of applicable read-only comparisons. Each check still evaluates its own prerequisites.' : 'Start by establishing what one permitted request does. POST and other write operations still require the writes profile and explicit authorization.',
      can_run: canRun, requires, owner_request: ownerLines.join('\n\n'), denial_message: DENIAL_MESSAGE};
  }
  function trafficSummary(input) {
    input = input || {};
    const profile = PROFILES.find(item => item.id === input.profile) || PROFILES[1];
    const operationCount = Math.max(0, Number(input.operation_count) || 0);
    const perOperation = Math.min(profile.budget, Math.max(1, Number(input.request_budget) || profile.budget));
    const endpointBound = operationCount * perOperation;
    const inventoryKnown = Number.isFinite(input.inventory_planned_requests);
    const inventory = input.inventory === true ? (inventoryKnown ? Math.max(0, input.inventory_planned_requests) : null) : 0;
    return {endpoint_upper_bound: endpointBound, per_operation_budget: perOperation,
      inventory_requests: inventory, inventory_label: inventory === null ? 'Inventory traffic is separate; its request count has not been planned.' : `${inventory} inventory requests planned separately.`,
      planned_endpoint_requests: Number.isFinite(input.planned_endpoint_requests) ? Math.max(0, input.planned_endpoint_requests) : null,
      total_upper_bound: inventory === null ? null : endpointBound + inventory,
      concurrency: Math.max(1, Number(input.concurrency) || profile.concurrency),
      label: `Up to ${endpointBound} endpoint attempts across ${operationCount} operations; ${perOperation} per-operation budget. This is an upper bound, not a coverage target.`,
      requests_sent: 0};
  }
  const api = {deriveSetup, requestFields, authenticationState, blockerAction, trafficSummary, placeholder, DENIAL_MESSAGE, PROFILES};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.NamazuSetup = api;
}(typeof globalThis !== 'undefined' ? globalThis : this));
