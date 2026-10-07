"""External entity probes for operations that accept XML.

The probe proves the capability without using it. An external entity is
pointed at a path that does not exist, named with a nonce, and the question is
whether the parser's own error echoes that path back: if it does, the parser
resolved an external entity, which is the whole finding. No real file is ever
requested, so nothing sensitive reaches the report and nothing on the target is
read.

Two things make this reportable without a callback server. Entity expansion is
self-discriminating: an entity declared as a nonce either comes back as the
nonce, meaning the parser expanded it, or comes back as ``&ns;``, meaning it
did not. And the probe works even when the document is rejected as invalid,
because entity expansion happens in the parser, before any model validation,
so a 400 that echoes the expanded value is as good as a 200.

The one way that reasoning fails is an endpoint that echoes the request body
back in its error. Then the nonce appears in the response having never been
expanded at all. So every signal is discarded if the response contains the
markup that was sent, and an echo control runs first to find out.
"""
from __future__ import annotations

import re
import secrets

from .model import finding, mark

# Media types whose bodies go to an XML parser.
XML_MEDIA = re.compile(r"^(?:application|text)/(?:[\w.+-]*\+)?xml$", re.IGNORECASE)
# A parser that says this has DTD processing turned off, which is the fix. Seeing
# it is a pass, and a reason to stop probing rather than spend another request.
REFUSED = re.compile(
    r"(?i)(doctype is disallowed|dtd(?:s)? (?:are|is) (?:not |dis)allowed|"
    r"doctypedecl|external entit(?:y|ies) (?:are |is )?(?:not allowed|disabled)|"
    r"entity expansion|disallow-doctype-decl|feature_secure_processing|"
    r"prohibit-dtd|xxe)")
# Markup that can only be in a response because the body came back. If the
# parser had expanded the entity, none of this would still be there. The
# escaped forms matter too: an endpoint that quotes the body into JSON or HTML
# escapes the angle brackets, and the nonce would still be sitting inside the
# declaration having never been expanded.
ECHOED = re.compile(r"(?i)(<!doctype|<!entity|&lt;!doctype|&lt;!entity|"
                    r"&ns;|&amp;ns;|\\u003c!doctype|\\u003c!entity)")
MAX_ELEMENTS = 3
NAME = re.compile(r"^[A-Za-z_][\w.-]*$")


def request_media(operation: dict) -> str:
    """The operation's declared XML request media type, or an empty string."""
    content = (operation.get("request_body") or operation.get("requestBody") or {}).get("content")
    if not isinstance(content, dict):
        return ""
    for name in content:
        if XML_MEDIA.match(str(name).split(";", 1)[0].strip()):
            return str(name)
    return ""


def _schema_for(operation: dict, media: str):
    content = (operation.get("request_body") or operation.get("requestBody") or {}).get("content")
    entry = content.get(media) if isinstance(content, dict) else None
    return entry.get("schema") if isinstance(entry, dict) else None


def _safe_name(value, fallback: str) -> str:
    text = str(value or "").strip()
    return text if NAME.match(text) else fallback


def shape(operation: dict, media: str) -> tuple[str, list[str]]:
    """A root element name and a few child names, from the contract.

    The document only has to reach the parser, not satisfy the model behind
    it, so this stays shallow on purpose: an element per scalar property, no
    nesting, no attributes.
    """
    schema = _schema_for(operation, media)
    schema = schema if isinstance(schema, dict) else {}
    xml_hint = schema.get("xml") if isinstance(schema.get("xml"), dict) else {}
    root = _safe_name(xml_hint.get("name") or schema.get("title"), "root")
    children: list[str] = []
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, definition in properties.items():
            if len(children) >= MAX_ELEMENTS:
                break
            kind = definition.get("type") if isinstance(definition, dict) else None
            if kind in ("object", "array"):
                continue
            hint = definition.get("xml") if isinstance(definition, dict) else None
            label = (hint or {}).get("name") if isinstance(hint, dict) else None
            children.append(_safe_name(label or name, f"field{len(children)}"))
    return root, children or ["field"]


def document(root: str, children: list[str], value: str, *, doctype: str = "") -> str:
    """A shallow XML document carrying ``value`` in its first element."""
    body = "".join(f"<{name}>{value if index == 0 else 'x'}</{name}>"
                   for index, name in enumerate(children))
    prologue = '<?xml version="1.0" encoding="UTF-8"?>'
    return f"{prologue}{doctype}<{root}>{body}</{root}>"


def internal_doctype(root: str, value: str) -> str:
    return f'<!DOCTYPE {root} [<!ENTITY ns "{value}">]>'


def external_doctype(root: str, path: str) -> str:
    return f'<!DOCTYPE {root} [<!ENTITY ns SYSTEM "{path}">]>'


def probe(executor, *, baseline, operation, endpoint, base_headers, media: str) -> list:
    """Three requests: does it echo, does it expand, does it resolve."""
    if not media or not executor.affordable(2):
        return []
    root, children = shape(operation, media)
    nonce = secrets.token_hex(4)
    headers = {**base_headers, "Content-Type": media}

    def send(label, value, doctype=""):
        return executor.send(
            baseline.method, baseline.url, label=label,
            body=document(root, children, value, doctype=doctype),
            content_type=media, headers=headers, identity="identity A", mutating=True)

    # The control, with a nonce as ordinary element text and no declaration of
    # any kind. What it establishes is whether this endpoint puts a field's
    # parsed value in its response, which is what an expanded entity would
    # ride back on, and it costs one request to know rather than guess.
    marker = f"namazu{nonce}plain"
    control = send("control: well-formed XML with no document type declaration", marker)
    if not control.ok:
        return []
    reflects = marker in (control.body or "")
    if REFUSED.search(control.body or ""):
        # The parser announced DTD processing is off before being asked.
        return []

    expanded = f"namazu{nonce}value"
    internal = send("probe an internal entity: does the parser expand a declared entity",
                    "&ns;", internal_doctype(root, expanded))
    if not internal.ok:
        return []
    internal_body = internal.body or ""
    if REFUSED.search(internal_body):
        return []
    # The nonce is in the response and the markup that declared it is not, so
    # something resolved the reference. Confirmed when the control showed this
    # endpoint reflects field values, because then expansion is the only way
    # it could have arrived; probable otherwise, where a verbose error is the
    # likelier carrier and worth reporting without asserting.
    seen = expanded in internal_body and not ECHOED.search(internal_body)
    expansion = bool(seen)

    out: list = []
    if expansion:
        out.append(finding(
            "xxe.entity-expansion", "The XML parser expands declared entities",
            "medium", "confirmed" if reflects else "probable",
            owasp="API8:2023 Security Misconfiguration",
            endpoint=endpoint,
            method=("Sent a document declaring an internal entity whose value was a one-off "
                    "nonce, referenced it in an element, and found the nonce in the response "
                    "where the reference had been, with none of the markup that declared it. "
                    "A control document carrying a nonce as ordinary element text was sent "
                    "first, to establish "
                    + ("that this endpoint reflects a field's parsed value, so expansion is "
                       "the only way the entity's value could have reached the response."
                       if reflects else
                       "whether this endpoint reflects field values; it does not, so the "
                       "nonce arrived by some other route, most likely a verbose error.")
                    + " No file or URL was requested."),
            highlights=[mark("expands declared entities", "weak",
                             "Document type declarations are being processed, which is the "
                             "prerequisite for an external entity attack.")],
            detail=(f"A declared entity was expanded in the response: the nonce “{expanded}” "
                    f"appeared where “&ns;” was sent. The parser processes document type "
                    "declarations. On its own this discloses nothing, but it is the setting "
                    "that external entity attacks depend on."),
            impact=("Entity processing is enabled. Whether that is exploitable depends on "
                    "external entity resolution, which is probed separately."),
            remediation=("Disable document type declarations on the parser. In Java set "
                         "FEATURE_SECURE_PROCESSING and disallow-doctype-decl; in Python use "
                         "defusedxml; in .NET leave XmlResolver null and DtdProcessing at "
                         "Prohibit."),
            evidence={"media_type": media, "root_element": root,
                      "status": internal.status, "reflects_field_values": reflects},
            exchanges=[control, internal],
        ))

    if not executor.affordable(1):
        return out

    # A path that cannot exist, so the only thing the probe can learn is
    # whether the parser tried to open it. Nothing on the target is read.
    absent = f"file:///namazu-{nonce}-not-a-real-path"
    external = send("probe an external entity pointed at a path that does not exist",
                    "&ns;", external_doctype(root, absent))
    if not external.ok:
        return out
    external_body = external.body or ""
    leaked = f"namazu-{nonce}-not-a-real-path" in external_body
    if REFUSED.search(external_body) or not leaked or ECHOED.search(external_body):
        return out

    out.append(finding(
        "xxe.external-entity", "The XML parser resolves external entities",
        "high", "confirmed", owasp="API8:2023 Security Misconfiguration", endpoint=endpoint,
        method=("Declared an external entity pointing at a local path that cannot exist, named "
                "with a one-off nonce, and found that path quoted back in the response. Only a "
                "parser that tried to open it could report it. The path was chosen so that "
                "nothing real was read: the capability is demonstrated, not used. A control "
                "document with no document type declaration was sent first to confirm the "
                "endpoint does not echo the body back."),
        highlights=[
            mark("resolves external entities", "weak",
                 "The parser fetches whatever a document's entities point at."),
            mark("quoted back in the response", "proof",
                 "The nonce path is unique to this run, so the parser must have attempted it."),
        ],
        detail=(f"An external entity pointing at “{absent}” was attempted by the parser: the "
                f"response quoted that path back, and it exists nowhere. Pointed at a real "
                "path instead, the same request returns the file's contents; pointed at a URL, "
                "it makes the server fetch it. Namazu did not do either."),
        impact=("Local files readable by the service can be retrieved through this endpoint, "
                "and the server can be made to issue requests to hosts it can reach but the "
                "caller cannot."),
        remediation=("Disable document type declarations and external entity resolution on the "
                     "parser. In Java set FEATURE_SECURE_PROCESSING with disallow-doctype-decl; "
                     "in Python use defusedxml; in .NET leave XmlResolver null and DtdProcessing "
                     "at Prohibit. Do not rely on filtering the document."),
        limitations=("Resolution was confirmed; disclosure was not attempted. Blind variants, "
                     "where the parser resolves the entity but reports nothing, need an "
                     "out-of-band listener and are not covered."),
        evidence={"media_type": media, "root_element": root, "entity_target": absent,
                  "status": external.status, "reflects_field_values": reflects,
                  "entity_expansion_seen": expansion},
        exchanges=[control, external],
    ))
    return out
