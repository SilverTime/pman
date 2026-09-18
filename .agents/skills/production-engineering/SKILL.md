---
name: production-engineering
description: Apply a production-grade delivery workflow whenever building or changing a user-facing application, desktop app, dashboard, SaaS feature, or full-stack workflow. Trigger especially for requests such as "commercial product", "production ready", "not an AI-generated page", "polished", "real software", or improving an existing app. Cover real domain behavior, state completeness, security, accessibility, testing, build verification, and browser-based acceptance. Use alongside frontend-design and ui-ux-pro-max for UI work; skip tiny text-only or isolated backend maintenance.
---

# Production Engineering

Deliver a coherent product, not a collection of attractive screens. Visual polish is successful only when the real workflow is understandable, resilient, secure, and verifiable.

## 1. Understand the product before editing

- Read the repository instructions, README, entry points, existing design tokens, API/command contracts, and tests before changing code.
- Identify the user, the screen's single job, the primary action, and the acceptance criteria. If the brief is ambiguous, choose the smallest coherent product behavior and state the assumption.
- Trace the real data path. Do not replace a working backend or command with mock data merely to make a screen look complete.
- Preserve unrelated user changes. Do not read credential stores, `.env` files, browser profiles, SSH material, or other secret-bearing files.

## 2. Design the complete state model

For every meaningful screen or action, account for:

- loading and in-progress states;
- success confirmation and the next sensible action;
- empty state with a useful explanation and CTA;
- validation errors beside the relevant field;
- recoverable failures with retry or correction guidance;
- disabled, expired, unauthorized, and destructive-action states;
- responsive, keyboard, focus, and reduced-motion behavior.

Use visible labels, semantic controls, descriptive button names, `aria-live` for asynchronous feedback, and a visible focus state. Modals need a labeled close action, an Escape/cancel route, and focus that does not strand the user.

## 3. Implement with a small, coherent system

- Establish semantic color, spacing, type, radius, elevation, and z-index tokens before adding one-off values.
- Reuse components and interaction patterns; keep one visual language across screens.
- Prefer native controls and inline SVG icons with accessible labels over emoji or unlabeled icon-only buttons.
- Keep primary actions visually dominant. Avoid adding decoration that does not explain the product or improve the task.
- Make copy user-facing: name the thing the user controls, explain what happened, and say how to recover.

## 4. Treat security as product behavior

- Enforce least privilege, explicit authorization, safe defaults, and clear scope before convenience.
- Never put secrets in UI state, logs, screenshots, test output, or responses. Only show safe metadata and redacted results.
- Validate and normalize user input at the boundary. Do not weaken existing policy, redaction, approval, or audit behavior to make a demo pass.
- For this pman project, follow the repository's credential rules exactly and use site aliases through the approved `pm` interface when access is genuinely required.

## 5. Verify before calling the work complete

Run the narrowest relevant checks and then the project build. Typical checks include:

- TypeScript/lint/build for the desktop app;
- Python unit tests for the pman core;
- Rust `cargo test` or the repository's documented Rust check when Rust code changes;
- browser verification of the actual local app, not only static source inspection.

For user-facing changes, exercise the primary flow and at least one failure/empty path. Inspect the result at compact, tablet, and desktop widths (roughly 375, 768, 1024/1440 where the platform allows), check keyboard navigation and focus, and capture screenshots as evidence. Do not use real credentials during visual or browser verification.

## 6. Handoff evidence

Finish with:

1. what changed and why;
2. the real user flow now supported;
3. commands/tests run and their results;
4. browser or screenshot checks performed;
5. known limitations or follow-up risks.

Do not claim production-ready when a required check was skipped; name the gap explicitly.
