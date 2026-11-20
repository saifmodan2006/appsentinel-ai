---
name: sentinel-design
description: Design and review AppTrust Sentinel's web workspace, including sign-in, scan intake, overview, navigation, and evidence reports.
---

Use the application as an Android APK analysis console. Start with the action the operator needs and the evidence behind it. In a report, lead with scan state, assessment, publisher identity, and findings. Keep raw metadata and tool details available further down.

- Use the surface, ink, and evergreen action colors in `apps/web/styles.css`. Reserve amber and red for review or adverse states. Show a text label as well as color for meaningful states.
- Use the CSS scan mark in `apps/web/index.html` and the existing local Geist and Lucide assets. Keep surfaces plain and static. Avoid generated hero art, gradients, glowing illustrations, decorative badges, automatic motion, and sales copy.
- Build overview metrics from the existing API responses. For new workspaces, show useful empty states and a path to submit an APK. Keep unknown publishers, unavailable checks, and active malware models distinct in the result.
- Inspect the guest view, narrow-screen navigation, APK picker, and actual completed report at desktop and phone widths. Check keyboard focus and overflow at 320 pixels. Run the signed-fixture Playwright workflow against Compose.

The project design rationale and vetted upstream references are in `docs/design.md`. The fixture and browser commands are in `docs/testing.md`.
