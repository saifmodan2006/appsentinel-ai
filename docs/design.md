# Web design

Sentinel uses a midnight indigo palette and self-hosted Geist typography. The welcome screen introduces APK analysis beside the sign-in form. The signed-in workspace prioritizes submission, scan status, and the evidence behind each result. The hero artwork is decorative. Statuses use text alongside color. Assessment counts and findings always come from the API.

Desktop navigation provides room for scan and account tools. On narrow screens, a button opens the same navigation and Escape closes it. The keyboard skip link leads to the page content. Scan polling preserves focus while a job stays in the same state.

## References for coding agents

- Use [OpenAI’s Frontend App Builder](https://github.com/openai/plugins/blob/main/plugins/build-web-apps/skills/frontend-app-builder/SKILL.md) for visual concepting, implementation, and browser-based review.
- Use [Anthropic’s Frontend Design skill](https://github.com/anthropics/skills/tree/main/skills/frontend-design) for visual direction, typography, and layout critique.
- Use [Tabler](https://github.com/tabler/tabler) as an MIT-licensed reference for dashboard navigation, form states, and data hierarchy. Sentinel uses an original HTML and CSS layout.
- Use [Lucide](https://github.com/lucide-icons/lucide) for consistent line icons. The web app ships selected glyphs from `lucide-static` 1.77.0 and preserves its license notices. [Lucide license](https://github.com/lucide-icons/lucide/blob/main/LICENSE)
- Use [Geist](https://github.com/vercel/geist-font) for the UI font. The bundled variable font comes from `geist` 1.9.2 and includes the SIL Open Font License. [Geist license](https://github.com/vercel/geist-font/blob/main/OFL.txt)

For future changes, review the welcome, dashboard, upload, processing, and report states at desktop and phone widths. Run the signed-APK Playwright workflow against a real Compose stack and check keyboard focus, empty states, and completed reports. See [the testing guide](testing.md).

The redesign was reviewed in Chrome at desktop and phone widths. Automated WCAG A and AA checks reported no violations across the seven tested view and viewport combinations. [axe-core](https://github.com/dequelabs/axe-core)

## Artwork

The welcome and overview panels use `apps/web/assets/sentinel-shield.webp`, created with the built-in ImageGen tool and encoded as WebP for the site.

> Landscape website hero artwork for AppTrust Sentinel, an Android application security analysis workspace. A single physically realistic obsidian and frosted-glass shield made of stacked diamond-shaped plates, its center contains a small inset geometric checkmark cut into the glass. Floating just above a matte midnight-indigo lab surface, surrounded by two very fine concentric scan rings etched into the surface. Calm cobalt-blue and soft pale-lavender light grazing the edges, subtle teal refraction, premium 3D product photography with a tactile glass treatment. Composition: subject on the RIGHT third, occupying 55 percent of the width, nearly featureless deep midnight indigo #101628 on the left half and perimeter to blend into the site. Low-key controlled studio lighting, clean silhouette, no busy background, no grids of code. 3:2 horizontal crop. No text, no lettering, no numbers, no logo, no UI, no watermark.
