/**
 * Strip C0/C1 control characters from caller-supplied text before it reaches
 * the terminal. Artifact paths come from the tree being protected, so a file
 * name carrying `ESC]` or `ESC[` could otherwise rewrite the operator's
 * terminal (OSC 8 links, cursor moves, title changes). `\n` and `\t` are kept.
 *
 * Shared by every formatter that renders artifact-derived text, so a new report
 * cannot reintroduce the hole by forgetting the helper.
 */
export function sanitizeTerminalText(text: string): string {
  return text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, "?");
}
