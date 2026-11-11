const ICONS = { pass: '✔', warn: '!', fail: '✘', info: 'i' };
const COLORS = { pass: 32, warn: 33, fail: 31, info: 36 };

function paint(text, code, enabled) {
  return enabled ? `\x1b[${code}m${text}\x1b[0m` : text;
}

/** Human-readable report for the terminal. */
export function formatReport(result, { color = false } = {}) {
  const gradeColor = result.score >= 75 ? 32 : result.score >= 45 ? 33 : 31;
  const lines = [
    '',
    `  ${paint('Security headers report', 1, color)}  ${result.finalUrl}`,
    result.finalUrl !== result.url ? `  (redirected from ${result.url})` : null,
    '',
    `  Grade ${paint(result.letter, `1;${gradeColor}`, color)}  ·  score ${result.score}/100  ·  HTTP ${result.status}`,
    '',
  ].filter((l) => l !== null);

  const sections = [['Headers', result.findings], ['Site checks', result.siteFindings ?? []]];
  for (const [heading, findings] of sections) {
    if (findings.length === 0) continue;
    lines.push(`  ${paint(heading, 1, color)}`);
    for (const f of findings) {
      const icon = paint(ICONS[f.status], COLORS[f.status], color);
      const score = f.max === 0 ? 'not scored' : `${String(f.points).padStart(2)}/${f.max}`;
      lines.push(`  ${icon} ${f.title.padEnd(32)} ${score}`);
      lines.push(`      ${f.message}`);
      if (f.fix && f.status !== 'pass') lines.push(paint(`      fix: ${f.fix}`, 2, color));
    }
    lines.push('');
  }
  return lines.join('\n');
}
