// Shields-style flat SVG badge: "McpStamp | 87 A".

export const GRADE_COLORS = { A: '#2ea44f', B: '#97ca00', C: '#dfb317', D: '#fe7d37', F: '#e05d44' };
const GREY = '#9f9f9f';

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Approximate Verdana 11px advance widths (shields uses the same approach).
function textWidth(s) {
  let w = 0;
  for (const ch of String(s)) {
    if ('ilI.,:;|!\''.includes(ch)) w += 3.5;
    else if ('fjrt()[] '.includes(ch)) w += 4.6;
    else if ('mwMW'.includes(ch)) w += 10.5;
    else if (ch >= 'A' && ch <= 'Z') w += 7.6;
    else if (ch >= '0' && ch <= '9') w += 7;
    else w += 6.6;
  }
  return Math.ceil(w);
}

/** @param {{score?:number,grade?:string}|null} result */
export function badgeSvg(result) {
  const label = 'McpStamp';
  const has = result && typeof result.score === 'number' && result.grade;
  const value = has ? `${result.score} ${result.grade}` : 'unchecked';
  const color = has ? GRADE_COLORS[result.grade] || GREY : GREY;
  const lw = textWidth(label) + 12;
  const vw = textWidth(value) + 12;
  const w = lw + vw;
  const title = has ? `McpStamp readiness score ${result.score}/100, grade ${result.grade}` : 'McpStamp: not checked yet';
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(title)}">` +
    `<title>${esc(title)}</title>` +
    `<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>` +
    `<clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>` +
    `<g clip-path="url(#r)"><rect width="${lw}" height="20" fill="#555"/><rect x="${lw}" width="${vw}" height="20" fill="${color}"/><rect width="${w}" height="20" fill="url(#s)"/></g>` +
    `<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">` +
    `<text x="${lw / 2}" y="15" fill="#010101" fill-opacity=".3">${esc(label)}</text><text x="${lw / 2}" y="14">${esc(label)}</text>` +
    `<text x="${lw + vw / 2}" y="15" fill="#010101" fill-opacity=".3">${esc(value)}</text><text x="${lw + vw / 2}" y="14">${esc(value)}</text>` +
    `</g></svg>`;
}
