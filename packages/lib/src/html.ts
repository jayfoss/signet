import sanitize from 'sanitize-html';

/** The most html a message may carry, in bytes (Section 8.4.1). */
export const MAX_HTML_BYTES = 262_144;

const TAGS = [
  'a', 'abbr', 'b', 'blockquote', 'br', 'code', 'dd', 'div', 'dl', 'dt', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img', 'li', 'ol', 'p', 'pre', 's', 'span', 'strong', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr', 'u', 'ul',
];

/** Removed with everything inside them. */
const DROP_WITH_CONTENT = ['script', 'style', 'iframe', 'object', 'embed', 'svg', 'math', 'form', 'head', 'title', 'noscript', 'template', 'textarea', 'option'];

/**
 * Reduce html to what may be shown (Section 8.4.1): a short list of elements and attributes, links only to http, https
 * and mailto, and images only as `cid:` references to attachments of the same message. Nothing here can run, restyle the
 * page, or make the reader's client fetch anything.
 */
export function sanitizeHtml(html: string, attachmentCids?: string[]): string {
  const known = attachmentCids ? new Set(attachmentCids) : undefined;
  const reduced = sanitize(html, {
    allowedTags: TAGS,
    allowedAttributes: { a: ['href', 'rel'], img: ['src', 'alt', 'width', 'height'], td: ['colspan', 'rowspan'], th: ['colspan', 'rowspan'] },
    allowedSchemes: ['http', 'https', 'mailto'],
    allowedSchemesByTag: { img: ['cid'] },
    allowProtocolRelative: false,
    nonTextTags: DROP_WITH_CONTENT,
    disallowedTagsMode: 'discard',
    transformTags: {
      a: (tagName, attribs) => {
        // Only an absolute http, https or mailto link survives: a relative one would resolve against wherever the html is shown.
        const { href, ...rest } = attribs;
        const ok = href !== undefined && /^(https?|mailto):/i.test(href.trim());
        return { tagName, attribs: { ...rest, ...(ok ? { href: href as string } : {}), rel: 'noopener noreferrer' } };
      },
      // An image that is not an attachment of the message is shown as its alt text.
      img: (tagName, attribs) => {
        const src = (attribs.src ?? '').trim();
        const cid = /^cid:/i.test(src) ? src.slice(4) : undefined;
        return cid !== undefined && (!known || known.has(cid)) ? { tagName, attribs } : { tagName: 'span', attribs: {}, text: attribs.alt ?? '' };
      },
    },
  });
  // An image replaced by empty alt text leaves an empty span, which says nothing.
  return reduced.replace(/<span><\/span>/g, '');
}

const entities: Record<string, string> = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&nbsp;': ' ' };

/** The plain text of html, as a person would read it. Reduces the html first, so it is safe to use on anything. */
export function htmlToText(html: string): string {
  const spaced = sanitizeHtml(html)
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|li|tr|h[1-6]|blockquote|pre|dd|dt)>/gi, '\n');
  const bare = sanitize(spaced, { allowedTags: [], allowedAttributes: {} });
  return bare
    .replace(/&(amp|lt|gt|quot|#39|nbsp);/g, (entity) => entities[entity])
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/** Words, ignoring web addresses: a text alternative often spells out where a link goes, and the html does not repeat it. */
const words = (text: string): string[] => text.toLowerCase().replace(/\b(?:https?:\/\/|mailto:)\S+/g, ' ').match(/[\p{L}\p{N}]+/gu) ?? [];

/**
 * Whether a message's text and its html say different things: more than a third of the words of either are missing
 * from the other. Plain-text alternatives are often shorter or laid out differently, so small differences pass.
 */
export function textDiverges(text: string, html: string): boolean {
  const fromText = words(text);
  const fromHtml = words(htmlToText(html));
  if (fromText.length < 3 && fromHtml.length < 3) return false;
  const missing = (of: string[], from: string[]): number => {
    if (of.length === 0) return 0;
    const known = new Set(from);
    return of.filter((word) => !known.has(word)).length / of.length;
  };
  return missing(fromHtml, fromText) > 1 / 3 || missing(fromText, fromHtml) > 1 / 3;
}
