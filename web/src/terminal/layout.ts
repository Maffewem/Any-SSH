/** A tab's panes as a tree of splits. Panes are rendered flat (see rects) so a split never remounts a live terminal. */
export type Layout = { kind: 'pane'; id: string } | { kind: 'split'; dir: 'row' | 'col'; a: Layout; b: Layout };

export const MAX_PANES = 6;

export const leaves = (l: Layout): string[] => (l.kind === 'pane' ? [l.id] : [...leaves(l.a), ...leaves(l.b)]);

/** Splits pane `id` into itself and a new pane `newId`. 'row' puts them side by side, 'col' stacks them. */
export function split(l: Layout, id: string, dir: 'row' | 'col', newId: string): Layout {
  if (l.kind === 'pane') return l.id === id ? { kind: 'split', dir, a: l, b: { kind: 'pane', id: newId } } : l;
  return { ...l, a: split(l.a, id, dir, newId), b: split(l.b, id, dir, newId) };
}

/** Removes pane `id`; its sibling takes the freed space. The last pane cannot be removed. */
export function remove(l: Layout, id: string): Layout {
  if (l.kind === 'pane') return l;
  if (l.a.kind === 'pane' && l.a.id === id) return l.b;
  if (l.b.kind === 'pane' && l.b.id === id) return l.a;
  return { ...l, a: remove(l.a, id), b: remove(l.b, id) };
}

export interface Rect {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** Each pane's position as percentages of the tab, every split being half and half. */
export function rects(l: Layout, r: Rect = { left: 0, top: 0, width: 100, height: 100 }, out: Record<string, Rect> = {}): Record<string, Rect> {
  if (l.kind === 'pane') {
    out[l.id] = r;
  } else if (l.dir === 'row') {
    rects(l.a, { ...r, width: r.width / 2 }, out);
    rects(l.b, { ...r, left: r.left + r.width / 2, width: r.width / 2 }, out);
  } else {
    rects(l.a, { ...r, height: r.height / 2 }, out);
    rects(l.b, { ...r, top: r.top + r.height / 2, height: r.height / 2 }, out);
  }
  return out;
}
