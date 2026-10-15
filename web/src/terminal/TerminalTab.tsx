import { MAX_PANES, leaves, rects, type Layout } from './layout';
import { TerminalSession, type TerminalState } from './TerminalSession';
import type { ConnectChoice, Server } from '../api';

export interface PaneState {
  attempt: number;
  state: TerminalState;
}

export interface TabModel {
  tabId: string;
  server: Server;
  /** Credentials chosen for this tab; absent means the server's saved ones. Memory only. */
  choice?: ConnectChoice | undefined;
  layout: Layout;
  panes: Record<string, PaneState>;
  focused: string;
}

/** The tab's overall state, for the dot in the tab bar. */
export function tabState(tab: TabModel): TerminalState {
  const states = Object.values(tab.panes).map((p) => p.state);
  if (states.includes('reconnecting')) return 'reconnecting';
  if (states.includes('connecting')) return 'connecting';
  if (states.includes('connected')) return 'connected';
  return 'closed';
}

/**
 * One tab: its panes laid out by their rectangles. Panes are a flat list of absolutely positioned
 * boxes, so splitting or closing one never remounts (and so never drops) the others' terminals.
 */
export function TerminalTab(props: {
  tab: TabModel;
  active: boolean;
  onPaneState: (paneId: string, state: TerminalState) => void;
  onFocus: (paneId: string) => void;
  onSplit: (paneId: string, dir: 'row' | 'col') => void;
  onClosePane: (paneId: string) => void;
}) {
  const { tab } = props;
  const place = rects(tab.layout);
  const ids = leaves(tab.layout);
  return (
    <div className="pane-area" hidden={!props.active}>
      {ids.map((id) => {
        const r = place[id]!;
        return (
          <div
            key={id}
            className="pane"
            style={{ left: `${r.left}%`, top: `${r.top}%`, width: `${r.width}%`, height: `${r.height}%` }}
          >
            <TerminalSession
              server={tab.server}
              {...(tab.choice ? { choice: tab.choice } : {})}
              active={props.active}
              focused={tab.focused === id}
              attempt={tab.panes[id]!.attempt}
              onState={(s) => props.onPaneState(id, s)}
              onFocus={() => props.onFocus(id)}
              onSplit={(dir) => props.onSplit(id, dir)}
              canSplit={ids.length < MAX_PANES}
              {...(ids.length > 1 ? { onClosePane: () => props.onClosePane(id) } : {})}
            />
          </div>
        );
      })}
    </div>
  );
}
