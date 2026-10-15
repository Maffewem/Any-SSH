import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { useEffect, useRef, useState } from 'react';
import { ApiError, notifyLocked, post, type ConnectChoice, type Server } from '../api';
import { Field, Form, Modal } from '../ui';

type Prompt =
  | { kind: 'hostkey'; fingerprint: string; keyType: string; host: string; port: number }
  | { kind: 'password'; username: string; host: string };

export type TerminalState = 'connecting' | 'connected' | 'reconnecting' | 'closed';

/** Gives up re-attaching after this many tries (about ten minutes at the capped delay). */
const MAX_RETRIES = 45;

/** Keys a phone keyboard lacks. */
const EXTRA_KEYS: { label: string; seq?: string; mod?: 'ctrl' | 'alt' }[] = [
  { label: 'Esc', seq: '\x1b' },
  { label: 'Tab', seq: '\t' },
  { label: 'Ctrl', mod: 'ctrl' },
  { label: 'Alt', mod: 'alt' },
  { label: '↑', seq: '\x1b[A' },
  { label: '↓', seq: '\x1b[B' },
  { label: '←', seq: '\x1b[D' },
  { label: '→', seq: '\x1b[C' },
  { label: '|', seq: '|' },
  { label: '~', seq: '~' },
  { label: '/', seq: '/' },
  { label: '-', seq: '-' },
];

export function TerminalSession(props: {
  server: Server;
  /** Credentials for this session, including a one-off key that is never saved. */
  choice?: ConnectChoice;
  /** This pane's tab is on screen. */
  active: boolean;
  /** This pane has the keyboard. */
  focused: boolean;
  attempt: number;
  onState: (s: TerminalState) => void;
  onFocus: () => void;
  /** Pane controls; `onClosePane` is absent for a tab's only pane. */
  onSplit: (dir: 'row' | 'col') => void;
  onClosePane?: () => void;
  canSplit: boolean;
}) {
  const container = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const modifier = useRef<'ctrl' | 'alt' | null>(null);
  const [mod, setMod] = useState<'ctrl' | 'alt' | null>(null);
  const [prompt, setPrompt] = useState<Prompt | null>(null);
  const [password, setPassword] = useState('');
  const latest = useRef(props);
  latest.current = props;

  const send = (msg: unknown) => {
    if (ws.current?.readyState === WebSocket.OPEN) ws.current.send(JSON.stringify(msg));
  };

  const sendInput = (data: string) => {
    let out = data;
    if (modifier.current === 'ctrl' && data.length === 1) {
      const c = data.toUpperCase().charCodeAt(0);
      if (c >= 64 && c <= 95) out = String.fromCharCode(c - 64);
    } else if (modifier.current === 'alt') {
      out = `\x1b${data}`;
    }
    if (modifier.current) {
      modifier.current = null;
      setMod(null);
    }
    send({ type: 'input', data: out });
  };

  // Create the terminal once.
  useEffect(() => {
    const t = new Terminal({
      cursorBlink: true,
      fontFamily: 'ui-monospace, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
      fontSize: window.matchMedia('(max-width: 600px)').matches ? 12 : 14,
      theme: { background: '#0b0f14', foreground: '#e6edf3', cursor: '#4ade80' },
      scrollback: 5000,
      allowProposedApi: false,
    });
    const f = new FitAddon();
    t.loadAddon(f);
    t.loadAddon(new WebLinksAddon((_e, uri) => window.open(uri, '_blank', 'noopener,noreferrer')));
    t.open(container.current!);
    term.current = t;
    fit.current = f;
    const sub = t.onData(sendInput);
    const onResize = () => {
      if (!container.current?.offsetParent) return;
      f.fit();
      send({ type: 'resize', cols: t.cols, rows: t.rows });
    };
    const ro = new ResizeObserver(onResize);
    ro.observe(container.current!);
    window.visualViewport?.addEventListener('resize', onResize);
    return () => {
      sub.dispose();
      ro.disconnect();
      window.visualViewport?.removeEventListener('resize', onResize);
      t.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // (Re)connect whenever `attempt` changes. If the connection drops while the terminal is up, the
  // server keeps the SSH session for a while; this re-attaches to it with a fresh ticket and the
  // missed output is replayed, instead of starting over.
  useEffect(() => {
    const t = term.current!;
    let disposed = false;
    let sessionId: string | null = null;
    let exited = false;
    let retries = 0;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let retryNow: (() => void) | null = null;

    const lost = () => {
      if (disposed) return;
      if (exited || !sessionId || retries >= MAX_RETRIES) {
        setPrompt(null);
        return props.onState('closed');
      }
      if (retries === 0) t.writeln('\r\n\x1b[33m[Connection lost. Reconnecting…]\x1b[0m');
      props.onState('reconnecting');
      const delay = Math.min(1000 * 2 ** retries, 15_000);
      retries += 1;
      timer = setTimeout(() => void open(sessionId!), delay);
      retryNow = () => {
        if (timer) clearTimeout(timer);
        void open(sessionId!);
      };
    };

    const open = async (resume?: string) => {
      retryNow = null;
      if (!resume) {
        props.onState('connecting');
        t.reset();
        fit.current?.fit();
      }
      let ticket: string;
      try {
        ticket = (await post<{ ticket: string }>(`/api/servers/${props.server.id}/connect`, resume ? { resume } : (props.choice ?? {}))).ticket;
      } catch (e) {
        if (disposed) return;
        // Offline or the server is restarting: keep trying to re-attach. Anything else is final.
        const transient = resume && (!(e instanceof ApiError) || e.status >= 500);
        if (transient) return lost();
        t.writeln(`\r\n\x1b[31m${resume ? 'The terminal was closed while you were away. Use ↻ to start a new one.' : e instanceof Error ? e.message : String(e)}\x1b[0m`);
        return props.onState('closed');
      }
      if (disposed) return;
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      const socket = new WebSocket(`${proto}://${location.host}/api/terminal?ticket=${encodeURIComponent(ticket)}&cols=${t.cols}&rows=${t.rows}`);
      ws.current = socket;
      socket.onmessage = (ev) => {
        const m = JSON.parse(ev.data as string);
        switch (m.type) {
          case 'data':
            t.write(m.data);
            break;
          case 'replay':
            // Everything the server saw while we were away, replacing what is on screen.
            t.reset();
            t.write(m.data);
            break;
          case 'status':
            if (m.message !== 'Reconnected') t.writeln(`\x1b[90m${m.message}\x1b[0m`);
            break;
          case 'ready':
            sessionId = m.session;
            retries = 0;
            props.onState('connected');
            if (latest.current.focused && latest.current.active) t.focus();
            send({ type: 'resize', cols: t.cols, rows: t.rows });
            break;
          case 'hostkey':
            setPrompt({ kind: 'hostkey', fingerprint: m.fingerprint, keyType: m.keyType, host: m.host, port: m.port });
            break;
          case 'password':
            setPrompt({ kind: 'password', username: m.username, host: m.host });
            break;
          case 'error':
            if (m.code === 'session_gone') exited = true;
            t.writeln(`\r\n\x1b[1;31m${m.message}\x1b[0m`);
            break;
          case 'exit':
            exited = true;
            t.writeln(`\r\n\x1b[90m[${m.reason}]\x1b[0m`);
            break;
          case 'locked':
            // The server paused this terminal because the session locked (perhaps from another tab).
            notifyLocked();
            break;
        }
      };
      socket.onclose = (ev) => {
        if (ws.current === socket) ws.current = null;
        if (ev.code === 4001) exited = true; // another window took this terminal over
        lost();
      };
    };

    const onOnline = () => retryNow?.();
    window.addEventListener('online', onOnline);
    document.addEventListener('visibilitychange', onOnline);
    void open();

    return () => {
      disposed = true;
      window.removeEventListener('online', onOnline);
      document.removeEventListener('visibilitychange', onOnline);
      if (timer) clearTimeout(timer);
      ws.current?.close();
      ws.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.attempt, props.server.id]);

  useEffect(() => {
    if (props.active) {
      requestAnimationFrame(() => {
        fit.current?.fit();
        if (props.focused) term.current?.focus();
      });
    }
  }, [props.active, props.focused]);

  return (
    <div className={`terminal-session ${props.focused ? 'focused' : ''}`} onMouseDownCapture={props.onFocus} onFocusCapture={props.onFocus}>
      <div className="pane-tools">
        {props.canSplit && (
          <>
            <button title="Split to the right" aria-label="Split right" onClick={() => props.onSplit('row')}>
              ◫
            </button>
            <button title="Split below" aria-label="Split down" onClick={() => props.onSplit('col')}>
              ⬓
            </button>
          </>
        )}
        {props.onClosePane && (
          <button title="Close this pane" aria-label="Close pane" onClick={props.onClosePane}>
            ✕
          </button>
        )}
      </div>
      <div className="terminal-host" ref={container} />
      <div className="extra-keys" role="toolbar" aria-label="Extra keys">
        {EXTRA_KEYS.map((k) => (
          <button
            key={k.label}
            className={k.mod && mod === k.mod ? 'active' : ''}
            // Keep focus (and the on-screen keyboard) on the terminal.
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => {
              if (k.mod) {
                modifier.current = modifier.current === k.mod ? null : k.mod;
                setMod(modifier.current);
              } else if (k.seq) {
                sendInput(k.seq);
              }
              term.current?.focus();
            }}
          >
            {k.label}
          </button>
        ))}
      </div>
      {prompt?.kind === 'hostkey' && (
        <Modal title="Verify host key" onClose={() => (send({ type: 'hostkey', accept: false }), setPrompt(null))}>
          <p>
            This is the first connection to <strong>{prompt.host}</strong>
            {prompt.port !== 22 ? `:${prompt.port}` : ''}. Check that the fingerprint below matches the server before trusting it
            (on the server: <code>ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub</code>).
          </p>
          <p className="fingerprint mono">
            {prompt.keyType}
            <br />
            {prompt.fingerprint}
          </p>
          <p className="muted small">Once trusted, the key is pinned. Any change later is refused as a possible attack.</p>
          <div className="row">
            <button className="primary" onClick={() => (send({ type: 'hostkey', accept: true }), setPrompt(null))}>
              Trust and connect
            </button>
            <button onClick={() => (send({ type: 'hostkey', accept: false }), setPrompt(null))}>Cancel</button>
          </div>
        </Modal>
      )}
      {prompt?.kind === 'password' && (
        <Modal title={`Password for ${prompt.username}@${prompt.host}`} onClose={() => (ws.current?.close(), setPrompt(null))}>
          <Form
            submit="Connect"
            onSubmit={async () => {
              send({ type: 'password', password });
              setPassword('');
              setPrompt(null);
            }}
          >
            <Field label="Password" hint="Used for this connection only; not stored.">
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" autoFocus required />
            </Field>
          </Form>
        </Modal>
      )}
    </div>
  );
}
