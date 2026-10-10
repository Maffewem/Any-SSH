import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { useEffect, useRef, useState } from 'react';
import { post, type ConnectChoice, type Server } from '../api';
import { Field, Form, Modal } from '../ui';

type Prompt =
  | { kind: 'hostkey'; fingerprint: string; keyType: string; host: string; port: number }
  | { kind: 'password'; username: string; host: string };

export type TerminalState = 'connecting' | 'connected' | 'closed';

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
  active: boolean;
  attempt: number;
  onState: (s: TerminalState) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const modifier = useRef<'ctrl' | 'alt' | null>(null);
  const [mod, setMod] = useState<'ctrl' | 'alt' | null>(null);
  const [prompt, setPrompt] = useState<Prompt | null>(null);
  const [password, setPassword] = useState('');

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

  // (Re)connect whenever `attempt` changes.
  useEffect(() => {
    const t = term.current!;
    let disposed = false;
    props.onState('connecting');
    t.reset();
    fit.current?.fit();

    (async () => {
      let ticket: string;
      try {
        ticket = (await post<{ ticket: string }>(`/api/servers/${props.server.id}/connect`, props.choice ?? {})).ticket;
      } catch (e) {
        t.writeln(`\x1b[31m${e instanceof Error ? e.message : String(e)}\x1b[0m`);
        props.onState('closed');
        return;
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
          case 'status':
            t.writeln(`\x1b[90m${m.message}\x1b[0m`);
            break;
          case 'ready':
            props.onState('connected');
            if (props.active) t.focus();
            break;
          case 'hostkey':
            setPrompt({ kind: 'hostkey', fingerprint: m.fingerprint, keyType: m.keyType, host: m.host, port: m.port });
            break;
          case 'password':
            setPrompt({ kind: 'password', username: m.username, host: m.host });
            break;
          case 'error':
            t.writeln(`\r\n\x1b[1;31m${m.message}\x1b[0m`);
            break;
          case 'exit':
            t.writeln(`\r\n\x1b[90m[${m.reason}]\x1b[0m`);
            break;
        }
      };
      socket.onclose = () => {
        setPrompt(null);
        props.onState('closed');
      };
    })();

    return () => {
      disposed = true;
      ws.current?.close();
      ws.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.attempt, props.server.id]);

  useEffect(() => {
    if (props.active) {
      requestAnimationFrame(() => {
        fit.current?.fit();
        term.current?.focus();
      });
    }
  }, [props.active]);

  return (
    <div className="terminal-session" hidden={!props.active}>
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
