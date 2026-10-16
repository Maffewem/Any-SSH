import { createContext, useCallback, useContext, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { errorMessage } from './api';

export function Modal(props: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && props.onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [props.onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div className={`modal ${props.wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={props.title}>
        <div className="modal-head">
          <h2>{props.title}</h2>
          <button className="ghost" onClick={props.onClose} aria-label="Close">
            ✕
          </button>
        </div>
        {props.children}
      </div>
    </div>
  );
}

/** Form wrapper that handles busy state and shows the server's error message. */
export function Form(props: { /** Resolve with `false` to abort without a confirmation (for example when the user cancelled a dialog). */
  onSubmit: () => Promise<void | false>;
  children: ReactNode;
  submit: string;
  danger?: boolean;
  success?: string;
}) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const handle = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await props.onSubmit();
      if (result !== false && props.success) toast.success(props.success);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={handle} className="form">
      {props.children}
      {error && <p className="error">{error}</p>}
      <button type="submit" className={props.danger ? 'danger' : 'primary'} disabled={busy}>
        {busy ? 'Please wait…' : props.submit}
      </button>
    </form>
  );
}

export function Field(props: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="field">
      <span>{props.label}</span>
      {props.children}
      {props.hint && <small>{props.hint}</small>}
    </label>
  );
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const toast = useToast();
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard.writeText(text).then(
          () => {
            setDone(true);
            setTimeout(() => setDone(false), 1500);
            toast.success('Copied to the clipboard.');
          },
          () => toast.error('Couldn’t copy. Select the text and copy it manually.'),
        );
      }}
    >
      {done ? 'Copied' : label}
    </button>
  );
}

/** Shows a secret exactly once, with a copy button and a clear warning. */
export function SecretOnce({ label, value }: { label: string; value: string }) {
  return (
    <div className="secret-once">
      <p>
        <strong>{label}</strong> It won’t be shown again.
      </p>
      <div className="row">
        <code className="secret">{value}</code>
        <CopyButton text={value} />
      </div>
    </div>
  );
}

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    fn().then(
      (d) => live && (setData(d), setError(null)),
      (e) => live && setError(errorMessage(e)),
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, reload: () => setTick((t) => t + 1) };
}

/** Tab id kept for the browser session, so returning to a page reopens the same section. */
export function useRememberedTab<T extends string>(storageKey: string, ids: readonly T[], fallback: T): [T, (id: T) => void] {
  const [tab, setTab] = useState<T>(() => {
    try {
      const saved = sessionStorage.getItem(storageKey);
      return ids.includes(saved as T) ? (saved as T) : fallback;
    } catch {
      return fallback;
    }
  });
  const choose = (id: T) => {
    setTab(id);
    try {
      sessionStorage.setItem(storageKey, id);
    } catch {
      /* the tab simply is not remembered */
    }
  };
  return [tab, choose];
}

export function SubTabs<T extends string>(props: { label: string; tabs: readonly { id: T; label: string }[]; current: T; onChoose: (id: T) => void }) {
  return (
    <nav className="subtabs" role="tablist" aria-label={props.label}>
      {props.tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={props.current === t.id} className={props.current === t.id ? 'current' : ''} onClick={() => props.onChoose(t.id)}>
          {t.label}
        </button>
      ))}
    </nav>
  );
}

type ToastKind = 'success' | 'error';
type ToastItem = { id: number; kind: ToastKind; text: string };
type Toasts = { success: (text: string) => void; error: (text: string) => void };

const ToastContext = createContext<Toasts>({ success: () => {}, error: () => {} });
export const useToast = () => useContext(ToastContext);

/**
 * One feedback pattern for every completed action. The two live regions exist from the start so
 * screen readers announce messages added later: success politely, errors assertively.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const next = useRef(0);
  const dismiss = useCallback((id: number) => setItems((all) => all.filter((t) => t.id !== id)), []);
  const push = useCallback(
    (kind: ToastKind, text: string) => {
      const id = ++next.current;
      setItems((all) => [...all.slice(-3), { id, kind, text }]);
      setTimeout(() => dismiss(id), kind === 'error' ? 8000 : 4000);
    },
    [dismiss],
  );
  const api = useRef<Toasts>({ success: (t) => push('success', t), error: (t) => push('error', t) }).current;
  const render = (kind: ToastKind) =>
    items
      .filter((t) => t.kind === kind)
      .map((t) => (
        <div key={t.id} className={`toast ${kind}`}>
          <span>{t.text}</span>
          <button className="ghost" onClick={() => dismiss(t.id)} aria-label="Dismiss">
            ✕
          </button>
        </div>
      ));
  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toasts">
        <div role="status" aria-live="polite">
          {render('success')}
        </div>
        <div role="alert" aria-live="assertive">
          {render('error')}
        </div>
      </div>
    </ToastContext.Provider>
  );
}

export type ConfirmOptions = { title: string; message?: ReactNode; confirmLabel: string; danger?: boolean };
type Confirm = (options: ConfirmOptions) => Promise<boolean>;

const ConfirmContext = createContext<Confirm>(() => Promise.resolve(false));
export const useConfirm = () => useContext(ConfirmContext);

/** Named confirmation dialog for destructive or far-reaching actions; replaces window.confirm. */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<{ options: ConfirmOptions; resolve: (ok: boolean) => void } | null>(null);
  const confirm = useCallback<Confirm>((options) => new Promise((resolve) => setPending({ options, resolve })), []);
  const settle = (ok: boolean) => {
    pending?.resolve(ok);
    setPending(null);
  };
  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {pending && (
        <Modal title={pending.options.title} onClose={() => settle(false)}>
          {pending.options.message && <div className="confirm-message">{pending.options.message}</div>}
          <div className="row confirm-actions">
            <button autoFocus onClick={() => settle(false)}>
              Cancel
            </button>
            <button className={pending.options.danger ? 'danger' : 'primary'} onClick={() => settle(true)}>
              {pending.options.confirmLabel}
            </button>
          </div>
        </Modal>
      )}
    </ConfirmContext.Provider>
  );
}
