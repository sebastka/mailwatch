import { useEffect, useRef, useState } from 'react';

/** Tracks an element's content-box width. */
export function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      if (entry) setWidth(Math.floor(entry.contentRect.width));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}

/**
 * Loads data whenever deps change. The previous value is kept while reloading, so charts can
 * dim instead of flashing a skeleton; `loading` is derived rather than set inside the effect.
 */
export function useAsync<T>(
  fn: () => Promise<T>,
  deps: unknown[],
): { data: T | null; loading: boolean; error: string | null } {
  const key = JSON.stringify(deps);
  const [state, setState] = useState<{ key: string | null; data: T | null; error: string | null }>({
    key: null,
    data: null,
    error: null,
  });
  useEffect(() => {
    let cancelled = false;
    fn().then(
      (data) => !cancelled && setState({ key, data, error: null }),
      (e: Error) => !cancelled && setState((s) => ({ ...s, key, error: e.message })),
    );
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return { data: state.data, loading: state.key !== key, error: state.key === key ? state.error : null };
}
