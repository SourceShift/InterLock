import { useEffect, useMemo, useSyncExternalStore } from "react";
import { Shell } from "./design/Shell";
import { ConsoleStore } from "./store";
import { computeVals } from "./vals";

export function App() {
  const store = useMemo(() => new ConsoleStore(), []);
  useSyncExternalStore(store.subscribe, store.getVersion);
  useEffect(() => {
    store.start();
    return () => store.stop();
  }, [store]);
  const v = computeVals(store.S, store.D, store.actions);
  useEffect(() => {
    const title = v.pendingCount ? "(" + v.pendingCount + ") waiting · interlock console" : "interlock console";
    if (document.title !== title) document.title = title;
  }, [v.pendingCount]);
  return <Shell v={v} />;
}
