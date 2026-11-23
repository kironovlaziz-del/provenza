// usePollWhileVisible (the Runtime page's sensor list): every interval while
// the tab is visible, not while hidden, at once when it comes back, and not
// after the page is left.
import { renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { usePollWhileVisible } from "@/lib/use_poll";

let state: DocumentVisibilityState = "visible";
beforeEach(() => {
  vi.useFakeTimers();
  state = "visible";
  vi.spyOn(document, "visibilityState", "get").mockImplementation(() => state);
});
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

describe("usePollWhileVisible", () => {
  it("polls only while the tab is visible", () => {
    const fn = vi.fn();
    const { unmount } = renderHook(() => usePollWhileVisible(fn, 30_000));
    expect(fn).not.toHaveBeenCalled();
    vi.advanceTimersByTime(30_000);
    expect(fn).toHaveBeenCalledTimes(1);

    state = "hidden";
    document.dispatchEvent(new Event("visibilitychange"));
    vi.advanceTimersByTime(90_000);
    expect(fn).toHaveBeenCalledTimes(1);

    state = "visible";
    document.dispatchEvent(new Event("visibilitychange"));
    expect(fn).toHaveBeenCalledTimes(2);

    unmount();
    vi.advanceTimersByTime(90_000);
    document.dispatchEvent(new Event("visibilitychange"));
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("calls the latest function", () => {
    const a = vi.fn(), b = vi.fn();
    const { rerender } = renderHook(({ f }) => usePollWhileVisible(f, 10_000), { initialProps: { f: a } });
    rerender({ f: b });
    vi.advanceTimersByTime(10_000);
    expect(a).not.toHaveBeenCalled();
    expect(b).toHaveBeenCalledTimes(1);
  });
});
