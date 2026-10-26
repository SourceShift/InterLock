/**
 * Detector picker: the searchable replacement for the playground's detector
 * menu. What matters is that a long catalog is reachable by typing, and that
 * keyboard selection does the same thing a click does.
 */
import { fireEvent, render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { DetectorPicker } from "./DetectorPicker";

const options = [
  { v: "network_egress_guard" },
  { v: "shell_destructive_guard" },
  { v: "prompt_injection_guard" },
];

function open(value = "shell_destructive_guard") {
  const onChange = vi.fn();
  render(<DetectorPicker value={value} options={options} onChange={onChange} />);
  fireEvent.click(screen.getByRole("button", { name: "Detector" }));
  return { onChange, filter: screen.getByRole("textbox", { name: "Filter detectors" }) };
}

test("filters on any part of the key, not just the prefix", () => {
  const { filter } = open();
  fireEvent.change(filter, { target: { value: "egress" } });
  expect(screen.getAllByRole("option").map((o) => o.textContent)).toEqual(["network_egress_guard"]);
});

test("a click picks the filtered row", () => {
  const { onChange, filter } = open();
  fireEvent.change(filter, { target: { value: "egress" } });
  fireEvent.click(screen.getByRole("option"));
  expect(onChange).toHaveBeenCalledWith({ target: { value: "network_egress_guard" } });
  expect(screen.queryByRole("listbox")).toBeNull();
});

test("arrow keys move the active row and Enter picks it", () => {
  const { onChange, filter } = open();
  fireEvent.change(filter, { target: { value: "guard" } });
  fireEvent.keyDown(filter, { key: "ArrowDown" });
  fireEvent.keyDown(filter, { key: "Enter" });
  expect(onChange).toHaveBeenCalledWith({ target: { value: "shell_destructive_guard" } });
});

test("escape closes without changing the value", () => {
  const { onChange, filter } = open();
  fireEvent.keyDown(filter, { key: "Escape" });
  expect(screen.queryByRole("listbox")).toBeNull();
  expect(onChange).not.toHaveBeenCalled();
});

test("a query that matches nothing says so and Enter is a no-op", () => {
  const { onChange, filter } = open();
  fireEvent.change(filter, { target: { value: "zzz" } });
  fireEvent.keyDown(filter, { key: "Enter" });
  expect(screen.queryAllByRole("option")).toHaveLength(0);
  expect(screen.getByText(/no detector matches/)).toBeTruthy();
  expect(onChange).not.toHaveBeenCalled();
});
