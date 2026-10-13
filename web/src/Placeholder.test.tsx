import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Placeholder } from "./Placeholder";

describe("Placeholder", () => {
  it("renders the given title and note", () => {
    render(<Placeholder title="Detector catalog" note="not yet landed" />);
    expect(screen.getByText("Detector catalog")).toBeTruthy();
    expect(screen.getByText("not yet landed")).toBeTruthy();
  });
});
