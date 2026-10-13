import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { NavBar } from "./NavBar";

describe("NavBar", () => {
  it("renders the four feature links with their stable test ids", () => {
    render(<NavBar />);
    for (const testId of ["nav-catalog", "nav-playground", "nav-audit", "nav-inspector"]) {
      expect(screen.getByTestId(testId)).toBeTruthy();
    }
  });

  it("renders every link as a real anchor, reachable by keyboard", () => {
    render(<NavBar />);
    const link = screen.getByTestId("nav-catalog");
    expect(link.tagName).toBe("A");
    expect(link.getAttribute("href")).toBe("#/catalog");
  });
});
