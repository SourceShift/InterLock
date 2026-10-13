interface NavItem {
  href: string;
  label: string;
  testId: string;
}

const NAV_ITEMS: readonly NavItem[] = [
  { href: "#/catalog", label: "Catalog", testId: "nav-catalog" },
  { href: "#/playground", label: "Playground", testId: "nav-playground" },
  { href: "#/audit", label: "Audit", testId: "nav-audit" },
  { href: "#/inspector", label: "Inspector", testId: "nav-inspector" },
];

export function NavBar() {
  return (
    <nav className="top-nav" aria-label="Primary">
      <a className="brand" href="#/">
        interlock console
      </a>
      <ul>
        {NAV_ITEMS.map((item) => (
          <li key={item.testId}>
            <a href={item.href} data-testid={item.testId}>
              {item.label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}
