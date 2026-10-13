export interface PlaceholderProps {
  title: string;
  note: string;
}

export function Placeholder({ title, note }: PlaceholderProps) {
  return (
    <section>
      <h1>{title}</h1>
      <p>{note}</p>
    </section>
  );
}
