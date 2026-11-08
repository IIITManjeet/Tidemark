import { DocsNav } from "@/components/docs";

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-auto grid max-w-6xl gap-8 px-4 py-10 sm:px-6 lg:grid-cols-[220px_minmax(0,1fr)] lg:gap-12">
      <aside className="min-w-0">
        <DocsNav />
      </aside>
      <div className="min-w-0 max-w-3xl">{children}</div>
    </div>
  );
}
