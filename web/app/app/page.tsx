import type { Metadata } from "next";
import { Tools } from "@/components/Tools";

export const metadata: Metadata = { title: "Try it · Tidemark" };

export default function Page() {
  return <Tools />;
}
