import { C, Callout, Code, DocPage, DocTable, H2, P, Steps } from "@/components/docs";

export const metadata = { title: "VS Code extension · Tidemark docs" };

export default function Page() {
  return (
    <DocPage
      title="VS Code extension"
      lead="Before you run anchor deploy, compare your local build with what is on chain, without leaving the editor."
    >
      <H2 id="install">Install</H2>
      <Callout title="Not on the Marketplace yet">
        The extension runs from source today. A Marketplace listing will follow; the steps below take about a minute.
      </Callout>
      <Steps
        items={[
          {
            title: "Build the engine for Node",
            body: (
              <>
                Needs the <C>wasm32-unknown-unknown</C> target and <C>wasm-bindgen-cli 0.2.130</C>.
                <Code>{`rustup target add wasm32-unknown-unknown\ncargo install wasm-bindgen-cli --version 0.2.130 --locked\nbash scripts/build-vscode.sh`}</Code>
              </>
            ),
          },
          {
            title: "Open the extension",
            body: (
              <>
                Open the <C>vscode/</C> folder in VS Code and press <C>F5</C>. A second window starts with Tidemark loaded.
              </>
            ),
          },
          {
            title: "Run a command",
            body: (
              <>
                Open the command palette (<C>Ctrl+Shift+P</C>) and type <C>Tidemark</C>.
              </>
            ),
          },
        ]}
      />

      <H2 id="commands">Commands</H2>
      <DocTable
        head={["Command", "What it does"]}
        rows={[
          [
            "Tidemark: Review a build against the deployed program",
            "Asks for a program id, fetches its ProgramData over RPC and reviews your local .so against it",
          ],
          ["Tidemark: Review two program binaries", "Compares any two .so files"],
        ]}
      />
      <P>
        The report opens in the <C>Tidemark</C> output channel in the same layout as the CLI, with the verdict hash. A
        warning pops up when the risk reaches your threshold.
      </P>

      <H2 id="settings">Settings</H2>
      <DocTable
        head={["Setting", "Default", "Meaning"]}
        rows={[
          [<C key="1">tidemark.rpc</C>, "devnet", "RPC used to fetch the deployed program (finalized commitment)"],
          [<C key="2">tidemark.warnAt</C>, "high", "Risk level that raises a warning"],
        ]}
      />
      <Callout tone="warn" title="One RPC">
        The extension trusts the RPC you configure for the deployed bytes. Use a provider you trust, or cross-check with{" "}
        <C>tidemark fetch</C>.
      </Callout>
    </DocPage>
  );
}
