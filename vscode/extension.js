const vscode = require("vscode");
const fs = require("node:fs/promises");
const { fetchDeployed, review, format, atLeast } = require("./review.js");

let channel;

function config() {
  const c = vscode.workspace.getConfiguration("tidemark");
  return { rpc: c.get("rpc"), warnAt: c.get("warnAt") };
}

async function pickSo(title) {
  const picked = await vscode.window.showOpenDialog({
    title,
    canSelectMany: false,
    filters: { "Solana program": ["so"], "All files": ["*"] },
  });
  return picked?.[0];
}

function show(result, label) {
  const { warnAt } = config();
  channel.clear();
  channel.appendLine(label);
  channel.appendLine("");
  channel.appendLine(format(result));
  channel.show(true);
  const risk = result.report.risk;
  const msg = `Tidemark: ${risk.toUpperCase()} risk, ${result.report.findings.length} finding(s)`;
  if (atLeast(risk, warnAt)) vscode.window.showWarningMessage(msg, "Show report").then((a) => a && channel.show());
  else vscode.window.showInformationMessage(msg);
}

async function reviewFiles() {
  const oldUri = await pickSo("Current program (.so)");
  if (!oldUri) return;
  const newUri = await pickSo("New build (.so)");
  if (!newUri) return;
  const [a, b] = await Promise.all([fs.readFile(oldUri.fsPath), fs.readFile(newUri.fsPath)]);
  show(review(a, b), `${oldUri.fsPath}\n  -> ${newUri.fsPath}`);
}

async function reviewDeployed() {
  const programId = await vscode.window.showInputBox({
    title: "Program id to compare against",
    placeHolder: "base58 program id",
    validateInput: (v) => (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(v.trim()) ? null : "Not a base58 program id"),
  });
  if (!programId) return;
  const newUri = await pickSo("Your new build (.so)");
  if (!newUri) return;
  const { rpc } = config();
  const deployed = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `Fetching ${programId} from ${rpc}` },
    () => fetchDeployed(rpc, programId.trim()),
  );
  const local = await fs.readFile(newUri.fsPath);
  show(
    review(deployed.elf, local),
    `deployed ${programId} (slot ${deployed.slot}, authority ${deployed.authority ?? "none"})\n  -> ${newUri.fsPath}`,
  );
}

function guard(fn) {
  return async () => {
    try {
      await fn();
    } catch (e) {
      vscode.window.showErrorMessage(`Tidemark: ${e.message ?? e}`);
    }
  };
}

function activate(context) {
  channel = vscode.window.createOutputChannel("Tidemark");
  context.subscriptions.push(
    channel,
    vscode.commands.registerCommand("tidemark.reviewFiles", guard(reviewFiles)),
    vscode.commands.registerCommand("tidemark.reviewDeployed", guard(reviewDeployed)),
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
