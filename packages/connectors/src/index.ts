import type { Provider } from "@cloudaisecurity/checks";
import { anthropicConnector } from "./anthropic.js";
import { cloudflareAccountConnector } from "./cloudflare-account.js";
import { cloudflareAiGatewayConnector } from "./cloudflare-ai-gateway.js";
import { openaiConnector } from "./openai.js";
import type { Connector } from "./types.js";

export * from "./types.js";
export { openaiConnector, anthropicConnector, cloudflareAiGatewayConnector, cloudflareAccountConnector };

/** Connectors that need credentials. The `repo` provider is scanned locally by the CLI and has no connector. */
export const connectors: { [P in Exclude<Provider, "repo">]: Connector<P> } = {
  openai: openaiConnector,
  anthropic: anthropicConnector,
  "cloudflare-ai-gateway": cloudflareAiGatewayConnector,
  "cloudflare-account": cloudflareAccountConnector,
};

export function connectorFor<P extends Exclude<Provider, "repo">>(provider: P): Connector<P> {
  return connectors[provider] as Connector<P>;
}
