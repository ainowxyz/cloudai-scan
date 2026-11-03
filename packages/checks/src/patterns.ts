/** Shared detection patterns for Workers, repo scans and connectors. Names and hostnames only; never secret values. */

export const PROVIDER_KEY_NAME = /(OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_(GENAI|AI|GENERATIVE)|MISTRAL|COHERE|HUGGING ?FACE|HF_TOKEN|OPENROUTER|GROQ|TOGETHER|PERPLEXITY|XAI|DEEPSEEK|REPLICATE|AZURE_OPENAI)/i;

/** Direct model-provider API hosts. Calls to these bypass any gateway. */
export const PROVIDER_HOSTS = [
  "api.openai.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
  "aiplatform.googleapis.com",
  "api.mistral.ai",
  "api.cohere.com",
  "api.cohere.ai",
  "api-inference.huggingface.co",
  "router.huggingface.co",
  "openrouter.ai",
  "api.groq.com",
  "api.together.xyz",
  "api.perplexity.ai",
  "api.x.ai",
  "api.deepseek.com",
  "api.replicate.com",
  "bedrock-runtime",
  "openai.azure.com",
];

export const GATEWAY_HOSTS = ["gateway.ai.cloudflare.com", "/ai-gateway/", "ai-gateway"];

/** SDK packages that call providers directly unless configured with a gateway base URL. */
export const PROVIDER_SDKS = ["openai", "@anthropic-ai/sdk", "@google/generative-ai", "@google/genai", "@mistralai/mistralai", "cohere-ai", "groq-sdk", "@huggingface/inference", "together-ai"];

export const MCP_PACKAGES = ["@modelcontextprotocol/sdk", "agents/mcp", "@cloudflare/mcp-agent", "workers-mcp"];

/** Value shapes that look like live provider credentials. Used only to flag plaintext config; values are never reported. */
export const SECRET_VALUE = /^(sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,}|hf_[A-Za-z0-9]{20,}|gsk_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{20,})$/;

export function looksLikeMcp(name: string): boolean {
  return /(^|[-_])mcp([-_]|$)/i.test(name);
}
