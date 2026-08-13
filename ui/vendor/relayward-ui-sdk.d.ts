export declare const MANIFEST_API_VERSION_V1: "relayward.plugin/v1";
export declare const MANIFEST_API_VERSION_V2: "relayward.plugin/v2";
export declare const MANIFEST_API_VERSION: "relayward.plugin/v2";
export declare const UI_API_MAJOR: 1;
export declare const UI_BRIDGE_API_VERSION: "relayward.plugin-ui/v1";
export type ErrorCode = "invalid_argument" | "unauthenticated" | "permission_denied" | "not_found" | "conflict" | "unsupported" | "unavailable" | "internal";
export interface FieldViolation {
    field: string;
    description: string;
}
export interface Problem {
    code: ErrorCode;
    message: string;
    retryable: boolean;
    violations?: FieldViolation[];
}
export type Theme = "light" | "dark";
export type Locale = "zh-CN" | "en";
export type NavigationTarget = "plugins" | "nodes" | "users" | "authorizations" | "audit";
export interface UINodeScope {
    kind: "node";
    node_id: string;
}
export interface UIContext {
    plugin_id: string;
    theme: Theme;
    locale: Locale;
    scope?: UINodeScope;
}
export interface ConfirmOptions {
    title: string;
    message: string;
    confirm_label?: string;
    destructive?: boolean;
}
export interface UITransport {
    send(message: PluginUIRequest): void;
    subscribe(listener: (message: unknown) => void): () => void;
}
export interface RelaywardUIClient {
    context(): Promise<UIContext>;
    rpc<T>(method: string, parameters: Record<string, unknown>): Promise<T>;
    navigate(target: NavigationTarget): Promise<void>;
    confirm(options: ConfirmOptions): Promise<boolean>;
    dispose(): void;
}
type BridgeMethod = "context" | "rpc" | "navigate" | "confirm";
export interface PluginUIRequest {
    api_version: typeof UI_BRIDGE_API_VERSION;
    direction: "plugin-to-host";
    id: string;
    method: BridgeMethod;
    payload: unknown;
}
export interface PluginUIResponse {
    api_version: typeof UI_BRIDGE_API_VERSION;
    direction: "host-to-plugin";
    id: string;
    ok: boolean;
    result?: unknown;
    problem?: Problem;
}
export declare function createRelaywardUIClient(transport: UITransport, timeoutMilliseconds?: number): RelaywardUIClient;
export declare function browserUITransport(): UITransport;
export declare class RelaywardUIError extends Error {
    readonly problem: Problem;
    constructor(problem: Problem);
}
export {};
