export const MANIFEST_API_VERSION_V1 = "relayward.plugin/v1";
export const MANIFEST_API_VERSION_V2 = "relayward.plugin/v2";
export const MANIFEST_API_VERSION = MANIFEST_API_VERSION_V2;
export const UI_API_MAJOR = 1;
export const UI_BRIDGE_API_VERSION = "relayward.plugin-ui/v1";
const uiMethodPattern = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const maximumUIJSONBytes = 512 << 10;
export function createRelaywardUIClient(transport, timeoutMilliseconds = 15_000) {
    if (!Number.isSafeInteger(timeoutMilliseconds) || timeoutMilliseconds < 1 || timeoutMilliseconds > 60_000) {
        throw new Error("timeoutMilliseconds must be between 1 and 60000");
    }
    let sequence = 0;
    let disposed = false;
    const pending = new Map();
    const unsubscribe = transport.subscribe((candidate) => {
        if (!isPluginUIResponse(candidate))
            return;
        const request = pending.get(candidate.id);
        if (!request)
            return;
        pending.delete(candidate.id);
        clearTimeout(request.timer);
        if (candidate.ok) {
            request.resolve(candidate.result);
            return;
        }
        request.reject(new RelaywardUIError(candidate.problem ?? internalProblem()));
    });
    function call(method, payload) {
        if (disposed)
            return Promise.reject(new Error("Relayward UI client is disposed"));
        const normalizedPayload = normalizeJSON(payload);
        const id = `ui-${Date.now().toString(36)}-${(++sequence).toString(36)}`;
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                pending.delete(id);
                reject(new Error("Relayward UI host request timed out"));
            }, timeoutMilliseconds);
            pending.set(id, { resolve, reject, timer });
            try {
                transport.send({
                    api_version: UI_BRIDGE_API_VERSION,
                    direction: "plugin-to-host",
                    id,
                    method,
                    payload: normalizedPayload,
                });
            }
            catch (cause) {
                clearTimeout(timer);
                pending.delete(id);
                reject(cause instanceof Error ? cause : new Error("Relayward UI host request failed"));
            }
        });
    }
    return {
        async context() {
            const value = await call("context", {});
            if (!isUIContext(value))
                throw new Error("Relayward UI host returned an invalid context");
            return value;
        },
        async rpc(method, parameters) {
            if (method.length > 128 || !uiMethodPattern.test(method))
                throw new Error("Invalid plugin UI RPC method");
            return await call("rpc", { method, parameters });
        },
        async navigate(target) {
            if (!["plugins", "nodes", "users", "authorizations", "audit"].includes(target)) {
                throw new Error("Invalid Relayward navigation target");
            }
            await call("navigate", { target });
        },
        async confirm(options) {
            const value = await call("confirm", options);
            if (typeof value !== "boolean")
                throw new Error("Relayward UI host returned an invalid confirmation");
            return value;
        },
        dispose() {
            if (disposed)
                return;
            disposed = true;
            unsubscribe();
            for (const request of pending.values()) {
                clearTimeout(request.timer);
                request.reject(new Error("Relayward UI client is disposed"));
            }
            pending.clear();
        },
    };
}
export function browserUITransport() {
    if (typeof window === "undefined" || window.parent === window) {
        throw new Error("Relayward UI SDK must run inside a plugin iframe");
    }
    const parent = window.parent;
    return {
        send(message) {
            parent.postMessage(message, "*");
        },
        subscribe(listener) {
            const receive = (event) => {
                if (event.source === parent)
                    listener(event.data);
            };
            window.addEventListener("message", receive);
            return () => window.removeEventListener("message", receive);
        },
    };
}
export class RelaywardUIError extends Error {
    problem;
    constructor(problem) {
        super(problem.message);
        this.name = "RelaywardUIError";
        this.problem = problem;
    }
}
function normalizeJSON(value) {
    let encoded;
    try {
        encoded = JSON.stringify(value);
    }
    catch {
        throw new Error("Relayward UI request must be JSON serializable");
    }
    if (encoded === undefined || encoded.length > maximumUIJSONBytes) {
        throw new Error(`Relayward UI request must contain at most ${maximumUIJSONBytes} bytes of JSON`);
    }
    return JSON.parse(encoded);
}
function isPluginUIResponse(value) {
    if (!isRecord(value) || value.api_version !== UI_BRIDGE_API_VERSION || value.direction !== "host-to-plugin" ||
        typeof value.id !== "string" || value.id.length === 0 || typeof value.ok !== "boolean")
        return false;
    if (value.ok)
        return value.problem === undefined;
    return value.result === undefined && (value.problem === undefined || isProblem(value.problem));
}
function isProblem(value) {
    if (!isRecord(value) || typeof value.code !== "string" || typeof value.message !== "string" || typeof value.retryable !== "boolean")
        return false;
    return ["invalid_argument", "unauthenticated", "permission_denied", "not_found", "conflict", "unsupported", "unavailable", "internal"].includes(value.code);
}
function isUIContext(value) {
    return isRecord(value) && typeof value.plugin_id === "string" && value.plugin_id.length > 0 &&
        (value.theme === "light" || value.theme === "dark") && (value.locale === "zh-CN" || value.locale === "en") &&
        (value.scope === undefined || (isRecord(value.scope) && value.scope.kind === "node" &&
            typeof value.scope.node_id === "string" && value.scope.node_id.length > 0));
}
function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function internalProblem() {
    return { code: "internal", message: "Relayward UI host request failed.", retryable: false };
}
