//! OpenAPI / JSON Schema generation for Kovanica JSON-RPC.
//!
//! Generates an OpenAPI 3.1 specification from the RPC method definitions.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// OpenAPI 3.1 specification structure.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: OpenApiInfo,
    pub servers: Vec<OpenApiServer>,
    pub paths: BTreeMap<String, OpenApiPathItem>,
    pub components: OpenApiComponents,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiInfo {
    pub title: String,
    pub version: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiServer {
    pub url: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiPathItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post: Option<OpenApiOperation>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiOperation {
    pub summary: String,
    pub description: String,
    #[serde(rename = "operationId")]
    pub operation_id: String,
    pub tags: Vec<String>,
    #[serde(rename = "requestBody")]
    pub request_body: Option<OpenApiRequestBody>,
    pub responses: BTreeMap<String, OpenApiResponse>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiRequestBody {
    pub required: bool,
    pub content: BTreeMap<String, OpenApiMediaType>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiMediaType {
    pub schema: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiResponse {
    pub description: String,
    pub content: BTreeMap<String, OpenApiMediaType>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpenApiComponents {
    pub schemas: BTreeMap<String, Value>,
}

/// Generate the OpenAPI 3.1 specification for Kovanica JSON-RPC.
pub fn generate_openapi_spec() -> OpenApiSpec {
    let mut spec = OpenApiSpec {
        openapi: "3.1.0".to_string(),
        info: OpenApiInfo {
            title: "Kovanica JSON-RPC API".to_string(),
            version: "0.1.0".to_string(),
            description: "JSON-RPC API for Kovanica (kovanica) node. All methods use JSON-RPC 2.0 over HTTP POST to /rpc endpoint.".to_string(),
        },
        servers: vec![
            OpenApiServer {
                url: "http://localhost:8545/rpc".to_string(),
                description: "Local development node".to_string(),
            },
            OpenApiServer {
                url: "https://rpc.kovanica.example/rpc".to_string(),
                description: "Public testnet node (placeholder — replaced at launch)".to_string(),
            },
        ],
        paths: BTreeMap::new(),
        components: OpenApiComponents {
            schemas: BTreeMap::new(),
        },
    };

    // Add common schemas
    spec.components.schemas.insert(
        "JsonRpcRequest".to_string(),
        json!({
            "type": "object",
            "required": ["jsonrpc", "method"],
            "properties": {
                "jsonrpc": { "type": "string", "const": "2.0" },
                "method": { "type": "string" },
                "params": { "type": "array", "items": {} },
                "id": { "type": ["string", "number", "null"] }
            }
        }),
    );

    spec.components.schemas.insert(
        "JsonRpcResponse".to_string(),
        json!({
            "type": "object",
            "properties": {
                "jsonrpc": { "type": "string", "const": "2.0" },
                "result": {},
                "error": { "$ref": "#/components/schemas/JsonRpcError" },
                "id": { "type": ["string", "number", "null"] }
            }
        }),
    );

    spec.components.schemas.insert(
        "JsonRpcError".to_string(),
        json!({
            "type": "object",
            "required": ["code", "message"],
            "properties": {
                "code": { "type": "integer" },
                "message": { "type": "string" },
                "data": {}
            }
        }),
    );

    spec.components.schemas.insert(
        "Address".to_string(),
        json!({
            "type": "string",
            "pattern": "^kvnc[a-f0-9]{64}dag$",
            "description": "Canonical Kovanica address format (kvnc<hex>dag with blake3 checksum)"
        }),
    );

    spec.components.schemas.insert(
        "Hash".to_string(),
        json!({
            "type": "string",
            "pattern": "^0x[a-f0-9]{64}$",
            "description": "32-byte hash as 0x-prefixed hex"
        }),
    );

    spec.components.schemas.insert(
        "Quantity".to_string(),
        json!({
            "type": "string",
            "pattern": "^0x[a-f0-9]+$",
            "description": "Ethereum-style quantity (minimal hex)"
        }),
    );

    spec.components.schemas.insert(
        "Transaction".to_string(),
        json!({
            "type": "object",
            "properties": {
                "hash": { "$ref": "#/components/schemas/Hash" },
                "sender": { "$ref": "#/components/schemas/Address" },
                "nonce": { "$ref": "#/components/schemas/Quantity" },
                "fee": { "$ref": "#/components/schemas/Quantity" },
                "kind": { "$ref": "#/components/schemas/TransactionKind" },
                "signature": { "type": "string", "pattern": "^0x[a-f0-9]{128}$" }
            }
        }),
    );

    spec.components.schemas.insert("TransactionKind".to_string(), json!({
        "oneOf": [
            { "type": "object", "properties": { "type": { "const": "transfer" }, "to": { "$ref": "#/components/schemas/Address" }, "amount": { "$ref": "#/components/schemas/Quantity" } } },
            { "type": "object", "properties": { "type": { "const": "stake" }, "amount": { "$ref": "#/components/schemas/Quantity" } } },
            { "type": "object", "properties": { "type": { "const": "unstake" }, "amount": { "$ref": "#/components/schemas/Quantity" } } },
            { "type": "object", "properties": { "type": { "const": "delegate" }, "validator": { "$ref": "#/components/schemas/Address" }, "amount": { "$ref": "#/components/schemas/Quantity" } } },
            { "type": "object", "properties": { "type": { "const": "claim_rewards" }, "validator": { "type": ["string", "null"] } } },
            { "type": "object", "properties": { "type": { "const": "deploy" }, "code": { "type": "string", "pattern": "^0x[a-f0-9]+$" } } },
            { "type": "object", "properties": { "type": { "const": "call" }, "contract": { "$ref": "#/components/schemas/Address" }, "method": { "type": "string" }, "args": { "type": "string", "pattern": "^0x[a-f0-9]*$" }, "gas_limit": { "$ref": "#/components/schemas/Quantity" } } }
        ]
    }));

    spec.components.schemas.insert("Block".to_string(), json!({
        "type": "object",
        "properties": {
            "hash": { "$ref": "#/components/schemas/Hash" },
            "author": { "$ref": "#/components/schemas/Address" },
            "round": { "$ref": "#/components/schemas/Quantity" },
            "parents": { "type": "array", "items": { "$ref": "#/components/schemas/Hash" } },
            "transactions": { "type": "array", "items": { "$ref": "#/components/schemas/Hash" } },
            "timestamp": { "$ref": "#/components/schemas/Quantity" }
        }
    }));

    spec.components.schemas.insert(
        "Account".to_string(),
        json!({
            "type": "object",
            "properties": {
                "address": { "$ref": "#/components/schemas/Address" },
                "balance": { "$ref": "#/components/schemas/Quantity" },
                "nonce": { "$ref": "#/components/schemas/Quantity" },
                "code_hash": { "$ref": "#/components/schemas/Hash" },
                "is_contract": { "type": "boolean" }
            }
        }),
    );

    spec.components.schemas.insert(
        "Validator".to_string(),
        json!({
            "type": "object",
            "properties": {
                "address": { "$ref": "#/components/schemas/Address" },
                "public_key": { "type": "string", "pattern": "^0x[a-f0-9]{64}$" },
                "stake": { "$ref": "#/components/schemas/Quantity" },
                "active": { "type": "boolean" },
                "commission_bps": { "type": "integer" }
            }
        }),
    );

    spec.components.schemas.insert(
        "GetLogsFilter".to_string(),
        json!({
            "type": "object",
            "properties": {
                "fromBlock": {
                    "oneOf": [
                        { "type": "string", "enum": ["latest", "earliest", "pending"] },
                        { "$ref": "#/components/schemas/Quantity" }
                    ],
                    "description": "Start committed-leader height (default: latest)"
                },
                "toBlock": {
                    "oneOf": [
                        { "type": "string", "enum": ["latest", "earliest", "pending"] },
                        { "$ref": "#/components/schemas/Quantity" }
                    ],
                    "description": "End committed-leader height (default: latest)"
                },
                "address": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Address" },
                        { "type": "array", "items": { "$ref": "#/components/schemas/Address" } }
                    ]
                },
                "topics": {
                    "type": "array",
                    "items": {
                        "oneOf": [
                            { "type": "null" },
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" } }
                        ]
                    }
                }
            }
        }),
    );

    spec.components.schemas.insert(
        "Log".to_string(),
        json!({
            "type": "object",
            "properties": {
                "address": { "$ref": "#/components/schemas/Address" },
                "topics": { "type": "array", "items": { "type": "string", "pattern": "^0x[a-f0-9]*$" } },
                "data": { "type": "string", "pattern": "^0x[a-f0-9]*$" },
                "blockNumber": { "$ref": "#/components/schemas/Quantity" },
                "blockHash": { "type": ["string", "null"] },
                "transactionHash": { "$ref": "#/components/schemas/Hash" },
                "transactionIndex": { "$ref": "#/components/schemas/Quantity" },
                "logIndex": { "$ref": "#/components/schemas/Quantity" },
                "removed": { "type": "boolean" }
            }
        }),
    );

    spec.components.schemas.insert(
        "SyncStatus".to_string(),
        json!({
            "type": "object",
            "description": "Node sync / catch-up and peer status (kovanica_syncStatus)",
            "properties": {
                "localTipRound": { "type": ["integer", "null"], "description": "Local DAG tip round" },
                "committedHeight": { "type": ["integer", "null"], "description": "Committed leader height" },
                "catchingUp": { "type": "boolean" },
                "catchUpTarget": { "type": ["integer", "null"], "description": "Peer-advertised tip being chased" },
                "behindBy": { "type": ["integer", "null"], "description": "Rounds behind the catch-up target" },
                "peerCount": { "type": "integer" },
                "networkTag": {
                    "type": "string",
                    "description": "Network tag (<chain_id>-<16 hex of the genesis digest>) this node logs at startup. Peers must share it."
                },
                "peers": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/SyncPeerStatus" }
                }
            },
            "required": ["catchingUp", "peerCount", "peers"]
        }),
    );

    spec.components.schemas.insert(
        "SyncPeerStatus".to_string(),
        json!({
            "type": "object",
            "properties": {
                "peerId": { "type": "string" },
                "listenAddr": { "type": ["string", "null"] },
                "reportedTipRound": { "type": ["integer", "null"] }
            },
            "required": ["peerId"]
        }),
    );

    // Define all RPC methods
    let methods = vec![
        (
            "kovanica_getBlockByHash",
            "Get block by hash",
            "Chain",
            json!({
                "type": "array",
                "items": [
                    { "$ref": "#/components/schemas/Hash" },
                    { "type": "boolean" }
                ],
                "minItems": 1,
                "maxItems": 2
            }),
            json!({
                "type": "object",
                "properties": {
                    "block": { "$ref": "#/components/schemas/Block" },
                    "full_transactions": { "type": "boolean" }
                }
            }),
        ),
        (
            "kovanica_getBlockByNumber",
            "Get block by height/round",
            "Chain",
            json!({
                "type": "array",
                "items": [
                    { "$ref": "#/components/schemas/Quantity" },
                    { "type": "boolean" }
                ],
                "minItems": 1,
                "maxItems": 2
            }),
            json!({
                "type": "object",
                "properties": {
                    "block": { "$ref": "#/components/schemas/Block" },
                    "full_transactions": { "type": "boolean" }
                }
            }),
        ),
        (
            "kovanica_sendRawTransaction",
            "Submit signed transaction",
            "Transactions",
            json!({
                "type": "array",
                "items": { "type": "string", "pattern": "^0x[a-f0-9]+$" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "string",
                "pattern": "^0x[a-f0-9]{64}$",
                "description": "Transaction hash"
            }),
        ),
        (
            "kovanica_getTransactionReceipt",
            "Get transaction receipt",
            "Transactions",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Hash" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "object",
                "properties": {
                    "tx_hash": { "$ref": "#/components/schemas/Hash" },
                    "success": { "type": "boolean" },
                    "gas_used": { "$ref": "#/components/schemas/Quantity" },
                    "error": { "type": ["string", "null"] },
                    "events": { "type": "array", "items": { "type": "object" } }
                }
            }),
        ),
        (
            "kovanica_getTransactionByHash",
            "Get transaction by hash",
            "Transactions",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Hash" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "$ref": "#/components/schemas/Transaction"
            }),
        ),
        (
            "kovanica_getTransactionHistory",
            "Newest-first committed transactions for an address",
            "Transactions",
            json!({
                "type": "object",
                "required": ["address"],
                "properties": {
                    "address": { "$ref": "#/components/schemas/Address" },
                    "limit": {
                        "$ref": "#/components/schemas/Quantity",
                        "description": "Page size. Default 20, hard max 100."
                    },
                    "cursor": {
                        "type": "string",
                        "description": "Opaque cursor from a previous next_cursor."
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["sent", "received", "all"],
                        "default": "all"
                    }
                }
            }),
            json!({
                "type": "object",
                "required": ["entries", "next_cursor"],
                "properties": {
                    "entries": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["hash", "height", "timestamp", "from", "to", "amount", "fee", "kind", "status"],
                            "properties": {
                                "hash": { "$ref": "#/components/schemas/Hash" },
                                "height": { "$ref": "#/components/schemas/Quantity" },
                                "timestamp": { "type": ["string", "null"] },
                                "from": { "$ref": "#/components/schemas/Address" },
                                "to": { "type": ["string", "null"] },
                                "amount": { "$ref": "#/components/schemas/Quantity" },
                                "fee": { "$ref": "#/components/schemas/Quantity" },
                                "kind": { "type": "string" },
                                "status": { "type": "string", "enum": ["success", "failed"] }
                            }
                        }
                    },
                    "next_cursor": { "type": ["string", "null"] }
                }
            }),
        ),
        (
            "kovanica_getLogs",
            "Query transaction logs by block range, address and topics",
            "Transactions",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/GetLogsFilter" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Log" }
            }),
        ),
        (
            "kovanica_getBalance",
            "Get account balance",
            "Accounts",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Address" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_getNonce",
            "Get account nonce",
            "Accounts",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Address" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_getCode",
            "Get contract code",
            "Contracts",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Address" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "string",
                "pattern": "^0x[a-f0-9]*$"
            }),
        ),
        (
            "kovanica_getStorageAt",
            "Get contract storage slot",
            "Contracts",
            json!({
                "type": "array",
                "items": [
                    { "$ref": "#/components/schemas/Address" },
                    { "$ref": "#/components/schemas/Hash" }
                ],
                "minItems": 2,
                "maxItems": 2
            }),
            json!({
                "type": "string",
                "pattern": "^0x[a-f0-9]{64}$"
            }),
        ),
        (
            "kovanica_getValidators",
            "Get active validators",
            "Staking",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Validator" }
            }),
        ),
        (
            "kovanica_getStake",
            "Get total stake for address",
            "Staking",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Address" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_getRewards",
            "Get cumulative rewards",
            "Staking",
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Address" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_getPendingTransactions",
            "Get pending transaction hashes",
            "Mempool",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "type": "array",
                "items": { "$ref": "#/components/schemas/Hash" }
            }),
        ),
        (
            "kovanica_estimateFee",
            "Estimate fee rate",
            "Mempool",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_getLeaderSchedule",
            "Get upcoming leader schedule",
            "Consensus",
            json!({
                "type": "array",
                "items": { "type": "integer" },
                "minItems": 0,
                "maxItems": 1
            }),
            json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "round": { "$ref": "#/components/schemas/Quantity" },
                        "leader": { "$ref": "#/components/schemas/Address" }
                    }
                }
            }),
        ),
        (
            "kovanica_getCommittee",
            "Get current committee",
            "Consensus",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "type": "object",
                "properties": {
                    "epoch": { "$ref": "#/components/schemas/Quantity" },
                    "authorities": {
                        "type": "array",
                        "items": { "$ref": "#/components/schemas/Validator" }
                    }
                }
            }),
        ),
        (
            "kovanica_blockNumber",
            "Get committed leader height",
            "Chain",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "$ref": "#/components/schemas/Quantity"
            }),
        ),
        (
            "kovanica_syncStatus",
            "Get node sync / catch-up and peer status",
            "Chain",
            json!({
                "type": "array",
                "items": {}
            }),
            json!({
                "$ref": "#/components/schemas/SyncStatus"
            }),
        ),
        // WebSocket subscription methods
        (
            "kovanica_subscribe",
            "Subscribe to events",
            "PubSub",
            json!({
                "type": "array",
                "items": { "type": "string", "enum": ["newHeads", "newCommittedLeader", "pendingTransactions", "logs", "newSealedHeader"] },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "string",
                "description": "Subscription ID"
            }),
        ),
        (
            "kovanica_unsubscribe",
            "Unsubscribe from events",
            "PubSub",
            json!({
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "boolean"
            }),
        ),
    ];

    // Create method enum schema for oneOf discriminator
    let mut method_variants = Vec::new();
    for (method, summary, tag, params_schema, _result_schema) in &methods {
        method_variants.push(json!({
            "type": "object",
            "required": ["jsonrpc", "method", "params", "id"],
            "properties": {
                "jsonrpc": { "type": "string", "const": "2.0" },
                "method": { "type": "string", "const": method },
                "params": params_schema,
                "id": { "type": ["string", "number", "null"] }
            },
            "description": format!("{} - {}", method, summary),
            "x-tag": tag
        }));
    }

    // Create request body schema with oneOf for all methods
    let request_body_schema = json!({
        "oneOf": method_variants,
        "discriminator": {
            "propertyName": "method",
            "mapping": method_variants.iter().map(|v| {
                let method = v["properties"]["method"]["const"].as_str().unwrap();
                (method.to_string(), format!("#/components/schemas/JsonRpcRequest{}", method.replace("kovanica_", "")))
            }).collect::<std::collections::BTreeMap<_, _>>()
        }
    });

    // Create response schema with oneOf for all result types
    let mut response_variants = Vec::new();
    for (method, _, _, _, result_schema) in &methods {
        let result_schema_name =
            format!("{}Result", method.replace("kovanica_", "").replace(".", ""));
        // Add result schema to components
        spec.components
            .schemas
            .insert(result_schema_name.clone(), result_schema.clone());
        response_variants.push(json!({
            "type": "object",
            "required": ["jsonrpc", "result", "id"],
            "properties": {
                "jsonrpc": { "type": "string", "const": "2.0" },
                "result": { "$ref": format!("#/components/schemas/{}", result_schema_name) },
                "error": { "$ref": "#/components/schemas/JsonRpcError" },
                "id": { "type": ["string", "number", "null"] }
            }
        }));
    }

    let response_body_schema = json!({
        "oneOf": response_variants,
        "discriminator": {
            "propertyName": "result",
            "mapping": methods.iter().map(|(m, _, _, _, _)| {
                let name = m.replace("kovanica_", "").replace(".", "");
                (name.clone(), format!("#/components/schemas/{}Result", name))
            }).collect::<std::collections::BTreeMap<_, _>>()
        }
    });

    // Add the single /rpc endpoint
    let path = "/rpc";
    let operation = OpenApiOperation {
        summary: "Kovanica JSON-RPC endpoint".to_string(),
        description: "All Kovanica JSON-RPC 2.0 methods are available via this single endpoint. The method is specified in the request body's 'method' field.".to_string(),
        operation_id: "jsonrpc".to_string(),
        tags: vec!["JSON-RPC".to_string()],
        request_body: Some(OpenApiRequestBody {
            required: true,
            content: {
                let mut content = BTreeMap::new();
                content.insert("application/json".to_string(), OpenApiMediaType {
                    schema: request_body_schema
                });
                content
            },
        }),
        responses: {
            let mut responses = BTreeMap::new();
            responses.insert("200".to_string(), OpenApiResponse {
                description: "Successful response".to_string(),
                content: {
                    let mut content = BTreeMap::new();
                    content.insert("application/json".to_string(), OpenApiMediaType {
                        schema: response_body_schema
                    });
                    content
                },
            });
            responses
        },
    };

    spec.paths.entry(path.to_string()).or_default().post = Some(operation);

    spec
}

/// Write OpenAPI spec to JSON file.
pub fn write_openapi_json(path: &std::path::Path) -> Result<(), std::io::Error> {
    let spec = generate_openapi_spec();
    let json = serde_json::to_string_pretty(&spec)?;
    std::fs::write(path, json)
}

/// Write OpenAPI spec to YAML file.
pub fn write_openapi_yaml(path: &std::path::Path) -> Result<(), std::io::Error> {
    let spec = generate_openapi_spec();
    let yaml = serde_yaml::to_string(&spec).map_err(std::io::Error::other)?;
    std::fs::write(path, yaml)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_generation() {
        let spec = generate_openapi_spec();
        assert_eq!(spec.openapi, "3.1.0");
        assert_eq!(spec.info.title, "Kovanica JSON-RPC API");
        assert!(spec.paths.contains_key("/rpc"));
        assert!(spec.components.schemas.contains_key("Transaction"));
        assert!(spec.components.schemas.contains_key("Address"));
    }

    #[test]
    fn test_openapi_json_serialization() {
        let spec = generate_openapi_spec();
        let json = serde_json::to_string_pretty(&spec).unwrap();
        // The method name appears in the request body schema as a const value
        assert!(
            json.contains("\"kovanica_getBlockByHash\""),
            "Missing kovanica_getBlockByHash"
        );
        assert!(
            json.contains("\"kovanica_sendRawTransaction\""),
            "Missing kovanica_sendRawTransaction"
        );
        assert!(
            json.contains("\"kovanica_subscribe\""),
            "Missing kovanica_subscribe"
        );
        assert!(
            json.contains("\"kovanica_getTransactionHistory\""),
            "Missing kovanica_getTransactionHistory"
        );
    }
}
