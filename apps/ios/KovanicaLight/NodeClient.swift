import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Blocking-enough JSON-RPC helper. Call it off the main actor.
enum NodeClient {
    static func call(base: String, method: String, params: [Any]) throws -> Any? {
        let url = URL(string: rpcURL(base))!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body: [String: Any] = ["jsonrpc": "2.0", "method": method, "params": params, "id": 1]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try synchronous(request)
        try check(response, data, url.absoluteString)
        let parsed = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        if let error = parsed["error"], !(error is NSNull) {
            throw NodeError.message("RPC \(method) failed: \(error)")
        }
        let result = parsed["result"]
        if result is NSNull { return nil }
        return result
    }

    static func faucet(base: String, address: String) throws -> String {
        let root = base.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            .replacingOccurrences(of: "/rpc", with: "")
        let url = URL(string: root + "/faucet")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["address": address])
        let (data, response) = try synchronous(request)
        try check(response, data, url.absoluteString)
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func rpcURL(_ base: String) -> String {
        let trimmed = base.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return trimmed.hasSuffix("/rpc") ? trimmed : trimmed + "/rpc"
    }

    private static func synchronous(_ request: URLRequest) throws -> (Data, URLResponse) {
        let slot = Slot()
        let sem = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error {
                slot.result = .failure(error)
            } else if let data, let response {
                slot.result = .success((data, response))
            } else {
                slot.result = .failure(NodeError.message("empty response"))
            }
            sem.signal()
        }.resume()
        sem.wait()
        return try slot.result!.get()
    }

    private static func check(_ response: URLResponse, _ data: Data, _ url: String) throws {
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        if !(200..<300).contains(code) {
            let text = String(data: data, encoding: .utf8) ?? ""
            throw NodeError.message("HTTP \(code) from \(url): \(text)")
        }
    }
}

enum NodeError: Error {
    case message(String)
}

/// The URLSession callback and the waiter share this slot. The semaphore
/// orders the write before the read.
private final class Slot: @unchecked Sendable {
    var result: Result<(Data, URLResponse), Error>?
}

func parseQuantity(_ value: Any?) throws -> UInt64 {
    switch value {
    case let number as NSNumber:
        return number.uint64Value
    case let text as String:
        let raw = text.hasPrefix("0x") ? String(text.dropFirst(2)) : text
        guard let parsed = UInt64(raw, radix: 16) else {
            throw NodeError.message("invalid quantity \(text)")
        }
        return parsed
    default:
        throw NodeError.message("expected a quantity")
    }
}
