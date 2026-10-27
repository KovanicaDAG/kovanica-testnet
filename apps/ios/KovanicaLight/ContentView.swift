import SwiftUI

/// Light client screens. Argon2id runs off the main actor.
/// A gap since the last sealed header starts a new checkpoint.
/// Desktop `kovanica-lightnode` submits witnesses while the phone is asleep.
struct ContentView: View {
    @AppStorage("rpc") private var rpc = "http://127.0.0.1:8545"
    @AppStorage("chainId") private var chainId = "1337"
    @AppStorage("epoch") private var epoch = "0"
    @AppStorage("keystore") private var keystore = ""
    @AppStorage("header") private var header = ""
    @State private var passphrase = ""
    @State private var mnemonic = ""
    @State private var recipient = ""
    @State private var amount = "1"
    @State private var status = "Kovanica light client"
    @State private var revealedMnemonic = ""

    private let bond: UInt64 = 100_000_000_000

    private struct Outcome {
        var status: String
        var keystore: String?
        var header: String?
        var mnemonic: String?
        var clearMnemonic = false
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                TextField("RPC", text: $rpc).textFieldStyle(.roundedBorder)
                TextField("Chain id", text: $chainId).textFieldStyle(.roundedBorder)
                TextField("Committee epoch", text: $epoch).textFieldStyle(.roundedBorder)
                SecureField("Passphrase", text: $passphrase).textFieldStyle(.roundedBorder)
                TextField("24-word seed (import)", text: $mnemonic).textFieldStyle(.roundedBorder)
                Button("Create wallet") { run("creating wallet", onCreate) }
                Button("Import wallet") { run("importing wallet", onImport) }
                Button("Sync sealed header") { run("syncing", onSync) }
                Button("Balance") { run("reading balance", onBalance) }
                TextField("Recipient", text: $recipient).textFieldStyle(.roundedBorder)
                TextField("Amount (atoms)", text: $amount).textFieldStyle(.roundedBorder)
                Button("Send") { run("sending", onSend) }
                Text("Light node: a desktop kovanica-lightnode submits the witness while this phone is asleep. Open the app about once per day.")
                Button("Bond 100 KUNA") { run("bonding", onBond) }
                Button("Submit witness") { run("witness", onWitness) }
                Button("Exit light node") { run("exiting", onExit) }
                if faucetAllowed(chainId: chainValue()) {
                    Button("Testnet faucet") { run("faucet", onFaucet) }
                }
                if !revealedMnemonic.isEmpty {
                    Text("Mnemonic, shown once:\n\(revealedMnemonic)")
                }
                Text(status).font(.footnote)
            }
            .padding()
        }
    }

    private func onCreate() throws -> Outcome {
        let created = try createWallet(passphrase: passphrase)
        return Outcome(status: "address \(created.address)", keystore: created.keystoreJson, mnemonic: created.mnemonic)
    }

    private func onImport() throws -> Outcome {
        let imported = try importWallet(mnemonic: mnemonic, passphrase: passphrase)
        return Outcome(status: "address \(imported.address)", keystore: imported.keystoreJson, clearMnemonic: true)
    }

    private func onSync() throws -> Outcome {
        let headerValue = try NodeClient.call(base: rpc, method: "kovanica_getLeaderHeader", params: [])
        guard let headerObject = headerValue as? [String: Any] else {
            return Outcome(status: "no sealed header yet")
        }
        let height = try parseQuantity(headerObject["committedHeight"])
        let seals = try NodeClient.call(base: rpc, method: "kovanica_getCommitSeals", params: [hex(height)])
        let committee = try NodeClient.call(base: rpc, method: "kovanica_getCommittee", params: [])
        let headerJSON = try json(headerObject)
        let verified = try verifyHeader(
            chainId: chainValue(),
            epoch: epochValue(),
            committeeJson: try json(committee as Any),
            headerJson: headerJSON,
            sealsJson: try json(seals as Any),
            parentJson: try parentJSON(height)
        )
        return Outcome(
            status: "verified height \(verified.committedHeight)\nheader \(verified.headerHash)\nepoch \(verified.epoch)",
            header: headerJSON
        )
    }

    private func onBalance() throws -> Outcome {
        let address = try walletAddress(keystoreJson: requireKeystore())
        let proof = try NodeClient.call(base: rpc, method: "kovanica_getAccountProof", params: [address])
        guard proof != nil else {
            return Outcome(status: "address \(address)\nbalance unverified (no account proof)")
        }
        guard !header.isEmpty else {
            return Outcome(status: "address \(address)\nbalance unverified (sync a header first)")
        }
        let snapshot = try confirmAccount(headerJson: header, proofJson: try json(proof as Any))
        return Outcome(status: "address \(address)\nbalance \(snapshot.balance) atoms\nnonce \(snapshot.nonce)\nverified")
    }

    private func onSend() throws -> Outcome {
        let address = try walletAddress(keystoreJson: requireKeystore())
        let nonce = try parseQuantity(NodeClient.call(base: rpc, method: "kovanica_getNonce", params: [address]))
        let rate = try parseQuantity(NodeClient.call(base: rpc, method: "kovanica_estimateFee", params: []))
        let raw = try signTransferRaw(
            keystoreJson: requireKeystore(),
            passphrase: passphrase,
            chainId: chainValue(),
            to: recipient,
            amount: UInt64(amount) ?? 0,
            nonce: nonce,
            feeRate: rate
        )
        let hash = try NodeClient.call(base: rpc, method: "kovanica_sendRawTransaction", params: [raw])
        return Outcome(status: "submitted \(hash ?? "")")
    }

    private func onBond() throws -> Outcome {
        try signed("bond") { nonce, rate in
            try signBondRaw(
                keystoreJson: requireKeystore(),
                passphrase: passphrase,
                chainId: chainValue(),
                stake: bond,
                nonce: nonce,
                feeRate: rate
            )
        }
    }

    private func onWitness() throws -> Outcome {
        let address = try walletAddress(keystoreJson: requireKeystore())
        let set = try NodeClient.call(base: rpc, method: "kovanica_getLightSet", params: []) as? [String: Any] ?? [:]
        guard let beacon = set["beacon"] as? String else {
            return Outcome(status: "epoch \(try parseQuantity(set["epoch"])) has no beacon yet")
        }
        let epoch = try parseQuantity(set["epoch"])
        let raw = try signedRaw { nonce, rate in
            try signWitnessRaw(
                keystoreJson: requireKeystore(),
                passphrase: passphrase,
                chainId: chainValue(),
                epoch: epoch,
                beaconHex: beacon,
                nonce: nonce,
                feeRate: rate
            )
        }
        return Outcome(status: "witness submitted \(raw)\n\(lightLine(set, address))")
    }

    private func onExit() throws -> Outcome {
        try signed("exit") { nonce, rate in
            try signExitRaw(
                keystoreJson: requireKeystore(),
                passphrase: passphrase,
                chainId: chainValue(),
                nonce: nonce,
                feeRate: rate
            )
        }
    }

    private func onFaucet() throws -> Outcome {
        let address = try walletAddress(keystoreJson: requireKeystore())
        return Outcome(status: try NodeClient.faucet(base: rpc, address: address))
    }

    private func signed(_ label: String, sign: (UInt64, UInt64) throws -> String) throws -> Outcome {
        let hash = try signedRaw(sign: sign)
        return Outcome(status: "\(label) submitted \(hash)")
    }

    private func signedRaw(sign: (UInt64, UInt64) throws -> String) throws -> String {
        let address = try walletAddress(keystoreJson: requireKeystore())
        let nonce = try parseQuantity(NodeClient.call(base: rpc, method: "kovanica_getNonce", params: [address]))
        let rate = try parseQuantity(NodeClient.call(base: rpc, method: "kovanica_estimateFee", params: []))
        let raw = try sign(nonce, rate)
        let hash = try NodeClient.call(base: rpc, method: "kovanica_sendRawTransaction", params: [raw])
        return "\(hash ?? "")"
    }

    private func parentJSON(_ height: UInt64) throws -> String {
        guard !header.isEmpty, let object = try JSONSerialization.jsonObject(with: Data(header.utf8)) as? [String: Any] else {
            return ""
        }
        let previous = try parseQuantity(object["committedHeight"])
        return previous &+ 1 == height ? header : ""
    }

    private func lightLine(_ set: [String: Any], _ address: String) -> String {
        let nodes = set["nodes"] as? [[String: Any]] ?? []
        guard let node = nodes.first(where: { ($0["address"] as? String) == address }) else {
            return "bond: not registered"
        }
        return "active \(node["active"] ?? false) witnessed \(node["witnessed"] ?? false) selected \(node["selected"] ?? false)"
    }

    private func run(_ label: String, _ work: @escaping () throws -> Outcome) {
        status = label
        Task.detached {
            let outcome: Outcome
            do {
                outcome = try work()
            } catch {
                outcome = Outcome(status: "\(error)")
            }
            await MainActor.run {
                if let keystore = outcome.keystore { self.keystore = keystore }
                if let header = outcome.header { self.header = header }
                if let mnemonic = outcome.mnemonic { revealedMnemonic = mnemonic }
                if outcome.clearMnemonic { revealedMnemonic = "" }
                status = outcome.status
            }
        }
    }

    private func requireKeystore() throws -> String {
        if keystore.isEmpty { throw NodeError.message("create or import a wallet first") }
        return keystore
    }

    private func chainValue() -> UInt64 { UInt64(chainId) ?? 1337 }
    private func epochValue() -> UInt64 { UInt64(epoch) ?? 0 }
    private func hex(_ value: UInt64) -> String { String(format: "0x%llx", value) }

    private func json(_ value: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: value)
        return String(data: data, encoding: .utf8) ?? "{}"
    }
}
