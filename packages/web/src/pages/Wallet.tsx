import { useState } from 'react'
import { Link } from 'react-router-dom'
import { formatAmount, DEFAULT_RPC_URL } from '../types'

export function Wallet() {
  const [balance, setBalance] = useState<string>('0')
  const [nonce, setNonce] = useState<number>(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [address, setAddress] = useState('')

  const fetchAccount = async () => {
    if (!address.trim()) return
    try {
      setLoading(true)
      setError(null)

      const [balRes, nonceRes] = await Promise.all([
        fetch(`${DEFAULT_RPC_URL}/rpc`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'kovanica_getBalance',
            params: [address],
            id: 1,
          }),
        }),
        fetch(`${DEFAULT_RPC_URL}/rpc`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'kovanica_getNonce',
            params: [address],
            id: 1,
          }),
        }),
      ])

      const balData = await balRes.json()
      const nonceData = await nonceRes.json()

      if (balData.error) throw new Error(balData.error.message)
      if (nonceData.error) throw new Error(nonceData.error.message)

      setBalance(balData.result)
      setNonce(parseInt(nonceData.result, 16))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch account')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="wallet">
      <div className="page-header">
        <h1 className="page-title">Wallet</h1>
      </div>

      <div className="card" style={{ maxWidth: '600px' }}>
        <h3 style={{ marginBottom: '16px' }}>Account Lookup</h3>
        <div className="form-group">
          <label className="form-label">Kovanica Address</label>
          <input
            type="text"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="kovanica... or 0x... or bare hex"
            onKeyDown={(e) => e.key === 'Enter' && fetchAccount()}
          />
        </div>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <button className="btn-primary" onClick={fetchAccount} disabled={loading || !address.trim()}>
            {loading ? 'Loading...' : 'Lookup'}
          </button>
          <button className="btn-secondary" onClick={() => setAddress('')}>
            Clear
          </button>
        </div>
      </div>

      {error && (
        <div className="card" style={{ backgroundColor: 'rgba(248, 81, 73, 0.1)', borderColor: 'var(--color-danger)', marginTop: '16px' }}>
          <strong style={{ color: 'var(--color-danger)' }}>Error:</strong> {error}
        </div>
      )}

      {balance && (
        <div className="card" style={{ marginTop: '16px' }}>
          <div className="stat-grid">
            <div className="stat-card">
              <div className="stat-label">Address</div>
              <div className="address monospace">{address}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Balance</div>
              <div className="stat-value monospace">{formatAmount(balance)} KUNA</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Nonce</div>
              <div className="stat-value monospace">{nonce}</div>
            </div>
          </div>
        </div>
      )}

      <div className="card" style={{ marginTop: '16px' }}>
        <h3 style={{ marginBottom: '16px' }}>Actions</h3>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <Link to="/wallet/transfer" className="btn-primary">
            Transfer KUNA
          </Link>
          <Link to="/wallet/stake" className="btn-secondary">
            Stake
          </Link>
          <Link to="/wallet/delegate" className="btn-secondary">
            Delegate
          </Link>
          <Link to="/wallet/claim" className="btn-secondary">
            Claim Rewards
          </Link>
        </div>
        <p style={{ marginTop: '16px', color: 'var(--color-text-muted)', fontSize: '13px' }}>
          Full wallet functionality (signing, transaction building) requires the{' '}
          <code>kovanica-cli</code> tool or a connected wallet extension.
        </p>
      </div>

      <div className="card" style={{ marginTop: '16px' }}>
        <h3 style={{ marginBottom: '16px' }}>Quick RPC Access</h3>
        <p style={{ color: 'var(--color-text-muted)', fontSize: '13px', marginBottom: '8px' }}>
          Connect to your local node or a public RPC endpoint:
        </p>
        <div className="form-group">
          <label className="form-label">RPC URL</label>
          <input
            type="text"
            value="http://127.0.0.1:8545"
            readOnly
            style={{ backgroundColor: 'var(--color-bg)' }}
          />
        </div>
        <p style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
          Default local node: <code>http://127.0.0.1:8545</code> | Testnet: <code>https://rpc-testnet.kovanica.online/rpc</code>
        </p>
      </div>
    </div>
  )
}