import { useState, useEffect } from 'react'
import { Validator } from '../types'
import { formatAmount, formatAddress, DEFAULT_RPC_URL } from '../types'

interface NetworkStatus {
  block_height: number
  peer_count: number
  mempool_size: number
  latest_block_hash: string
  latest_block_time: number
  validators_active: number
  validators_total: number
}

export function StatusPage() {
  const [status, setStatus] = useState<NetworkStatus | null>(null)
  const [validators, setValidators] = useState<Validator[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 5000)
    return () => clearInterval(interval)
  }, [])

  const fetchStatus = async () => {
    try {

      // Fetch all data in parallel
      const [blockRes, peersRes, mempoolRes, validatorsRes] = await Promise.all([
        fetch(`${DEFAULT_RPC_URL}/rpc`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', method: 'kovanica_blockNumber', params: [], id: 1 }),
        }),
        fetch(`${DEFAULT_RPC_URL}/health`),
        fetch(`${DEFAULT_RPC_URL}/rpc`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', method: 'kovanica_getPendingTransactions', params: [], id: 1 }),
        }),
        fetch(`${DEFAULT_RPC_URL}/rpc`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', method: 'kovanica_getValidators', params: [], id: 1 }),
        }),
      ])

      const [blockData, peersData, mempoolData, validatorsData] = await Promise.all([
        blockRes.json(),
        peersRes.json(),
        mempoolRes.json(),
        validatorsRes.json(),
      ])

      if (blockData.error) throw new Error(blockData.error.message)
      if (validatorsData.error) throw new Error(validatorsData.error.message)

      const height = parseInt(blockData.result, 16)
      const peers = peersData.peer_count || 0
      const mempool = mempoolData.result?.length || 0
      const vals = validatorsData.result || []

      setStatus({
        block_height: height,
        peer_count: peers,
        mempool_size: mempool,
        latest_block_hash: '',
        latest_block_time: Date.now(),
        validators_active: vals.filter((v: any) => v.active).length,
        validators_total: vals.length,
      })
      setValidators(vals.map((v: any) => ({
        address: v.address,
        stake: v.stake,
        commission_bps: v.commission_bps,
        active: v.active,
        payout_address: v.payout_address,
        public_key: v.public_key,
      })))
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="status">
      <div className="page-header">
        <h1 className="page-title">Network Status</h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className={`badge ${status?.peer_count ? 'badge-success' : 'badge-danger'}`}>
            {status?.peer_count ? 'Online' : 'Offline'}
          </span>
          <button className="btn-secondary" onClick={fetchStatus} disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Block Height</div>
          <div className="stat-value monospace">{status?.block_height?.toLocaleString() || '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Peers</div>
          <div className="stat-value monospace">{status?.peer_count || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Mempool Size</div>
          <div className="stat-value monospace">{status?.mempool_size || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Active Validators</div>
          <div className="stat-value monospace">{status?.validators_active || 0} / {status?.validators_total || 0}</div>
        </div>
      </div>

      <div className="tabs">
        <button className="tab active">Overview</button>
        <button className="tab">Validators</button>
        <button className="tab">Peers</button>
        <button className="tab">Metrics</button>
      </div>

      <div className="card">
        <h3 style={{ marginBottom: '16px' }}>Active Validators</h3>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Address</th>
                <th>Stake</th>
                <th>Commission</th>
                <th>Status</th>
                <th>Payout</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={5} className="loading"><div className="spinner"></div>Loading validators...</td></tr>
              ) : validators.length === 0 ? (
                <tr><td colSpan={5} className="empty-state">No validators found</td></tr>
              ) : (
                validators.map(v => (
                  <tr key={v.address}>
                    <td className="address"><code>{formatAddress(v.address)}</code></td>
                    <td className="monospace">{formatAmount(v.stake)} KUNA</td>
                    <td className="monospace">{(v.commission_bps / 100).toFixed(2)}%</td>
                    <td>
                      <span className={`badge ${v.active ? 'badge-success' : 'badge-neutral'}`}>
                        {v.active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="address">{formatAddress(v.payout_address)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ marginTop: '24px' }}>
        <h3 style={{ marginBottom: '16px' }}>RPC Endpoints</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
          <div className="card">
            <strong>Local Node</strong>
            <code className="monospace" style={{ display: 'block', marginTop: '8px' }}>http://127.0.0.1:8545</code>
          </div>
          <div className="card">
            <strong>Testnet (coming soon)</strong>
            <code className="monospace" style={{ display: 'block', marginTop: '8px' }}>https://testnet.kovanica.online/rpc</code>
          </div>
          <div className="card">
            <strong>Mainnet (coming soon)</strong>
            <code className="monospace" style={{ display: 'block', marginTop: '8px' }}>https://rpc.kovanica.online</code>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: '24px' }}>
        <h3 style={{ marginBottom: '16px' }}>Health Checks</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
          <div className="stat-card">
            <div className="stat-label">RPC Status</div>
            <div className="stat-value badge badge-success">Online</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">P2P Status</div>
            <div className="stat-value badge badge-success">Connected</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Consensus</div>
            <div className="stat-value badge badge-success">Running</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Execution</div>
            <div className="stat-value badge badge-success">Running</div>
          </div>
        </div>
      </div>
    </div>
  )
}