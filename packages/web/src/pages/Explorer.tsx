import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { ExplorerBlock, ExplorerTransaction } from '../types'
import { formatAddress, formatAmount, formatRelativeTime, DEFAULT_RPC_URL } from '../types'

export function Explorer() {
  const [blocks, setBlocks] = useState<ExplorerBlock[]>([])
  const [latestHeight, setLatestHeight] = useState<number>(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [rpcUrl, setRpcUrl] = useState(DEFAULT_RPC_URL)

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 10000)
    return () => clearInterval(interval)
  }, [rpcUrl])

  const fetchData = async () => {
    try {
      setLoading(true)
      setError(null)
      const res = await fetch(`${rpcUrl}/rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'kovanica_blockNumber',
          params: [],
          id: 1,
        }),
      })
      const data = await res.json()
      if (data.error) throw new Error(data.error.message)
      const height = parseInt(data.result, 16)
      setLatestHeight(height)

      // Fetch last 10 blocks
      const blockPromises: Promise<ExplorerBlock | null>[] = []
      for (let i = 0; i < 10; i++) {
        const h = height - i
        if (h < 0) break
        blockPromises.push(fetchBlock(h))
      }
      const results = await Promise.all(blockPromises)
      setBlocks(results.filter((b): b is ExplorerBlock => b !== null) as ExplorerBlock[])
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch data')
    } finally {
      setLoading(false)
    }
  }

  const fetchBlock = async (height: number): Promise<ExplorerBlock | null> => {
    try {
      const res = await fetch(`${rpcUrl}/rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'kovanica_getBlockByNumber',
          params: [height, true],
          id: 1,
        }),
      })
      const data = await res.json()
      if (data.error) throw new Error(data.error.message)
      if (!data.result) return null

      const block = data.result
      const txs: ExplorerTransaction[] = (block.transactions || []).map((tx: any) => ({
        hash: tx.hash,
        sender: tx.sender || '',
        nonce: parseInt(tx.nonce || '0', 16),
        fee: tx.fee || '0',
        kind: parseTxKind(tx),
        timestamp: Date.now() - (10 - (block.number ? parseInt(block.number, 16) : 0)) * 12000,
      }))

      return {
        hash: block.hash,
        round: block.number ? parseInt(block.number, 16) : 0,
        parent_hashes: block.parent_hashes || [],
        transactions: txs,
        author: block.author || 0,
        timestamp: Date.now(),
      }
    } catch {
      return null
    }
  }

  return (
    <div className="explorer">
      <div className="page-header">
        <h1 className="page-title">Block Explorer</h1>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">RPC Endpoint</label>
            <input
              type="text"
              value={rpcUrl}
              onChange={(e) => setRpcUrl(e.target.value)}
              placeholder="http://127.0.0.1:8545"
              style={{ width: '300px' }}
            />
          </div>
          <button className="btn-secondary" onClick={fetchData} disabled={loading}>
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>
      </div>

      {error && (
        <div className="card" style={{ backgroundColor: 'rgba(248, 81, 73, 0.1)', borderColor: 'var(--color-danger)' }}>
          <strong style={{ color: 'var(--color-danger)' }}>Error:</strong> {error}
        </div>
      )}

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Block Height</div>
          <div className="stat-value monospace">{latestHeight.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Latest Block</div>
          <div className="stat-value monospace">{blocks[0] ? `#${blocks[0].round}` : '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Total TXs (last 10 blocks)</div>
          <div className="stat-value monospace">{blocks.reduce((sum, b) => sum + b.transactions.length, 0)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Avg TXs/Block</div>
          <div className="stat-value monospace">
            {blocks.length > 0
              ? (blocks.reduce((sum, b) => sum + b.transactions.length, 0) / blocks.length).toFixed(1)
              : '—'}
          </div>
        </div>
      </div>

      <div className="tabs">
        <button className="tab active">Blocks</button>
        <button className="tab">Transactions</button>
        <button className="tab">Accounts</button>
        <button className="tab">Validators</button>
      </div>

      <div className="card">
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Round</th>
                <th>Hash</th>
                <th>Author</th>
                <th>TXs</th>
                <th>Parent Hashes</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {loading && blocks.length === 0 ? (
                <tr><td colSpan={6} className="loading"><div className="spinner"></div>Loading blocks...</td></tr>
              ) : blocks.length === 0 ? (
                <tr><td colSpan={6} className="empty-state">No blocks found</td></tr>
              ) : (
                blocks.map(block => (
                  <tr key={block.hash}>
                    <td className="monospace">#{block.round}</td>
                    <td className="address"><Link to={`/block/${block.hash}`}>{formatAddress(block.hash)}</Link></td>
                    <td className="monospace">{block.author}</td>
                    <td className="monospace">{block.transactions.length}</td>
                    <td className="address monospace">{block.parent_hashes.slice(0, 2).map(formatAddress).join(', ') || '—'}</td>
                    <td>{formatRelativeTime(block.timestamp)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ marginTop: '24px' }}>
        <h3 style={{ marginBottom: '16px' }}>Recent Transactions</h3>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Hash</th>
                <th>Sender</th>
                <th>Nonce</th>
                <th>Fee</th>
                <th>Kind</th>
              </tr>
            </thead>
            <tbody>
              {blocks.flatMap(b => b.transactions).slice(0, 20).map((tx, i) => (
                <tr key={tx.hash || i}>
                  <td className="address"><Link to={`/tx/${tx.hash}`}>{formatAddress(tx.hash)}</Link></td>
                  <td className="address">{formatAddress(tx.sender)}</td>
                  <td className="monospace">{tx.nonce}</td>
                  <td className="monospace">{formatAmount(tx.fee)} KUNA</td>
                  <td>{tx.kind.type}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function parseTxKind(tx: any): ExplorerTransaction['kind'] {
  if (tx.kind && typeof tx.kind === 'object') {
    const keys = Object.keys(tx.kind)
    if (keys.length === 1) {
      const type = keys[0]
      const value = tx.kind[type]
      return { type, ...value }
    }
  }
  return { type: 'Other', data: JSON.stringify(tx.kind) }
}