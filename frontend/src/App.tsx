import { useEffect, useState } from 'react';
import { api, type Config } from './api';
import { ErrorBox, usePoll } from './components/ui';
import AgentSimulator from './tabs/AgentSimulator';
import Auditor from './tabs/Auditor';
import Mempool from './tabs/Mempool';
import MiningArena from './tabs/MiningArena';
import ChainExplorer from './tabs/ChainExplorer';

type Tab = 'agent' | 'review' | 'mempool' | 'mining' | 'chain';

function loadTab(): Tab {
  try {
    return (localStorage.getItem('ledger.tab') as Tab) || 'agent';
  } catch {
    return 'agent';
  }
}

export default function App() {
  const [tab, setTab] = useState<Tab>(loadTab);
  const [config, setConfig] = useState<Config | null>(null);
  const [configErr, setConfigErr] = useState<unknown>(null);
  const [stats, statsErr, reloadStats] = usePoll(api.stats, 2000);

  useEffect(() => {
    api.config().then(setConfig, setConfigErr);
  }, []);
  useEffect(() => {
    try {
      localStorage.setItem('ledger.tab', tab);
    } catch {
      /* storage unavailable */
    }
  }, [tab]);

  const steps: { id: Tab; n: string; t: string; c?: number | string }[] = [
    { id: 'agent', n: '1 · Agents', t: 'Agent work', c: stats?.work_total },
    { id: 'review', n: '2 · Human', t: 'Review & sign', c: stats?.pending_review },
    { id: 'mempool', n: '3 · Pending', t: 'Mempool', c: stats?.mempool },
    { id: 'mining', n: '4 · Consensus', t: 'Mining arena', c: stats?.mining ? '⛏' : undefined },
    { id: 'chain', n: '5 · Ledger', t: 'Chain', c: stats ? `#${stats.height}` : undefined },
  ];

  const resetAll = async () => {
    if (!confirm('Delete all work items, transactions and blocks (keeps genesis, miners and auditors)?')) return;
    await api.reset();
    reloadStats();
  };

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>AI Agent Accountability Ledger</h1>
          <div className="sub">
            Permissioned proof-of-work chain · human signatures for medium-confidence AI work
            {config && (
              <>
                {' '}
                · rules <code>{config.rules_version}</code>
              </>
            )}
          </div>
        </div>
        <div className="spacer" />
        <button className="btn small danger" onClick={resetAll}>
          Reset demo data
        </button>
      </header>

      {!!(configErr || statsErr) && (
        <ErrorBox error={`Cannot reach the C++ node: ${String(configErr ?? statsErr)}. Is ledger_server running?`} />
      )}

      <nav className="flow">
        {steps.map((s) => (
          <button key={s.id} className={`step${tab === s.id ? ' active' : ''}`} onClick={() => setTab(s.id)}>
            <div className="n">{s.n}</div>
            <div className="t">{s.t}</div>
            {s.c !== undefined && <div className="c">{s.c}</div>}
          </button>
        ))}
      </nav>

      {config && (
        <main>
          {tab === 'agent' && <AgentSimulator config={config} onChange={reloadStats} onGoReview={() => setTab('review')} />}
          {tab === 'review' && <Auditor onChange={reloadStats} onGoMempool={() => setTab('mempool')} />}
          {tab === 'mempool' && <Mempool onGoMining={() => setTab('mining')} />}
          {tab === 'mining' && <MiningArena config={config} onChange={reloadStats} onGoChain={() => setTab('chain')} />}
          {tab === 'chain' && <ChainExplorer />}
        </main>
      )}
    </div>
  );
}
