import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Network, RefreshCw, Layers, ShieldAlert, Cpu, Share2 } from 'lucide-react';

export const CampaignGraphPage: React.FC = () => {
  const [graphData, setGraphData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const fetchGraph = async () => {
    setLoading(true);
    try {
      const data = await api.getCorrelationGraph();
      setGraphData(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraph();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            ENTITY CORRELATION & CAMPAIGN GRAPH
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Graph-based threat infrastructure clustering, shared IoC discovery, and connected component analysis
          </p>
        </div>

        <button
          onClick={fetchGraph}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Recompute Graph</span>
        </button>
      </div>

      {/* Graph Summary Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="cyber-card p-4">
          <div className="text-xs text-slate-400 font-mono uppercase">Total Network Entities</div>
          <div className="text-2xl font-black text-cyan-400 font-mono mt-1">
            {graphData?.total_nodes || 0}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">Emails, Domains, IPs, URLs, Hashes</div>
        </div>

        <div className="cyber-card p-4">
          <div className="text-xs text-slate-400 font-mono uppercase">Correlated Relationships</div>
          <div className="text-2xl font-black text-blue-400 font-mono mt-1">
            {graphData?.total_edges || 0}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">Transmission, Delivery, Hosting Links</div>
        </div>

        <div className="cyber-card p-4">
          <div className="text-xs text-slate-400 font-mono uppercase">Detected Campaign Clusters</div>
          <div className="text-2xl font-black text-purple-400 font-mono mt-1">
            {graphData?.campaign_clusters?.length || 0}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">Connected Components</div>
        </div>
      </div>

      {/* Interactive Entity Network Canvas */}
      <div className="cyber-card p-6 space-y-4">
        <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
          <Share2 className="w-4 h-4 text-cyan-400" />
          Network Topology Canvas
        </h3>

        <div className="h-[400px] bg-[#070b14] rounded-xl border border-slate-800/80 p-6 flex flex-col justify-center items-center relative overflow-hidden">
          {graphData?.nodes && graphData.nodes.length > 0 ? (
            <div className="w-full h-full flex flex-wrap content-center justify-center gap-4 overflow-y-auto p-4">
              {graphData.nodes.map((node: any) => {
                const isEmail = node.type === 'Email';
                const isDomain = node.type === 'Domain';
                const isIp = node.type === 'IP';
                const isUrl = node.type === 'URL';

                return (
                  <div
                    key={node.id}
                    className={`p-3 rounded-xl border transition-all duration-200 cursor-pointer shadow-md ${
                      isEmail
                        ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-200'
                        : isDomain
                        ? 'bg-purple-950/40 border-purple-500/50 text-purple-200'
                        : isIp
                        ? 'bg-blue-950/40 border-blue-500/50 text-blue-200'
                        : isUrl
                        ? 'bg-amber-950/40 border-amber-500/50 text-amber-200'
                        : 'bg-slate-900 border-slate-700 text-slate-200'
                    }`}
                  >
                    <div className="text-[10px] font-mono uppercase tracking-wider font-bold opacity-75">
                      {node.type}
                    </div>
                    <div className="text-xs font-semibold max-w-[180px] truncate mt-0.5">
                      {node.label}
                    </div>
                    {node.centrality !== undefined && (
                      <div className="text-[9px] font-mono text-slate-400 mt-1">
                        Centrality: {node.centrality}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center text-slate-500 text-xs italic">
              No entities in graph repository yet. Ingest emails or test scenarios to build correlations.
            </div>
          )}
        </div>
      </div>

      {/* Campaign Clusters Breakdown */}
      {graphData?.campaign_clusters && graphData.campaign_clusters.length > 0 && (
        <div className="cyber-card p-6 space-y-4">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
            <Layers className="w-4 h-4 text-purple-400" />
            Identified Threat Campaign Clusters
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {graphData.campaign_clusters.map((cluster: any) => (
              <div
                key={cluster.cluster_id}
                className="p-4 bg-purple-950/20 border border-purple-500/30 rounded-xl space-y-2 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-purple-300 font-mono">{cluster.cluster_id}</span>
                  <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono text-[10px]">
                    {cluster.node_count} Linked Entities
                  </span>
                </div>
                <div className="text-slate-400 font-mono text-[11px]">
                  Graph Density: {cluster.density}
                </div>
                <div className="pt-2 flex flex-wrap gap-1">
                  {cluster.nodes.slice(0, 6).map((n: string, idx: number) => (
                    <span key={idx} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-300 font-mono">
                      {n.split(':')[0]}: {n.split(':')[1]?.slice(0, 16)}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
