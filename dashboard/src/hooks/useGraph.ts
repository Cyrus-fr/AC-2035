import { useCallback, useEffect, useRef, useState } from 'react';
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { api } from '../api/client';
import type { CyNode, GraphData } from '../types';

cytoscape.use(dagre);

// Read the palette from the CSS custom properties so the canvas graph shares
// the single source of truth in index.css — no hardcoded hex here either.
function palette() {
  const s = getComputedStyle(document.documentElement);
  const v = (name: string) => s.getPropertyValue(name).trim();
  return {
    cyan: v('--accent-cyan') || '#00d4ff',
    purple: v('--accent-purple') || '#8b5cf6',
    green: v('--accent-green') || '#00ff88',
    red: v('--accent-red') || '#ff3366',
    amber: v('--accent-amber') || '#ffaa00',
    surface: v('--bg-surface') || '#0f1521',
    elevated: v('--bg-elevated') || '#151c2e',
    text: v('--text-primary') || '#e2e8f0',
    dim: v('--text-dim') || '#445566',
    border: v('--border-glow') || '#2a4060',
  };
}

function buildStylesheet(): cytoscape.StylesheetJson {
  const c = palette();
  return [
    {
      selector: 'node',
      style: {
        label: 'data(label)',
        color: c.text,
        'font-family': 'JetBrains Mono, monospace',
        'font-size': 9,
        'text-valign': 'bottom',
        'text-margin-y': 6,
        'text-wrap': 'ellipsis',
        'text-max-width': '90px',
        width: 34,
        height: 34,
        'border-width': 1.5,
        'background-color': c.elevated,
        'border-color': c.border,
      },
    },
    { selector: 'node[type="ExternalIP"]', style: { shape: 'hexagon', 'border-color': c.red, 'background-color': c.surface } },
    { selector: 'node[type="Pod"]', style: { shape: 'round-rectangle', 'border-color': c.cyan, 'background-color': c.surface } },
    { selector: 'node[type="Honeytoken"]', style: { shape: 'diamond', 'border-color': c.amber, 'background-color': c.surface, width: 40, height: 40 } },
    { selector: 'node[type="Identity"]', style: { shape: 'ellipse', 'border-color': c.purple, 'background-color': c.surface } },
    { selector: 'node[type="Technique"]', style: { shape: 'pentagon', 'border-color': c.dim, width: 24, height: 24, 'font-size': 7 } },
    // attack-path nodes get a coloured halo (cytoscape's underlay ≈ glow).
    {
      selector: 'node[?attack_path]',
      style: {
        'underlay-color': c.red,
        'underlay-opacity': 0.35,
        'underlay-padding': 8,
        'border-width': 2.5,
      },
    },

    {
      selector: 'edge',
      style: {
        width: 1.2,
        'line-color': c.cyan,
        'target-arrow-color': c.cyan,
        'curve-style': 'bezier',
        'arrow-scale': 0.8,
        opacity: 0.75,
      },
    },
    { selector: 'edge[type="CONNECTED_TO"]', style: { width: 1.2, 'line-color': c.cyan, 'target-arrow-color': c.cyan, 'target-arrow-shape': 'triangle' } },
    { selector: 'edge[type="MOVED_TO"]', style: { width: 3, 'line-color': c.red, 'target-arrow-color': c.red, 'target-arrow-shape': 'triangle' } },
    { selector: 'edge[type="ACCESSED"]', style: { width: 1.6, 'line-color': c.amber, 'line-style': 'dashed', 'target-arrow-color': c.amber, 'target-arrow-shape': 'triangle' } },
    { selector: 'edge[type="TRIGGERED"]', style: { width: 3, 'line-color': c.red, 'line-style': 'dashed', 'target-arrow-color': c.red, 'target-arrow-shape': 'triangle', 'underlay-color': c.red, 'underlay-opacity': 0.4, 'underlay-padding': 4 } },
    {
      selector: 'edge[?attack_path]',
      style: {
        width: 3,
        'line-color': c.red,
        'target-arrow-color': c.red,
        'target-arrow-shape': 'triangle',
        opacity: 1,
        'underlay-color': c.red,
        'underlay-opacity': 0.3,
        'underlay-padding': 3,
      },
    },
  ] as unknown as cytoscape.StylesheetJson;
}

const DAGRE = (rankDir: 'TB' | 'LR') =>
  ({ name: 'dagre', rankDir, padding: 30, nodeSep: 45, rankSep: 75, animate: true, animationDuration: 300 }) as unknown as cytoscape.LayoutOptions;

export function useGraph() {
  const [nodes, setNodes] = useState<CyNode[]>([]);
  const [edges, setEdges] = useState<GraphData['edges']>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<CyNode['data'] | null>(null);

  const cyRef = useRef<Core | null>(null);

  const containerRef = useCallback((el: HTMLDivElement | null) => {
    if (el && !cyRef.current) {
      const cy = cytoscape({ container: el, style: buildStylesheet(), elements: [], wheelSensitivity: 0.2, minZoom: 0.1, maxZoom: 3 });
      cy.on('tap', 'node', (evt) => setSelectedNode(evt.target.data() as CyNode['data']));
      cy.on('tap', (evt) => {
        if (evt.target === cy) setSelectedNode(null);
      });
      cyRef.current = cy;
    }
  }, []);

  const render = useCallback((data: GraphData, rankDir: 'TB' | 'LR') => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().remove();
    cy.add([...data.nodes, ...data.edges] as ElementDefinition[]);
    cy.layout(DAGRE(rankDir)).run();
    cy.fit(undefined, 40);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getGraph();
      setNodes(data.nodes);
      setEdges(data.edges);
      render(data, 'TB');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [render]);

  const loadAttackPath = useCallback(async (tokenId: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getAttackPath(tokenId);
      if (!data) {
        setError(`No attack path found for ${tokenId}`);
        return;
      }
      const cy = cyRef.current;
      if (!cy) return;
      // Merge the attack path onto the existing graph, flagging attack_path.
      [...data.nodes, ...data.edges].forEach((el) => {
        const existing = cy.getElementById(el.data.id);
        if (existing.nonempty()) existing.data('attack_path', true);
        else cy.add({ ...el, data: { ...el.data, attack_path: true } } as ElementDefinition);
      });
      cy.layout(DAGRE('LR')).run();
      cy.fit(undefined, 40);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  const clear = useCallback(async () => {
    await api.clearGraph();
    cyRef.current?.elements().remove();
    setNodes([]);
    setEdges([]);
    setSelectedNode(null);
  }, []);

  const fit = useCallback(() => cyRef.current?.fit(undefined, 40), []);

  useEffect(
    () => () => {
      cyRef.current?.destroy();
      cyRef.current = null;
    },
    [],
  );

  return {
    containerRef,
    nodes,
    edges,
    loading,
    error,
    refresh,
    loadAttackPath,
    clear,
    fit,
    selectedNode,
    clearSelection: () => setSelectedNode(null),
  };
}
