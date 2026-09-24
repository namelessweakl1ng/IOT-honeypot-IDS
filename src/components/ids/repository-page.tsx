'use client'

// Repository — secondary view. Technical project inspector.
// Sharp panels, no gradients, monospace.

import { useEffect, useState, useMemo } from 'react'
import {
  ChevronRight, ChevronDown, Folder, FolderOpen, FileText, FileCode, FileJson,
  FileTerminal, FileCog, Download, Search, Copy, Check, FileArchive, File as FileIcon,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Panel } from './shared'
import { ScrollArea } from '@/components/ui/scroll-area'
import { toast } from 'sonner'

type Lang = 'python' | 'typescript' | 'javascript' | 'bash' | 'powershell' | 'yaml' | 'json' | 'markdown' | 'html' | 'css' | 'text' | 'csv' | 'jsonl' | 'file'

interface TreeNode {
  name: string
  path: string
  type: 'file' | 'directory'
  children?: TreeNode[]
  size?: number
  lang?: Lang
  stats?: { files: number; dirs: number; size: number }
}

const LANG_COLORS: Record<Lang, string> = {
  python: 'text-yellow-400',
  typescript: 'text-blue-400',
  javascript: 'text-yellow-300',
  bash: 'text-green-400',
  powershell: 'text-blue-300',
  yaml: 'text-purple-400',
  json: 'text-orange-400',
  markdown: 'text-slate-300',
  html: 'text-orange-400',
  css: 'text-blue-400',
  text: 'text-slate-400',
  csv: 'text-emerald-400',
  jsonl: 'text-orange-300',
  file: 'text-slate-400',
}

const LANG_ICON: Record<Lang, typeof FileText> = {
  python: FileCode, typescript: FileCode, javascript: FileCode,
  bash: FileTerminal, powershell: FileTerminal, yaml: FileCog, json: FileJson,
  markdown: FileText, html: FileCode, css: FileCode, text: FileText,
  csv: FileText, jsonl: FileJson, file: FileIcon,
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

function countInTree(node: TreeNode): { files: number; dirs: number } {
  if (node.type === 'file') return { files: 1, dirs: 0 }
  let files = 0; let dirs = 1
  for (const c of node.children || []) {
    const r = countInTree(c)
    files += r.files; dirs += r.dirs
  }
  return { files, dirs }
}

function expandAllDirs(node: TreeNode, expand: boolean): Set<string> {
  const ids = new Set<string>()
  if (node.type === 'directory') {
    if (expand) ids.add(node.path)
    for (const c of node.children || []) expandAllDirs(c, expand).forEach(x => ids.add(x))
  }
  return ids
}

function collectAllDirPaths(node: TreeNode): Set<string> {
  const out = new Set<string>()
  if (node.type === 'directory') {
    out.add(node.path)
    for (const c of node.children || []) collectAllDirPaths(c).forEach(p => out.add(p))
  }
  return out
}

function TreeRow({
  node, depth, expanded, toggle, selectedPath, setSelectedPath, visiblePaths,
}: {
  node: TreeNode
  depth: number
  expanded: Set<string>
  toggle: (p: string) => void
  selectedPath: string | null
  setSelectedPath: (p: string) => void
  visiblePaths: Set<string>
}) {
  if (!visiblePaths.has(node.path) && node.path !== 'iot-honeypot-ids') return null
  const isDir = node.type === 'directory'
  const isOpen = expanded.has(node.path)
  const isSelected = selectedPath === node.path
  const padding = 8 + depth * 16

  const Icon = isDir ? (isOpen ? FolderOpen : Folder) : (node.lang ? LANG_ICON[node.lang] : FileIcon)
  const color = isDir ? 'text-amber-400' : node.lang ? LANG_COLORS[node.lang] : 'text-slate-400'

  return (
    <>
      <div
        role="treeitem"
        aria-expanded={isDir ? isOpen : undefined}
        aria-selected={isSelected}
        onClick={(e) => {
          e.stopPropagation()
          if (isDir) toggle(node.path)
          setSelectedPath(node.path)
        }}
        className={`flex items-center gap-2 py-[2px] pr-2 cursor-pointer border-l-2 ${isSelected ? 'border-l-foreground bg-muted/30' : 'border-l-transparent'} hover:bg-muted/20`}
        style={{ paddingLeft: `${padding}px` }}
      >
        <span className="w-3 flex items-center justify-center text-slate-500">
          {isDir ? (isOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />) : null}
        </span>
        <Icon className={`w-3.5 h-3.5 ${color} flex-shrink-0`} />
        <span className="text-[11px] font-mono text-foreground truncate">{node.name}</span>
        {isDir && node.children && (
          <span className="text-slate-600 text-[9px] ml-auto font-mono">{node.children.length}</span>
        )}
      </div>
      {isDir && isOpen && node.children?.map(child => (
        <TreeRow
          key={child.path}
          node={child}
          depth={depth + 1}
          expanded={expanded}
          toggle={toggle}
          selectedPath={selectedPath}
          setSelectedPath={setSelectedPath}
          visiblePaths={visiblePaths}
        />
      ))}
    </>
  )
}

export function RepositoryPage() {
  const [tree, setTree] = useState<TreeNode | null>(null)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [query, setQuery] = useState('')
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/folder-tree.json')
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() })
      .then(data => {
        setTree(data)
        const init = new Set<string>(['iot-honeypot-ids'])
        for (const c of data.children || []) if (c.type === 'directory') init.add(c.path)
        setExpanded(init)
      })
      .catch(e => setError(String(e)))
  }, [])

  const visiblePaths = useMemo(() => {
    const visible = new Set<string>()
    if (!tree) return visible
    if (query) {
      const walk = (node: TreeNode): boolean => {
        let matched = false
        if (node.type === 'file' && node.name.toLowerCase().includes(query.toLowerCase())) matched = true
        for (const c of node.children || []) if (walk(c)) matched = true
        if (matched) visible.add(node.path)
        return matched
      }
      walk(tree)
      const add = (n: TreeNode) => {
        if (n.type === 'directory') visible.add(n.path)
        for (const c of n.children || []) add(c)
      }
      add(tree)
    }
    return visible
  }, [tree, query])

  const toggle = (path: string) => {
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(path)) next.delete(path); else next.add(path)
      return next
    })
  }

  const handleDownload = () => {
    const a = document.createElement('a')
    a.href = '/iot-honeypot-ids.zip'
    a.download = 'iot-honeypot-ids.zip'
    document.body.appendChild(a); a.click(); document.body.removeChild(a)
    toast.success('Download started', { description: 'iot-honeypot-ids.zip' })
  }

  const handleCopyPath = () => {
    if (selectedPath) {
      navigator.clipboard.writeText(selectedPath)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }
  }

  const selectedNode = useMemo(() => {
    if (!tree || !selectedPath) return null
    const find = (n: TreeNode): TreeNode | null => {
      if (n.path === selectedPath) return n
      for (const c of n.children || []) {
        const r = find(c); if (r) return r
      }
      return null
    }
    return find(tree)
  }, [tree, selectedPath])

  const stats = useMemo(() => (tree ? countInTree(tree) : null), [tree])

  if (error) {
    return (
      <div className="p-4">
        <Panel title="ERROR">
          <pre className="text-[11px] font-mono text-rose-400 whitespace-pre-wrap">{error}</pre>
        </Panel>
      </div>
    )
  }

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-baseline gap-3 border-b border-border pb-2">
        <h2 className="text-sm font-semibold tracking-wider text-foreground">REPOSITORY</h2>
        {stats && (
          <span className="text-[10px] font-mono text-muted-foreground ml-auto">{stats.files - 1} FILES · {stats.dirs} DIRS</span>
        )}
        <Button size="sm" onClick={handleDownload} className="h-7 text-[11px] font-mono bg-primary text-primary-foreground hover:bg-primary/90 ml-2">
          <Download className="w-3 h-3 mr-1" /> ZIP
        </Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_240px] gap-3">
        <Panel title="iot-honeypot-ids/" right={`${stats?.files ?? 0} FILES`}>
          <div className="flex items-center gap-2 mb-2">
            <Search className="w-3 h-3 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="FILTER FILES..."
              className="h-6 text-[11px] font-mono bg-background border-border text-foreground placeholder:text-muted-foreground"
            />
            <button onClick={() => tree && setExpanded(expandAllDirs(tree, true))} className="text-[10px] font-mono text-muted-foreground hover:text-foreground">EXPAND</button>
            <button onClick={() => setExpanded(new Set(['iot-honeypot-ids']))} className="text-[10px] font-mono text-muted-foreground hover:text-foreground">COLLAPSE</button>
          </div>
          <ScrollArea className="h-[60vh]">
            <div className="py-1">
              {tree ? (
                <TreeRow
                  node={tree}
                  depth={0}
                  expanded={query ? collectAllDirPaths(tree) : expanded}
                  toggle={toggle}
                  selectedPath={selectedPath}
                  setSelectedPath={setSelectedPath}
                  visiblePaths={visiblePaths}
                />
              ) : (
                <div className="px-4 py-8 text-center text-[11px] font-mono text-muted-foreground">LOADING…</div>
              )}
            </div>
          </ScrollArea>
        </Panel>

        <div className="space-y-3">
          <Panel title="SELECTION">
            {selectedNode ? (
              <div className="text-[11px] font-mono space-y-1">
                <div className="flex items-center gap-1 border border-border bg-background px-1.5 py-1">
                  <span className="text-muted-foreground truncate flex-1">{selectedNode.path}</span>
                  <button onClick={handleCopyPath} className="text-muted-foreground hover:text-foreground">
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
                <div className="flex items-baseline justify-between">
                  <span className="text-muted-foreground text-[10px] uppercase">TYPE</span>
                  <span className="text-foreground">{selectedNode.type}</span>
                </div>
                {selectedNode.type === 'file' && (
                  <div className="flex items-baseline justify-between">
                    <span className="text-muted-foreground text-[10px] uppercase">SIZE</span>
                    <span className="text-foreground">{formatBytes(selectedNode.size || 0)}</span>
                  </div>
                )}
                {selectedNode.type === 'directory' && (
                  <div className="flex items-baseline justify-between">
                    <span className="text-muted-foreground text-[10px] uppercase">CHILDREN</span>
                    <span className="text-foreground">{selectedNode.children?.length || 0}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-[11px] font-mono text-muted-foreground">SELECT A FILE OR FOLDER</div>
            )}
          </Panel>

          <Panel title="PROJECT ARTIFACT">
            <div className="text-[11px] font-mono space-y-1.5">
              <div className="text-muted-foreground text-[10px]">iot-honeypot-ids.zip</div>
              <div className="text-foreground">~250 KB</div>
              <div className="text-muted-foreground text-[10px]">EXCLUDES: node_modules, .venv, .git, __pycache__, .env</div>
              <Button size="sm" onClick={handleDownload} className="w-full h-7 text-[11px] font-mono bg-primary text-primary-foreground hover:bg-primary/90 mt-2">
                <Download className="w-3 h-3 mr-1" /> DOWNLOAD
              </Button>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  )
}
