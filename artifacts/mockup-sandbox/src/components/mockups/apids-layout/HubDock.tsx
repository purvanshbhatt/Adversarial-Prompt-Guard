import React from "react";
import {
  Shield,
  BarChart2,
  FlaskConical,
  EyeOff,
  MessageSquare,
  Globe,
  Zap,
  Cpu,
  List,
  TrendingUp,
  FileText,
  CheckCircle2,
  ArrowRight,
  Download
} from "lucide-react";

export function HubDock() {
  const dockItems = [
    { icon: Shield, label: "Analyze", active: false },
    { icon: BarChart2, label: "Dashboard", active: true },
    { icon: FlaskConical, label: "Test Cases", active: false },
    { icon: EyeOff, label: "Obfuscation", active: false },
    { icon: MessageSquare, label: "Multi-Turn", active: false },
    { icon: Globe, label: "Real-World", active: false },
    { icon: Zap, label: "Attack Gen", active: false },
    { icon: Cpu, label: "Train", active: false },
    { icon: List, label: "Logs", active: false },
    { icon: TrendingUp, label: "Benchmark", active: false },
    { icon: FileText, label: "Report", active: false },
  ];

  return (
    <div className="flex flex-col w-full h-[800px] max-w-[1280px] bg-zinc-950 text-zinc-100 font-sans overflow-hidden border border-zinc-800 rounded-xl shadow-2xl mx-auto">
      {/* 1. Top Header Bar */}
      <header className="h-14 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between px-6 shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xl font-bold text-zinc-100 flex items-center gap-1">
              <span className="text-yellow-400">⚡</span> APIDS
            </span>
          </div>
          <div className="h-4 w-px bg-zinc-700" />
          <span className="text-xs text-zinc-400 font-medium tracking-wide">
            Adversarial Prompt Injection Detection System
          </span>
        </div>

        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 px-2.5 py-1 bg-zinc-950/50 rounded-md border border-zinc-800/50">
              <span className="text-xs font-medium text-zinc-400">ML Model</span>
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-xs text-zinc-300">Trained</span>
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 bg-zinc-950/50 rounded-md border border-zinc-800/50">
              <span className="text-xs font-medium text-zinc-400">Semantic</span>
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-xs text-zinc-300">Loaded</span>
            </div>
          </div>
          
          <div className="text-xs text-zinc-500 font-medium">
            247 analyzed <span className="text-zinc-700 mx-1">&middot;</span> 25.5% detection rate
          </div>
        </div>
      </header>

      {/* 2. Main Canvas Area */}
      <main className="flex-1 bg-zinc-950 p-8 overflow-y-auto">
        <div className="grid grid-cols-3 gap-5 max-w-6xl mx-auto h-full content-center">
          
          {/* Card 1 - Analyze Prompt */}
          <div className="bg-zinc-900 rounded-2xl p-6 border border-zinc-800 hover:border-cyan-400/50 transition-colors group flex flex-col justify-between h-[280px]">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="w-10 h-10 rounded-xl bg-cyan-400/10 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-cyan-400" />
                </div>
              </div>
              <div className="text-4xl font-bold text-zinc-100 tracking-tight mb-1">247</div>
              <div className="text-sm font-medium text-zinc-400">Analyzed</div>
              <div className="text-xs text-zinc-500 mt-1">Last: 2min ago</div>
            </div>
            
            <div className="mt-6 flex-1 flex flex-col justify-end">
              <div className="h-16 w-full flex items-end mb-4">
                <svg className="w-full h-full overflow-visible" preserveAspectRatio="none" viewBox="0 0 100 40">
                  <path d="M0,35 L20,30 L40,32 L60,15 L80,20 L100,5" fill="none" stroke="currentColor" strokeWidth="2" className="text-cyan-400 drop-shadow-[0_0_8px_rgba(34,211,238,0.4)]" vectorEffect="non-scaling-stroke" />
                  <circle cx="100" cy="5" r="3" className="fill-cyan-400" />
                </svg>
              </div>
              <div className="flex items-center text-xs font-semibold text-cyan-400 group-hover:text-cyan-300 transition-colors cursor-pointer">
                Open <ArrowRight className="w-3.5 h-3.5 ml-1 inline" />
              </div>
            </div>
          </div>

          {/* Card 2 - Dashboard */}
          <div className="bg-zinc-900 rounded-2xl p-6 border border-emerald-500/30 hover:border-emerald-400/50 transition-colors group flex flex-col justify-between h-[280px] shadow-[0_0_30px_-10px_rgba(16,185,129,0.1)] relative overflow-hidden">
            <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-400/5 rounded-bl-full pointer-events-none" />
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="w-10 h-10 rounded-xl bg-emerald-400/10 flex items-center justify-center">
                  <BarChart2 className="w-5 h-5 text-emerald-400" />
                </div>
                <div className="px-2 py-1 bg-emerald-400/10 text-emerald-400 text-[10px] font-bold tracking-wider rounded-md uppercase">Active</div>
              </div>
              <div className="text-4xl font-bold text-zinc-100 tracking-tight mb-1">25.5%</div>
              <div className="text-sm font-medium text-zinc-400">Detection Rate</div>
              <div className="text-xs text-zinc-500 mt-1">63 malicious / 247 total</div>
            </div>
            
            <div className="mt-6 flex-1 flex flex-col justify-end">
              <div className="h-16 w-full flex items-center mb-4 gap-4">
                <div className="relative w-12 h-12">
                   <svg viewBox="0 0 36 36" className="w-12 h-12 transform -rotate-90">
                    <path className="text-zinc-800" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" strokeWidth="4" />
                    <path className="text-emerald-400" strokeDasharray="25.5, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" strokeWidth="4" />
                  </svg>
                </div>
                <div className="flex-1 flex flex-col justify-center gap-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-zinc-400 flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-400"></span> Blocked</span>
                    <span className="text-zinc-300 font-medium">63</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-zinc-400 flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-zinc-700"></span> Passed</span>
                    <span className="text-zinc-300 font-medium">184</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center text-xs font-semibold text-emerald-400 group-hover:text-emerald-300 transition-colors cursor-pointer">
                View Dashboard <ArrowRight className="w-3.5 h-3.5 ml-1 inline" />
              </div>
            </div>
          </div>

          {/* Card 3 - Attack Generator */}
          <div className="bg-zinc-900 rounded-2xl p-6 border border-zinc-800 hover:border-orange-400/50 transition-colors group flex flex-col justify-between h-[280px]">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="w-10 h-10 rounded-xl bg-orange-400/10 flex items-center justify-center">
                  <Zap className="w-5 h-5 text-orange-400" />
                </div>
              </div>
              <div className="text-4xl font-bold text-zinc-100 tracking-tight mb-1">100<span className="text-2xl text-zinc-600">/100</span></div>
              <div className="text-sm font-medium text-zinc-400">Robustness Score</div>
              <div className="text-xs text-zinc-500 mt-1">Defeated all latest mutations</div>
            </div>
            
            <div className="mt-6 flex-1 flex flex-col justify-end">
              <div className="mb-6">
                <div className="h-2 w-full bg-zinc-800 rounded-full overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-orange-500 to-green-500 w-full rounded-full" />
                </div>
                <div className="flex justify-between text-[10px] text-zinc-500 mt-2">
                  <span>Vulnerable</span>
                  <span className="text-green-500 font-medium">Resilient</span>
                </div>
              </div>
              <div className="flex items-center text-xs font-semibold text-orange-400 group-hover:text-orange-300 transition-colors cursor-pointer">
                Open <ArrowRight className="w-3.5 h-3.5 ml-1 inline" />
              </div>
            </div>
          </div>

          {/* Card 4 - Benchmark */}
          <div className="bg-zinc-900 rounded-2xl p-6 border border-zinc-800 hover:border-violet-400/50 transition-colors group flex flex-col justify-between h-[280px]">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="w-10 h-10 rounded-xl bg-violet-400/10 flex items-center justify-center">
                  <TrendingUp className="w-5 h-5 text-violet-400" />
                </div>
              </div>
              <div className="text-4xl font-bold text-zinc-100 tracking-tight mb-1">0.12</div>
              <div className="text-sm font-medium text-zinc-400">ISR (Injection Success Rate)</div>
              <div className="text-xs text-zinc-500 mt-1">PIVS: 38.4</div>
            </div>
            
            <div className="mt-6 flex-1 flex flex-col justify-end">
              <div className="h-16 flex items-center justify-start mb-4">
                <svg className="w-16 h-16" viewBox="0 0 100 100">
                  <polygon points="50,5 90,25 90,75 50,95 10,75 10,25" fill="none" stroke="currentColor" strokeWidth="1" className="text-zinc-800" />
                  <polygon points="50,20 80,35 70,65 50,80 30,70 20,40" fill="none" stroke="currentColor" strokeWidth="2" className="text-violet-400/30" />
                  <polygon points="50,30 70,40 65,60 50,70 35,60 30,45" fill="currentColor" className="text-violet-400/20" stroke="currentColor" strokeWidth="1.5" />
                </svg>
                <div className="ml-4 flex flex-col gap-2">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-violet-400" />
                    <span className="text-xs text-zinc-400">Current Model</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-zinc-700" />
                    <span className="text-xs text-zinc-500">Baseline</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center text-xs font-semibold text-violet-400 group-hover:text-violet-300 transition-colors cursor-pointer">
                Open <ArrowRight className="w-3.5 h-3.5 ml-1 inline" />
              </div>
            </div>
          </div>

          {/* Card 5 - Real-World Eval */}
          <div className="bg-zinc-900 rounded-2xl p-6 border border-zinc-800 hover:border-sky-400/50 transition-colors group flex flex-col justify-between h-[280px]">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="w-10 h-10 rounded-xl bg-sky-400/10 flex items-center justify-center">
                  <Globe className="w-5 h-5 text-sky-400" />
                </div>
              </div>
              <div className="text-4xl font-bold text-zinc-100 tracking-tight mb-1">0.4%</div>
              <div className="text-sm font-medium text-zinc-400">ΔF1 (Generalization gap)</div>
              <div className="text-xs text-zinc-500 mt-1">Synthetic vs Real-world data</div>
            </div>
            
            <div className="mt-6 flex-1 flex flex-col justify-end">
              <div className="h-16 flex items-end justify-start gap-3 mb-4">
                <div className="flex flex-col items-center gap-1">
                  <div className="w-8 h-12 bg-zinc-800 rounded-t-sm" />
                  <span className="text-[10px] text-zinc-500">Synth</span>
                </div>
                <div className="flex flex-col items-center gap-1">
                  <div className="w-8 h-11 bg-sky-400 rounded-t-sm" />
                  <span className="text-[10px] text-zinc-500">Real</span>
                </div>
              </div>
              <div className="flex items-center text-xs font-semibold text-sky-400 group-hover:text-sky-300 transition-colors cursor-pointer">
                Open <ArrowRight className="w-3.5 h-3.5 ml-1 inline" />
              </div>
            </div>
          </div>

          {/* Card 6 - Research Report */}
          <div className="bg-zinc-900 rounded-2xl p-6 border border-zinc-800 hover:border-amber-400/50 transition-colors group flex flex-col justify-between h-[280px]">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="w-10 h-10 rounded-xl bg-amber-400/10 flex items-center justify-center">
                  <FileText className="w-5 h-5 text-amber-400" />
                </div>
              </div>
              <div className="text-4xl font-bold text-zinc-100 tracking-tight mb-1">Ready</div>
              <div className="text-sm font-medium text-zinc-400">Export Available</div>
              <div className="text-xs text-zinc-500 mt-1">arXiv-format LaTeX & PDF</div>
            </div>
            
            <div className="mt-6 flex-1 flex flex-col justify-end">
              <div className="mb-5">
                <button className="w-full flex items-center justify-center gap-2 py-2.5 px-4 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-sm font-medium rounded-lg transition-colors border border-zinc-700">
                  <Download className="w-4 h-4 text-amber-400" />
                  Download PDF
                </button>
              </div>
              <div className="flex items-center text-xs font-semibold text-amber-400 group-hover:text-amber-300 transition-colors cursor-pointer">
                Open <ArrowRight className="w-3.5 h-3.5 ml-1 inline" />
              </div>
            </div>
          </div>

        </div>
      </main>

      {/* 3. Bottom Dock */}
      <nav className="h-16 bg-zinc-900/90 backdrop-blur-xl border-t border-zinc-800 flex items-center justify-center px-4 shrink-0">
        <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar max-w-full">
          {dockItems.map((item, idx) => (
            <button
              key={idx}
              className={`
                flex items-center gap-2 px-3.5 py-2 rounded-lg transition-all whitespace-nowrap
                ${item.active 
                  ? 'bg-zinc-700/80 text-zinc-100 shadow-sm ring-1 ring-zinc-600/50' 
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50'
                }
              `}
            >
              <item.icon className={`w-4 h-4 ${item.active ? 'text-emerald-400' : ''}`} />
              <span className={`text-sm font-medium ${item.active ? 'text-zinc-100' : ''}`}>
                {item.label}
              </span>
            </button>
          ))}
        </div>
      </nav>
    </div>
  );
}
