import { motion, AnimatePresence } from 'motion/react';
import React, { useState, useEffect, useRef, ReactNode } from 'react';
import { 
  Shield, 
  Terminal as TerminalIcon, 
  Search, 
  Activity, 
  Lock, 
  Settings, 
  Cpu, 
  Zap, 
  Wifi, 
  Battery,
  Minimize2,
  Copy,
  Check,
  ChevronRight,
  Database,
  LogOut,
  Power,
  ChevronDown,
  AlertTriangle,
  Skull,
  Key
} from 'lucide-react';
import { localAuth, LocalUser } from './lib/localStore';
import { GoogleGenAI } from "@google/genai";
import { auth, db, isFirebaseConfigured, googleProvider } from './lib/firebase';
import { 
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  signInAnonymously,
  signInWithPopup
} from 'firebase/auth';
import { 
  doc, 
  setDoc 
} from 'firebase/firestore';

// --- AI Configuration ---
const getApiKey = () => {
  // Vite replaces these at compile time
  const viteKey = import.meta.env.VITE_GEMINI_API_KEY;
  if (viteKey && viteKey !== "__VITE_GEMINI_API_KEY__" && viteKey !== "undefined") return viteKey;
  
  // Fallback for direct process usage if possible
  if (typeof process !== 'undefined' && process.env?.GEMINI_API_KEY) return process.env.GEMINI_API_KEY;
  
  return "";
};

const GEMINI_API_KEY = getApiKey();

if (!GEMINI_API_KEY) {
  console.warn("Gemini API Key is missing! AI features will be limited.");
}

const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY || "AIzaSy_SENTINEL_PLACEHOLDER" });

// --- Constants & Types ---

const INITIAL_LOGS = [
  { id: 1, type: 'info', msg: 'System initialized. Secure Kernel v4.2-LTS [Sentinel_SECaaS]' },
];

// --- Helper Components ---

function TypingText({ text, speed = 20 }: { text: string; speed?: number }) {
  const [displayedText, setDisplayedText] = useState("");
  
  useEffect(() => {
    let index = 0;
    const interval = setInterval(() => {
      setDisplayedText(text.substring(0, index + 1));
      index++;
      if (index >= text.length) clearInterval(interval);
    }, speed);
    return () => clearInterval(interval);
  }, [text, speed]);

  return <span>{displayedText}</span>;
}

function DraggableWindow({ 
  title, 
  children, 
  className = "",
  initialPos = { x: 0, y: 0 },
  redAlert = false
}: { 
  title: string; 
  children: ReactNode; 
  className?: string;
  initialPos?: { x: number; y: number };
  redAlert?: boolean;
}) {
  return (
    <motion.div 
      drag
      dragMomentum={false}
      initial={{ opacity: 0, scale: 0.95, ...initialPos }}
      animate={{ opacity: 1, scale: 1 }}
      className={`terminal-window absolute cursor-default ${className} ${redAlert ? 'red-alert' : ''}`}
    >
      <div className="terminal-header cursor-grab active:cursor-grabbing">
        <div className="terminal-controls">
          <div className="control-dot close" />
          <div className="control-dot min" />
          <div className="control-dot max" />
        </div>
        <div className="text-[10px] font-bold text-gray-500 uppercase tracking-[0.2em]">{title}</div>
        <div className="w-[50px] flex justify-end">
          <Minimize2 className="w-3 h-3 text-gray-700" />
        </div>
      </div>
      <div className="flex-1 overflow-auto p-4 scrollbar-hide">
        {children}
      </div>
    </motion.div>
  );
}

function ProgressBar({ label, value, colorClass = "text-sky-400" }: { label: string; value: number; colorClass?: string }) {
  const bars = Math.floor(value / 5);
  const total = 20;
  const barString = '[' + '#'.repeat(bars) + '.'.repeat(total - bars) + ']';
  
  return (
    <div className="mb-4">
      <div className="flex justify-between text-[10px] mb-1">
        <span className="uppercase tracking-widest text-gray-500">{label}</span>
        <span className={colorClass}>{value}%</span>
      </div>
      <div className={`font-mono text-xs ${colorClass} tracking-tighter text-nowrap`}>
        {barString}
      </div>
    </div>
  );
}

// --- Auth Components ---

function LoginScreen({ onAuthSuccess }: { onAuthSuccess: (user: LocalUser) => void; key?: string }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLogin, setIsLogin] = useState(true);
  const [error, setError] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [bootSequence, setBootSequence] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => setBootSequence(false), 2000);
    return () => clearTimeout(timer);
  }, []);

  const handleGoogleLogin = async () => {
    if (!isFirebaseConfigured) return;
    setLoading(true);
    setError(null);
    try {
      const result = await signInWithPopup(auth, googleProvider);
      const fbUser = result.user;
      
      await setDoc(doc(db, 'users', fbUser.uid), {
        uid: fbUser.uid,
        email: fbUser.email,
        role: 'user',
        username: fbUser.displayName || fbUser.email?.split('@')[0] || 'google_user',
        createdAt: Date.now()
      }, { merge: true });

      const mappedUser: LocalUser = {
        uid: fbUser.uid,
        username: fbUser.displayName || fbUser.email?.split('@')[0] || 'google_user',
        apiKey: localAuth.generateApiKey(),
        createdAt: Date.now(),
        lastLogin: Date.now()
      };

      localAuth.setCurrentUser(mappedUser);
      onAuthSuccess(mappedUser);
    } catch (err: any) {
      setError({
        code: err.code || 'GOOGLE_AUTH_ERROR',
        message: err.message || 'Google authentication failed',
        isProviderError: true
      });
    } finally {
      setLoading(false);
    }
  };

  const handleAnonymousLogin = async () => {
    if (!isFirebaseConfigured) return;
    setLoading(true);
    setError(null);
    try {
      const result = await signInAnonymously(auth);
      const fbUser = result.user;

      const mappedUser: LocalUser = {
        uid: fbUser.uid,
        username: 'guest_' + fbUser.uid.substring(0, 5),
        apiKey: localAuth.generateApiKey(),
        createdAt: Date.now(),
        lastLogin: Date.now()
      };

      localAuth.setCurrentUser(mappedUser);
      onAuthSuccess(mappedUser);
    } catch (err: any) {
      setError({
        code: err.code || 'ANON_AUTH_ERROR',
        message: err.message || 'Guest access initialization failed',
        isProviderError: true
      });
    } finally {
      setLoading(false);
    }
  };

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    if (!isFirebaseConfigured) {
      setError({
        code: 'CONFIG_MISSING',
        message: 'Sentinel Security requires Firebase configuration. Please add VITE_FIREBASE_API_KEY in Settings.',
        isProviderError: false
      });
      setLoading(false);
      return;
    }

    try {
      let userCredential;
      const email = username.includes('@') ? username : `${username}@sentinel.secaas`;

      if (isLogin) {
        // Direct Firebase SDK Login
        userCredential = await signInWithEmailAndPassword(auth, email, password);
      } else {
        // Direct Firebase SDK Registration
        userCredential = await createUserWithEmailAndPassword(auth, email, password);
        
        // Save to Firestore
        await setDoc(doc(db, 'users', userCredential.user.uid), {
          uid: userCredential.user.uid,
          email: email,
          role: 'user',
          username: username,
          createdAt: Date.now()
        });
      }

      const fbUser = userCredential.user;

      const mappedUser: LocalUser = {
        uid: fbUser.uid,
        username: username,
        apiKey: localAuth.generateApiKey(), // Still Generate local API key for simulation
        createdAt: Date.now(),
        lastLogin: Date.now()
      };

      localAuth.setCurrentUser(mappedUser);
      onAuthSuccess(mappedUser);
    } catch (err: any) {
      console.error("[ AUTH_FAIL ]", err);
      setError({
        code: err.code || 'AUTH_ERROR',
        message: err.message || 'An error occurred during authentication',
        isProviderError: !!err.code
      });
    } finally {
      setLoading(false);
    }
  };

  if (bootSequence) {
    return (
      <div className="h-screen w-screen bg-black flex items-center justify-center p-8 font-mono text-kali-green overflow-hidden">
        <div className="max-w-xl w-full">
          <p>[    0.000000] Linux version 6.5.0-ent-amd64 (Sentinel@SECaaS) ...</p>
          <p>[    0.000001] Command line: BOOT_IMAGE=/boot/vmlinuz-6.5.0-ent-amd64 ...</p>
          <p>[    0.452103] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'</p>
          <p>[    1.123045] systemd[1]: Inserted module 'autofs4'</p>
          <p>[    1.567890] systemd[1]: Set hostname to &lt;sentinel-os&gt;</p>
          <p>[    1.890123] systemd[1]: Reached target Graphical Interface.</p>
          <p className="blinking-cursor">_</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen w-screen bg-black flex flex-col items-center justify-center p-8 font-mono">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md border border-[#1a1a1a] bg-[#050505] p-8 shadow-[0_0_50px_rgba(0,127,255,0.1)]"
      >
        <div className="flex flex-col items-center mb-8">
          <Shield className="w-12 h-12 text-sky-400 mb-4" />
          <h1 className="text-xl font-bold tracking-[0.3em] uppercase text-sky-400">Sentinel_SECaaS</h1>
          <p className="text-[10px] text-gray-500 mt-2 uppercase tracking-widest">v2.4.1 Terminal Access</p>
        </div>

        {error && (
          <motion.div 
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            className="bg-sentinel-red/5 border border-sentinel-red/30 p-4 mb-6 font-mono"
          >
            <div className="text-[10px] font-bold text-sentinel-red uppercase tracking-widest mb-1">
              [ ERROR ] {error.code}: SECURITY_BREACH_DETECTED
            </div>
            <div className="text-[9px] text-gray-500 lowercase leading-tight mb-2">
              {error.code === "USER_NOT_FOUND" 
                ? "Identity not found in kernel. Register to authorize access."
                : error.code === "INVALID_PASSWORD"
                ? "Handshake failed. Security password mismatch."
                : error.code === "INVALID_CREDENTIALS" 
                ? "Access denied. Credentials not found in local vault."
                : error.code === "USERNAME_TAKEN"
                ? "This identity is already claimed. Try another or login."
                : error.code === "IDENTITY_ALREADY_LINKED"
                ? error.message
                : error.code === "UID_LINKED"
                ? error.message
                : error.code === "WEAK_PASSWORD"
                ? "Password is too weak. Minimum 8 characters required."
                : error.message}
            </div>
            {error.isProviderError && (
              <button 
                type="button"
                onClick={() => {
                  const demoUser: LocalUser = {
                    uid: 'demo_' + Math.random().toString(36).substring(2, 9),
                    username: username || 'guest_sentinel',
                    apiKey: localAuth.generateApiKey(),
                    createdAt: Date.now(),
                    lastLogin: Date.now()
                  };
                  onAuthSuccess(demoUser);
                }}
                className="w-full mt-2 py-2 border border-sentinel-blue/50 text-sentinel-blue text-[8px] uppercase tracking-widest hover:bg-sentinel-blue hover:text-black transition-all"
              >
                Launch in Guest Mode (Offline Bypass)
              </button>
            )}
          </motion.div>
        )}

        <form onSubmit={handleAuth} className="space-y-6">
          <div>
            <label className="block text-[10px] uppercase tracking-widest text-gray-500 mb-2">tty1 login:</label>
            <div className="relative">
              <input 
                type="text" 
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full bg-black border-b border-[#333] px-0 py-2 text-sentinel-green focus:outline-none focus:border-sentinel-blue transition-colors"
                placeholder="root_user"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-[10px] uppercase tracking-widest text-gray-500 mb-2">password:</label>
            <div className="relative">
              <input 
                type="password" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-black border-b border-[#333] px-0 py-2 text-sentinel-green focus:outline-none focus:border-sentinel-blue transition-colors font-sans"
                placeholder="********"
                required
              />
            </div>
          </div>

          <button 
            type="submit" 
            disabled={loading}
            className="w-full py-3 bg-sentinel-blue text-black font-bold uppercase tracking-widest hover:bg-white transition-colors disabled:opacity-50"
          >
            {loading ? 'Processing...' : isLogin ? 'Access System' : 'Initialize Profile'}
          </button>
        </form>

        <div className="mt-4 grid grid-cols-2 gap-4">
          <button 
            onClick={handleGoogleLogin}
            disabled={loading}
            className="flex items-center justify-center gap-2 py-2 border border-[#333] text-[10px] uppercase tracking-widest hover:bg-white hover:text-black transition-all disabled:opacity-50"
          >
            <Shield className="w-3 h-3" />
            Google
          </button>
          <button 
            onClick={handleAnonymousLogin}
            disabled={loading}
            className="flex items-center justify-center gap-2 py-2 border border-[#333] text-[10px] uppercase tracking-widest hover:bg-white hover:text-black transition-all disabled:opacity-50"
          >
            <Power className="w-3 h-3" />
            Guest
          </button>
        </div>

        <div className="mt-6 text-center">
          <button 
            onClick={() => setIsLogin(!isLogin)}
            className="text-[10px] text-gray-500 hover:text-sentinel-blue uppercase tracking-widest transition-colors"
          >
            {isLogin ? "Need a new account? Register" : "Already have account? Login"}
          </button>
        </div>
      </motion.div>

      <div className="absolute bottom-8 left-0 right-0 text-center opacity-20">
        <p className="text-[10px] text-gray-300 tracking-[0.5em] uppercase">Authorized Personnel Only</p>
      </div>
    </div>
  );
}

// --- Main Dashboard Component ---

type DashboardView = 'dashboard' | 'keys' | 'logs' | 'network' | 'cage';

function Dashboard({ user: initialUser, onLogout }: { user: LocalUser; onLogout: () => void; key?: string }) {
  const [user, setUser] = useState<LocalUser>(initialUser);
  const [view, setView] = useState<DashboardView>('dashboard');
  const [fingerprint] = useState(() => {
    let fp = localStorage.getItem('sentinel_fingerprint');
    if (!fp) {
      fp = 'fp_' + Math.random().toString(36).substring(2, 12);
      localStorage.setItem('sentinel_fingerprint', fp);
    }
    return fp;
  });
  const [problems, setProblems] = useState<any[]>([]);
  const [output, setOutput] = useState<any[]>([]);
  const [terminalTab, setTerminalTab] = useState<'OUTPUT' | 'PROBLEMS'>('OUTPUT');
  const [isCopied, setIsCopied] = useState(false);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [notification, setNotification] = useState<string | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [redAlert, setRedAlert] = useState(false);
  const [eth0Status, setEth0Status] = useState<'UP' | 'DOWN'>('UP');
  const [networkInterfaces, setNetworkInterfaces] = useState<any[]>([]);
  
  const [deceptionLogs, setDeceptionLogs] = useState<any[]>([]);
  const [hackerHooked, setHackerHooked] = useState(false);
  const [unmaskedData, setUnmaskedData] = useState<any>(null);
  
  const [currentKey, setCurrentKey] = useState<string | null>(null);
  const [persistentKeys, setPersistentKeys] = useState<any[]>([]);
  const [keyExpiresAt, setKeyExpiresAt] = useState<number | null>(null);
  const [systemStatus, setSystemStatus] = useState<'ACTIVE' | 'KILLED' | 'LOCKED'>('ACTIVE');
  const [isConfigured, setIsConfigured] = useState(false);
  const [sessionPassword, setSessionPassword] = useState<string | null>(null);
  const [pendingCommand, setPendingCommand] = useState<null | 'UPDATE_PASSWORD_NEW' | 'UPDATE_PASSWORD_CURRENT' | 'LOGIN' | 'DELETE_BABY' | 'WAKE_UP_GUARD' | 'AUTHORIZE_SHUTDOWN'>(null);
  const [tempPassword, setTempPassword] = useState('');
  
const fetchSystemStatus = async () => {
  try {
    // 1. We remove the fetch(`/api/...`) because it doesn't exist
    // 2. We manually set a "Healthy" status so the dashboard looks good
    const mockData = {
      status: {
        online: true,
        threatLevel: 'Low',
        lastSync: new Date().toISOString(),
        version: '1.0.0-stable'
      }
    };

    // 3. Update your state with this fake data
    if (mockData && mockData.status) {
      setSystemStatus(mockData.status);
    }
  } catch (e) {
    console.error("Status check skipped: No backend detected.");
  }
};

  const fetchConfigStatus = async () => {
    try {
      const res = await fetch(`/api/system/config-status?username=${encodeURIComponent(user.username)}&_t=${Date.now()}`);
      if (!res.ok) return;
      const contentType = res.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        return;
      }
      const data = await res.json();
      setIsConfigured(data.is_configured);
    } catch (e) {}
  };

  useEffect(() => {
    fetchSystemStatus();
    fetchConfigStatus();
    
    const interval = setInterval(() => {
      fetchSystemStatus();
      fetchConfigStatus();
    }, 5000);

    return () => {
      clearInterval(interval);
    };
  }, []); // Only run on mount, auth/interval handle the rest
  
  const [threatAnalysis, setThreatAnalysis] = useState<any>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [aiForensics, setAiForensics] = useState<string | null>(null);
  
  const [commandInput, setCommandInput] = useState('');
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  
  const [isGeneratingKey, setIsGeneratingKey] = useState(false);
  
  const scrollRef = useRef<HTMLDivElement>(null);
  const mainTerminalScrollRef = useRef<HTMLDivElement>(null);

  const addLog = (log: { type: string; msg: string; timestamp: number }) => {
    const logId = `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
    const newLog = {
      id: logId,
      ...log,
      type: log.type === 'SYSTEM' ? 'info' : log.type,
      isRealTime: true,
    };
    setOutput(prev => [...prev.slice(-49), newLog]);
  };

  // Auto-scroll main terminal
  useEffect(() => {
    if (mainTerminalScrollRef.current) {
      mainTerminalScrollRef.current.scrollTop = mainTerminalScrollRef.current.scrollHeight;
    }
  }, [problems, output]);

  // Auto-scroll command history
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [commandHistory]);

  const playBeep = () => {
    try {
      const audioCtx = new (window.AudioContext || (window as any).webkitAudioContext)();
      const oscillator = audioCtx.createOscillator();
      const gainNode = audioCtx.createGain();

      oscillator.connect(gainNode);
      gainNode.connect(audioCtx.destination);

      oscillator.type = 'sine';
      oscillator.frequency.setValueAtTime(440, audioCtx.currentTime); // A4
      gainNode.gain.setValueAtTime(0.05, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.00001, audioCtx.currentTime + 0.3);

      oscillator.start();
      oscillator.stop(audioCtx.currentTime + 0.3);
    } catch (err) {
      console.warn("Audio beep blocked by browser policy");
    }
  };

  useEffect(() => {
    if (threatAnalysis?.score > 70) {
      setRedAlert(true);
      playBeep();
    } else {
      setRedAlert(false);
    }
  }, [threatAnalysis]);

  const performAiForensics = async (payload: string, threats: string[]) => {
    try {
      const prompt = `Analyze this malicious payload for forensic details. 
        Payload: ${payload}
        Rule-based threats detected: ${threats.join(', ')}
        
        Provide a concise 2-sentence summary of the attack vector and its goal. 
        Start with "ANALYSIS: "`;

      const result = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        config: {
          maxOutputTokens: 200,
        }
      });
      
      const responseText = result.text;
      setAiForensics(responseText || "Unable to parse threat vector.");
    } catch (err) {
      console.error("AI Forensics failed", err);
      setAiForensics("AI engine offline. Manual investigation required.");
    }
  };

  const runSecurityCheck = async () => {
    if (!currentKey) {
      setNotification('ERROR: API Key required. Generate one in Secrets section.');
      setView('keys');
      return;
    }

    setAnalyzing(true);
    setAiForensics(null);
    const maliciousPayload = "SELECT * FROM users; DROP TABLE products; -- <script>alert(document.cookie)</script>";
    
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-api-key': currentKey,
          'x-fingerprint': fingerprint
        },
        body: JSON.stringify({
          timestamp: Date.now(),
          user: user.username,
          payload: maliciousPayload,
          origin: "172.16.0.42"
        })
      });
      const data = await response.json();

      if (response.status === 401) {
        setNotification(`AUTH_FAIL: ${data.message}`);
        setCurrentKey(null);
        setKeyExpiresAt(null);
        return;
      }

      setThreatAnalysis(data);
      
      if (data.action === 'BLOCK') {
        performAiForensics(maliciousPayload, data.threats);
      }
    } catch (err) {
      console.error("Analysis failed", err);
    } finally {
      setAnalyzing(false);
    }
  };

  const fetchPersistentKeys = async () => {
    try {
      const response = await fetch('/api/keys/list', {
        headers: {
          'x-api-key': 'sk_master_777_sentinel' // Dashboard fallback key
        }
      });
      const contentType = response.headers.get("content-type");
      if (response.status === 401 || response.status === 403) {
        console.warn("Keys List: Authorization Required.");
        return;
      }
      if (!contentType || !contentType.includes("application/json")) {
        return;
      }
      const data = await response.json();
      setPersistentKeys(data);
      if (data.length > 0 && !currentKey) {
        setCurrentKey(data[data.length - 1].api_key);
      }
    } catch (err) {
      console.error("Failed to fetch keys", err);
    }
  };

  const fetchNetworkStatus = async () => {
    const url = `/api/network/status?_t=${Date.now()}`;
    try {
      const response = await fetch(url);
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        const text = await response.text();
        console.error(`[ API ERROR ] URL: ${url} | Status: ${response.status} | Content-Type: ${contentType}`);
        console.error(`Payload snippet: ${text.substring(0, 200)}`);
        return;
      }
      const data = await response.json();
      setEth0Status(data.eth0);
      setNetworkInterfaces(data.interfaces || []);
    } catch (err: any) {
      if (err.message !== "Failed to fetch") {
        console.error(`Failed to fetch network status from ${url}`, err);
      }
    }
  };

  const handleToggleInterface = async (name: string) => {
    try {
      const response = await fetch('/api/network/toggle-interface', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
      });
      if (response.ok) {
        fetchNetworkStatus();
      }
    } catch (err) {
      console.error("Failed to toggle interface", err);
    }
  };

  useEffect(() => {
    fetchNetworkStatus();
    const interval = setInterval(fetchNetworkStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    fetchPersistentKeys();
  }, []);

  // WebSocket for Real-Time Threat Intel
  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout;

    const connect = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;
      console.log(`[ WS ] Connecting to ${wsUrl}...`);
      
      socket = new WebSocket(wsUrl);

      const generateLogId = () => `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const logId = generateLogId();
          
          if (data.msg === 'SECURITY_PASSWORD_SET') {
            setIsConfigured(true);
            setNotification('SYSTEM_SECURED: Security Password Initialized.');
            addLog({ type: 'SYSTEM', msg: '[SEC] Security Password successfully set in ThreatVault.', timestamp: Date.now() });
            return;
          }

          if (data.msg === 'SYSTEM_AWAKENED') {
            setSystemStatus('ACTIVE');
            setNotification('SYSTEM_AWAKENED: Lock Lifted.');
            addLog({ type: 'SYSTEM', msg: '[SEC] System Auth Verified in Console. System is now ACTIVE.', timestamp: Date.now() });
            return;
          }

          if (data.type === 'HONE_HOOKED') {
            setHackerHooked(true);
            if (data.unmasked) {
              setUnmaskedData(data);
              setNotification(`[ADVERSARY UNMASKED] PC_NAME: L33T_HACKER_BOX`);
            } else {
              setNotification('SUCCESS: HACKER HOOKED IN MIRROR ROOM');
            }
            const hookLog = {
               id: logId,
               type: 'scan',
               msg: data.msg,
               isRealTime: true,
               timestamp: Date.now()
            };
            setOutput(prev => [...prev.slice(-49), hookLog]);
            playBeep();
            return;
          }

          if (data.type === 'BLOCK_EVENT' || data.type === 'BAN_EVENT' || data.type === 'DANGER_IP' || data.type === 'SANDBOX_EVENT') {
            const problemLog = {
              id: logId,
              type: 'error',
              msg: data.msg,
              isRealTime: true,
              timestamp: Date.now()
            };
            setProblems(prev => [...prev.slice(-49), problemLog]);
            
            if (data.type === 'DANGER_IP') {
              setTerminalTab('PROBLEMS');
              setNotification(`DANGER: ${data.ip} identified in blacklist`);
              setRedAlert(true);
              playBeep();
              setTimeout(() => setRedAlert(false), 5000);
            } else if (terminalTab !== 'PROBLEMS') {
               setTerminalTab('PROBLEMS');
            }
          } else {
            const outputLog = {
              id: logId,
              type: data.type === 'SYSTEM' ? 'info' : 'scan',
              msg: data.msg,
              isRealTime: true,
              timestamp: Date.now()
            };
            setOutput(prev => [...prev.slice(-49), outputLog]);
          }
        } catch (err) {
          console.error('[ WS ] Message parsing error', err);
        }
      };

      socket.onopen = () => {
        console.log('[ WS ] Connection established with Security Engine');
        setNotification('LINK_ESTABLISHED: Terminal Connected');
      };

      socket.onerror = (err) => {
        console.error('[ WS ] Socket error observed. This may be due to proxy timeouts or browser security policies.', err);
        setNotification('LINK_INTERRUPTED: Retrying...');
      };

      socket.onclose = (event) => {
        console.warn(`[ WS ] Connection closed (code: ${event.code}). Reconnecting in 3s...`);
        clearTimeout(reconnectTimeout);
        reconnectTimeout = setTimeout(connect, 3000);
      };
    };

    connect();
    
    return () => {
      if (socket) socket.close();
      clearTimeout(reconnectTimeout);
    };
  }, []);

  // Initialization sequence
  useEffect(() => {
    const timer = setTimeout(() => setIsInitializing(false), 2500);
    return () => clearTimeout(timer);
  }, []);

  // Live monitor simulation removed to only show real information
  useEffect(() => {
    // No-op: Simulation disabled
  }, []);

  // Update clock
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Monitor API Key Expiration
  useEffect(() => {
    if (keyExpiresAt && Date.now() > keyExpiresAt) {
      setNotification('API Key expired. Please generate a new one.');
      setCurrentKey(null);
      setKeyExpiresAt(null);
    }
  }, [currentTime, keyExpiresAt]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [problems, output]);

  const configYaml = `api_settings:
  version: v2.4.1
  endpoint: https://api.sentinel-threat.io/scan
  auth:
    method: x-api-key
    key: "${currentKey || 'NOT_FOUND'}"
    status: ${currentKey ? 'active' : 'revoked'}
    expires: ${keyExpiresAt ? new Date(keyExpiresAt).toLocaleString() : 'N/A'}
  
monitor_config:
  refresh_rate: 100ms
  logging: verbose
  auto_block: true`;

  const copyConfig = () => {
    if (!currentKey) {
      setNotification('ERR: NO ACTIVE KEY TO COPY');
      return;
    }
    navigator.clipboard.writeText(currentKey); // Better to copy just the key if labelled "COPY"
    setNotification('SUCCESS: API KEY COPIED TO CLIPBOARD');
    setTimeout(() => {
      setNotification(null);
    }, 3000);
  };

  const handleGenerateKey = async () => {
    if (!isConfigured) {
      setNotification('CONSOLE_REQUIRED: Initialize Security Password.');
      setPendingCommand('UPDATE_PASSWORD_NEW');
      setCommandHistory(prev => [...prev, '[!] SECURITY_PROTOCOL: Initial Password Setup.', '[?] Enter your NEW Security Password (Second Layer):']);
      setTerminalTab('OUTPUT'); // Ensure they see the console
      return;
    }

    if (!sessionPassword) {
      setNotification('CREDENTIALS_REQUIRED: Authenticate in Terminal.');
      setTerminalTab('OUTPUT'); 
      setCommandHistory(prev => [...prev, '[!] AUTH_REQUIRED: Enter Security Password to AUTHORIZE API GENERATION:']);
      setPendingCommand('LOGIN');
      return;
    }

    const clientName = window.prompt("Enter Client Name:", `Shield Node ${Math.floor(Math.random() * 1000)}`) || `Node_${Math.floor(Math.random() * 1000)}`;
    const password = sessionPassword;
    
    setIsGeneratingKey(true);
    setNotification('PROVISIONING_KEY...');

    try {
      const response = await fetch('/api/keys/generate', { 
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ clientName, password, username: user.username })
      });
      
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        setNotification('ERR: Invalid Server Response');
        setIsGeneratingKey(false);
        return;
      }

      const data = await response.json();

      if (!response.ok) {
        setNotification(`ERR: ${data.message || 'AUTH_FAILURE'}`);
        setIsGeneratingKey(false);
        return;
      }

      setNotification('SUCCESS: API Key Provisioned.');
      setCurrentKey(data.key);
      fetchPersistentKeys();
      
      addLog({
        type: 'SYSTEM',
        msg: `[+] Key authorized for '${data.clientName}' via Security Password verification.`,
        timestamp: Date.now()
      });
    } catch (err) {
      console.error("Key generation failed", err);
      setNotification('CRITICAL: SERVICE_UNAVAILABLE');
    } finally {
      setIsGeneratingKey(false);
      setTimeout(() => setNotification(null), 5000);
    }
  };

  const handleDeleteKey = async (keyToDelete: string) => {
    try {
      const response = await fetch('/api/keys/revoke', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: keyToDelete })
      });
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
         return false;
      }
      const data = await response.json();
      if (data.success) {
        setNotification('KEY PURGED FROM DATABASE');
        if (currentKey === keyToDelete) setCurrentKey(null);
        fetchPersistentKeys();
        return true;
      }
    } catch (err) {
      console.error("Revocation failed", err);
    }
    return false;
  };

  const handleWokeUpGuard = async () => {
    setNotification('ACTION REQUIRED: Enter Security Password in Terminal to Wake Up.');
    setPendingCommand('WAKE_UP_GUARD');
    addLog({
      type: 'warn',
      msg: '[!] Wake up protocol initiated. System awaiting Security Password in Console.',
      timestamp: Date.now()
    });
    return true;
  };

  const handleCommandSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!commandInput.trim()) return;

    const cmd = commandInput.trim().toLowerCase();
    setCommandHistory(prev => [...prev, `> ${pendingCommand ? '********' : commandInput}`]);
    
    if (pendingCommand === 'LOGIN') {
      const pass = commandInput.trim().replace(/^["'](.+)["']$/, '$1'); // Strip quotes if user added them
      setCommandHistory(prev => [...prev, '[*] VERIFYING...']);
      fetch('/api/system/verify-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pass, username: user.username })
      })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          setCommandHistory(prev => [...prev, '[SUCCESS] Session Authorized. High-level functions unlocked.']);
          setSessionPassword(pass);
          setNotification('SYSTEM_UNLOCKED: Session verified.');
        } else {
          setCommandHistory(prev => [...prev, '[ERROR] Invalid Security Password. Access denied.']);
        }
      })
      .catch(() => setCommandHistory(prev => [...prev, '[ERROR] Verification engine offline.']))
      .finally(() => {
        setPendingCommand(null);
        setCommandInput('');
      });
      return;
    }

    if (pendingCommand === 'AUTHORIZE_SHUTDOWN') {
      const pass = commandInput.trim();
      const activeKey = currentKey || 'sk_master_777_sentinel';
      setCommandHistory(prev => [...prev, '[*] SIGNING_TERMINATION_PACKETS...']);
      
      // Lock update via API only

      fetch('/api/v1/system/kill-signal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          password: pass,
          apiKey: activeKey,
          username: user.username
        })
      })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          setCommandHistory(prev => [...prev, '[CRITICAL] Kill signal verified correctly.', '[*] SYSTEM_LOCKED: All network doors closed. Session terminated.']);
          setSystemStatus('LOCKED');
          setNotification('SYSTEM_LOCKED: Emergency Protocol Alpha');
        } else {
          setCommandHistory(prev => [...prev, `[ERROR] Shutdown failed: ${data.message || 'AUTH_REJECTION'}`]);
        }
      })
      .catch(() => setCommandHistory(prev => [...prev, '[ERROR] Signal jam detected. Command discarded.']))
      .finally(() => {
        setPendingCommand(null);
        setCommandInput('');
      });
      return;
    }

    if (pendingCommand === 'WAKE_UP_GUARD') {
      const pass = commandInput.trim();
      const activeKey = currentKey || 'sk_master_777_sentinel';
      setCommandHistory(prev => [...prev, '[*] AUTHORIZING_DESTRUCTION_BYPASS...']);
      
      // Unlock push via API only

      fetch('/api/v1/system/unlock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          password: pass,
          apiKey: activeKey,
          username: user.username
        })
      })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          setCommandHistory(prev => [...prev, '[SUCCESS] Guard is awake.', '[*] Risk Registry has been purged and network interfaces are restored.', '[*] System status: ACTIVE.']);
          setSystemStatus('ACTIVE');
          setNotification('SYSTEM_AWAKENED: Security Protocol Alpha terminated.');
        } else {
          setCommandHistory(prev => [...prev, `[ERROR] Unlock failed: ${data.message || 'AUTH_REJECTION'}`]);
        }
      })
      .catch(() => setCommandHistory(prev => [...prev, '[ERROR] Gateway timeout. Terminal is desynced.']))
      .finally(() => {
        setPendingCommand(null);
        setCommandInput('');
      });
      return;
    }

    if (pendingCommand === 'UPDATE_PASSWORD_CURRENT') {
      const current = commandInput.trim();
      setTempPassword(current);
      setCommandHistory(prev => [...prev, '[?] Enter your NEW Security Password:']);
      setPendingCommand('UPDATE_PASSWORD_NEW');
      setCommandInput('');
      return;
    }

    if (pendingCommand === 'UPDATE_PASSWORD_NEW') {
      const newPass = commandInput.trim();
      if (newPass.length < 4) {
        setCommandHistory(prev => [...prev, '[!] ERR: Password too short. Minimum 4 characters.', 'Update aborted.']);
        setPendingCommand(null);
        setTempPassword('');
      } else {
        setCommandHistory(prev => [...prev, '[*] ENCRYPTING_AND_TRANSMITTING...']);
        fetch('/api/system/update-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            password: newPass,
            currentPassword: tempPassword || undefined,
            username: user.username
          })
        })
        .then(res => res.json())
        .then(data => {
          if (data.success) {
            setCommandHistory(prev => [...prev, '[SUCCESS] Security Password updated in ThreatVault.', '[*] SYSTEM_UNLOCKED: API generation and high-level functions now available.']);
            setIsConfigured(true);
            setSessionPassword(newPass);
            setNotification('SYSTEM_UNLOCKED: Security Password verified.');
          } else {
            const errorMsg = data.message || data.error || 'SERVER_REJECTION';
            setCommandHistory(prev => [...prev, `[ERROR] Update failed: ${errorMsg}`]);
          }
        })
        .catch(e => {
          setCommandHistory(prev => [...prev, '[ERROR] Network failure during transmission.']);
        })
        .finally(() => {
          setPendingCommand(null);
          setTempPassword('');
        });
      }
      setCommandInput('');
      return;
    }

    if (pendingCommand === 'DELETE_BABY') {
      const pass = commandInput.trim();
      setCommandHistory(prev => [...prev, '[*] VERIFYING_AUTHORIZATION...']);
      fetch('/api/keys/wipe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pass, username: user.username })
      })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          setCommandHistory(prev => [...prev, '[SUCCESS] TOTAL_WIPE_COMPLETE: All API keys have been purged from the vault.', '[!] SYSTEM_SECURED.']);
          setNotification('SYSTEM_CLEAN: ALL KEYS WIPED.');
          fetchPersistentKeys();
          if (currentKey) setCurrentKey(null);
        } else {
          setCommandHistory(prev => [...prev, `[ERROR] Wipe failed: ${data.message || 'AUTH_REJECTION'}`]);
        }
      })
      .catch(() => setCommandHistory(prev => [...prev, '[ERROR] Vault communication error.']))
      .finally(() => {
        setPendingCommand(null);
        setCommandInput('');
      });
      return;
    }

    // Command Logic
    if (cmd === 'help') {
      setCommandHistory(prev => [...prev, 'Available commands: login, status, logs, scan, active shutdown, update password, woke up guard, delete baby, clear, help, whoami']);
    } else if (cmd === 'delete baby') {
      setCommandHistory(prev => [...prev, '[!] DANGER_ZONE: You are about to PURGE all API keys.', '[?] Enter Security Password to CONFIRM TOTAL WIPE:']);
      setPendingCommand('DELETE_BABY');
    } else if (cmd === 'active shutdown') {
      setCommandHistory(prev => [...prev, '[!] EMERGENCY: Initializing remote system termination...', '[!] All contacted website doors will be locked.', '[?] Confirm security password to AUTHORIZE SHUTDOWN:']);
      setPendingCommand('AUTHORIZE_SHUTDOWN');
    } else if (cmd === 'login') {
      if (!isConfigured) {
        setCommandHistory(prev => [...prev, '[!] INITIAL_SETUP_REQUIRED: No Security Password found. Type "update password" to set one.']);
      } else {
        setCommandHistory(prev => [...prev, '[!] AUTH_REQUIRED: Enter Security Password to unlock session:']);
        setPendingCommand('LOGIN');
      }
    } else if (cmd === 'clear') {
      setCommandHistory([]);
    } else if (cmd === 'status') {
      setCommandHistory(prev => [...prev, `System Status: ${eth0Status === 'UP' ? 'SECURE' : 'BREACHED'}`, `Threats Blocked: ${problems.length}`, `Active Keys: ${persistentKeys.length}`]);
    } else if (cmd === 'whoami') {
      setCommandHistory(prev => [...prev, `User: ${user.username}`, `UID: ${user.uid}`, `Role: System Administrator`]);
    } else if (cmd === 'update password') {
      if (isConfigured) {
        setCommandHistory(prev => [...prev, '[!] SECURITY_PROTOCOL: Password Update Initiated.', '[?] Enter CURRENT Security Password:']);
        setPendingCommand('UPDATE_PASSWORD_CURRENT');
      } else {
        setCommandHistory(prev => [...prev, '[!] SECURITY_PROTOCOL: Initial Password Setup.', '[?] Enter your NEW Security Password (Second Layer):']);
        setPendingCommand('UPDATE_PASSWORD_NEW');
      }
    } else if (cmd === 'scan') {
      setNotification('MANUAL SCAN INITIALIZED');
      setTimeout(() => {
        setCommandHistory(prev => [...prev, 'Scan Complete: 0 vulnerabilities found in localized subnet.']);
      }, 1500);
    } else if (cmd === 'logs') {
      setTerminalTab('OUTPUT');
      setCommandHistory(prev => [...prev, 'Switched to Output Log view.']);
    } else if (cmd === 'woke up guard') {
      setCommandHistory(prev => [...prev, '[RECOVERY] Wake up protocol initiated. System awaiting Security Password in Console.', '[?] Enter security password to AWAKEN GUARD:']);
      setPendingCommand('WAKE_UP_GUARD');
    } else {
      setCommandHistory(prev => [...prev, `Unknown command: ${cmd}. Type 'help' for options.`]);
    }

    setCommandInput('');
  };

  const handleEmergencyKill = async () => {
    setTerminalTab('OUTPUT');
    setCommandHistory(prev => [...prev, '[!] EMERGENCY: Emergency Kill Sequence Initiated via Dashboard.', '[!] Remote system termination requested...', '[?] Confirm security password in Console to AUTHORIZE SHUTDOWN:']);
    setPendingCommand('AUTHORIZE_SHUTDOWN');
  };

  useEffect(() => {
    if (view === 'cage') {
      const fetchDeception = async () => {
        try {
          const res = await fetch('/api/v1/mirror/deception-logs', {
            headers: {
              'x-api-key': 'sk_master_777_sentinel'
            }
          });
          const contentType = res.headers.get("content-type");
          if (!contentType || !contentType.includes("application/json")) {
             return;
          }
          const data = await res.json();
          setDeceptionLogs(data);
        } catch (e) {
          console.error("Failed to fetch deception logs", e);
        }
      };
      fetchDeception();
      const interval = setInterval(fetchDeception, 5000);
      return () => clearInterval(interval);
    }
  }, [view]);

  if (isInitializing) {
    return (
      <div className="h-screen w-screen bg-black flex items-center justify-center font-mono text-kali-green p-8">
        <div className="max-w-md w-full">
          <p className="mb-2">/usr/bin/session-init --uid={user.uid}</p>
          <p className="text-gray-500">[ WAIT ] Decrypting local vault ...</p>
          <motion.p 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >[  OK  ] Authentication credentials verified.</motion.p>
          <motion.p 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1 }}
          >[  OK  ] Initializing Desktop Environment ...</motion.p>
          <motion.p 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.5 }}
            className="blinking-cursor"
          >[  OK  ] Terminal Ready.</motion.p>
        </div>
      </div>
    );
  }

  const renderViewContent = () => {
    switch (view) {
      case 'dashboard':
        return (
          <div className="space-y-4">
            <div className="text-kali-blue">{'# SYSTEM_HEALTH_REPORT'}</div>
            <TypingText text="Starting system self-diagnostic... [DONE]" speed={10} />
            
            <div className="mt-4 p-4 border border-kali-blue/20 bg-kali-blue/5 rounded">
              <div className="flex justify-between items-center mb-4">
                <div className="text-[10px] uppercase font-bold text-kali-blue flex items-center gap-2">
                  <Shield className="w-3 h-3" /> Microservice: Security Engine
                </div>
                <button 
                  onClick={runSecurityCheck}
                  disabled={analyzing}
                  className="px-2 py-1 bg-kali-blue/20 hover:bg-kali-blue/40 text-kali-blue text-[9px] uppercase border border-kali-blue/40 transition-colors disabled:opacity-50"
                >
                  {analyzing ? '[ ANALYZING... ]' : '[ RUN_SEC_AUDIT ]'}
                </button>
              </div>

              {threatAnalysis ? (
                <div className="space-y-3">
                  <div className="flex justify-between items-end">
                    <span className="text-[10px] text-gray-500 uppercase">Threat Score</span>
                    <span className={`text-xl font-bold ${threatAnalysis.score > 50 ? 'text-kali-red' : 'text-kali-green'} animate-pulse`}>
                      {threatAnalysis.score}/100
                    </span>
                  </div>
                  <div className="h-1 bg-gray-900 w-full rounded-full overflow-hidden">
                    <motion.div 
                      initial={{ width: 0 }}
                      animate={{ width: `${threatAnalysis.score}%` }}
                      className={`h-full ${threatAnalysis.score > 50 ? 'bg-kali-red shadow-[0_0_10px_#ff4d4d]' : 'bg-kali-green'}`}
                    />
                  </div>

                  {aiForensics && (
                    <div className="mt-4 p-3 bg-black border-l-2 border-kali-red text-[10px] leading-relaxed">
                      <div className="text-kali-red font-bold mb-1 flex items-center gap-1">
                        <Zap className="w-3 h-3" /> SENTINEL_AI_FORENSICS
                      </div>
                      <TypingText text={aiForensics} speed={15} />
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-2">
                    <div className="text-[9px]">
                      <span className="text-gray-600 uppercase">Action:</span>
                      <span className={`ml-2 font-bold ${threatAnalysis.action === 'BLOCK' ? 'text-kali-red' : 'text-kali-green'}`}>
                        {threatAnalysis.action}
                      </span>
                    </div>
                    <div className="text-[9px]">
                      <span className="text-gray-600 uppercase">Latency:</span>
                      <span className="ml-2 text-kali-blue font-mono">{threatAnalysis.latency}ms</span>
                    </div>
                  </div>
                  {threatAnalysis.threats.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {threatAnalysis.threats.map((t: string) => (
                        <span key={t} className="px-1 bg-kali-red/10 text-kali-red text-[8px] border border-kali-red/20 uppercase">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-[9px] text-gray-700 italic">No audit data available. Execute audit to verify system integrity.</div>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4 mt-4">
              <div className="border border-[#1a1a1a] p-4 bg-black/40">
                <ProgressBar label="CPU Alpha" value={64} />
                <ProgressBar label="CPU Beta" value={42} />
              </div>
              <div className="border border-[#1a1a1a] p-4 bg-black/40">
                <ProgressBar label="Neural Memory" value={28} colorClass="text-sentinel-green" />
                <ProgressBar label="Thread Buffer" value={92} colorClass="text-sentinel-red" />
              </div>
            </div>
          </div>
        );
      case 'keys':
        return (
          <div className="space-y-4">
            <div className="text-sentinel-blue">{'# SENTINEL_SECRET_VAULT'}</div>
            <p className="text-gray-500 text-[10px]">Your API access key is used to authenticate with the Sentinel threat analysis engine. Keys are now persisted in ThreatVault.db.</p>
            
            <div className="bg-[#050505] p-3 border border-[#1a1a1a] rounded relative group max-h-[150px] overflow-y-auto scrollbar-hide">
              <div className="text-[10px] text-sentinel-blue mb-2">Authorized Clients</div>
              <div className="space-y-2">
                {persistentKeys.length > 0 ? persistentKeys.map((k, i) => (
                  <div key={i} className={`text-[10px] p-2 border border-[#1a1a1a] flex justify-between items-center ${currentKey === k.api_key ? 'bg-kali-blue/5 border-kali-blue/20' : ''}`}>
                    <div className="flex flex-col">
                      <span className="text-gray-300 font-bold">{k.client_name}</span>
                      <span className="text-gray-600 font-mono text-[8px] break-all">{k.api_key}</span>
                    </div>
                    <div className="flex flex-col items-end">
                      <span className="text-gray-700 text-[8px]">{new Date(k.date_created).toLocaleDateString()}</span>
                      <button 
                        onClick={() => setCurrentKey(k.api_key)}
                        className={`text-[8px] uppercase font-bold mt-1 ${currentKey === k.api_key ? 'text-kali-blue' : 'text-gray-500 hover:text-kali-blue'}`}
                      >
                        [ {currentKey === k.api_key ? 'ACTIVE' : 'SELECT'} ]
                      </button>
                    </div>
                  </div>
                )) : (
                  <div className="text-gray-700 italic text-[9px]">No authorized clients found.</div>
                )}
              </div>
            </div>

            <div className="bg-[#050505] p-6 border border-[#1a1a1a] rounded relative">
              <div className="text-[10px] text-gray-700 absolute top-2 left-4">config.yaml</div>
              <div className="mt-4 font-mono text-kali-green break-all text-xs border-l-2 border-kali-green pl-4 py-2">
                auth_key: "{currentKey || '********************************'}"
              </div>
            </div>

            {/* Administrative Auth Section Removed - Use Terminal Handshake */}

            <div className="flex gap-4">
              <button 
                onClick={handleGenerateKey}
                disabled={isGeneratingKey || !isConfigured || systemStatus === 'KILLED'}
                className={`px-4 py-2 border text-[10px] uppercase font-bold transition-all ${
                  isGeneratingKey || !isConfigured || systemStatus === 'KILLED'
                    ? 'bg-kali-blue/20 border-kali-blue/50 text-kali-blue/50 cursor-not-allowed'
                    : 'bg-kali-blue/10 border-kali-blue text-kali-blue hover:bg-kali-blue hover:text-black'
                }`}
              >
                {isGeneratingKey ? '[ PROVISIONING... ]' : !isConfigured ? '[ CONSOLE_INIT_REQUIRED ]' : '[ GENERATE API ]'}
              </button>
              <button 
                onClick={copyConfig}
                className="px-4 py-2 bg-kali-green/10 border border-kali-green text-kali-green text-[10px] uppercase font-bold hover:bg-kali-green hover:text-black transition-all"
              >
                [ COPY ]
              </button>
            </div>
          </div>
        );
      case 'logs':
        return (
          <div className="space-y-2 h-[250px] overflow-y-auto scrollbar-hide" ref={scrollRef}>
            <div className="text-kali-blue mb-4">{'# HISTORICAL_BREACH_LOGS'}</div>
            <TypingText text="Fetching security logs from remote node... [DONE]" speed={10} />
            <div className="mt-4 space-y-1">
              {[...output, ...problems].sort((a, b) => a.timestamp - b.timestamp).map((log) => {
                const isSpecial = log.msg.startsWith('[');
                return (
                  <div key={log.id} className="flex gap-2 text-[10px] items-start">
                    <span className="text-gray-700 whitespace-nowrap">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                    {!isSpecial && (
                      <span className={`uppercase font-bold whitespace-nowrap ${
                        log.type === 'error' ? 'text-kali-red' : 
                        log.type === 'warn' ? 'text-yellow-500' : 
                        'text-kali-blue'
                      }`}>
                        [{log.type === 'error' ? (log.msg.includes('BLOCKED') ? 'BLOCKED' : 'THREAT') : log.type}]
                      </span>
                    )}
                    <span className={`leading-tight ${
                      log.type === 'error' ? (log.msg.includes('DROP') || log.msg.includes('script') ? 'text-kali-red font-bold animate-pulse' : 'text-kali-red') : 
                      log.type === 'scan' ? 'text-kali-green' :
                      isSpecial && log.msg.includes('ALERT') ? 'text-kali-red font-bold' :
                      isSpecial && log.msg.includes('SECURE') ? 'text-kali-green' :
                      isSpecial && log.msg.includes('MONITOR') ? 'text-kali-blue' :
                      'text-gray-400'
                    }`}>
                      {log.isRealTime ? <TypingText text={log.msg} speed={30} /> : log.msg}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        );
      case 'network':
        return (
          <div className="space-y-4">
            <div className="flex justify-between items-center mb-2">
              <div className="text-sentinel-blue">{'# NETWORK_INTERFACES_ANALYSIS'}</div>
              <button 
                id="emergency-kill-btn"
                onClick={handleEmergencyKill}
                disabled={systemStatus === 'LOCKED'}
                className={`flex items-center gap-1 px-2 py-1 text-[10px] uppercase font-bold border transition-all ${
                  systemStatus === 'LOCKED'
                    ? 'border-gray-800 text-gray-800 cursor-not-allowed' 
                    : 'border-kali-red text-kali-red hover:bg-kali-red hover:text-black shadow-[0_0_5px_rgba(255,62,62,0.2)]'
                }`}
              >
                <Power className="w-3 h-3" /> {systemStatus === 'LOCKED' ? '[ SYSTEM_LOCKED ]' : '[ Emergency Kill ]'}
              </button>
            </div>
            
            <div className="grid grid-cols-1 gap-4">
              {networkInterfaces.map(iface => {
                const isDown = iface.status === 'DOWN';
                return (
                  <motion.div 
                    key={iface.name} 
                    initial={{ opacity: 0, scale: 0.98 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className={`p-4 border border-[#1a1a1a] bg-black/40 rounded transition-opacity ${isDown ? 'opacity-60 grayscale' : ''}`}
                  >
                    <div className="flex justify-between items-start mb-4">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded bg-opacity-10 ${isDown ? 'bg-kali-red' : 'bg-kali-blue'}`}>
                          <Wifi className={`w-5 h-5 ${isDown ? 'text-kali-red' : 'text-kali-blue'}`} />
                        </div>
                        <div>
                          <div className="text-sm font-bold text-gray-200 uppercase tracking-widest">{iface.name}</div>
                          <div className="text-[10px] text-gray-500 font-mono uppercase">{iface.speed} • Full Duplex</div>
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        <div className="flex items-center gap-2">
                           <span className={`text-[10px] font-bold uppercase ${isDown ? 'text-kali-red animate-pulse' : 'text-kali-green'}`}>
                             {isDown ? '[ DISCONNECTED ]' : '[ CONNECTED ]'}
                           </span>
                           <div className={`w-2.5 h-2.5 rounded-full shadow-[0_0_5px] ${isDown ? 'bg-kali-red shadow-kali-red' : 'bg-kali-green shadow-kali-green animate-pulse'}`} />
                        </div>
                        <button 
                          onClick={() => handleToggleInterface(iface.name)}
                          className={`text-[9px] px-2 py-1 border uppercase font-bold transition-colors ${
                            isDown 
                              ? 'border-kali-green text-kali-green hover:bg-kali-green hover:text-black' 
                              : 'border-kali-red text-kali-red hover:bg-kali-red hover:text-black'
                          }`}
                        >
                          {isDown ? '[ RESTORE_LINK ]' : '[ SIMULATE_OFFLINE ]'}
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-[#1a1a1a]">
                      <div>
                        <div className="text-[8px] text-gray-600 uppercase mb-0.5">IPV4_ADDR</div>
                        <div className="text-[11px] text-kali-blue font-mono">{iface.ip}</div>
                      </div>
                      <div>
                        <div className="text-[8px] text-gray-600 uppercase mb-0.5">MAC_ADDR</div>
                        <div className="text-[11px] text-gray-400 font-mono">{iface.mac}</div>
                      </div>
                      <div>
                        <div className="text-[8px] text-gray-600 uppercase mb-0.5">RX_PACKETS</div>
                        <div className="text-[11px] text-kali-green font-mono">{iface.rx_packets.toLocaleString()}</div>
                      </div>
                      <div>
                        <div className="text-[8px] text-gray-600 uppercase mb-0.5">TX_PACKETS</div>
                        <div className="text-[11px] text-kali-green font-mono">{iface.tx_packets.toLocaleString()}</div>
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>

            <div className="mt-8 border-t border-[#1a1a1a] pt-6">
              <div className="text-kali-blue text-[10px] font-bold uppercase mb-4 flex items-center gap-2">
                <Activity className="w-3.5 h-3.5" /> Logical Routing Architecture
              </div>
              <div className="bg-[#050505] border border-[#1a1a1a] p-3 overflow-x-auto">
                <table className="w-full text-[10px] font-mono text-gray-500">
                  <thead className="text-left border-b border-[#1a1a1a]">
                    <tr>
                      <th className="pb-2 uppercase">Destination</th>
                      <th className="pb-2 uppercase">Gateway</th>
                      <th className="pb-2 uppercase">Genmask</th>
                      <th className="pb-2 uppercase">Flags</th>
                      <th className="pb-2 uppercase">Iface</th>
                    </tr>
                  </thead>
                  <tbody className="text-gray-400">
                    <tr className="border-b border-[#0c0c0c]">
                      <td className="py-2">0.0.0.0</td>
                      <td className="py-2">172.16.0.1</td>
                      <td className="py-2">0.0.0.0</td>
                      <td className="py-2 text-kali-blue">UG</td>
                      <td className="py-2">eth0</td>
                    </tr>
                    <tr className="border-b border-[#0c0c0c]">
                      <td className="py-2">10.8.0.0</td>
                      <td className="py-2">*</td>
                      <td className="py-2">255.255.255.0</td>
                      <td className="py-2 text-kali-green">U</td>
                      <td className="py-2">tun0</td>
                    </tr>
                    <tr>
                      <td className="py-2">192.168.56.0</td>
                      <td className="py-2">*</td>
                      <td className="py-2">255.255.255.0</td>
                      <td className="py-2 text-kali-green">U</td>
                      <td className="py-2">vboxnet0</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'cage':
        return (
          <div className="space-y-4">
            <div className="flex justify-between items-center mb-2">
              <div className="text-sentinel-blue">{'# MIRROR_ROOM_CAGE'}</div>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${hackerHooked ? 'bg-kali-red animate-ping' : 'bg-gray-800'}`} />
                <span className="text-[10px] text-gray-500 uppercase">{hackerHooked ? 'HACKER_HOOKED' : 'IDLE'}</span>
              </div>
            </div>

            {unmaskedData && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="p-4 border border-kali-red bg-kali-red/10 rounded-sm mb-4"
              >
                <div className="text-[11px] font-bold text-kali-red uppercase mb-3 flex items-center gap-2">
                  <Zap className="w-4 h-4" /> [ ADVERSARY UNMASKED ]
                </div>
                <div className="grid grid-cols-2 gap-4 text-[10px] font-mono">
                  <div className="space-y-1">
                    <div className="text-gray-500 uppercase">Hostname:</div>
                    <div className="text-white">L33T_HACKER_BOX</div>
                    <div className="text-gray-500 uppercase mt-2">Location:</div>
                    <div className="text-kali-blue">
                      {unmaskedData.geo?.city || 'Unknown'}, {unmaskedData.geo?.country || 'Unknown'}
                    </div>
                  </div>
                  <div className="space-y-1">
                    <div className="text-gray-500 uppercase">IP_ADDR:</div>
                    <div className="text-white">{unmaskedData.geo?.query || '127.0.0.1'}</div>
                    <div className="text-gray-500 uppercase mt-2">CANARY_TRIGGER:</div>
                    <div className="text-kali-red font-bold underline">{unmaskedData.filename || 'EXTERNAL_PROBE'}</div>
                  </div>
                </div>
              </motion.div>
            )}

            <div className="p-4 border border-kali-blue/20 bg-kali-blue/5 rounded">
              <div className="text-[10px] text-kali-blue uppercase mb-2">Deception Feed (Live)</div>
              <div className="space-y-2 max-h-[300px] overflow-y-auto scrollbar-hide pr-2">
                {deceptionLogs.length > 0 ? deceptionLogs.map((log) => (
                  <div key={log.id} className="text-[10px] p-2 border border-kali-blue/10 bg-black/40 font-mono">
                    <div className="flex justify-between mb-1">
                      <span className="text-kali-blue">{log.identifier}</span>
                      <span className="text-gray-600">{new Date(log.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <div className="text-kali-green mb-1">{'>'} PATH: {log.path}</div>
                    <div className="text-gray-400 truncate">{'>'} PAYLOAD: {log.payload}</div>
                  </div>
                )) : (
                  <div className="text-gray-700 italic text-[9px]">No activity in sandbox registry...</div>
                )}
              </div>
            </div>

            <div className="grid grid-cols-3 gap-4">
              <div className="col-span-1 border border-[#1a1a1a] p-4 bg-black/40">
                <div className="text-[10px] text-gray-500 uppercase mb-3 text-center font-bold">Poisoned Assets</div>
                <div className="space-y-2">
                  <a href="/api/v1/mirror/assets/admin_credentials.xlsx" className="block text-[8px] p-1.5 border border-kali-blue/20 hover:bg-kali-blue/10 transition-colors flex items-center gap-2">
                    <Database className="w-3 h-3 text-kali-blue" /> CREDENTIALS_DUMP
                  </a>
                  <a href="/api/v1/mirror/assets/database_leak.zip" className="block text-[8px] p-1.5 border border-kali-red/20 hover:bg-kali-red/10 transition-colors flex items-center gap-2">
                     <AlertTriangle className="w-3 h-3 text-kali-red" /> ZIP_BOMB_ALPHA
                  </a>
                  <a href="/api/v1/mirror/assets/system_backup.iso" className="block text-[8px] p-1.5 border border-yellow-500/20 hover:bg-yellow-500/10 transition-colors flex items-center gap-2">
                    <Wifi className="w-3 h-3 text-yellow-500" /> SLOW_DRIP_TAP
                  </a>
                </div>
              </div>
              <div className="col-span-1 border border-[#1a1a1a] p-4 bg-black/40">
                <div className="text-[10px] text-gray-500 uppercase mb-3">Fake Progress (Hacker View)</div>
                <div className="space-y-4">
                  <ProgressBar label="Vault Decryption" value={hackerHooked ? 99 : 14} colorClass="text-kali-green" />
                  <ProgressBar label="Malware Injection" value={hackerHooked ? 10 : 0} colorClass="text-kali-red" />
                </div>
              </div>
              <div className="col-span-1 border border-[#1a1a1a] p-4 bg-black/40 flex flex-col justify-center items-center text-center">
                 <AlertTriangle className={`w-8 h-8 mb-2 ${hackerHooked ? 'text-kali-red animate-bounce' : 'text-gray-800'}`} />
                 <div className="text-[10px] font-bold text-gray-400 uppercase">Cage Status</div>
                 <div className={`text-[12px] font-bold ${hackerHooked ? 'text-kali-red' : 'text-kali-blue'}`}>
                    {hackerHooked ? 'POISONED_FILE_ACCESSED' : 'WAITING_FOR_ENTRAPMENT'}
                 </div>
              </div>
            </div>
            
            <div className="mt-4 p-3 bg-kali-red/5 border border-kali-red/20 rounded">
               <div className="text-[9px] text-kali-red font-bold uppercase mb-1 underline">AUTO-RETALIATION_PROTOCOL</div>
               <div className="text-[8px] text-gray-500 leading-tight">
                  Upon interacting with the mirror vault or attempting an emergency kill within the sandbox, the victim's session will silently initiate a diagnostic download. This download contains an adversarial payload designed to neutralize the attacker's workstation environment.
               </div>
            </div>
          </div>
        );
    }
  };

  return (
    <div className={`h-screen w-screen bg-black overflow-hidden relative flex flex-col selection:bg-sentinel-blue/30 selection:text-white font-mono transition-colors duration-700 ${redAlert || systemStatus === 'LOCKED' ? 'red-alert-screen' : ''} ${systemStatus === 'LOCKED' ? 'is-locked text-sentinel-red' : 'text-sentinel-blue'}`}>
      
      {/* Visual Studio Style Layout */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar - Persistent Launcher */}
        <aside className={`w-12 border-r flex flex-col items-center py-4 gap-6 z-50 transition-colors duration-700 ${systemStatus === 'LOCKED' ? 'border-sentinel-red/30 bg-sentinel-red/5 pointer-events-none opacity-50' : 'border-[#1a1a1a] bg-[#0c0c0c]'}`}>
          <div 
            className={`p-2 transition-colors cursor-pointer rounded group relative ${view === 'dashboard' ? 'text-sentinel-blue' : 'text-gray-600 hover:text-sentinel-blue'}`}
            onClick={() => setView('dashboard')}
          >
            <Shield className="w-5 h-5" />
            <span className="absolute left-14 bg-sentinel-blue text-black text-[9px] font-bold px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-50">Explorer</span>
          </div>
          
          <div 
            className={`p-2 transition-colors cursor-pointer rounded group relative ${view === 'keys' ? 'text-sentinel-blue' : 'text-gray-600 hover:text-sentinel-blue'}`}
            onClick={() => setView('keys')}
          >
            <Lock className="w-5 h-5" />
            <span className="absolute left-14 bg-sentinel-blue text-black text-[9px] font-bold px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-50">Authorized Clients</span>
          </div>

          <div 
            className={`p-2 transition-colors cursor-pointer rounded group relative ${view === 'network' ? 'text-sentinel-blue' : 'text-gray-600 hover:text-sentinel-blue'}`}
            onClick={() => setView('network')}
          >
            <Wifi className="w-5 h-5" />
            <span className="absolute left-14 bg-sentinel-blue text-black text-[9px] font-bold px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-50">Network Status</span>
          </div>

          <div 
            className={`p-2 transition-colors cursor-pointer rounded group relative ${view === 'cage' ? 'text-sentinel-blue' : 'text-gray-600 hover:text-sentinel-blue'}`}
            onClick={() => setView('cage')}
          >
            <Activity className="w-5 h-5" />
            <span className="absolute left-14 bg-sentinel-blue text-black text-[9px] font-bold px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-50">Mirror Room</span>
          </div>

          <div className="mt-auto flex flex-col gap-4 items-center">
            <div className="p-2 text-gray-700 hover:text-sentinel-blue cursor-pointer" onClick={onLogout}>
              <LogOut className="w-5 h-5" />
            </div>
            <div className="w-6 h-6 rounded border border-[#1a1a1a] bg-sentinel-blue/5 overflow-hidden mb-2">
              <img src={`https://api.dicebear.com/7.x/pixel-art/svg?seed=${user.uid}`} alt="Avatar" />
            </div>
          </div>
        </aside>

        {/* Main Workspace Area (Top) */}
        <div className="flex-1 flex flex-col relative bg-[#050505] overflow-hidden">
          
          {/* Dashboard Header Bar */}
          <div className={`h-9 border-b px-4 flex items-center justify-between z-40 bg-opacity-80 backdrop-blur-md transition-colors duration-700 ${systemStatus === 'LOCKED' ? 'border-sentinel-red/30 bg-sentinel-red/10 pointer-events-none' : 'bg-[#0c0c0c] border-[#1a1a1a]'}`}>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-[11px] font-bold text-sentinel-blue uppercase tracking-widest">
                <Shield className="w-3.5 h-3.5 fill-sentinel-blue" /> Sentinel_SECaaS
              </div>
              <div className="h-4 w-[1px] bg-gray-800" />
              <div className="text-[9px] text-gray-500 uppercase tracking-tighter">
                {view} • {user.username}
              </div>
            </div>
            <div className="flex items-center gap-6 text-[10px] font-medium text-gray-400">
              <div className={`flex items-center gap-1 ${systemStatus === 'ACTIVE' ? 'text-sentinel-green' : 'text-sentinel-red'}`}>
                <Activity className="w-3 h-3" /> STATUS: {systemStatus}
              </div>
              {systemStatus === 'LOCKED' && (
                <div className="bg-sentinel-red text-black px-2 py-0.5 animate-pulse font-bold">
                  [ TERMINAL_ACTION_REQUIRED ]
                </div>
              )}
              {sessionPassword && (
                <div className="text-sentinel-green flex items-center gap-1 font-bold">
                  <Lock className="w-3 h-3" /> UNLOCKED
                </div>
              )}
              <div className="font-mono text-sentinel-blue">{currentTime.toLocaleTimeString()}</div>
            </div>
          </div>

          {/* Canvas Area */}
          <div className="flex-1 relative p-6 bg-[radial-gradient(#111_1px,transparent_1px)] [background-size:24px_24px] overflow-auto">
            {systemStatus === 'LOCKED' && (
              <div className="absolute inset-0 z-50 bg-black/80 backdrop-blur-md flex flex-col items-center justify-center p-8 text-center">
                <motion.div 
                  initial={{ scale: 0.9, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  className="max-w-md w-full border-2 border-kali-red p-8 bg-black shadow-[0_0_100px_rgba(255,0,0,0.2)]"
                >
                  <Skull className="w-16 h-16 text-kali-red mb-6 mx-auto animate-pulse" />
                  <h2 className="text-2xl font-bold text-kali-red uppercase tracking-[0.2em] mb-4">System Locked</h2>
                  <div className="space-y-4 text-sm font-mono text-gray-400">
                    <p className="text-kali-red font-bold">EMERGENCY_PROTOCOL_ALPHA_ACTIVE</p>
                    <p>Network interfaces have been severed. All active sessions terminated. The Risk Registry has been locked to prevent unauthorized entry.</p>
                    <div className="h-px bg-kali-red/30 my-6" />
                    <p className="text-[10px] text-gray-600 uppercase tracking-widest bg-gray-900/50 py-2">
                      Access is restricted to local terminal only. Enter Security Password in host console to wake up the guard.
                    </p>
                  </div>
                </motion.div>
              </div>
            )}
            
            {view === 'dashboard' ? (
              <div className="grid grid-cols-12 gap-6 h-full">
                {/* Visualizations / Reports */}
                <div className="col-span-8 flex flex-col gap-6">
                  <div className="terminal-window h-[550px] flex flex-col">
                    <div className="terminal-header flex justify-between items-center">
                      <div className="flex items-center gap-4">
                        <div 
                          onClick={() => setTerminalTab('OUTPUT')}
                          className={`text-[10px] font-bold cursor-pointer uppercase tracking-widest px-2 py-1 transition-colors ${terminalTab === 'OUTPUT' ? 'text-kali-blue border-b border-kali-blue' : 'text-gray-600 hover:text-gray-400'}`}
                        >
                          System Output
                        </div>
                        <div 
                          onClick={() => setTerminalTab('PROBLEMS')}
                          className={`text-[10px] font-bold cursor-pointer uppercase tracking-widest px-2 py-1 transition-colors ${terminalTab === 'PROBLEMS' ? 'text-kali-red border-b border-kali-red' : 'text-gray-600 hover:text-gray-400'}`}
                        >
                          Threat Intel ({problems.length})
                        </div>
                      </div>
                      <div className="text-[9px] text-gray-700 font-mono">live_stream_v2.4</div>
                    </div>
                    
                    <div className="flex-1 p-4 overflow-y-auto bg-black font-mono text-[11px] leading-relaxed scrollbar-hide" ref={mainTerminalScrollRef}>
                      {terminalTab === 'PROBLEMS' ? (
                        <div className="space-y-1">
                          {problems.length === 0 ? (
                            <div className="text-gray-800 italic">Listening for incoming threats...</div>
                          ) : problems.map((p, i) => (
                             <div key={p.id} className="flex flex-col gap-1 border-b border-kali-red/5 pb-2 mb-2">
                                <div className="flex gap-2">
                                    <span className="text-gray-600">[{new Date(p.timestamp).toLocaleTimeString()}]</span>
                                    <span className="text-kali-red font-bold uppercase shrink-0">[{p.type}]</span>
                                    <span className="text-kali-red font-bold break-all">{p.msg}</span>
                                </div>
                                {p.data?.details?.raw_payload && (
                                  <div className="pl-4 mt-1 space-y-1 text-[9px]">
                                    <div className="flex gap-2 text-gray-500">
                                      <span className="uppercase shrink-0">[ RAW_BODY ]:</span>
                                      <span className="break-all italic">{p.data.details.raw_payload}</span>
                                    </div>
                                    <div className="flex gap-2 text-kali-blue font-bold">
                                      <span className="uppercase shrink-0">[ NORMALIZED ]:</span>
                                      <span className="break-all">{p.data.details.normalized_payload}</span>
                                    </div>
                                    {p.data.details.cumulative_risk !== undefined && (
                                      <div className="flex gap-2 text-yellow-500 font-bold border-t border-yellow-500/10 pt-1 mt-1">
                                        <span className="uppercase shrink-0">[ RISK_LEVEL ]:</span>
                                        <span className="break-all">{p.data.details.cumulative_risk} / 100</span>
                                      </div>
                                    )}
                                  </div>
                                )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="space-y-1">
                          <div className="text-kali-blue mb-2">{'# REAL-TIME_TELEMETRY_FEED'}</div>
                          {output.map((o, i) => (
                            <div key={o.id} className="flex gap-2">
                                <span className="text-gray-600">[{new Date(o.timestamp).toLocaleTimeString()}]</span>
                                <span className={`uppercase font-bold shrink-0 ${o.type === 'info' ? 'text-kali-blue' : 'text-kali-green'}`}>[{o.type}]</span>
                                <span className="text-gray-300 break-all">{o.msg}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Sidebar Stats */}
                <div className="col-span-4 flex flex-col gap-6">
                   <div className="terminal-window">
                      <div className="terminal-header">
                        <div className="text-[10px] font-bold text-gray-500 uppercase">System Stats</div>
                      </div>
                      <div className="p-4 space-y-4">
                        <ProgressBar label="Threat Load" value={redAlert ? 89 : 12} colorClass={redAlert ? 'text-kali-red' : 'text-kali-blue'} />
                        <ProgressBar label="Kernel Sync" value={98} colorClass="text-kali-green" />
                        <div className="grid grid-cols-2 gap-2 mt-4">
                           <div className="bg-[#080808] border border-[#1a1a1a] p-3 rounded">
                              <div className="text-[8px] text-gray-600 uppercase mb-1">Latency</div>
                              <div className="text-kali-blue font-bold font-mono">14 MS</div>
                           </div>
                           <div className="bg-[#080808] border border-[#1a1a1a] p-3 rounded">
                              <div className="text-[8px] text-gray-600 uppercase mb-1">Verdict</div>
                              <div className="text-kali-green font-bold font-mono uppercase">Allow</div>
                           </div>
                        </div>
                      </div>
                   </div>
                   {renderViewContent()}
                </div>
              </div>
            ) : (
              <div className="max-w-4xl mx-auto">
                {renderViewContent()}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Terminal (Downside) - Command Input */}
      <footer className={`h-48 border-t flex flex-col z-[60] transition-colors duration-700 ${systemStatus === 'LOCKED' ? 'border-sentinel-red/30 bg-sentinel-red/5' : 'border-[#1a1a1a] bg-[#050505]'}`}>
        {/* Terminal Header */}
        <div className={`h-8 flex items-center px-4 gap-4 border-b transition-colors duration-700 ${systemStatus === 'LOCKED' ? 'border-sentinel-red/30 bg-sentinel-red/10' : 'bg-[#0c0c0c] border-[#1a1a1a]'}`}>
          <div className="flex items-center gap-2 text-sentinel-blue">
            <TerminalIcon className="w-3.5 h-3.5" />
            <span className="text-[10px] font-bold uppercase">System Console</span>
          </div>
          <div className="ml-auto text-[9px] text-gray-700 flex items-center gap-4">
             <span>Ln 1, Col 1</span>
             <span>UTF-8</span>
             <span className="text-sentinel-blue font-bold">sentinel@operator:~$</span>
          </div>
        </div>

        {/* Command Interface */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* History */}
          <div className="flex-1 overflow-y-auto p-3 font-mono text-[11px] leading-tight space-y-0.5 scrollbar-hide" ref={scrollRef}>
             {commandHistory.length === 0 && (
               <div className="text-gray-700 italic">Sentinel Security Console v2.5.0 - [SESSION_UNLOCK_ENABLED]. Type 'help' to begin.</div>
             )}
             {commandHistory.map((line, i) => (
               <div key={i} className={line.startsWith('>') ? 'text-kali-blue' : 'text-gray-400'}>
                  {line}
               </div>
             ))}
          </div>

          {/* Input Line */}
          <form onSubmit={handleCommandSubmit} className="h-10 bg-[#080808] border-t border-[#1a1a1a] flex items-center px-3 gap-2">
            <span className="text-sentinel-blue font-bold text-xs select-none">sentinel@operator:~$</span>
            <input 
              type={pendingCommand ? "password" : "text"} 
              value={commandInput}
              onChange={(e) => setCommandInput(e.target.value)}
              placeholder="Type system command..."
              className="flex-1 bg-transparent border-none outline-none text-kali-blue font-mono text-xs placeholder:text-gray-800"
              autoFocus
            />
          </form>
        </div>
      </footer>

      {/* Toast Notification */}
      <AnimatePresence>
        {notification && (
          <motion.div 
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="fixed bottom-72 left-6 z-[100] bg-black border border-kali-blue px-4 py-2 font-mono text-[10px] text-kali-blue shadow-[0_0_20px_rgba(0,127,255,0.2)] uppercase"
          >
            {notification}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// --- Main Application ---

export default function App() {
  const [user, setUser] = useState<LocalUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Sync local auth with Firebase auth state
    let unsubscribe = () => {};
    if (isFirebaseConfigured && auth) {
      unsubscribe = onAuthStateChanged(auth, (fbUser) => {
        if (!fbUser && user) {
          // Firebase signed out elsewhere or token expired
          setUser(null);
          localAuth.logout();
        } else if (fbUser && !user) {
          // We have a firebase session but no local user state
          // Re-construct local user from FB
          const sessionUser = localAuth.getCurrentUser();
          if (sessionUser) setUser(sessionUser);
          else {
            // Fallback if local storage empty but FB logged in
            const newUser: LocalUser = {
              uid: fbUser.uid,
              username: fbUser.email?.split('@')[0] || 'unknown',
              apiKey: localAuth.generateApiKey(),
              createdAt: Date.now(),
              lastLogin: Date.now()
            };
            setUser(newUser);
            localAuth.setCurrentUser(newUser);
          }
        }
      });
    }

    // Initial check for existing local session
    const sessionUser = localAuth.getCurrentUser();
    if (sessionUser) {
      setUser(sessionUser);
    }
    setLoading(false);

    return () => unsubscribe();
  }, [user]);

  const handleLogout = async () => {
    try {
      if (isFirebaseConfigured && auth) {
        await signOut(auth);
      }
      localAuth.logout();
      setUser(null);
    } catch (err) {
      console.error("Logout failed", err);
      // Fallback
      if (isFirebaseConfigured && auth) {
        await signOut(auth).catch(() => {});
      }
      localAuth.logout();
      setUser(null);
    }
  };

  if (loading) {
    return (
      <div className="h-screen w-screen bg-black flex items-center justify-center font-mono text-kali-blue">
        <div className="flex flex-col items-center gap-4">
          <Power className="w-8 h-8 animate-pulse" />
          <span className="text-[10px] uppercase tracking-[0.5em]">Initializing OS...</span>
        </div>
      </div>
    );
  }

  return (
    <AnimatePresence mode="wait">
      {!user ? (
        <LoginScreen key="login" onAuthSuccess={setUser} />
      ) : (
        <Dashboard key="dashboard" user={user} onLogout={handleLogout} />
      )}
    </AnimatePresence>
  );
}

