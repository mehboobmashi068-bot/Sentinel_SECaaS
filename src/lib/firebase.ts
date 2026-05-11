import { initializeApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';

// These values match your Firebase project: reliable-security-43cce
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: "reliable-security-43cce.firebaseapp.com",
  projectId: "reliable-security-43cce",
  storageBucket: "reliable-security-43cce.firebasestorage.app",
  messagingSenderId: "591456220366",
  appId: "1:591456220366:web:866416972e38202957f12e"
};

const app = initializeApp(firebaseConfig);

// Exporting these allows you to use them in your Login/Register pages
export const auth = getAuth(app);
export const db = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();

// Guard against missing API key to prevent hard crash
const isFirebaseConfigured = !!firebaseConfig.apiKey && firebaseConfig.apiKey !== "";

if (!isFirebaseConfigured) {
  console.warn("[ FIREBASE ] Missing configuration. Please set VITE_FIREBASE_API_KEY in Settings.");
}

// Initialize Firebase
const app = isFirebaseConfigured ? initializeApp(firebaseConfig) : null;
export const auth = app ? getAuth(app) : null as any;
export const db = app ? getFirestore(app) : null as any;
export const googleProvider = new GoogleAuthProvider();

export { isFirebaseConfigured };
