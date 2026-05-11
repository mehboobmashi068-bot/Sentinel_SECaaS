import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';

// Your existing Firebase configuration
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: "reliable-security.firebaseapp.com",
  projectId: "reliable-security",
  storageBucket: "reliable-security.firebasestorage.app",
  messagingSenderId: "532036786743",
  appId: "1:532036786743:web:32a1087aba89cf2252fdb2"
};

// Initialize Firebase once. 
// This check prevents "Firebase: App named '[DEFAULT]' already exists" errors during HMR.
const app = !getApps().length ? initializeApp(firebaseConfig) : getApp();

// Single export declarations
export const auth = getAuth(app);
export const db = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();

// Set custom parameters for Google Auth if needed (optional)
googleProvider.setCustomParameters({ prompt: 'select_account' });

export default app;
