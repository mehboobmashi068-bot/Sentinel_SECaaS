import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: "reliable-security.firebaseapp.com",
  projectId: "reliable-security",
  storageBucket: "reliable-security.firebasestorage.app",
  messagingSenderId: "532036786743",
  appId: "1:532036786743:web:32a1087aba89cf2252fdb2"
};

// Check if the API key exists (This is what App.tsx is looking for)
export const isFirebaseConfigured = !!import.meta.env.VITE_FIREBASE_API_KEY;

// Initialize Firebase safely
const app = !getApps().length ? initializeApp(firebaseConfig) : getApp();

export const auth = getAuth(app);
export const db = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();

export default app;