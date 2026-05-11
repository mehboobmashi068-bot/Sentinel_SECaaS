/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface LocalUser {
  uid: string;
  username: string;
  apiKey: string;
  createdAt: number;
  lastLogin: number;
}

const USERS_KEY = 'sentinel_users';
const SESSION_KEY = 'sentinel_session';

export const localAuth = {
  getUsers: (): LocalUser[] => {
    const data = localStorage.getItem(USERS_KEY);
    return data ? JSON.parse(data) : [];
  },

  setUsers: (users: LocalUser[]) => {
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
  },

  getCurrentUser: (): LocalUser | null => {
    const data = localStorage.getItem(SESSION_KEY);
    return data ? JSON.parse(data) : null;
  },

  setCurrentUser: (user: LocalUser | null) => {
    if (user) {
      localStorage.setItem(SESSION_KEY, JSON.stringify(user));
    } else {
      localStorage.removeItem(SESSION_KEY);
    }
  },

  logout: () => {
    localStorage.removeItem(SESSION_KEY);
  },

  generateApiKey: () => {
    const array = new Uint8Array(24);
    window.crypto.getRandomValues(array);
    const entropy = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    const timestamp = Date.now().toString(36);
    return `sk_v2_${timestamp}_${entropy.substring(0, 32)}`;
  },

  updateUser: (updatedUser: LocalUser) => {
    const users = localAuth.getUsers();
    const newUsers = users.map(u => u.uid === updatedUser.uid ? updatedUser : u);
    localAuth.setUsers(newUsers);
    
    const session = localAuth.getCurrentUser();
    if (session && session.uid === updatedUser.uid) {
      localAuth.setCurrentUser(updatedUser);
    }
  }
};
