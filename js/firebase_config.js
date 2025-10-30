// js/firebase-config.js
import { initializeApp } from "https://www.gstatic.com/firebasejs/12.4.0/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/12.4.0/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyDAl2aYpHy3fFW8ljuojcN8UZ-ZYERsTdg",
  authDomain: "afriskana-d1bf5.firebaseapp.com",
  projectId: "afriskana-d1bf5",
  storageBucket: "afriskana-d1bf5.firebasestorage.app",
  messagingSenderId: "180164869219",
  appId: "1:180164869219:web:92e3dab0c586be0582cc56"
};

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
