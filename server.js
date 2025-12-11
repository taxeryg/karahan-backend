// server.js → TAM SÜRÜM: Kayıt + Giriş + Avatar + Kick Chat + Silah Mekaniği + Render Uyumlu

import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

import { fileURLToPath } from 'url';
import path from 'path';
import { createClient } from "@retconned/kick-js";
import http from "http";
import { Server as SocketIOServer } from "socket.io";

import { initializeApp, cert } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3002; // RENDER İÇİN ZORUNLU!
const CLIENT_URL = process.env.CLIENT_URL || "https://karahanbest.netlify.app"; // Frontend adresi

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- HTTP + Socket.IO ----------
const server = http.createServer(app);
const io = new SocketIOServer(server, {
    cors: {
        origin: CLIENT_URL,
        methods: ["GET", "POST"]
    }
});

// ---------- Firebase ----------
let db;
let usersCollection;

function initializeFirebase() {
    try {
        let serviceAccount;

        // 1. Önce Render/Environment Variable kontrol et
        if (process.env.FIREBASE_SERVICE_ACCOUNT) {
            // Render'da JSON içeriğini string olarak saklayacağız, burada parse ediyoruz
            serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
            console.log("Firebase config Environment Variable üzerinden alındı.");
        } else {
            // 2. Yoksa yerel dosyadan oku (Localhost için)
            serviceAccount = require(path.join(__dirname, 'firebase-adminsdk.json'));
            console.log("Firebase config yerel dosyadan alındı.");
        }

        initializeApp({ credential: cert(serviceAccount) });
        db = getFirestore();
        usersCollection = db.collection('users');
        console.log("Firebase veritabanı bağlandı");
    } catch (err) {
        console.error("Firebase başlatılamadı:", err.message);
        console.error("HATA İPUCU: Eğer Render'daysanız 'FIREBASE_SERVICE_ACCOUNT' environment variable'ını eklediniz mi?");
    }
}
initializeFirebase();

// ---------- Middleware ----------
app.use(cors({ origin: CLIENT_URL }));
app.use(bodyParser.json());

// ---------- Oyun Değişkenleri ----------
let activePlayers = [];
let currentSelectedPlayerId = null;
let waitingForTarget = false; // silah çıktı mı?

function getRandomColor() {
    const letters = "0123456789ABCDEF";
    let color = "#";
    for (let i = 0; i < 6; i++) color += letters[Math.floor(Math.random() * 16)];
    return color;
}

// ---------- JWT Middleware ----------
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// ---------- REGISTER ----------
app.post("/register", async (req, res) => {
    if (!usersCollection) return res.status(503).json({ success: false, message: "DB yok" });
    const { username, password } = req.body;
    try {
        const snap = await usersCollection.where('username', '==', username).get();
        if (!snap.empty) return res.status(409).json({ success: false, message: "Kullanıcı var" });

        const hashed = await bcrypt.hash(password, 10);
        await usersCollection.add({
            username,
            password: hashed,
            role: 'oyuncu',
            score: 0,
            coins: 100,
            bio: "Yeni oyuncuyum!",
            profilePicture: "default_avatar.png"
        });
        res.json({ success: true, message: "Kayıt oldu!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Hata" });
    }
});

// ---------- LOGIN ----------
app.post("/login", async (req, res) => {
    if (!usersCollection) return res.status(503).json({ success: false, message: "DB yok" });
    const { username, password } = req.body;
    try {
        const snap = await usersCollection.where('username', '==', username).limit(1).get();
        if (snap.empty) return res.status(401).json({ success: false, message: "Yanlış" });

        const userDoc = snap.docs[0];
        const data = userDoc.data();
        const match = await bcrypt.compare(password, data.password);
        if (!match) return res.status(401).json({ success: false, message: "Yanlış" });

        const token = jwt.sign(
            { userId: userDoc.id, username: data.username, role: data.role },
            process.env.JWT_SECRET || 'fallback-secret',
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            username: data.username,
            role: data.role,
            score: data.score,
            profilePicture: data.profilePicture
        });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// ---------- AVATAR GÜNCELLE ----------
app.post("/update-avatar", authenticateToken, async (req, res) => {
    const { newAvatarPath } = req.body;
    const userId = req.user.userId;
    try {
        await usersCollection.doc(userId).update({ profilePicture: newAvatarPath });
        res.json({ success: true, newPath: newAvatarPath });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// ---------- KICK CHAT BAĞLANTISI ----------
function startKickListener(channel = "karahank7") {
    const client = createClient(channel, { readOnly: true, logger: false });

    client.on("ready", () => console.log(`Kick bot hazır → ${channel}`));

    client.on("ChatMessage", (msg) => {
        const username = msg.sender?.username;
        const content = msg.content?.trim();
        if (!username || !content) return;

        console.log(`[KICK] ${username}: ${content}`);

        // !katıl
        if (content.toLowerCase() === "!katıl") {
            if (activePlayers.some(p => p.username === username)) return;
            const player = {
                id: Date.now() + Math.random(),
                username,
                lives: 1,
                joinOrder: activePlayers.length + 1,
                color: getRandomColor()
            };
            activePlayers.push(player);
            io.emit("playerJoined", player);
            return;
        }

        // Sadece seçili oyuncu yazabilir
        const player = activePlayers.find(p => p.username === username);
        if (!player || player.id !== currentSelectedPlayerId) return;
        if (player.hasTurn === false) return;

        const num = parseInt(content, 10);

        if (waitingForTarget) {
            // Hedef numarası
            player.hasTurn = false;
            waitingForTarget = false;
            io.emit("playerMessage", { playerId: player.id, content: `TARGET:${num}` });
            return;
        }

        if (isNaN(num) || num < 1 || num > 70) {
            player.hasTurn = false;
            io.emit("playerMessage", { playerId: player.id, content: null });
            return;
        }

        player.hasTurn = false;
        io.emit("playerMessage", { playerId: player.id, content: content });
    });
}

// ---------- SOCKET.IO ENDPOINTLER ----------
io.on("connection", (socket) => {
    console.log("Bir host bağlandı");
});

app.post("/api/select-player", (req, res) => {
    const { playerId } = req.body;
    activePlayers.forEach(p => p.hasTurn = false);
    const player = activePlayers.find(p => p.id === playerId);
    if (player) player.hasTurn = true;
    currentSelectedPlayerId = playerId;
    waitingForTarget = false;
    res.json({ success: true });
});

app.post("/api/trigger-gun", (req, res) => {
    const { playerId } = req.body;
    const player = activePlayers.find(p => p.id === playerId);
    if (player) {
        player.hasTurn = true;        // ekstra hak
        waitingForTarget = true;
    }
    res.json({ success: true });
});

app.post("/api/reset-game", (req, res) => {
    activePlayers = [];
    currentSelectedPlayerId = null;
    waitingForTarget = false;
    io.emit("gameReset");
    res.json({ success: true });
});

// ---------- BAŞLAT ----------
startKickListener("karahank7"); // KANAL ADINI DEĞİŞTİR

server.listen(PORT, "0.0.0.0", () => {
    console.log(`ANA SERVER ÇALIŞIYOR → https://karahanbest.netlify.app:${PORT}`);
    console.log(`Frontend URL → ${CLIENT_URL}`);
});