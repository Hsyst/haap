require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const multer = require('multer');
const rateLimit = require('express-rate-limit');

const configPath = path.join(__dirname, 'haap-config.json');
let config = {
    app: {
        name: "HAAP",
        version: "1.0.0",
        port: 3001,
        secret: crypto.randomBytes(32).toString('hex'),
        jwtExpiration: "24h",
        callbackCodeExpiration: 30,
        externalTokenUses: 3,
        externalTokenExpiration: "24h",
        defaultProfilePicture: "/assets/default-profile.png",
        requireEmailVerification: false,
        corsEnabled: true,
        rateLimiting: {
            enabled: false,
            windowMs: 15 * 60 * 1000,
            max: 100
        }
    },
    database: {
        filename: "haap-db.sqlite"
    },
    email: {
        enabled: false,
        service: "smtp",
        smtp: {
            host: "mail.hsyst.xyz",
            port: 587,
            secure: false,
            auth: {
                user: "noreply@hsyst.xyz",
                pass: "NoReply@#123"
            }
        },
        from: "noreply@hsyst.xyz"
    },
    paths: {
        public: "./public",
        service: "./service"
    }
};

if (fs.existsSync(configPath)) {
    const savedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    config = { ...config, ...savedConfig };
} else {
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
}

const db = new sqlite3.Database(config.database.filename);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        display_name TEXT,
        pronouns TEXT,
        description TEXT,
        profile_picture TEXT,
        is_verified INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT UNIQUE,
        expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS callback_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        code TEXT UNIQUE,
        expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS external_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        link_code TEXT UNIQUE,
        service_name TEXT,
        callback_url TEXT,
        homepage_url TEXT,
        provides TEXT,
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS external_logins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        link_id INTEGER,
        user_id INTEGER,
        token TEXT UNIQUE,
        uses_left INTEGER,
        expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(link_id) REFERENCES external_links(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS email_verification_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        code TEXT UNIQUE,
        expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS user_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.get("SELECT COUNT(*) as count FROM users WHERE is_admin = 1", (err, row) => {
        if (err) throw err;
        if (row.count === 0) {
            const adminPassword = crypto.randomBytes(8).toString('hex');
            bcrypt.hash(adminPassword, 10, (err, hash) => {
                if (err) throw err;
                db.run(
                    "INSERT INTO users (username, email, password, display_name, is_admin, is_verified, is_active) VALUES (?, ?, ?, ?, 1, 1, 1)",
                    ["admin", "admin@haap.com", hash, "Administrador"],
                    (err) => {
                        if (err) throw err;
                        console.log(`Usuário admin criado com senha: ${adminPassword}`);
                    }
                );
            });
        }
    });
});

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

if (config.app.corsEnabled) {
    app.use(cors({
        origin: true,
        credentials: true
    }));
}

if (config.app.rateLimiting.enabled) {
    const limiter = rateLimit({
        windowMs: config.app.rateLimiting.windowMs,
        max: config.app.rateLimiting.max,
        message: "Too many requests from this IP, please try again later."
    });
    app.use(limiter);
}

const uploadsDir = path.join(__dirname, config.paths.service, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, `${crypto.randomBytes(16).toString('hex')}${ext}`);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Apenas imagens são permitidas!'));
        }
    }
}).single('profile_picture');

let mailTransporter;
if (config.email.enabled) {
    if (config.email.service === "smtp") {
        mailTransporter = nodemailer.createTransport({
            host: config.email.smtp.host,
            port: config.email.smtp.port,
            secure: config.email.smtp.secure,
            auth: {
                user: config.email.smtp.auth.user,
                pass: config.email.smtp.auth.pass
            },
            tls: {
                rejectUnauthorized: false
            }
        });
    } else {
        mailTransporter = nodemailer.createTransport({
            service: config.email.service,
            auth: {
                user: config.email.smtp.auth.user,
                pass: config.email.smtp.auth.pass
            }
        });
    }
}

function generateRandomCode(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

function verifyJWT(token) {
    try {
        return jwt.verify(token, config.app.secret);
    } catch (err) {
        return null;
    }
}

function isAuthenticated(req, res, next) {
    const token = req.cookies.haap_token || req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: "Não autenticado" });
    }

    const decoded = verifyJWT(token);
    if (!decoded) {
        return res.status(401).json({ error: "Token inválido ou expirado" });
    }

    req.user = decoded;
    next();
}

function isAdmin(req, res, next) {
    if (!req.user || !req.user.is_admin) {
        return res.status(403).json({ error: "Acesso negado: requer privilégios de administrador" });
    }
    next();
}

function saveConfig() {
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
}

function logActivity(userId, type, data = {}) {
    db.run(
        "INSERT INTO user_activity (user_id, type, data) VALUES (?, ?, ?)",
        [userId, type, JSON.stringify(data)],
        (err) => {
            if (err) console.error("Erro ao registrar atividade:", err);
        }
    );
}

const publicDir = path.join(__dirname, config.paths.public);
const serviceDir = path.join(__dirname, config.paths.service);

function checkForConflicts() {
    const publicFiles = getAllFiles(publicDir);
    const serviceFiles = getAllFiles(serviceDir);

    const conflicts = publicFiles.filter(file =>
        serviceFiles.includes(file.replace(publicDir, serviceDir))
    );

    if (conflicts.length > 0) {
        console.error('Conflitos encontrados entre os diretórios public e service:');
        conflicts.forEach(conflict => {
            console.error(`- ${path.relative(publicDir, conflict)} existe em ambos os diretórios`);
        });
        return true;
    }
    return false;
}

function getAllFiles(dir, fileList = []) {
    const files = fs.readdirSync(dir);

    files.forEach(file => {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);

        if (stat.isDirectory()) {
            getAllFiles(filePath, fileList);
        } else {
            fileList.push(filePath);
        }
    });

    return fileList;
}

if (checkForConflicts()) {
    console.error('Por favor, resolva os conflitos antes de continuar.');
    process.exit(1);
}

app.use((req, res, next) => {
    const requestedPath = req.path;

    if (requestedPath.endsWith('/')) {
        return res.redirect(301, requestedPath + 'index.html');
    }

    const publicFile = path.join(publicDir, requestedPath);
    const serviceFile = path.join(serviceDir, requestedPath);

    if (fs.existsSync(publicFile) && !fs.existsSync(serviceFile)) {
        const token = req.cookies.haap_token || req.headers['authorization']?.split(' ')[1];
        const decoded = verifyJWT(token);

        if (!decoded) {
            return res.redirect('/login.html');
        }

        return express.static(publicDir)(req, res, next);
    }

    if (fs.existsSync(serviceFile)) {
        return express.static(serviceDir)(req, res, next);
    }

    next();
});

app.post('/api/register', (req, res) => {
    const { email, password, username } = req.body;

    if (!email || !password || !username) {
        return res.status(400).json({ error: "E-mail, nome de usuário e senha são obrigatórios" });
    }

    db.get("SELECT * FROM users WHERE email = ? OR username = ?", [email, username], (err, row) => {
        if (err) {
            return res.status(500).json({ error: "Erro no servidor" });
        }

        if (row) {
            return res.status(400).json({ error: "E-mail ou nome de usuário já cadastrado" });
        }

        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                return res.status(500).json({ error: "Erro ao criar conta" });
            }

            db.run(
                "INSERT INTO users (username, email, password, display_name, description, pronouns, profile_picture, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    username,
                    email,
                    hash,
                    username,
                    "Estou no HAAP!",
                    "they/them",
                    config.app.defaultProfilePicture,
                    config.app.requireEmailVerification ? 0 : 1
                ],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: "Erro ao criar conta" });
                    }

                    const userId = this.lastID;
                    logActivity(userId, 'user_registered');

                    if (config.app.requireEmailVerification && config.email.enabled) {
                        const verificationCode = generateRandomCode(32);
                        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

                        db.run(
                            "INSERT INTO email_verification_codes (user_id, code, expires_at) VALUES (?, ?, ?)",
                            [userId, verificationCode, expiresAt.toISOString()],
                            (err) => {
                                if (err) {
                                    return res.status(500).json({ error: "Erro ao gerar código de verificação" });
                                }

                                const mailOptions = {
                                    from: config.email.from,
                                    to: email,
                                    subject: "Verifique seu e-mail no HAAP",
                                    html: `
                                        <h1>Bem-vindo ao HAAP!</h1>
                                        <p>Por favor, clique no link abaixo para verificar seu e-mail:</p>
                                        <a href="http://${req.headers.host}/api/verify-email?code=${verificationCode}">Verificar e-mail</a>
                                        <p>Se você não criou uma conta no HAAP, ignore este e-mail.</p>
                                    `
                                };

                                mailTransporter.sendMail(mailOptions, (error, info) => {
                                    if (error) {
                                        console.error("Erro ao enviar e-mail:", error);
                                        return res.status(500).json({
                                            error: "Erro ao enviar e-mail de verificação",
                                            account_created: true
                                        });
                                    }

                                    res.json({
                                        message: "Conta criada com sucesso! Verifique seu e-mail para ativar sua conta.",
                                        account_created: true
                                    });
                                });
                            }
                        );
                    } else {
                        res.json({
                            message: "Conta criada com sucesso!",
                            account_created: true
                        });
                    }
                }
            );
        });
    });
});

app.get('/api/verify-email', (req, res) => {
    const { code } = req.query;

    if (!code) {
        return res.status(400).json({ error: "Código de verificação é obrigatório" });
    }

    db.get(
        "SELECT user_id, expires_at FROM email_verification_codes WHERE code = ?",
        [code],
        (err, row) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            if (!row) {
                return res.status(400).json({ error: "Código de verificação inválido" });
            }

            const now = new Date();
            const expiresAt = new Date(row.expires_at);

            if (now > expiresAt) {
                return res.status(400).json({ error: "Código de verificação expirado" });
            }

            db.run(
                "UPDATE users SET is_verified = 1 WHERE id = ?",
                [row.user_id],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: "Erro ao verificar e-mail" });
                    }

                    db.run("DELETE FROM email_verification_codes WHERE code = ?", [code]);
                    logActivity(row.user_id, 'email_verified');

                    res.json({ message: "E-mail verificado com sucesso!" });
                }
            );
        }
    );
});

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.status(400).json({ error: "Login e senha são obrigatórios" });
    }

    db.get(
        "SELECT * FROM users WHERE email = ? OR username = ?",
        [login, login],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            if (!user) {
                return res.status(401).json({ error: "Credenciais inválidas" });
            }

            if (!user.is_active) {
                return res.status(403).json({ error: "Conta desativada" });
            }

            if (config.app.requireEmailVerification && !user.is_verified) {
                return res.status(403).json({ error: "E-mail não verificado" });
            }

            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    return res.status(500).json({ error: "Erro no servidor" });
                }

                if (!result) {
                    return res.status(401).json({ error: "Credenciais inválidas" });
                }

                const callbackCode = generateRandomCode(32);
                const expiresAt = new Date(Date.now() + config.app.callbackCodeExpiration * 1000);

                db.run(
                    "INSERT INTO callback_codes (user_id, code, expires_at) VALUES (?, ?, ?)",
                    [user.id, callbackCode, expiresAt.toISOString()],
                    (err) => {
                        if (err) {
                            return res.status(500).json({ error: "Erro ao gerar código de callback" });
                        }

                        logActivity(user.id, 'login_success');
                        res.json({
                            callback_code: callbackCode,
                            expires_in: config.app.callbackCodeExpiration
                        });
                    }
                );
            });
        }
    );
});

app.post('/api/callback', (req, res) => {
    const { login, password, callback_code } = req.body;

    if (!login || !password || !callback_code) {
        return res.status(400).json({ error: "Login, senha e código de callback são obrigatórios" });
    }

    db.get(
        "SELECT * FROM users WHERE email = ? OR username = ?",
        [login, login],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            if (!user) {
                return res.status(401).json({ error: "Credenciais inválidas" });
            }

            if (!user.is_active) {
                return res.status(403).json({ error: "Conta desativada" });
            }

            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    return res.status(500).json({ error: "Erro no servidor" });
                }

                if (!result) {
                    return res.status(401).json({ error: "Credenciais inválidas" });
                }

                db.get(
                    "SELECT * FROM callback_codes WHERE code = ? AND user_id = ?",
                    [callback_code, user.id],
                    (err, codeRow) => {
                        if (err) {
                            return res.status(500).json({ error: "Erro no servidor" });
                        }

                        if (!codeRow) {
                            return res.status(400).json({ error: "Código de callback inválido" });
                        }

                        const now = new Date();
                        const expiresAt = new Date(codeRow.expires_at);

                        if (now > expiresAt) {
                            return res.status(400).json({ error: "Código de callback expirado" });
                        }

                        db.run("DELETE FROM callback_codes WHERE code = ?", [callback_code]);

                        const token = jwt.sign(
                            {
                                id: user.id,
                                username: user.username,
                                email: user.email,
                                is_admin: user.is_admin,
                                is_verified: user.is_verified
                            },
                            config.app.secret,
                            { expiresIn: config.app.jwtExpiration }
                        );

                        db.run(
                            "INSERT INTO user_sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
                            [user.id, token, new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()],
                            (err) => {
                                if (err) console.error("Erro ao registrar sessão:", err);
                            }
                        );

                        res.cookie('haap_token', token, {
                            httpOnly: true,
                            secure: process.env.NODE_ENV === 'production',
                            maxAge: 24 * 60 * 60 * 1000
                        });

                        res.json({
                            token: token,
                            expires_in: config.app.jwtExpiration
                        });
                    }
                );
            });
        }
    );
});

app.post('/api/logout', isAuthenticated, (req, res) => {
    const token = req.cookies.haap_token || req.headers['authorization']?.split(' ')[1];

    db.run("DELETE FROM user_sessions WHERE token = ?", [token], (err) => {
        if (err) console.error("Erro ao remover sessão:", err);
    });

    logActivity(req.user.id, 'logout');
    res.clearCookie('haap_token');
    res.json({ message: "Logout realizado com sucesso" });
});

app.get('/api/profile', isAuthenticated, (req, res) => {
    db.get(
        "SELECT id, username, email, display_name, pronouns, description, profile_picture, is_admin, is_verified FROM users WHERE id = ?",
        [req.user.id],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            if (!user) {
                return res.status(404).json({ error: "Usuário não encontrado" });
            }

            res.json(user);
        }
    );
});

app.put('/api/profile', isAuthenticated, upload, (req, res) => {
    const { display_name, pronouns, description } = req.body;
    let profilePicture = req.user.profile_picture;

    if (req.file) {
        profilePicture = `/uploads/${req.file.filename}`;
    }

    db.run(
        "UPDATE users SET display_name = ?, pronouns = ?, description = ?, profile_picture = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [
            display_name || req.user.username,
            pronouns || "they/them",
            description || "Estou no HAAP!",
            profilePicture,
            req.user.id
        ],
        (err) => {
            if (err) {
                return res.status(500).json({ error: "Erro ao atualizar perfil" });
            }

            logActivity(req.user.id, 'profile_updated', {
                display_name: display_name,
                pronouns: pronouns,
                description: description
            });
            res.json({ message: "Perfil atualizado com sucesso!" });
        }
    );
});

app.post('/api/change-password', isAuthenticated, (req, res) => {
    const { current_password, new_password } = req.body;

    if (!current_password || !new_password) {
        return res.status(400).json({ error: "Senha atual e nova senha são obrigatórias" });
    }

    db.get("SELECT password FROM users WHERE id = ?", [req.user.id], (err, user) => {
        if (err) {
            return res.status(500).json({ error: "Erro no servidor" });
        }

        bcrypt.compare(current_password, user.password, (err, result) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            if (!result) {
                return res.status(401).json({ error: "Senha atual incorreta" });
            }

            bcrypt.hash(new_password, 10, (err, hash) => {
                if (err) {
                    return res.status(500).json({ error: "Erro ao alterar senha" });
                }

                db.run(
                    "UPDATE users SET password = ? WHERE id = ?",
                    [hash, req.user.id],
                    (err) => {
                        if (err) {
                            return res.status(500).json({ error: "Erro ao alterar senha" });
                        }

                        db.run("DELETE FROM user_sessions WHERE user_id = ?", [req.user.id]);
                        logActivity(req.user.id, 'password_changed');

                        res.json({ message: "Senha alterada com sucesso!" });
                    }
                );
            });
        });
    });
});

app.post('/api/external-links', isAuthenticated, (req, res) => {
    const { service_name, callback_url, homepage_url, provides } = req.body;

    if (!service_name || !callback_url || !homepage_url || !provides) {
        return res.status(400).json({ error: "Nome do serviço, URL de callback, URL da homepage e informações fornecidas são obrigatórios" });
    }

    const linkCode = generateRandomCode(32);

    db.run(
        "INSERT INTO external_links (user_id, link_code, service_name, callback_url, homepage_url, provides) VALUES (?, ?, ?, ?, ?, ?)",
        [req.user.id, linkCode, service_name, callback_url, homepage_url, JSON.stringify(provides)],
        function(err) {
            if (err) {
                return res.status(500).json({ error: "Erro ao criar link de login externo" });
            }

            const linkId = this.lastID;
            logActivity(req.user.id, 'external_link_created', {
                service_name: service_name,
                link_id: linkId
            });

            res.json({
                link_id: linkId,
                link_code: linkCode,
                login_url: `${req.headers.host}/ext-login.html#link=${linkCode}`,
                message: "Link de login externo criado com sucesso!"
            });
        }
    );
});

app.get('/api/external-links', isAuthenticated, (req, res) => {
    db.all(
        "SELECT id, link_code, service_name, callback_url, homepage_url, provides, is_active, created_at FROM external_links WHERE user_id = ?",
        [req.user.id],
        (err, links) => {
            if (err) {
                return res.status(500).json({ error: "Erro ao listar links de login externo" });
            }

            res.json(links.map(link => ({
                ...link,
                provides: JSON.parse(link.provides),
                login_url: `${req.headers.host}/ext-login.html#link=${link.link_code}`
            })));
        }
    );
});

app.get('/api/external-links/:link_code', (req, res) => {
    const { link_code } = req.params;

    db.get(
        "SELECT el.id, el.link_code, el.service_name, el.provides, u.username, u.display_name, u.profile_picture FROM external_links el JOIN users u ON el.user_id = u.id WHERE el.link_code = ? AND el.is_active = 1",
        [link_code],
        (err, link) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            if (!link) {
                return res.status(404).json({ error: "Link de login não encontrado ou desativado" });
            }

            res.json({
                ...link,
                provides: JSON.parse(link.provides)
            });
        }
    );
});

app.get('/api/external-links/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;

    db.get(
        "SELECT el.id, el.link_code, el.service_name, el.callback_url, el.homepage_url, el.provides, el.is_active, u.username FROM external_links el JOIN users u ON el.user_id = u.id WHERE el.id = ? AND el.user_id = ?",
        [id, req.user.id],
        (err, link) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            if (!link) {
                return res.status(404).json({ error: "Link de login não encontrado" });
            }

            res.json({
                ...link,
                provides: JSON.parse(link.provides)
            });
        }
    );
});

app.put('/api/external-links/:id/status', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const { is_active } = req.body;

    if (typeof is_active !== 'boolean') {
        return res.status(400).json({ error: "Parâmetro is_active é obrigatório (boolean)" });
    }

    db.get(
        "SELECT id, user_id FROM external_links WHERE id = ?",
        [id],
        (err, link) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            if (!link) {
                return res.status(404).json({ error: "Link não encontrado" });
            }

            const isAdminRequest = req.user.is_admin;

            if (!isAdminRequest) {
                return res.status(403).json({
                    error: "Acesso negado: você não é o dono deste link e não tem privilégios de administrador"
                });
            }

            if (isAdminRequest) {
                logActivity(req.user.id, 'admin_disabled_external_link', {
                    link_id: id,
                    owner_id: link.user_id
                });
            }

            db.run(
                "UPDATE external_links SET is_active = ? WHERE id = ?",
                [is_active ? 1 : 0, id],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: "Erro ao atualizar link" });
                    }

                    logActivity(req.user.id, 'external_link_updated', {
                        link_id: id,
                        is_active: is_active,
                        by_admin: isAdminRequest
                    });

                    res.json({ message: "Link atualizado com sucesso!" });
                }
            );
        }
    );
});

app.get('/api/external-links/:id/logins', isAuthenticated, (req, res) => {
    const { id } = req.params;

    db.all(
        `SELECT el.id, el.token, el.uses_left, el.expires_at, el.created_at
         FROM external_logins el
         JOIN external_links l ON el.link_id = l.id
         WHERE el.link_id = ? AND l.user_id = ?
         ORDER BY el.created_at DESC`,
        [id, req.user.id],
        (err, logins) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            res.json(logins);
        }
    );
});

app.post('/api/external-links/:link_code/authorize', isAuthenticated, (req, res) => {
    const { link_code } = req.params;
    const { authorize } = req.body;

    if (typeof authorize !== 'boolean') {
        return res.status(400).json({ error: "Parâmetro 'authorize' é obrigatório (true/false)" });
    }

    db.get(
        "SELECT id, user_id, callback_url, homepage_url FROM external_links WHERE link_code = ? AND is_active = 1",
        [link_code],
        (err, link) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            if (!link) {
                return res.status(404).json({ error: "Link de login não encontrado ou desativado" });
            }

            if (!authorize) {
                return res.json({ redirect_to: link.homepage_url });
            }

            const externalToken = generateRandomCode(64);
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

            db.run(
                "INSERT INTO external_logins (link_id, user_id, token, uses_left, expires_at) VALUES (?, ?, ?, ?, ?)",
                [link.id, req.user.id, externalToken, config.app.externalTokenUses, expiresAt.toISOString()],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: "Erro ao autorizar login externo" });
                    }

                    logActivity(req.user.id, 'external_login_authorized', {
                        link_id: link.id,
                        service_name: link.service_name
                    });

                    const callbackUrl = new URL(link.callback_url);
                    callbackUrl.searchParams.append('callback_code', externalToken);

                    res.json({ redirect_to: callbackUrl.toString() });
                }
            );
        }
    );
});

app.get('/api/external-verify', (req, res) => {
    const { token } = req.query;

    if (!token) {
        return res.status(400).json({ error: "Token é obrigatório" });
    }

    db.get(
        `SELECT el.token, el.uses_left, el.expires_at,
                u.id as user_id, u.username, u.email, u.display_name, u.profile_picture,
                elink.provides
         FROM external_logins el
         JOIN users u ON el.user_id = u.id
         JOIN external_links elink ON el.link_id = elink.id
         WHERE el.token = ?`,
        [token],
        (err, login) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            if (!login) {
                return res.status(404).json({ error: "Token inválido" });
            }

            const now = new Date();
            const expiresAt = new Date(login.expires_at);

            if (now > expiresAt) {
                return res.status(400).json({ error: "Token expirado" });
            }

            if (login.uses_left <= 0) {
                return res.status(400).json({ error: "Token já utilizado o número máximo de vezes" });
            }

            db.run(
                "UPDATE external_logins SET uses_left = uses_left - 1 WHERE token = ?",
                [token],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: "Erro no servidor" });
                    }

                    const provides = JSON.parse(login.provides);
                    const userData = {};

                    if (provides.includes('id')) userData.id = login.user_id;
                    if (provides.includes('username')) userData.username = login.username;
                    if (provides.includes('email')) userData.email = login.email;
                    if (provides.includes('display_name')) userData.display_name = login.display_name;
                    if (provides.includes('profile_picture')) userData.profile_picture = login.profile_picture;

                    logActivity(login.user_id, 'external_login_used', {
                        link_id: login.link_id,
                        token: token
                    });

                    res.json({
                        valid: true,
                        user: userData,
                        uses_left: login.uses_left - 1,
                        expires_at: login.expires_at
                    });
                }
            );
        }
    );
});

app.get('/api/activity', isAuthenticated, (req, res) => {
    db.all(
        "SELECT id, type, data, created_at FROM user_activity WHERE user_id = ? ORDER BY created_at DESC LIMIT 10",
        [req.user.id],
        (err, activities) => {
            if (err) {
                return res.status(500).json({ error: "Erro ao carregar atividades" });
            }

            res.json(activities.map(activity => ({
                ...activity,
                data: activity.data ? JSON.parse(activity.data) : null
            })));
        }
    );
});

app.get('/api/admin/users', isAuthenticated, isAdmin, (req, res) => {
    db.all(
        "SELECT id, username, email, display_name, is_admin, is_verified, is_active, created_at FROM users",
        (err, users) => {
            if (err) {
                return res.status(500).json({ error: "Erro ao listar usuários" });
            }

            res.json(users);
        }
    );
});

app.get('/api/admin/users/:id', isAuthenticated, isAdmin, (req, res) => {
    const { id } = req.params;

    db.get(
        "SELECT id, username, email, display_name, is_admin, is_verified, is_active, created_at FROM users WHERE id = ?",
        [id],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: "Erro no servidor" });
            }

            if (!user) {
                return res.status(404).json({ error: "Usuário não encontrado" });
            }

            res.json(user);
        }
    );
});

app.put('/api/admin/users/:id', isAuthenticated, isAdmin, (req, res) => {
    const { id } = req.params;
    const { is_admin, is_active } = req.body;

    if (typeof is_admin !== 'boolean' || typeof is_active !== 'boolean') {
        return res.status(400).json({ error: "Parâmetros is_admin e is_active são obrigatórios (boolean)" });
    }

    if (parseInt(id) === req.user.id && !is_active) {
        return res.status(400).json({ error: "Você não pode desativar sua própria conta" });
    }

    db.run(
        "UPDATE users SET is_admin = ?, is_active = ? WHERE id = ?",
        [is_admin ? 1 : 0, is_active ? 1 : 0, id],
        (err) => {
            if (err) {
                return res.status(500).json({ error: "Erro ao atualizar usuário" });
            }

            if (!is_active) {
                db.run("DELETE FROM user_sessions WHERE user_id = ?", [id]);
            }

            logActivity(req.user.id, 'admin_user_updated', {
                user_id: id,
                is_admin: is_admin,
                is_active: is_active
            });

            res.json({ message: "Usuário atualizado com sucesso!" });
        }
    );
});

app.get('/api/admin/external-links', isAuthenticated, isAdmin, (req, res) => {
    db.all(
        `SELECT el.id, el.link_code, el.service_name, el.callback_url, el.is_active, el.created_at,
                u.username, u.display_name
         FROM external_links el
         JOIN users u ON el.user_id = u.id
         ORDER BY el.created_at DESC`,
        (err, links) => {
            if (err) {
                return res.status(500).json({ error: "Erro ao listar links externos" });
            }

            res.json(links);
        }
    );
});

app.get('/api/admin/settings', isAuthenticated, isAdmin, (req, res) => {
    res.json({
        requireEmailVerification: config.app.requireEmailVerification,
        emailEnabled: config.email.enabled,
        corsEnabled: config.app.corsEnabled,
        rateLimiting: config.app.rateLimiting
    });
});

app.put('/api/admin/settings', isAuthenticated, isAdmin, (req, res) => {
    const { requireEmailVerification, emailEnabled, corsEnabled, rateLimiting } = req.body;

    if (typeof requireEmailVerification !== 'boolean' ||
        typeof emailEnabled !== 'boolean' ||
        typeof corsEnabled !== 'boolean') {
        return res.status(400).json({ error: "Parâmetros inválidos" });
    }

    config.app.requireEmailVerification = requireEmailVerification;
    config.app.corsEnabled = corsEnabled;

    if (rateLimiting && typeof rateLimiting.enabled === 'boolean' &&
        typeof rateLimiting.windowMs === 'number' &&
        typeof rateLimiting.max === 'number') {
        config.app.rateLimiting = rateLimiting;
    }

    config.email.enabled = emailEnabled;

    saveConfig();
    logActivity(req.user.id, 'system_settings_updated');

    res.json({ message: "Configurações atualizadas com sucesso!" });
});

app.get('/api/admin/email-settings', isAuthenticated, isAdmin, (req, res) => {
    res.json({
        service: config.email.service,
        smtp: {
            host: config.email.smtp.host,
            port: config.email.smtp.port,
            secure: config.email.smtp.secure
        },
        auth: {
            user: config.email.smtp.auth.user
        },
        from: config.email.from,
        enabled: config.email.enabled
    });
});

app.put('/api/admin/email-settings', isAuthenticated, isAdmin, (req, res) => {
    const { emailService, emailHost, emailPort, emailSecure, emailUser, emailPass, emailFrom } = req.body;

    if (!emailService || !emailUser || !emailPass || !emailFrom) {
        return res.status(400).json({ error: "Campos obrigatórios faltando" });
    }

    config.email.service = emailService;
    config.email.smtp.host = emailHost || "";
    config.email.smtp.port = emailPort || 587;
    config.email.smtp.secure = emailSecure || false;
    config.email.smtp.auth.user = emailUser;
    config.email.smtp.auth.pass = emailPass;
    config.email.from = emailFrom;
    config.email.enabled = true;

    if (mailTransporter) {
        mailTransporter.close();
    }

    if (emailService === "smtp") {
        mailTransporter = nodemailer.createTransport({
            host: config.email.smtp.host,
            port: config.email.smtp.port,
            secure: config.email.smtp.secure,
            requireTLS: true,
            auth: {
                user: config.email.smtp.auth.user,
                pass: config.email.smtp.auth.pass
            }
        });
    } else {
        mailTransporter = nodemailer.createTransport({
            service: config.email.service,
            auth: {
                user: config.email.smtp.auth.user,
                pass: config.email.smtp.auth.pass
            }
        });
    }

    saveConfig();
    logActivity(req.user.id, 'email_settings_updated');

    res.json({ message: "Configurações de e-mail atualizadas com sucesso!" });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Algo deu errado!');
});

app.listen(config.app.port, () => {
    console.log(`HAAP rodando na porta ${config.app.port}`);
    console.log(`Abra a página HTTP(S)://URL_DO_SEU_SERVIÇO/admin.html para acessar a página de administração.`)
});
