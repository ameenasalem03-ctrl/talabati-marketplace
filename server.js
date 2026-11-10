require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('./generated/prisma');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const multer = require('multer');

// --- Helpers: Password hashing, JWT, and Auth ---
function hashPasswordSync(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${derived}`;
}

function verifyPassword(password, stored) {
    try {
        if (!stored || typeof stored !== 'string') return false;
        const [salt, keyHex] = stored.split(':');
        if (!salt || !keyHex) return false;
        const derived = crypto.scryptSync(password, salt, 64);
        const keyBuffer = Buffer.from(keyHex, 'hex');
        if (keyBuffer.length !== derived.length) return false;
        return crypto.timingSafeEqual(keyBuffer, derived);
    } catch (err) {
        console.error('verifyPassword error', err);
        return false;
    }
}

async function currentUser(req) {
    try {
        const auth = req.headers?.authorization;
        if (!auth) return null;
        if (auth.startsWith('Bearer ')) {
            const token = auth.slice(7).trim();
            const secret = process.env.JWT_SECRET;
            if (!secret) return null;
            try {
                const payload = jwt.verify(token, secret);
                const userId = payload && (payload.userId || payload.id);
                if (userId) {
                    const user = await prisma.user.findUnique({ where: { id: Number(userId) } });
                    if (!user) return null;
                    const { passwordHash, ...safe } = user;
                    return safe;
                }
            } catch (err) {
                return null;
            }
        }
        return null;
    } catch (err) {
        console.error('currentUser error', err);
        return null;
    }
}

function requireAuth(roles = []) {
    return async (req, res, next) => {
        try {
            const user = await currentUser(req);
            if (!user) return res.status(401).json({ error: 'Unauthorized' });
            if (Array.isArray(roles) && roles.length > 0) {
                // دعم أدوار متعددة مفصولة بفاصلة
                const userRoles = String(user.role || '').split(',').map(r => r.trim());
                const hasRole = roles.some(role => userRoles.includes(role));
                if (!hasRole) return res.status(403).json({ error: 'Forbidden' });
            }
            req.user = user;
            next();
        } catch (err) {
            console.error('requireAuth error', err);
            res.status(500).json({ error: 'Auth failure' });
        }
    };
}
// --- Prisma / Express setup ---
const prisma = new PrismaClient();
const app = express();
const PORT = Number(process.env.PORT) || 3100;
let dbReady = false;

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Static files (including uploads) ---
app.use(express.static(path.join(__dirname), {
    setHeaders(res, filePath) {
        if (filePath.endsWith('.html')) res.setHeader('Content-Type', 'text/html; charset=utf-8');
    }
}));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

app.use((req, res, next) => {
    if (!dbReady && req.path.startsWith('/api')) return res.status(503).json({ error: 'Database not ready. Try later.' });
    next();
});

async function ensureAdminUser() {
    const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
    const password = String(process.env.ADMIN_PASSWORD || '');
    if (!email || !password) return;
    try {
        const existing = await prisma.user.findUnique({ where: { email } });
        if (existing) return;
        if (password.length < 8) {
            console.error('ADMIN_PASSWORD must be at least 8 characters');
            return;
        }
        const role = process.env.ADMIN_ROLE || 'admin,store_owner';
        const user = await prisma.user.create({
            data: {
                email,
                name: process.env.ADMIN_NAME || 'مدير المنصة',
                passwordHash: hashPasswordSync(password),
                role
            }
        });
        if (role.split(',').map(part => part.trim()).includes('store_owner')) {
            const storeName = process.env.ADMIN_STORE_NAME || 'متجر الإدارة';
            await prisma.store.create({
                data: { name: storeName, slug: await makeUniqueSlug(storeName), ownerId: user.id }
            });
        }
        console.log(`✅ Created initial admin account: ${email}`);
    } catch (err) {
        console.error('ensureAdminUser failed:', err && err.message ? err.message : err);
    }
}

(async () => {
    try {
        await prisma.$connect();
        dbReady = true;
        console.log('✅ Prisma connected to DB');
        await ensureAdminUser();
    } catch (err) {
        dbReady = false;
        console.error('❌ Prisma failed to connect to DB:', err && err.message ? err.message : err);
    }
})();

// --- Ensure uploads directory exists ---
const uploadsDir = path.join(__dirname, 'public', 'uploads');
try { fs.mkdirSync(uploadsDir, { recursive: true }); } catch (e) { }

// --- Multer setup for image uploads ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const name = path.basename(file.originalname, ext).replace(/[^a-z0-9-_]/gi, '_');
        const filename = `${Date.now()}-${name}${ext}`;
        cb(null, filename);
    }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB

// --- Auth routes ---
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body || {};
        if (!email || !password) return res.status(400).json({ error: 'email and password required' });
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        if (!verifyPassword(password, user.passwordHash)) return res.status(401).json({ error: 'Invalid credentials' });
        const payload = { userId: user.id, role: user.role };
        const secret = process.env.JWT_SECRET;
        if (!secret) return res.status(500).json({ error: 'Server misconfiguration: JWT_SECRET missing' });
        const token = jwt.sign(payload, secret, { expiresIn: process.env.JWT_EXPIRES_IN || '1h' });
        const { passwordHash, ...safe } = user;
        res.json({ token, user: safe });
    } catch (err) {
        console.error('POST /api/auth/login error', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.get('/api/auth/me', requireAuth(), async (req, res) => {
    try {
        const userId = req.user && req.user.id;
        if (!userId) return res.status(401).json({ error: 'Unauthorized' });
        const user = await prisma.user.findUnique({
            where: { id: Number(userId) },
            include: { store: true }
        });
        if (!user) return res.status(404).json({ error: 'User not found' });
        const { passwordHash, ...safe } = user;
        res.json({ user: safe });
    } catch (err) {
        console.error('GET /api/auth/me error', err);
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

app.post('/api/auth/register-seller', async (req, res) => {
    try {
        const { email, password, name, storeName, themeColor, accentColor, logoUrl, description } = req.body || {};
        if (!email || !password || !storeName) return res.status(400).json({ error: 'email, password and storeName are required' });
        const existing = await prisma.user.findUnique({ where: { email } });
        if (existing) return res.status(409).json({ error: 'Email already registered' });
        const slug = await makeUniqueSlug(storeName);
        const passwordHash = hashPasswordSync(password);
        const created = await prisma.user.create({
            data: {
                email,
                passwordHash,
                name,
                role: 'store_owner',
                store: {
                    create: {
                        name: storeName,
                        slug,
                        themeColor: themeColor || undefined,
                        accentColor: accentColor || undefined,
                        logoUrl: logoUrl || undefined,
                        description: description || undefined
                    }
                }
            },
            include: { store: true }
        });
        const { passwordHash: _ph, ...safeUser } = created;
        res.status(201).json({ user: safeUser, store: created.store });
    } catch (err) {
        console.error('register-seller error', err);
        res.status(500).json({ error: 'Failed to register seller' });
    }
});

// --- Utility: make unique slug for store ---
async function makeUniqueSlug(baseName) {
    const raw = String(baseName || '').toLowerCase().trim();
    const base = raw
        .replace(/[\s_]+/g, '-')
        .replace(/[^a-z0-9-]/g, '')
        .replace(/-+/g, '-')
        .replace(/^-+|-+$/g, '') || `store-${Date.now()}`;
    let slug = base;
    let suffix = 0;
    while (true) {
        const exists = await prisma.store.findUnique({ where: { slug } });
        if (!exists) return slug;
        suffix += 1;
        slug = `${base}-${suffix}`;
        if (suffix > 50) {
            slug = `${base}-${crypto.randomBytes(4).toString('hex')}`;
            return slug;
        }
    }
}

// --- Image upload endpoint (protected) ---
app.post('/api/upload', requireAuth(['store_owner']), upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const webPath = `/uploads/${req.file.filename}`;
        res.json({ imageUrl: webPath, filename: req.file.filename });
    } catch (err) {
        console.error('POST /api/upload error', err);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// --- Admin Product CRUD (protected) ---
app.get('/api/admin/products', requireAuth(['store_owner']), async (req, res) => {
    try {
        const ownerId = req.user.id;
        const store = await prisma.store.findUnique({ where: { ownerId } });
        if (!store) return res.status(404).json({ error: 'Store not found' });
        const products = await prisma.product.findMany({ where: { storeId: store.id }, orderBy: { id: 'desc' } });
        res.json(products);
    } catch (err) {
        console.error('GET /api/admin/products error', err);
        res.status(500).json({ error: 'Failed to fetch admin products' });
    }
});

app.post('/api/admin/products', requireAuth(['store_owner']), async (req, res) => {
    try {
        const ownerId = req.user.id;
        const store = await prisma.store.findUnique({ where: { ownerId } });
        if (!store) return res.status(404).json({ error: 'Store not found' });
        const { name, description, price, imageUrl } = req.body || {};
        if (!name) return res.status(400).json({ error: 'Product name required' });
        const created = await prisma.product.create({
            data: {
                name,
                description: description || '',
                price: Number(price) || 0,
                imageUrl: imageUrl || null,
                store: { connect: { id: store.id } }
            }
        });
        res.status(201).json(created);
    } catch (err) {
        console.error('POST /api/admin/products error', err);
        res.status(500).json({ error: 'Failed to create product' });
    }
});

app.put('/api/admin/products/:id', requireAuth(['store_owner']), async (req, res) => {
    try {
        const ownerId = req.user.id;
        const store = await prisma.store.findUnique({ where: { ownerId } });
        if (!store) return res.status(404).json({ error: 'Store not found' });
        const prodId = Number(req.params.id);
        const product = await prisma.product.findUnique({ where: { id: prodId } });
        if (!product || product.storeId !== store.id) return res.status(404).json({ error: 'Product not found or not owned' });
        const { name, description, price, imageUrl } = req.body || {};
        const data = {};
        if (typeof name === 'string') data.name = name;
        if (typeof description === 'string') data.description = description;
        if (price !== undefined) data.price = Number(price) || 0;
        if (typeof imageUrl === 'string') data.imageUrl = imageUrl;
        const updated = await prisma.product.update({ where: { id: prodId }, data });
        res.json(updated);
    } catch (err) {
        console.error('PUT /api/admin/products/:id error', err);
        res.status(500).json({ error: 'Failed to update product' });
    }
});

app.delete('/api/admin/products/:id', requireAuth(['store_owner']), async (req, res) => {
    try {
        const ownerId = req.user.id;
        const store = await prisma.store.findUnique({ where: { ownerId } });
        if (!store) return res.status(404).json({ error: 'Store not found' });
        const prodId = Number(req.params.id);
        const product = await prisma.product.findUnique({ where: { id: prodId } });
        if (!product || product.storeId !== store.id) return res.status(404).json({ error: 'Product not found or not owned' });
        await prisma.product.delete({ where: { id: prodId } });
        res.json({ ok: true });
    } catch (err) {
        console.error('DELETE /api/admin/products/:id error', err);
        res.status(500).json({ error: 'Failed to delete product' });
    }
});

// --- Store settings (protected) ---
app.put('/api/store/settings', requireAuth(['store_owner']), async (req, res) => {
    try {
        const store = await prisma.store.findUnique({ where: { ownerId: req.user.id } });
        if (!store) return res.status(404).json({ error: 'Store not found' });
        const { name, themeColor, accentColor, logoUrl, description } = req.body || {};
        const data = {};
        if (typeof name === 'string' && name.trim()) data.name = name.trim();
        if (typeof themeColor === 'string') data.themeColor = themeColor || null;
        if (typeof accentColor === 'string') data.accentColor = accentColor || null;
        if (typeof logoUrl === 'string') data.logoUrl = logoUrl || null;
        if (typeof description === 'string') data.description = description;
        const updated = await prisma.store.update({ where: { id: store.id }, data });
        res.json(updated);
    } catch (err) {
        console.error('PUT /api/store/settings error', err);
        res.status(500).json({ error: 'Failed to update store settings' });
    }
});

// --- Orders Endpoints (protected) ---

// إنشاء طلب جديد (أي مستخدم مسجّل يمكنه الشراء)
app.post('/api/orders', requireAuth(), async (req, res) => {
    try {
        const buyerId = req.user.id;
        const { storeId, items } = req.body || {};
        if (!storeId || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: 'storeId and items are required' });
        }
        // تحقق من وجود المتجر
        const store = await prisma.store.findUnique({ where: { id: Number(storeId) } });
        if (!store) return res.status(404).json({ error: 'Store not found' });
        if (store.status === 'suspended') return res.status(403).json({ error: 'هذا المتجر موقوف حالياً' });

        // تحقق من المنتجات والكميات
        let total = 0;
        const orderItems = [];
        for (const item of items) {
            const product = await prisma.product.findUnique({ where: { id: Number(item.productId) } });
            if (!product || product.storeId !== store.id) {
                return res.status(400).json({ error: `Invalid product: ${item.productId}` });
            }
            const quantity = Math.max(1, Number(item.quantity) || 1);
            const price = Number(item.price) || product.price;
            total += price * quantity;
            orderItems.push({
                productId: product.id,
                quantity,
                price
            });
        }

        // إنشاء الطلب والعناصر
        const created = await prisma.order.create({
            data: {
                buyerId,
                storeId: store.id,
                status: 'pending',
                total,
                items: {
                    create: orderItems
                }
            },
            include: { items: true }
        });

        res.status(201).json(created);
    } catch (err) {
        console.error('POST /api/orders error', err);
        res.status(500).json({ error: 'Failed to create order' });
    }
});

// عرض الطلبات (المشتري يرى طلباته، البائع يرى الطلبات على متجره)
app.get('/api/orders', requireAuth(), async (req, res) => {
    try {
        const user = req.user;
        const roles = String(user.role || '').split(',').map(role => role.trim());
        let orders = [];
        if (roles.includes('buyer')) {
            orders = await prisma.order.findMany({
                where: { buyerId: user.id },
                include: { items: { include: { product: true } }, store: true }
            });
        } else if (roles.includes('store_owner')) {
            const store = await prisma.store.findUnique({ where: { ownerId: user.id } });
            if (!store) return res.status(404).json({ error: 'Store not found' });
            orders = await prisma.order.findMany({
                where: { storeId: store.id },
                include: { items: { include: { product: true } }, buyer: true }
            });
        } else {
            return res.status(403).json({ error: 'Forbidden' });
        }
        res.json(orders);
    } catch (err) {
        console.error('GET /api/orders error', err);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

// --- باقي Endpoints المتجر والمنتجات العامة ---
app.get('/api/stores/:slug', async (req, res) => {
    try {
        const slug = req.params.slug;
        if (!slug) return res.status(400).json({ error: 'Missing store slug' });
        const store = await prisma.store.findUnique({
            where: { slug },
            include: {
                products: { orderBy: { id: 'desc' } },
                owner: { select: { id: true, email: true, name: true } }
            }
        });
        if (!store) return res.status(404).json({ error: 'Store not found' });
        const products = (store.products || []).map(p => ({
            id: p.id,
            name: p.name,
            description: p.description,
            price: p.price,
            imageUrl: p.imageUrl
        }));
        const out = {
            id: store.id,
            name: store.name,
            slug: store.slug,
            themeColor: store.themeColor || '#54733b',
            accentColor: store.accentColor || '#dfeedd',
            logoUrl: store.logoUrl || '',
            description: store.description || '',
            owner: store.owner ? { id: store.owner.id, name: store.owner.name, email: store.owner.email } : null,
            products
        };
        res.json(out);
    } catch (err) {
        console.error('GET /api/stores/:slug error', err);
        res.status(500).json({ error: 'Failed to fetch store' });
    }
});

app.get('/api/products', async (req, res) => {
    try {
        const rows = await prisma.product.findMany({
            where: { store: { status: 'active' } },
            orderBy: { id: 'desc' },
            include: { store: true }
        });
        const out = rows.map(p => ({
            id: p.id,
            name: p.name,
            description: p.description,
            price: p.price,
            imageUrl: p.imageUrl,
            storeId: p.storeId,
            storeName: p.store?.name || '',
            store: {
                id: p.store?.id,
                name: p.store?.name || '',
                themeColor: p.store?.themeColor || '#54733b',
                accentColor: p.store?.accentColor || '#dfeedd'
            }
        }));
        res.json(out);
    } catch (err) {
        console.error('GET /api/products error', err);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

// --- Admin dashboard (admin only) ---
app.get('/api/admin/overview', requireAuth(['admin']), async (req, res) => {
    try {
        const [users, stores, products, orders, pendingOrders, suspendedStores, paidStores] = await Promise.all([
            prisma.user.count(),
            prisma.store.count(),
            prisma.product.count(),
            prisma.order.count(),
            prisma.order.count({ where: { status: 'pending' } }),
            prisma.store.count({ where: { status: 'suspended' } }),
            prisma.store.count({ where: { subscriptionPlan: { not: 'free' }, status: 'active' } })
        ]);
        const revenueAgg = await prisma.order.aggregate({
            _sum: { total: true },
            where: { status: { not: 'cancelled' } }
        });

        const days = [];
        const byDate = new Map();
        const start = new Date();
        start.setHours(0, 0, 0, 0);
        start.setDate(start.getDate() - 6);
        for (let i = 0; i < 7; i++) {
            const d = new Date(start);
            d.setDate(start.getDate() + i);
            const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
            const row = { date: key, total: 0 };
            days.push(row);
            byDate.set(key, row);
        }
        const recentOrders = await prisma.order.findMany({
            where: { createdAt: { gte: start }, status: { not: 'cancelled' } },
            select: { createdAt: true, total: true }
        });
        for (const order of recentOrders) {
            const created = new Date(order.createdAt);
            const key = `${created.getFullYear()}-${String(created.getMonth() + 1).padStart(2, '0')}-${String(created.getDate()).padStart(2, '0')}`;
            const row = byDate.get(key);
            if (row) row.total += Number(order.total) || 0;
        }

        res.json({
            users,
            stores,
            activeStores: stores - suspendedStores,
            suspendedStores,
            paidStores,
            products,
            orders,
            pendingOrders,
            revenue: Number(revenueAgg._sum.total) || 0,
            revenue7d: days
        });
    } catch (err) {
        console.error('GET /api/admin/overview error', err);
        res.status(500).json({ error: 'Failed to load overview' });
    }
});

app.get('/api/admin/stores', requireAuth(['admin']), async (req, res) => {
    try {
        const stores = await prisma.store.findMany({
            orderBy: { createdAt: 'desc' },
            include: {
                owner: { select: { id: true, name: true, email: true } },
                _count: { select: { products: true, orders: true } },
                orders: { select: { total: true, status: true } }
            }
        });
        const out = stores.map(store => ({
            id: store.id,
            name: store.name,
            slug: store.slug,
            themeColor: store.themeColor,
            logoUrl: store.logoUrl,
            status: store.status,
            subscriptionPlan: store.subscriptionPlan,
            subscriptionEndsAt: store.subscriptionEndsAt,
            createdAt: store.createdAt,
            owner: store.owner ? { id: store.owner.id, name: store.owner.name, email: store.owner.email } : null,
            products: store._count.products,
            orders: store._count.orders,
            revenue: store.orders
                .filter(order => order.status !== 'cancelled')
                .reduce((sum, order) => sum + (Number(order.total) || 0), 0)
        }));
        res.json(out);
    } catch (err) {
        console.error('GET /api/admin/stores error', err);
        res.status(500).json({ error: 'Failed to load stores' });
    }
});

app.patch('/api/admin/stores/:id', requireAuth(['admin']), async (req, res) => {
    try {
        const storeId = Number(req.params.id);
        const store = await prisma.store.findUnique({ where: { id: storeId } });
        if (!store) return res.status(404).json({ error: 'Store not found' });

        const { status, subscriptionPlan, extendDays } = req.body || {};
        const data = {};

        if (status !== undefined) {
            if (!['active', 'suspended'].includes(status)) {
                return res.status(400).json({ error: 'Invalid status' });
            }
            data.status = status;
        }

        if (subscriptionPlan !== undefined) {
            if (!['free', 'bronze', 'silver', 'gold'].includes(subscriptionPlan)) {
                return res.status(400).json({ error: 'Invalid subscription plan' });
            }
            data.subscriptionPlan = subscriptionPlan;
            if (subscriptionPlan === 'free') {
                data.subscriptionEndsAt = null;
            } else {
                const base = new Date();
                base.setDate(base.getDate() + 30);
                data.subscriptionEndsAt = base;
            }
        }

        if (extendDays !== undefined) {
            const days = Math.min(365, Math.max(1, Math.floor(Number(extendDays) || 0)));
            if (!Number.isFinite(days) || days < 1) {
                return res.status(400).json({ error: 'Invalid extendDays' });
            }
            const base = store.subscriptionEndsAt && store.subscriptionEndsAt > new Date()
                ? new Date(store.subscriptionEndsAt)
                : new Date();
            base.setDate(base.getDate() + days);
            data.subscriptionEndsAt = base;
        }

        if (Object.keys(data).length === 0) {
            return res.status(400).json({ error: 'Nothing to update' });
        }

        const updated = await prisma.store.update({ where: { id: storeId }, data });
        res.json({
            id: updated.id,
            status: updated.status,
            subscriptionPlan: updated.subscriptionPlan,
            subscriptionEndsAt: updated.subscriptionEndsAt
        });
    } catch (err) {
        console.error('PATCH /api/admin/stores/:id error', err);
        res.status(500).json({ error: 'Failed to update store' });
    }
});

app.get('/api/admin/users', requireAuth(['admin']), async (req, res) => {
    try {
        const users = await prisma.user.findMany({
            orderBy: { createdAt: 'desc' },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                createdAt: true,
                store: { select: { id: true, name: true, status: true, subscriptionPlan: true } },
                _count: { select: { orders: true } }
            }
        });
        res.json(users.map(user => ({
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            createdAt: user.createdAt,
            store: user.store,
            orders: user._count.orders
        })));
    } catch (err) {
        console.error('GET /api/admin/users error', err);
        res.status(500).json({ error: 'Failed to load users' });
    }
});

app.get('/api/admin/orders', requireAuth(['admin']), async (req, res) => {
    try {
        const orders = await prisma.order.findMany({
            orderBy: { id: 'desc' },
            take: 50,
            include: {
                buyer: { select: { name: true, email: true } },
                store: { select: { name: true } },
                items: { select: { quantity: true } }
            }
        });
        res.json(orders.map(order => ({
            id: order.id,
            total: order.total,
            status: order.status,
            createdAt: order.createdAt,
            buyer: order.buyer ? { name: order.buyer.name, email: order.buyer.email } : null,
            storeName: order.store ? order.store.name : '',
            itemsCount: order.items.reduce((sum, item) => sum + (Number(item.quantity) || 0), 0)
        })));
    } catch (err) {
        console.error('GET /api/admin/orders error', err);
        res.status(500).json({ error: 'Failed to load orders' });
    }
});

// --- Feedback (public submit, admin review) ---
app.post('/api/feedback', async (req, res) => {
    try {
        const { audience, rating, comment, suggestion } = req.body || {};
        const text = String(comment || '').trim();
        if (!text) return res.status(400).json({ error: 'اكتب رأيك أو مقترحك أولاً' });
        if (text.length > 1000) return res.status(400).json({ error: 'الرأي طويل جداً (الحد 1000 حرف)' });

        const normalizedAudience = audience === 'vendor' ? 'vendor' : 'buyer';
        const score = Math.min(5, Math.max(1, Math.round(Number(rating) || 5)));
        const suggestionText = String(suggestion || '').trim();
        const user = await currentUser(req);

        const feedback = await prisma.feedback.create({
            data: {
                audience: normalizedAudience,
                rating: score,
                comment: text,
                suggestion: suggestionText && suggestionText !== text ? suggestionText : null,
                userId: user ? user.id : null
            }
        });
        res.status(201).json({ id: feedback.id, message: 'تم استلام رأيك، شكراً لك' });
    } catch (err) {
        console.error('POST /api/feedback error', err);
        res.status(500).json({ error: 'تعذر حفظ الرأي' });
    }
});

app.get('/api/admin/feedback', requireAuth(['admin']), async (req, res) => {
    try {
        const items = await prisma.feedback.findMany({
            orderBy: { createdAt: 'desc' },
            take: 100,
            include: { user: { select: { id: true, name: true, email: true } } }
        });
        res.json({ items, unread: items.filter(item => !item.readAt).length });
    } catch (err) {
        console.error('GET /api/admin/feedback error', err);
        res.status(500).json({ error: 'Failed to load feedback' });
    }
});

app.patch('/api/admin/feedback/:id/read', requireAuth(['admin']), async (req, res) => {
    try {
        const feedbackId = Number(req.params.id);
        const existing = await prisma.feedback.findUnique({ where: { id: feedbackId } });
        if (!existing) return res.status(404).json({ error: 'Feedback not found' });
        const feedback = await prisma.feedback.update({
            where: { id: feedbackId },
            data: { readAt: existing.readAt || new Date() }
        });
        res.json(feedback);
    } catch (err) {
        console.error('PATCH /api/admin/feedback/:id/read error', err);
        res.status(500).json({ error: 'Failed to update feedback' });
    }
});

// --- Health and root ---
app.get('/health', (req, res) => res.json({ ok: true, dbReady }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// --- Error handler ---
app.use((err, req, res, next) => {
    console.error('Express error handler:', err);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
});

// --- Start server ---
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
// Endpoint لتعديل دور مستخدم (admin فقط)
app.put('/api/admin/users/:id/role', requireAuth(['admin']), async (req, res) => {
    try {
        const userId = Number(req.params.id);
        const { role } = req.body;
        if (!role) return res.status(400).json({ error: 'role is required' });
        const user = await prisma.user.update({
            where: { id: userId },
            data: { role }
        });
        res.json({ user });
    } catch (err) {
        console.error('PUT /api/admin/users/:id/role error', err);
        res.status(500).json({ error: 'Failed to update user role' });
    }
});