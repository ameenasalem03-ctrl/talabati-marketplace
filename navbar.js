(function () {
    'use strict';

    const TOKEN_KEY = 'saas_token';
    const USER_KEY = 'saas_user';
    const CART_KEY = 'cart';

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function currentPage() {
        const name = (location.pathname.split('/').pop() || '').toLowerCase();
        return name || 'index.html';
    }

    function cartCount() {
        try {
            const cart = JSON.parse(localStorage.getItem(CART_KEY) || '[]');
            if (!Array.isArray(cart)) return 0;
            return cart.reduce((sum, item) => sum + (Number(item.quantity) || 0), 0);
        } catch (e) {
            return 0;
        }
    }

    function readUser() {
        try {
            return JSON.parse(localStorage.getItem(USER_KEY) || 'null');
        } catch (e) {
            return null;
        }
    }

    function hasAdminRole(user) {
        return String((user && user.role) || '')
            .split(',')
            .map(function (role) { return role.trim(); })
            .includes('admin');
    }

    function injectStyles() {
        if (document.getElementById('site-navbar-styles')) return;
        const style = document.createElement('style');
        style.id = 'site-navbar-styles';
        style.textContent = `
            .site-navbar {
                position: sticky;
                top: 12px;
                z-index: 1030;
                background: rgba(255, 255, 255, 0.9);
                backdrop-filter: blur(14px);
                border: 1px solid rgba(84, 115, 59, 0.14);
                border-radius: 16px;
                box-shadow: 0 12px 30px rgba(31, 42, 36, 0.08);
                padding: 0.45rem 0.75rem;
                margin-bottom: 26px;
            }
            .site-brand {
                display: flex;
                align-items: center;
                gap: 0.6rem;
                font-weight: 800;
                color: #1f2a24;
                text-decoration: none;
            }
            .site-brand:hover { color: #54733b; }
            .site-brand-mark {
                width: 38px;
                height: 38px;
                border-radius: 12px;
                background: linear-gradient(135deg, #54733b, #7a9b5c);
                color: #fff;
                display: grid;
                place-items: center;
                font-weight: 800;
                font-size: 1.05rem;
                box-shadow: inset 0 -2px 0 rgba(0, 0, 0, 0.1);
            }
            .site-brand-text {
                display: flex;
                flex-direction: column;
                line-height: 1.05;
                font-size: 1.05rem;
            }
            .site-brand-text small {
                font-size: 0.62rem;
                color: #718078;
                font-weight: 600;
                letter-spacing: 0.08em;
            }
            .site-navbar .nav-link {
                color: #3f4c45;
                font-weight: 600;
                border-radius: 9px;
                padding: 0.45rem 0.8rem;
                display: flex;
                align-items: center;
                gap: 0.35rem;
            }
            .site-navbar .nav-link:hover { color: #54733b; background: #f0f5ec; }
            .site-navbar .nav-link.active { color: #3f5c2b; background: #e8f1e1; font-weight: 800; }
            .nav-cart-badge {
                min-width: 1.25rem;
                height: 1.25rem;
                padding: 0 0.35rem;
                border-radius: 999px;
                background: #54733b;
                color: #fff;
                font-size: 0.7rem;
                font-weight: 700;
                display: inline-grid;
                place-items: center;
            }
            .nav-cart-badge.is-empty { background: #c9d4c2; color: #3f4c45; }
            .nav-user {
                max-width: 170px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                color: #4d5a53;
                font-size: 0.85rem;
                font-weight: 600;
            }
            @media (max-width: 991.98px) {
                .site-navbar { top: 8px; }
                .site-navbar .navbar-collapse { padding-top: 0.6rem; }
            }
        `;
        document.head.appendChild(style);
    }

    function render() {
        injectStyles();
        const mount = document.getElementById('site-navbar');
        if (!mount) return;

        const page = currentPage();
        const loggedIn = !!localStorage.getItem(TOKEN_KEY);
        const user = loggedIn ? readUser() : null;
        const displayName = user ? (user.name || user.email || 'حسابي') : '';
        const count = cartCount();
        const active = (name) => (page === name ? ' active' : '');
        const badgeClass = count > 0 ? 'nav-cart-badge' : 'nav-cart-badge is-empty';

        const account = loggedIn
            ? `
                <span class="nav-user" title="${escapeHtml(displayName)}">مرحباً، ${escapeHtml(displayName)}</span>
                ${hasAdminRole(user) ? '<a class="btn btn-sm btn-outline-success" href="admin.html">لوحة المدير</a>' : ''}
                <a class="btn btn-sm btn-outline-success" href="dashboard.html">لوحتي</a>
                <button type="button" class="btn btn-sm btn-outline-danger" data-nav-logout>خروج</button>
            `
            : `
                <a class="btn btn-sm btn-outline-success" href="products.html?login=1">تسجيل الدخول</a>
                <a class="btn btn-sm btn-success" href="products.html?register=1">سجل كبائع</a>
            `;

        mount.innerHTML = `
            <nav class="navbar navbar-expand-lg site-navbar" aria-label="التنقل الرئيسي">
                <div class="container">
                    <a class="navbar-brand site-brand" href="index.html">
                        <span class="site-brand-mark">ط</span>
                        <span class="site-brand-text">طلباتي<small>Talabati</small></span>
                    </a>
                    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#siteNavMain"
                            aria-controls="siteNavMain" aria-expanded="false" aria-label="تبديل القائمة">
                        <span class="navbar-toggler-icon"></span>
                    </button>
                    <div class="collapse navbar-collapse" id="siteNavMain">
                        <ul class="navbar-nav me-auto mb-2 mb-lg-0 gap-lg-1">
                            <li class="nav-item"><a class="nav-link${active('index.html')}" href="index.html">الرئيسية</a></li>
                            <li class="nav-item"><a class="nav-link${active('products.html')}" href="products.html">المنتجات</a></li>
                            <li class="nav-item"><a class="nav-link${active('cart.html')}" href="cart.html">السلة<span id="nav-cart-count" class="${badgeClass}">${count}</span></a></li>
                            <li class="nav-item"><a class="nav-link${active('dashboard.html')}" href="dashboard.html">لوحة البائع</a></li>
                        </ul>
                        <div class="site-account d-flex flex-wrap align-items-center gap-2 mt-2 mt-lg-0">
                            ${account}
                        </div>
                    </div>
                </div>
            </nav>
        `;
    }

    function updateCartCount() {
        const el = document.getElementById('nav-cart-count');
        if (!el) return;
        const count = cartCount();
        el.textContent = count;
        el.classList.toggle('is-empty', count === 0);
    }

    window.renderSiteNavbar = render;
    window.updateNavCartCount = updateCartCount;

    document.addEventListener('click', function (event) {
        const logoutBtn = event.target.closest('[data-nav-logout]');
        if (!logoutBtn) return;
        event.preventDefault();
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
        window.location.href = 'index.html';
    });

    window.addEventListener('storage', function (event) {
        if (!event.key || event.key === CART_KEY) updateCartCount();
        if (!event.key || event.key === TOKEN_KEY || event.key === USER_KEY) render();
    });

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', render);
    } else {
        render();
    }
})();
