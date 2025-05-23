<?php
// One-File Security & Link Shortener System
// Save this as index.php

// ======= CONFIGURATION =======
define('ADMIN_USERNAME', 'admin');
define('ADMIN_PASSWORD', 'securepassword');
define('TARGET_URL', 'https://yourmainwebsite.com');
define('FALLBACK_URL', 'https://yourfallbackwebsite.com');
define('DB_FILE', 'data.db');
define('MAX_LOG_DAYS', 30);
define('BLOCKED_COUNTRIES', ['CN', 'RU', 'IR', 'KP']); // ISO country codes to block
define('ALLOW_BYPASS', true); // Enable checkbox verification
// =============================

session_start();

// Generate CSRF token if not already set
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

date_default_timezone_set('UTC');

// Initialize SQLite database
function initDB() {
    if (!file_exists(DB_FILE)) {
        $db = new SQLite3(DB_FILE);
        $db->exec("CREATE TABLE blocked_ips (ip TEXT PRIMARY KEY, reason TEXT, timestamp INTEGER)");
        $db->exec("CREATE TABLE access_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, user_agent TEXT, country TEXT, is_bot INTEGER, is_vpn INTEGER, timestamp INTEGER, path TEXT, status TEXT)");
        $db->exec("CREATE TABLE short_links (id INTEGER PRIMARY KEY AUTOINCREMENT, short_code TEXT UNIQUE, original_url TEXT, created_at INTEGER, hits INTEGER DEFAULT 0)");
        $db->exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)");
        $db->exec("INSERT INTO settings (key, value) VALUES ('maintenance_mode', '0')");
        $db->close();
    }
}

initDB();
$db = new SQLite3(DB_FILE);

// Get client IP
function getClientIP() {
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'] as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = trim(explode(',', $_SERVER[$key])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

// Get country from IP (using free IPAPI)
function getCountry($ip) {
    if ($ip === '127.0.0.1' || $ip === '::1') return 'LOCAL';
    
    // Check cache first
    $cacheFile = "ip_cache/{$ip}.json";
    if (file_exists($cacheFile) && time() - filemtime($cacheFile) < 86400) {
        $data = json_decode(file_get_contents($cacheFile), true);
        return $data['country'] ?? 'UNKNOWN';
    }
    
    // Free tier API (1000 requests/day)
    $response = @file_get_contents("http://ip-api.com/json/{$ip}?fields=countryCode");
    if ($response) {
        $data = json_decode($response, true);
        if (!file_exists('ip_cache')) mkdir('ip_cache');
        file_put_contents($cacheFile, $response);
        return $data['countryCode'] ?? 'UNKNOWN';
    }
    
    return 'UNKNOWN';
}

// Check if user agent is a bot
function isBot($userAgent) {
    if (empty($userAgent)) return true;
    
    $bots = ['bot', 'crawl', 'spider', 'slurp', 'search', 'archiver', 'facebook', 'telegram', 'whatsapp'];
    foreach ($bots as $bot) {
        if (stripos($userAgent, $bot)) return true;
    }
    return false;
}

// Simple VPN/proxy detection (using free IPAPI)
function isVPN($ip) {
    if ($ip === '127.0.0.1' || $ip === '::1') return false;
    
    $cacheFile = "ip_cache/{$ip}_vpn.json";
    if (file_exists($cacheFile)) {
        $data = json_decode(file_get_contents($cacheFile), true);
        return $data['proxy'] ?? false;
    }
    
    $response = @file_get_contents("http://ip-api.com/json/{$ip}?fields=proxy");
    if ($response) {
        $data = json_decode($response, true);
        file_put_contents($cacheFile, $response);
        return $data['proxy'] ?? false;
    }
    
    return false;
}

// Check if IP is blocked
function isBlocked($ip) {
    global $db;
    $stmt = $db->prepare("SELECT 1 FROM blocked_ips WHERE ip = :ip");
    $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $result = $stmt->execute();
    return $result->fetchArray() !== false;
}

// Block an IP
function blockIP($ip, $reason = 'Manual block') {
    global $db;
    $stmt = $db->prepare("INSERT OR REPLACE INTO blocked_ips (ip, reason, timestamp) VALUES (:ip, :reason, :time)");
    $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $stmt->bindValue(':reason', $reason, SQLITE3_TEXT);
    $stmt->bindValue(':time', time(), SQLITE3_INTEGER);
    $stmt->execute();
}

// Unblock an IP
function unblockIP($ip) {
    global $db;
    $stmt = $db->prepare("DELETE FROM blocked_ips WHERE ip = :ip");
    $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $stmt->execute();
}

// Log access attempt
function logAccess($ip, $userAgent, $country, $isBot, $isVPN, $path, $status) {
    global $db;
    $stmt = $db->prepare("INSERT INTO access_logs (ip, user_agent, country, is_bot, is_vpn, timestamp, path, status) VALUES (:ip, :ua, :country, :bot, :vpn, :time, :path, :status)");
    $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
    $stmt->bindValue(':ua', $userAgent, SQLITE3_TEXT);
    $stmt->bindValue(':country', $country, SQLITE3_TEXT);
    $stmt->bindValue(':bot', $isBot ? 1 : 0, SQLITE3_INTEGER);
    $stmt->bindValue(':vpn', $isVPN ? 1 : 0, SQLITE3_INTEGER);
    $stmt->bindValue(':time', time(), SQLITE3_INTEGER);
    $stmt->bindValue(':path', $path, SQLITE3_TEXT);
    $stmt->bindValue(':status', $status, SQLITE3_TEXT);
    $stmt->execute();
}

// Create short link
function createShortLink($url) {
    global $db;
    $code = substr(md5(uniqid()), 0, 6);
    $stmt = $db->prepare("INSERT INTO short_links (short_code, original_url, created_at) VALUES (:code, :url, :time)");
    $stmt->bindValue(':code', $code, SQLITE3_TEXT);
    $stmt->bindValue(':url', $url, SQLITE3_TEXT);
    $stmt->bindValue(':time', time(), SQLITE3_INTEGER);
    $stmt->execute();
    return $code;
}

// Get original URL from short code
function getShortLink($code) {
    global $db;
    $stmt = $db->prepare("SELECT original_url FROM short_links WHERE short_code = :code");
    $stmt->bindValue(':code', $code, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return $row ? $row['original_url'] : null;
}

// Increment short link hit counter
function incrementShortLinkHits($code) {
    global $db;
    $stmt = $db->prepare("UPDATE short_links SET hits = hits + 1 WHERE short_code = :code");
    $stmt->bindValue(':code', $code, SQLITE3_TEXT);
    $stmt->execute();
}

// Clean old logs
function cleanOldLogs() {
    global $db;
    $cutoff = time() - (MAX_LOG_DAYS * 86400);
    $db->exec("DELETE FROM access_logs WHERE timestamp < $cutoff");
}

// Dashboard authentication
function isAuthenticated() {
    return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
}

function authenticate($username, $password) {
    if ($username === ADMIN_USERNAME && $password === ADMIN_PASSWORD) {
        $_SESSION['authenticated'] = true;
        return true;
    }
    return false;
}

function logout() {
    session_unset();
    session_destroy();
}

// Handle form submissions

// CSRF Protection
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        // Log CSRF attempt or handle error appropriately
        // For now, we'll just redirect or show an error
        // logAccess(getClientIP(), $_SERVER['HTTP_USER_AGENT'] ?? '', getCountry(getClientIP()), isBot($_SERVER['HTTP_USER_AGENT'] ?? ''), isVPN(getClientIP()), $_SERVER['REQUEST_URI'], 'CSRF_ATTEMPT');
        header('HTTP/1.1 403 Forbidden');
        exit('CSRF token validation failed.');
    }
    // Regenerate token after successful validation to prevent double submission
    unset($_SESSION['csrf_token']);
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));


    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'login':
                if (authenticate($_POST['username'] ?? '', $_POST['password'] ?? '')) {
                    header("Location: ?page=dashboard");
                    exit;
                } else {
                    $loginError = "Invalid credentials";
                }
                break;
                
            case 'block_ip':
                if (isAuthenticated()) {
                    blockIP($_POST['ip'], $_POST['reason'] ?? 'Manual block');
                }
                break;
                
            case 'unblock_ip':
                if (isAuthenticated()) {
                    unblockIP($_POST['ip']);
                }
                break;
                
            case 'create_shortlink':
                if (isAuthenticated() && !empty($_POST['url'])) {
                    $code = createShortLink($_POST['url']);
                    $shortLinkCreated = "Short link created: {$_SERVER['HTTP_HOST']}/$code";
                }
                break;
                
            case 'toggle_maintenance':
                if (isAuthenticated()) {
                    $newValue = $_POST['maintenance_mode'] === '1' ? '1' : '0';
                    $db->exec("UPDATE settings SET value = '$newValue' WHERE key = 'maintenance_mode'");
                }
                break;
                
            case 'verify_human':
                if (ALLOW_BYPASS && isset($_POST['human_verified'])) {
                    setcookie('human_verified', '1', time() + 86400, '/');
                    header("Location: " . ($_POST['original_url'] ?? TARGET_URL));
                    exit;
                }
                break;
        }
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    logout();
    header("Location: ?");
    exit;
}

// Handle short links
$requestPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$shortCode = ltrim($requestPath, '/');
if (strlen($shortCode) === 6 && !isset($_GET['page'])) {
    $originalUrl = getShortLink($shortCode);
    if ($originalUrl) {
        incrementShortLinkHits($shortCode);
        header("Location: $originalUrl", true, 301);
        exit;
    }
}

// Main security logic
$clientIP = getClientIP();
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$isBot = isBot($userAgent);
$country = getCountry($clientIP);
$isVPN = isVPN($clientIP);
$isBlocked = isBlocked($clientIP);
$countryBlocked = in_array($country, BLOCKED_COUNTRIES);
$maintenanceMode = $db->querySingle("SELECT value FROM settings WHERE key = 'maintenance_mode'") === '1';

// Check if human verification is needed
$needsVerification = (ALLOW_BYPASS && !isset($_COOKIE['human_verified']) && ($isBot || $isVPN || $countryBlocked));

// Log the access attempt
$status = 'ALLOWED';
if ($isBlocked) $status = 'BLOCKED_IP';
if ($countryBlocked) $status = 'BLOCKED_COUNTRY';
if ($isBot) $status = 'BOT_DETECTED';
if ($isVPN) $status = 'VPN_DETECTED';
if ($maintenanceMode) $status = 'MAINTENANCE';
if ($needsVerification) $status = 'NEEDS_VERIFICATION';

logAccess($clientIP, $userAgent, $country, $isBot, $isVPN, $requestPath, $status);

// Clean old logs periodically (1% chance on each request)
if (mt_rand(1, 100) === 1) {
    cleanOldLogs();
}

// Dashboard pages
$page = $_GET['page'] ?? '';
if (isAuthenticated()) {
    switch ($page) {
        case 'dashboard':
            $blockedIPs = [];
            $result = $db->query("SELECT ip, reason, timestamp FROM blocked_ips ORDER BY timestamp DESC");
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $blockedIPs[] = $row;
            }
            
            $accessLogs = [];
            $result = $db->query("SELECT ip, user_agent, country, is_bot, is_vpn, timestamp, path, status FROM access_logs ORDER BY timestamp DESC LIMIT 100");
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $accessLogs[] = $row;
            }
            
            $shortLinks = [];
            $result = $db->query("SELECT short_code, original_url, created_at, hits FROM short_links ORDER BY created_at DESC");
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $shortLinks[] = $row;
            }
            
            $stats = [
                'total_blocked' => $db->querySingle("SELECT COUNT(*) FROM blocked_ips"),
                'total_bots' => $db->querySingle("SELECT COUNT(*) FROM access_logs WHERE is_bot = 1"),
                'total_vpns' => $db->querySingle("SELECT COUNT(*) FROM access_logs WHERE is_vpn = 1"),
                'total_shortlinks' => $db->querySingle("SELECT COUNT(*) FROM short_links"),
                'top_countries' => []
            ];
            
            $result = $db->query("SELECT country, COUNT(*) as count FROM access_logs GROUP BY country ORDER BY count DESC LIMIT 5");
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $stats['top_countries'][] = $row;
            }
            break;
    }
}

// Show verification page if needed
if ($needsVerification && !isAuthenticated() && $page !== 'dashboard') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verification Required</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .verification-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; text-align: center; }
            h1 { font-size: 1.5rem; margin-bottom: 1.5rem; }
            .checkbox-container { margin: 1.5rem 0; text-align: left; }
            button { background: #4CAF50; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 4px; cursor: pointer; font-size: 1rem; }
            button:hover { background: #45a049; }
            .reason { color: #666; margin-bottom: 1rem; }
        </style>
    </head>
    <body>
        <div class="verification-box">
            <h1>Please verify you are human</h1>
            <?php if ($isBot): ?>
                <div class="reason">Automated traffic detected</div>
            <?php elseif ($isVPN): ?>
                <div class="reason">VPN/Proxy detected</div>
            <?php elseif ($countryBlocked): ?>
                <div class="reason">Access from your country is restricted</div>
            <?php endif; ?>
            
            <form method="post">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <input type="hidden" name="action" value="verify_human">
                <input type="hidden" name="original_url" value="<?= htmlspecialchars(TARGET_URL) ?>">
                <div class="checkbox-container">
                    <label>
                        <input type="checkbox" name="human_verified" required> I'm not a robot
                    </label>
                </div>
                <button type="submit">Continue</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Redirect blocked requests
if ((!ALLOW_BYPASS || !isset($_COOKIE['human_verified'])) && ($isBlocked || $countryBlocked || $maintenanceMode) && !isAuthenticated()) {
    header("Location: " . FALLBACK_URL, true, 302);
    exit;
}

// Show dashboard or redirect to target
if (isAuthenticated() && ($page === 'dashboard' || empty($page))) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.datatables.net/1.11.5/css/dataTables.bootstrap5.min.css" rel="stylesheet">
        <style>
            .sidebar { position: fixed; top: 0; left: 0; bottom: 0; width: 250px; background: #343a40; color: white; padding: 20px; }
            .main-content { margin-left: 250px; padding: 20px; }
            .stat-card { border-radius: 8px; padding: 15px; margin-bottom: 20px; color: white; }
            .stat-card.bg-primary { background: #007bff; }
            .stat-card.bg-danger { background: #dc3545; }
            .stat-card.bg-warning { background: #ffc107; color: #212529; }
            .stat-card.bg-success { background: #28a745; }
            .nav-link { color: rgba(255,255,255,.5); }
            .nav-link:hover, .nav-link.active { color: white; }
        </style>
    </head>
    <body>
        <div class="sidebar">
            <h4 class="mb-4">Security Dashboard</h4>
            <ul class="nav flex-column">
                <li class="nav-item">
                    <a class="nav-link <?= $page === 'dashboard' || empty($page) ? 'active' : '' ?>" href="?page=dashboard">Dashboard</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="?page=blocked_ips">Blocked IPs</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="?page=access_logs">Access Logs</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="?page=short_links">Short Links</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="?page=settings">Settings</a>
                </li>
                <li class="nav-item mt-4">
                    <a class="nav-link text-danger" href="?logout">Logout</a>
                </li>
            </ul>
        </div>
        
        <div class="main-content">
            <?php if ($page === 'dashboard' || empty($page)): ?>
                <h2 class="mb-4">Dashboard Overview</h2>
                
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="stat-card bg-primary">
                            <h5>Blocked IPs</h5>
                            <h3><?= $stats['total_blocked'] ?></h3>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card bg-danger">
                            <h5>Bot Detections</h5>
                            <h3><?= $stats['total_bots'] ?></h3>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card bg-warning">
                            <h5>VPN Detections</h5>
                            <h3><?= $stats['total_vpns'] ?></h3>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card bg-success">
                            <h5>Short Links</h5>
                            <h3><?= $stats['total_shortlinks'] ?></h3>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-header">
                                <h5>Recent Access Logs</h5>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-striped">
                                        <thead>
                                            <tr>
                                                <th>IP</th>
                                                <th>Country</th>
                                                <th>Status</th>
                                                <th>Time</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach (array_slice($accessLogs, 0, 5) as $log): ?>
                                                <tr>
                                                    <td><?= htmlspecialchars($log['ip']) ?></td>
                                                    <td><?= htmlspecialchars($log['country']) ?></td>
                                                    <td><?= htmlspecialchars($log['status']) ?></td>
                                                    <td><?= date('Y-m-d H:i', $log['timestamp']) ?></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-header">
                                <h5>Top Countries</h5>
                            </div>
                            <div class="card-body">
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th>Country</th>
                                            <th>Visits</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($stats['top_countries'] as $country): ?>
                                            <tr>
                                                <td><?= htmlspecialchars($country['country']) ?></td>
                                                <td><?= $country['count'] ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h5>Create Short Link</h5>
                    </div>
                    <div class="card-body">
                        <form method="post">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                            <input type="hidden" name="action" value="create_shortlink">
                            <div class="input-group mb-3">
                                <input type="url" name="url" class="form-control" placeholder="Enter URL to shorten" required>
                                <button class="btn btn-primary" type="submit">Create</button>
                            </div>
                        </form>
                        <?php if (isset($shortLinkCreated)): ?>
                            <div class="alert alert-success"><?= htmlspecialchars($shortLinkCreated) ?></div>
                        <?php endif; ?>
                    </div>
                </div>
                
            <?php elseif ($page === 'blocked_ips'): ?>
                <h2 class="mb-4">Blocked IPs</h2>
                
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Block New IP</h5>
                    </div>
                    <div class="card-body">
                        <form method="post">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                            <input type="hidden" name="action" value="block_ip">
                            <div class="row g-3">
                                <div class="col-md-6">
                                    <label for="ip" class="form-label">IP Address</label>
                                    <input type="text" name="ip" class="form-control" placeholder="e.g., 192.168.1.1" required>
                                </div>
                                <div class="col-md-6">
                                    <label for="reason" class="form-label">Reason</label>
                                    <input type="text" name="reason" class="form-control" placeholder="Optional reason">
                                </div>
                                <div class="col-12">
                                    <button type="submit" class="btn btn-danger">Block IP</button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h5>Currently Blocked IPs</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table id="blockedIpsTable" class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Reason</th>
                                        <th>Blocked At</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($blockedIPs as $ip): ?>
                                        <tr>
                                            <td><?= htmlspecialchars($ip['ip']) ?></td>
                                            <td><?= htmlspecialchars($ip['reason']) ?></td>
                                            <td><?= date('Y-m-d H:i', $ip['timestamp']) ?></td>
                                            <td>
                                                <form method="post" style="display: inline;">
                                                    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                                                    <input type="hidden" name="action" value="unblock_ip">
                                                    <input type="hidden" name="ip" value="<?= htmlspecialchars($ip['ip']) ?>">
                                                    <button type="submit" class="btn btn-sm btn-success">Unblock</button>
                                                </form>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
            <?php elseif ($page === 'access_logs'): ?>
                <h2 class="mb-4">Access Logs</h2>
                
                <div class="card">
                    <div class="card-body">
                        <div class="table-responsive">
                            <table id="accessLogsTable" class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>IP</th>
                                        <th>User Agent</th>
                                        <th>Country</th>
                                        <th>Bot</th>
                                        <th>VPN</th>
                                        <th>Path</th>
                                        <th>Status</th>
                                        <th>Time</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($accessLogs as $log): ?>
                                        <tr>
                                            <td><?= htmlspecialchars($log['ip']) ?></td>
                                            <td><?= htmlspecialchars(substr($log['user_agent'], 0, 30)) . (strlen($log['user_agent']) > 30 ? '...' : '') ?></td>
                                            <td><?= htmlspecialchars($log['country']) ?></td>
                                            <td><?= $log['is_bot'] ? 'Yes' : 'No' ?></td>
                                            <td><?= $log['is_vpn'] ? 'Yes' : 'No' ?></td>
                                            <td><?= htmlspecialchars($log['path']) ?></td>
                                            <td><?= htmlspecialchars($log['status']) ?></td>
                                            <td><?= date('Y-m-d H:i', $log['timestamp']) ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
            <?php elseif ($page === 'short_links'): ?>
                <h2 class="mb-4">Short Links</h2>
                
                <div class="card mb-4">
                    <div class="card-header">
                        <h5>Create New Short Link</h5>
                    </div>
                    <div class="card-body">
                        <form method="post">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                            <input type="hidden" name="action" value="create_shortlink">
                            <div class="input-group mb-3">
                                <input type="url" name="url" class="form-control" placeholder="Enter URL to shorten" required>
                                <button class="btn btn-primary" type="submit">Create</button>
                            </div>
                        </form>
                        <?php if (isset($shortLinkCreated)): ?>
                            <div class="alert alert-success"><?= htmlspecialchars($shortLinkCreated) ?></div>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h5>Existing Short Links</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table id="shortLinksTable" class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Short Code</th>
                                        <th>Original URL</th>
                                        <th>Created At</th>
                                        <th>Hits</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($shortLinks as $link): ?>
                                        <tr>
                                            <td><a href="/<?= htmlspecialchars($link['short_code']) ?>" target="_blank"><?= htmlspecialchars($link['short_code']) ?></a></td>
                                            <td><?= htmlspecialchars(substr($link['original_url'], 0, 50)) . (strlen($link['original_url']) > 50 ? '...' : '') ?></td>
                                            <td><?= date('Y-m-d H:i', $link['created_at']) ?></td>
                                            <td><?= $link['hits'] ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
            <?php elseif ($page === 'settings'): ?>
                <h2 class="mb-4">Settings</h2>
                
                <div class="card">
                    <div class="card-body">
                        <form method="post">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                            <input type="hidden" name="action" value="toggle_maintenance">
                            <div class="mb-3 form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="maintenanceMode" name="maintenance_mode" value="1" <?= $maintenanceMode ? 'checked' : '' ?>>
                                <label class="form-check-label" for="maintenanceMode">Maintenance Mode (block all non-admin traffic)</label>
                            </div>
                            <button type="submit" class="btn btn-primary">Save Settings</button>
                        </form>
                    </div>
                </div>
                
            <?php endif; ?>
        </div>
        
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
        <script src="https://cdn.datatables.net/1.11.5/js/dataTables.bootstrap5.min.js"></script>
        <script>
            $(document).ready(function() {
                $('#blockedIpsTable, #accessLogsTable, #shortLinksTable').DataTable({
                    responsive: true,
                    order: [[2, 'desc']]
                });
            });
        </script>
    </body>
    </html>
    <?php
} elseif (isset($_GET['page']) && $_GET['page'] === 'login') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background: #f5f5f5; display: flex; justify-content: center; align-items: center; height: 100vh; }
            .login-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2 class="text-center mb-4">Admin Login</h2>
            <?php if (isset($loginError)): ?>
                <div class="alert alert-danger"><?= htmlspecialchars($loginError) ?></div>
            <?php endif; ?>
            <form method="post">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <input type="hidden" name="action" value="login">
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Login</button>
            </form>
        </div>
    </body>
    </html>
    <?php
} else {
    // Redirect to target URL if all checks pass
    header("Location: " . TARGET_URL, true, 302);
    exit;
}
?>