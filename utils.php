<?php
// Utility functions

// File paths for data storage
define('LINKS_FILE', __DIR__ . '/links.txt');
define('LOGS_FILE', __DIR__ . '/logs.txt');
define('BLOCKED_IPS_FILE', __DIR__ . '/blocked_ips.txt');
define('BLOCKED_COUNTRIES_FILE', __DIR__ . '/blocked_countries.txt');
define('IP_CACHE_FILE', __DIR__ . '/ip_cache.json');

// --- Cache Functions ---

// Load IP cache from file
function load_ip_cache() {
    $cache = [];
    if (file_exists(IP_CACHE_FILE)) {
        $content = file_get_contents(IP_CACHE_FILE);
        $cache = json_decode($content, true) ?? [];
    }
    return $cache;
}

// Save IP cache to file
function save_ip_cache($cache) {
    file_put_contents(IP_CACHE_FILE, json_encode($cache, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

// Get IP data from cache or API
function get_ip_data($ip) {
    $cache = load_ip_cache();
    $cache_duration = 24 * 60 * 60; // Cache for 24 hours

    // Check if data is in cache and not expired
    if (isset($cache[$ip]) && (time() - $cache[$ip]['timestamp']) < $cache_duration) {
        return $cache[$ip]['data'];
    }

    // Fetch data from API
    // Added 'city', 'isp' and 'org' fields to the request
    $response = @file_get_contents("http://ip-api.com/json/{$ip}?fields=countryCode,city,timezone,isp,org,proxy,hosting");
    if ($response === FALSE) {
        return null; // Handle API call failure
    }
    $data = json_decode($response, true);

    if ($data && $data['status'] === 'success') {
        // Store data in cache with timestamp
        $cache[$ip] = [
            'timestamp' => time(),
            'data' => $data
        ];
        save_ip_cache($cache);
        return $data;
    } else {
        return null; // Handle API response failure
    }
}

// --- Short Link Functions ---

// Load short links from file
function load_links() {
    $links = [];
    if (file_exists(LINKS_FILE)) {
        $lines = file(LINKS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $data = json_decode($line, true);
            if ($data && isset($data['short_code'])) {
                $links[$data['short_code']] = $data;
            }
        }
    }
    return $links;
}

// Save a new short link to file
function save_link($short_code, $target_url, $fallback_url = '') {
    $links = load_links();
    $links[$short_code] = [
        'short_code' => $short_code,
        'target_url' => $target_url,
        'fallback_url' => $fallback_url,
        'created_at' => date('Y-m-d H:i:s'),
    ];
    $file_content = '';
    foreach ($links as $link) {
        $file_content .= json_encode($link) . "\n";
    }
    file_put_contents(LINKS_FILE, $file_content);
}

// Update an existing short link
function update_link($short_code, $target_url, $fallback_url = '') {
    $links = load_links();
    if (isset($links[$short_code])) {
        $links[$short_code]['target_url'] = $target_url;
        $links[$short_code]['fallback_url'] = $fallback_url;
        // Optionally update 'updated_at' timestamp
        // $links[$short_code]['updated_at'] = date('Y-m-d H:i:s');

        $file_content = '';
        foreach ($links as $link) {
            $file_content .= json_encode($link) . "\n";
        }
        file_put_contents(LINKS_FILE, $file_content);
        return true; // Indicate success
    }
    return false; // Indicate link not found
}

// Delete a short link from file
function delete_link($short_code) {
    $links = load_links();
    if (isset($links[$short_code])) {
        unset($links[$short_code]);
        $file_content = '';
        foreach ($links as $link) {
            $file_content .= json_encode($link) . "\n";
        }
        file_put_contents(LINKS_FILE, $file_content);
    }
}

// Generate a unique short code
function generate_short_code($length = 6) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    $links = load_links();
    do {
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
    } while (isset($links[$randomString])); // Ensure uniqueness
    return $randomString;
}

// --- Logging Functions ---

// Log visitor information
function log_visitor($short_code, $ip, $country_code, $city, $bot_detection_reason, $timezone, $user_agent, $isp, $org) {
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'short_code' => $short_code,
        'ip' => $ip,
        'country_code' => $country_code,
        'city' => $city,
        'bot_detection_reason' => $bot_detection_reason, // Store the reason
        'timezone' => $timezone,
        'user_agent' => $user_agent,
        'isp' => $isp,
        'org' => $org
    ];
    file_put_contents(LOGS_FILE, json_encode($log_entry) . "\n", FILE_APPEND | LOCK_EX);
}

// Load visitor logs from file
function load_logs() {
    $logs = [];
    if (file_exists(LOGS_FILE)) {
        $lines = file(LOGS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $log = json_decode($line, true);
            if ($log) {
                $logs[] = $log;
            }
        }
    }
    // Sort logs by timestamp descending for real-time view
    usort($logs, function($a, $b) {
        return strtotime($b['timestamp']) - strtotime($a['timestamp']);
    });
    return $logs;
}

// --- Detection and Blocking Functions ---

// Get country from IP (requires external service or local database)
function get_country_from_ip($ip) {
    $data = get_ip_data($ip);
    return $data['countryCode'] ?? 'Unknown';
}

// Get timezone from IP (requires external service or local database)
function get_timezone_from_ip($ip) {
    $data = get_ip_data($ip);
    return $data['timezone'] ?? 'Unknown';
}

// Detect if user is a bot or VPN/Proxy
// This is a basic placeholder. Real detection is complex and requires external services or databases.
function is_bot_or_vpn($ip, $user_agent) {
    // Expanded list of known bot user agents
    $bots = [
        // Search Engine & SEO Bots (Expanded)
        'googlebot', 'google-inspectiontool', 'google-read-aloud', 'bingbot', 'bingpreview', 'yahoo! slurp', 'baiduspider', 
        'yandexbot', 'yandeximages', 'yandexmetrika', 'yandexmobilebot', 'duckduckbot', 'duckduckgo-favicons', 
        'applebot', 'seznambot', 'petalbot', 'sogou spider', 'sogou web spider', 'exabot', 'exalead', 'facebot', 
        'ia_archiver', 'gigabot', 'mojeekbot', 'ahrefsbot', 'mj12bot', 'semrushbot', 'dotbot', 'megaindex', 
        'blexbot', 'linkdexbot', 'rogerbot', 'seoscanners', 'serpstatbot', 'seokicks', 'seobility', 'seranking', 
        'searchmetricsbot', 'deepcrawl', 'siteimprove', 'qwantify', 'ccbot', '360spider', 'bytespider', 'genieo', 
        'ltx71', 'meanpathbot', 'omgili', 'proximic', 'zoombot', 'zgrab', 'zgrab',
    
        // Social Media & Content Crawlers (Expanded)
        'facebookexternalhit', 'facebookcatalog', 'facebookbot', 'linkedinbot', 'linkedinboz', 'pinterestbot', 
        'pinterest', 'twitterbot', 'tumblr', 'redditbot', 'quora bot', 'quora image proxy', 'hubspot', 
        'bufferbot', 'discordbot', 'telegrambot', 'slackbot', 'slack-imgproxy', 'mattermost', 'wechat', 
        'whatsapp', 'viber', 'line', 'kakaotalk', 'skypeuripreview', 'tiktokbot', 'snapchat', 'instagram',
    
        // Scrapers & Automation Tools (Expanded)
        'curl', 'wget', 'python-requests', 'python-urllib', 'go-http-client', 'java', 'php', 'perl', 'node-fetch', 
        'axios', 'scrapy', 'beautifulsoup', 'mechanize', 'phantomjs', 'selenium', 'puppeteer', 'playwright', 
        'apache-httpclient', 'okhttp', 'libwww-perl', 'winhttp', 'restsharp', 'guzzlehttp', 'typhoeus', 'faraday',
        'httrack', 'w3m', 'lwp', 'mechanize.rb', 'nokogiri', 'simplepie', 'feedparser', 'rssgraffiti',
    
        // Cloud, Proxy & VPN Services (Expanded)
        'cloudflare', 'amazon cloudfront', 'fastly', 'akamai', 'stackpath', 'incapsula', 'imperva', 'datacenter', 
        'proxy', 'vpn', 'tor exit node', 'luminati', 'oxylabs', 'scraperapi', 'brightdata', 'smartproxy', 
        'netnut', 'zyte', 'crawlera', 'geoedge', 'shadowsocks', 'v2ray', 'wireguard', 'openvpn', 'hidemyass',
        'proxymesh', 'nordvpn', 'expressvpn', 'ipvanish', 'windscribe', 'private internet access',
    
        // Headless & Browser Automation (Expanded)
        'headlesschrome', 'headless firefox', 'electron', 'chromium', 'webkit', 'blink', 'gecko', 'trident', 
        'presto', 'edge chromium', 'brave', 'vivaldi', 'opera', 'safari', 'phantom', 'casperjs', 'nightmare',
        'webdriver', 'watir', 'capybara', 'geb', 'testcafe', 'cypress', 'karma', 'jest-puppeteer',
    
        // API & Developer Tools (Expanded)
        'postman', 'insomnia', 'swagger', 'openapi', 'rest-client', 'fiddler', 'charles', 'wireshark', 'telerik', 
        'soapui', 'jmeter', 'katalon', 'loadrunner', 'gatling', 'vegeta', 'locust', 'artillery', 'newman',
        'graphql', 'grpc', 'thrift', 'avro', 'protobuf', 'json-rpc', 'xml-rpc', 'odata',
    
        // Security & Vulnerability Scanners (Expanded)
        'nmap', 'nessus', 'openvas', 'metasploit', 'burp', 'owasp', 'acunetix', 'nikto', 'sqlmap', 'wpscan', 
        'zap', 'qualys', 'rapid7', 'tenable', 'appscan', 'nexpose', 'retire.js', 'snyk', 'veracode', 
        'whitesource', 'checkmarx', 'fortify', 'sonarqube', 'clair', 'trivy', 'anchore', 'twistlock',
    
        // Monitoring & Analytics Bots (Expanded)
        'pingdom', 'uptimebot', 'newrelic', 'datadog', 'statuscake', 'gtmetrix', 'webpagetest', 'lighthouse', 
        'calibre', 'speedcurve', 'catchpoint', 'dynatrace', 'appdynamics', 'splunk', 'sumologic', 'loggly',
        'papertrail', 'sentry', 'rollbar', 'bugsnag', 'raygun', 'elastic', 'kibana', 'grafana',
    
        // Legacy & Rare Bots (For Maximum Coverage)
        'altavista', 'webcrawler', 'infoseek', 'lycos', 'hotbot', 'ask jeeves', 'inktomi', 'nutch', 'gurujibot', 
        'yodaobot', 'holmes', 'naverbot', 'daumoa', 'converkera', 'boitho', 'coccoc', 'dumbot', 'evrinid', 
        'furlbot', 'gigablast', 'heritrix', 'ichiro', 'irlbot', 'jyxobot', 'koepabot', 'larbin', 'mogimogi',
        'msrbot', 'rambler', 'scooter', 'scrubby', 'searchsight', 'snappy', 'steeler', 'tutorgig', 'webaltbot',
        'yeti', 'zao', 'zyborg', 'wwweasel', 'psbot', 'xenu', 'yacybot', 'zealbot', 'nextgensearchbot'
    ];

    foreach ($bots as $bot) {
        if (stripos($user_agent, $bot) !== false) {
            return 'bot'; // Flagged as known bot
        }
    }

    // Check for suspicious user agent patterns (e.g., missing common browser indicators)
    // This is a heuristic and can have false positives.
    $suspicious_patterns = [
        '/^$/', // Empty user agent
        '/^[a-z0-9]{10,20}$/i', // Short, random-looking strings
        '/^mozilla\/\d\.\d \(compatible; msiemobile \d\.\d; windows ce; iemobile \d\.\d\)$/i' // Old or unusual patterns
    ];

    foreach ($suspicious_patterns as $pattern) {
        if (preg_match($pattern, $user_agent)) {
            return 'suspicious_ua'; // Flagged as suspicious user agent
        }
    }

    // Basic check for potential proxy/VPN indicators based on headers.
    // This is highly unreliable without a dedicated service and can have false positives/negatives.
    // It's kept as a basic indicator but should not be solely relied upon.
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) || isset($_SERVER['HTTP_VIA']) || isset($_SERVER['HTTP_PROXY_CONNECTION'])) {
        // This might indicate a proxy or VPN, but needs more sophisticated checks.
        // For now, we'll flag it as potentially non-human based on headers.
        return 'vpn/proxy_ip_data'; // Flagged based on IP data indicating proxy/hosting
    }
    // Get IP data to check for proxy/hosting flags
    $ip_data = get_ip_data($ip);

    if ($ip_data && (isset($ip_data['proxy']) && $ip_data['proxy'] === true || isset($ip_data['hosting']) && $ip_data['hosting'] === true)) {
        return 'vpn/proxy_ip_data'; // Flagged based on IP data indicating proxy/hosting
    }

    return false; // Assume human if no indicators found
}

// Check if IP is blocked
function is_blocked_ip($ip) {
    if (!file_exists(BLOCKED_IPS_FILE)) {
        return false;
    }
    $blocked_ips = file(BLOCKED_IPS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    return in_array($ip, $blocked_ips);
}

// Check if country is blocked
function is_blocked_country($country_code) {
     if (!file_exists(BLOCKED_COUNTRIES_FILE)) {
        return false;
    }
    $blocked_countries = file(BLOCKED_COUNTRIES_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    return in_array($country_code, $blocked_countries);
}

// Add IP to blocked list
function block_ip($ip) {
    if (!is_blocked_ip($ip)) {
        file_put_contents(BLOCKED_IPS_FILE, $ip . "\n", FILE_APPEND | LOCK_EX);
    }
}

// Add country to blocked list
function block_country($country_code) {
     if (!is_blocked_country($country_code)) {
        file_put_contents(BLOCKED_COUNTRIES_FILE, $country_code . "\n", FILE_APPEND | LOCK_EX);
    }
}

// Remove IP from blocked list
function unblock_ip($ip) {
    if (is_blocked_ip($ip)) {
        $blocked_ips = file(BLOCKED_IPS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $blocked_ips = array_diff($blocked_ips, [$ip]);
        file_put_contents(BLOCKED_IPS_FILE, implode("\n", $blocked_ips) . "\n", LOCK_EX);
    }
}

// Remove country from blocked list
function unblock_country($country_code) {
     if (is_blocked_country($country_code)) {
        $blocked_countries = file(BLOCKED_COUNTRIES_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $blocked_countries = array_diff($blocked_countries, [$country_code]);
        file_put_contents(BLOCKED_COUNTRIES_FILE, implode("\n", $blocked_countries) . "\n", LOCK_EX);
    }
}

// --- Dashboard Authentication (Basic) ---

// Include configuration file for credentials
include_once __DIR__ . '/config.php';

// --- Session Management Functions ---

function is_logged_in() {
    return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}

function attempt_login($username, $password) {
    // Use credentials from config.php
    $user = DASHBOARD_USER;
    $pass = DASHBOARD_PASS;

    if ($username === $user && $password === $pass) {
        $_SESSION['logged_in'] = true;
        return true;
    } else {
        return false;
    }
}

function logout() {
    // Unset all session variables
    $_SESSION = array();

    // Destroy the session
    session_destroy();

    // Redirect to login page
    header('Location: login.php');
    exit();
}


// --- Dashboard Authentication (Session-based) ---

function check_auth() {
    if (!is_logged_in()) {
        header('Location: login.php');
        exit();
    }
    }


?>