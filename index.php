<?php
// Main redirect script

// Include necessary files
include 'utils.php';

// Get the short code from the URL
$short_code = $_SERVER['REQUEST_URI'];
$short_code = ltrim($short_code, '/');

// Remove query string if present
if (strpos($short_code, '?') !== false) {
    $short_code = substr($short_code, 0, strpos($short_code, '?'));
}

// Basic validation for short code format (e.g., alphanumeric)
if (!preg_match('/^[a-zA-Z0-9]+$/', $short_code)) {
    // Handle invalid short code
    header("HTTP/1.0 404 Not Found");
    exit();
}

// Load short links data
$links = load_links(); // Function to load links from links.txt

// Find the target URL for the short code
if (isset($links[$short_code])) {
    $target_url = $links[$short_code]['target_url'];
    $fallback_url = $links[$short_code]['fallback_url'];

    // Get visitor info
    $visitor_ip = $_SERVER['REMOTE_ADDR'];
    $visitor_user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $ip_data = get_ip_data($visitor_ip); // Get all IP data
    $visitor_country = $ip_data['countryCode'] ?? 'Unknown';
    $visitor_city = $ip_data['city'] ?? 'Unknown'; // Get city data
    $visitor_timezone = $ip_data['timezone'] ?? 'Unknown';
    $visitor_isp = $ip_data['isp'] ?? 'N/A';
    $visitor_org = $ip_data['org'] ?? 'N/A';
    $bot_detection_reason = is_bot_or_vpn($visitor_ip, $visitor_user_agent); // Function to detect bot/vpn, returns reason or false

    // Log visitor info, including city, ISP, Organization, and bot detection reason
    log_visitor($short_code, $visitor_ip, $visitor_country, $visitor_city, $bot_detection_reason, $visitor_timezone, $visitor_user_agent, $visitor_isp, $visitor_org); // Function to log

    // Check for blocking rules (IP/Country)
    if (is_blocked_ip($visitor_ip) || is_blocked_country($visitor_country)) {
        header("Location: " . $fallback_url);
        exit();
    }

    // Check for bot/vpn and show challenge if needed
    if ($bot_detection_reason !== false) {
        // Redirect to challenge page, passing target and fallback URLs
        header("Location: challenge.php?target=" . urlencode($target_url) . "&fallback=" . urlencode($fallback_url));
        exit();
    }

    // If not blocked and not bot, redirect to target URL
    header("Location: " . $target_url);
    exit();

} else {
    // Short code not found
    header("HTTP/1.0 404 Not Found");
    // Optionally redirect to a default page or show an error
    // header("Location: default_404_page.php");
    exit();
}

?>