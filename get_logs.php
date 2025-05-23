<?php
include 'utils.php';

// Load visitor logs
$logs = load_logs();

// Process logs to get statistics (needed for request counts)
$ip_request_counts = [];
$country_request_counts = [];
foreach ($logs as $log) {
    $ip = $log['ip'];
    if (!isset($ip_request_counts[$ip])) {
        $ip_request_counts[$ip] = 0;
    }
    $ip_request_counts[$ip]++;

    $country = $log['country'] ?? 'Unknown';
    if (!isset($country_request_counts[$country])) {
        $country_request_counts[$country] = 0;
    }
    $country_request_counts[$country]++;
}

// Aggregate logs by IP, keeping the latest entry and adding request count
$aggregated_logs = [];
// $logs is already sorted by timestamp descending (latest first) by load_logs()
foreach ($logs as $log) {
    $ip = $log['ip'];
    // Always add/update the entry for this IP. Since logs are sorted latest first,
    // the last time we see an IP in this loop will be its latest log entry.
    $aggregated_logs[$ip] = $log;
    $aggregated_logs[$ip]['request_count'] = $ip_request_counts[$ip] ?? 0;
    // Use country_code for consistency with dashboard JS
    $aggregated_logs[$ip]['country_code'] = $log['countryCode'] ?? 'Unknown';
    // Add city, ISP and Organization data from the log if available
    $aggregated_logs[$ip]['city'] = $log['city'] ?? 'Unknown';
    $aggregated_logs[$ip]['isp'] = $log['isp'] ?? 'N/A';
    $aggregated_logs[$ip]['org'] = $log['org'] ?? 'N/A';
    // Add bot detection reason
    $aggregated_logs[$ip]['bot_detection_reason'] = $log['bot_detection_reason'] ?? false;

    // Calculate current time in visitor's timezone
    $timezone = $log['timezone'] ?? 'UTC';
    try {
        $datetime = new DateTime('now', new DateTimeZone($timezone));
        $aggregated_logs[$ip]['current_time'] = $datetime->format('Y-m-d H:i:s');
    } catch (Exception $e) {
        $aggregated_logs[$ip]['current_time'] = 'N/A';
    }
}

// Convert associative array back to indexed array for JSON output
// The order is preserved from the last assignment in the loop, which is the latest entry due to prior sorting.
$final_logs = array_values($aggregated_logs);

// Output aggregated logs as JSON
header('Content-Type: application/json');
echo json_encode($final_logs);
exit();
?>