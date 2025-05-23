<?php
session_start();

// Dashboard script

// Include necessary files
include 'utils.php';

// Session-based authentication
check_auth();

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle short link creation form submission
    if (isset($_POST['target_url'])) {
        $target_url = $_POST['target_url'];
        $fallback_url = $_POST['fallback_url'] ?? ''; // Optional fallback URL

        // Generate a unique short code
        $short_code = generate_short_code(); // Function to generate unique code

        // Save the new link
        save_link($short_code, $target_url, $fallback_url); // Function to save to links.txt

    } elseif (isset($_POST['block_ip'])) {
        // Handle block IP submission
        $ip_to_block = $_POST['block_ip'];
        if (!empty($ip_to_block)) {
            block_ip($ip_to_block);
        }
    } elseif (isset($_POST['unblock_ip'])) {
        // Handle unblock IP submission
        $ip_to_unblock = $_POST['unblock_ip'];
        if (!empty($ip_to_unblock)) {
            unblock_ip($ip_to_unblock);
        }
    } elseif (isset($_POST['block_country'])) {
        // Handle block country submission
        $country_to_block = $_POST['block_country'];
        if (!empty($country_to_block)) {
            block_country($country_to_block);
        }
    } elseif (isset($_POST['unblock_country'])) {
        // Handle unblock country submission
        $country_to_unblock = $_POST['unblock_country'];
        if (!empty($country_to_unblock)) {
            unblock_country($country_to_unblock);
        }
    } elseif (isset($_POST['delete_short_code'])) {
        // Handle short link deletion form submission
        $short_code_to_delete = $_POST['delete_short_code'];
        if (!empty($short_code_to_delete)) {
            delete_link($short_code_to_delete); // Function to delete in utils.php
        }
    }

    // Redirect to prevent form resubmission
    header("Location: dashboard.php");
    exit();
} elseif (isset($_POST['edit_short_code'])) {
    // Handle short link update form submission
    $short_code = $_POST['edit_short_code'];
    $target_url = $_POST['edit_target_url'];
    $fallback_url = $_POST['edit_fallback_url'] ?? ''; // Optional fallback URL

    // Update the link
    $success = update_link($short_code, $target_url, $fallback_url); // Function to update in utils.php

    // Check if it's an AJAX request
    if (isset($_POST['ajax_update_link'])) {
        header('Content-Type: application/json');
        if ($success) {
            echo json_encode(['success' => true, 'short_code' => $short_code, 'target_url' => $target_url, 'fallback_url' => $fallback_url]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Link not found or failed to update.']);
        }
        exit();
    } else {
        // Redirect to prevent form resubmission for non-AJAX requests
        header("Location: dashboard.php");
        exit();
    }
}

// Handle logout request
if (isset($_POST['logout'])) {
    logout();
}

// Load existing short links



// Load existing short links
$links = load_links(); // Function to load links from links.txt

// Load visitor logs
$logs = load_logs(); // Function to load logs from logs.txt

// Process logs to get statistics
$link_stats = [];
$ip_request_counts = [];
foreach ($logs as $log) {
    $short_code = $log['short_code'];
    if (!isset($link_stats[$short_code])) {
        $link_stats[$short_code] = [
            'total_requests' => 0,
            'unique_visitors' => []
        ];
    }
    $link_stats[$short_code]['total_requests']++;
    $link_stats[$short_code]['unique_visitors'][$log['ip']] = true; // Use IP as key for uniqueness

    // Count requests per IP
    $ip = $log['ip'];
    if (!isset($ip_request_counts[$ip])) {
        $ip_request_counts[$ip] = 0;
    }
    $ip_request_counts[$ip]++;

    // Count requests per country
    $country = $log['country'] ?? 'Unknown';
    if (!isset($country_request_counts[$country])) {
        $country_request_counts[$country] = 0;
    }
    $country_request_counts[$country]++;
}

// Sort IPs by request count (descending)
arsort($ip_request_counts);

// Sort countries by request count (descending)
arsort($country_request_counts);

?>

<!DOCTYPE html>
<html>

<head>
    <title>Shortlink Dashboard</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .logout-form {
            position: absolute;
            top: 10px;
            right: 10px;
        }
    </style>
</head>

<body>
    <div class="container">
        <h1>Shortlink Dashboard</h1>

    <h2>Create New Shortlink</h2>
    <form method="POST">
        <label for="target_url">Target URL:</label>
        <input type="url" id="target_url" name="target_url" required>
        <br><br>
        <label for="fallback_url">Fallback URL (optional):</label>
        <input type="url" id="fallback_url" name="fallback_url">
        <br><br>
        <button type="submit">Create Shortlink</button>
    </form>

    <h2>Existing Shortlinks</h2>
    <table>
        <thead>
            <tr>
                <th>Short Code</th>
                <th>Target URL</th>
                <th>Fallback URL</th>
                <th>Total Requests</th>
                <th>Unique Visitors</th>
                <th>Actions</th>
                <th>Edit</th>
            </tr>
        </thead>
        <tbody>
            <?php
            foreach ($links as $code => $link) {
                $stats = $link_stats[$code] ?? ['total_requests' => 0, 'unique_visitors' => []];
                $unique_visitor_count = count($stats['unique_visitors']);
                echo "<tr>";
                echo "<td>" . htmlspecialchars($code) . "</td>";
                echo "<td>" . htmlspecialchars($link['target_url']) . "</td>";
                echo "<td>" . htmlspecialchars($link['fallback_url']) . "</td>";
                echo "<td>" . ($stats['total_requests'] ?? 0) . "</td>";
                echo "<td>" . ($unique_visitor_count ?? 0) . "</td>";
                echo "<td><form method='POST' style='display:inline;'><input type='hidden' name='delete_short_code' value='" . htmlspecialchars($code) . "'><button type='submit'>Delete</button></form></td>";
                echo "<td><button class='edit-button' data-code='" . htmlspecialchars($code) . "' data-target='" . htmlspecialchars($link['target_url']) . "' data-fallback='" . htmlspecialchars($link['fallback_url']) . "'>Edit</button></td>";
                echo "</tr>";
            }
            ?>

                </tbody>
    </table>

    <div id="edit-form-section" style="display: none;">
        <h2>Edit Shortlink</h2>
        <form id="edit_shortlink_form" method="POST">
            <input type="hidden" id="edit_short_code" name="edit_short_code">
            <label for="edit_target_url">Target URL:</label>
            <input type="url" id="edit_target_url" name="edit_target_url" required>
            <br><br>
            <label for="edit_fallback_url">Fallback URL (optional):</label>
            <input type="url" id="edit_fallback_url" name="edit_fallback_url">
            <br><br>
            <button type="submit">Update Shortlink</button>
            <button type="button" id="cancel-edit">Cancel</button>
        </form>
    </div>


   


    <h2>Blocked IPs</h2>
    <form method="POST">
        <label for="block_ip">Block IP:</label>
        <input type="text" id="block_ip" name="block_ip" required>
        <button type="submit">Block IP</button>
    </form>
    <table>
        <thead>
            <tr>
                <th>Blocked IP</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <?php
            $blocked_ips = file_exists(BLOCKED_IPS_FILE) ? file(BLOCKED_IPS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
            foreach ($blocked_ips as $ip) {
                echo "<tr>";
                echo "<td>" . htmlspecialchars($ip) . "</td>";
                echo "<td><form method='POST' style='display:inline;'><input type='hidden' name='unblock_ip' value='" . htmlspecialchars($ip) . "'><button type='submit'>Unblock</button></form></td>";
                echo "</tr>";
            }
            ?>
        </tbody>
    </table>

    <h2>Blocked Countries</h2>
    <form method="POST">
        <label for="block_country">Block Country Code (e.g., US):</label>
        <input type="text" id="block_country" name="block_country" required>
        <button type="submit">Block Country</button>
    </form>
    <table>
        <thead>
            <tr>
                <th>Blocked Country Code</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <?php
            $blocked_countries = file_exists(BLOCKED_COUNTRIES_FILE) ? file(BLOCKED_COUNTRIES_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
            foreach ($blocked_countries as $country_code) {
                echo "<tr>";
                echo "<td>" . htmlspecialchars($country_code) . "</td>";
                echo "<td><form method='POST' style='display:inline;'><input type='hidden' name='unblock_country' value='" . htmlspecialchars($country_code) . "'><button type='submit'>Unblock</button></form></td>";
                echo "</tr>";
            }
            ?>
        </tbody>
    </table>

    <div class="logout-form">
        <form method="POST" action="utils.php">
            <input type="hidden" name="logout" value="1">
            <button type="submit">Logout</button>
        </form>
    </div>

    <h2>Visitor Logs</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Short Code</th>
                <th>IP Address</th>
                <th>Location</th>
                <th>Bot/VPN</th>
                <th>Bot Detection Reason</th>
                <th>Timezone</th>
                <th>Current Time</th>
                <th>Request Count</th>
                <th>ISP</th>
                <th>Organization</th>
                <th>Info</th>
            </tr>
        </thead>
        <tbody>


        </tbody>
    </table>
    </div>

    <script>
        function fetchLogs() {
            fetch('get_logs.php')
                .then(response => response.json())
                .then(logs => {
                    const tbody = document.querySelector('.container table:last-of-type tbody');
                    tbody.innerHTML = ''; // Clear existing rows

                    // logs is now an array of aggregated data, one entry per unique IP
                    logs.forEach(log => {
                        const row = tbody.insertRow();
                        row.innerHTML = `
                            <td>${log.timestamp}</td>
                            <td>${log.short_code}</td>
                            <td>${log.ip}</td>
                            <td><img src='https://flagcdn.com/16x12/${log.country_code.toLowerCase()}.png' alt='${log.country_code} Flag'> ${log.country_code}, ${log.city}</td>
                            <td>${log.bot_detection_reason !== false ? '<span class="is-bot">Yes</span>' : 'No'}</td>
                            <td>${log.bot_detection_reason !== false ? log.bot_detection_reason : 'N/A'}</td>
                            <td>${log.timezone}</td>
                            <td>${log.current_time}</td>
                            <td>${log.request_count}</td>
                            <td>${log.isp}</td>
                            <td>${log.org}</td>
                            <td>${log.user_agent}</td>
                        `;
                    });
                    // The data is already sorted by latest timestamp from the backend
                })
                .catch(error => console.error('Error fetching logs:', error));
        }

        // Fetch logs initially and then every 5 seconds
        fetchLogs();
        setInterval(fetchLogs, 5000); // Update every 5 seconds

        // JavaScript for handling edit form
        document.querySelectorAll('.edit-button').forEach(button => {
            button.addEventListener('click', function() {
                const code = this.getAttribute('data-code');
                const target = this.getAttribute('data-target');
                const fallback = this.getAttribute('data-fallback');

                document.getElementById('edit_short_code').value = code;
                document.getElementById('edit_target_url').value = target;
                document.getElementById('edit_fallback_url').value = fallback;
                document.getElementById('edit-form-section').style.display = 'block';
            });
        });

        document.getElementById('cancel-edit').addEventListener('click', function() {
            document.getElementById('edit-form-section').style.display = 'none';
        });

        // Handle edit form submission via AJAX
        document.getElementById('edit_shortlink_form').addEventListener('submit', function(event) {
            event.preventDefault(); // Prevent default form submission

            const form = event.target;
            const formData = new FormData(form);

            // Add a flag to indicate this is an AJAX request for updating
            formData.append('ajax_update_link', '1');

            fetch('dashboard.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Find the row in the table and update it
                    const shortCode = data.short_code;
                    const targetUrl = data.target_url;
                    const fallbackUrl = data.fallback_url;

                    const tableRows = document.querySelectorAll('.container table:nth-of-type(2) tbody tr');
                    tableRows.forEach(row => {
                        // Assuming the first td contains the short code
                        if (row.cells[0].textContent === shortCode) {
                            row.cells[1].textContent = targetUrl; // Update Target URL cell
                            row.cells[2].textContent = fallbackUrl; // Update Fallback URL cell
                        }
                    });

                    // Hide the edit form
                    document.getElementById('edit-form-section').style.display = 'none';
                    alert('Shortlink updated successfully!');
                } else {
                    alert('Error updating shortlink: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred while updating the shortlink.');
            });
        });

    </script>
</body>

</html>