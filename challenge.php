<?php
// Challenge page for bot/VPN detection

$target_url = $_GET['target'] ?? '';
$fallback_url = $_GET['fallback'] ?? '';

// Basic validation
if (empty($target_url)) {
    header("HTTP/1.0 400 Bad Request");
    exit("Missing target URL.");
}

// Auto-submit form when checkbox is clicked using JavaScript
// No button needed for Cloudflare-like experience

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['i_am_human'])) {
    // User checked the box, assume they are human and redirect to target URL
    header("Location: " . urldecode($target_url));
    exit();
} else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // User submitted the form but didn't check the box, redirect to fallback
    header("Location: " . urldecode($fallback_url));
    exit();
}

?>

<!DOCTYPE html>
<html>
<head>
    <title>Security Check</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            text-align: center;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-color: #f5f5f5;
        }
        .challenge-container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 30px;
            max-width: 500px;
            width: 90%;
        }
        .cloudflare-logo {
            margin-bottom: 20px;
        }
        .challenge-title {
            color: #2c7cb0;
            font-size: 22px;
            margin-bottom: 15px;
            font-weight: 600;
        }
        .challenge-description {
            color: #4a4a4a;
            margin-bottom: 25px;
            font-size: 15px;
        }
        .checkbox-container {
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 20px 0;
        }
        .custom-checkbox {
            position: relative;
            cursor: pointer;
            font-size: 16px;
            user-select: none;
            display: flex;
            align-items: center;
        }
        .custom-checkbox input {
            position: absolute;
            opacity: 0;
            cursor: pointer;
            height: 0;
            width: 0;
        }
        .checkmark {
            height: 25px;
            width: 25px;
            background-color: #eee;
            border-radius: 4px;
            margin-right: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 1px solid #ddd;
            transition: all 0.2s ease;
        }
        .custom-checkbox:hover input ~ .checkmark {
            background-color: #ccc;
        }
        .custom-checkbox input:checked ~ .checkmark {
            background-color: #2c7cb0;
            border-color: #2c7cb0;
        }
        .checkmark:after {
            content: "";
            display: none;
        }
        .custom-checkbox input:checked ~ .checkmark:after {
            display: block;
            width: 5px;
            height: 10px;
            border: solid white;
            border-width: 0 2px 2px 0;
            transform: rotate(45deg);
        }
        .footer-text {
            color: #888;
            font-size: 12px;
            margin-top: 20px;
        }
        .powered-by {
            margin-top: 30px;
            font-size: 12px;
            color: #999;
        }
    </style>
</head>
<body>
    <div class="challenge-container">
        <div class="cloudflare-logo">
            <svg width="120" height="44" viewBox="0 0 109 40" xmlns="http://www.w3.org/2000/svg">
                <path d="M98.6 14.2L93 12.9l-1-.4-25.7.2v12.4l32.3.1z" fill="#fff"/>
                <path d="M88.1 24c.3-1 .2-2-.3-2.6-.5-.6-1.2-1-2.1-1.1l-17.4-.2c-.1 0-.2-.1-.3-.1-.1-.1-.1-.2 0-.3.1-.2.2-.3.4-.3l17.5-.2c2.1-.1 4.3-1.8 5.1-3.8l1-2.6c0-.1.1-.2 0-.3-1.1-5.1-5.7-8.9-11.1-8.9-5 0-9.3 3.2-10.8 7.7-1-.7-2.2-1.1-3.6-1-2.4.2-4.3 2.2-4.6 4.6-.1.6 0 1.2.1 1.8-3.9.1-7.1 3.3-7.1 7.3 0 .4 0 .7.1 1.1 0 .2.2.3.3.3h32.1c.2 0 .4-.1.5-.3l.2-.6z" fill="#f38020"/>
                <path d="M93 12.9l-1-.4-25.7.2v12.4l32.3.1z" fill="#fbae40"/>
                <path d="M26.9 33.8h-4.7V22.1h4.7v11.7zm40.5 0h-4.7V22.1h4.7v11.7zm-33.5 0h-5.9v-11.7h5.9v2.4c1-1.7 2.7-2.8 4.8-2.8 3.8 0 6.1 2.6 6.1 6.7v5.4H40v-5.2c0-2.2-1.1-3.4-3.1-3.4s-3.1 1.2-3.1 3.4v5.2zm56.1-6c0 3.8-3.2 6.4-7.5 6.4-4.4 0-7.5-2.6-7.5-6.4 0-3.8 3.1-6.4 7.5-6.4 4.3 0 7.5 2.6 7.5 6.4zm-4.7 0c0-1.7-1.1-2.8-2.8-2.8-1.7 0-2.8 1.1-2.8 2.8 0 1.7 1.1 2.8 2.8 2.8 1.7 0 2.8-1.1 2.8-2.8zm-31.1 0c0 3.8-3.2 6.4-7.5 6.4-4.4 0-7.5-2.6-7.5-6.4 0-3.8 3.1-6.4 7.5-6.4 4.4 0 7.5 2.6 7.5 6.4zm-4.7 0c0-1.7-1.1-2.8-2.8-2.8-1.7 0-2.8 1.1-2.8 2.8 0 1.7 1.1 2.8 2.8 2.8 1.7 0 2.8-1.1 2.8-2.8zm-25.4 6c-4.4 0-7.7-2.6-7.7-6.4 0-3.8 3.2-6.4 7.7-6.4 2.5 0 4.9 1 6.5 2.7l-3.3 3c-.8-.9-1.9-1.4-3.1-1.4-1.7 0-2.9 1.1-2.9 2.8 0 1.7 1.2 2.8 2.9 2.8 1.2 0 2.3-.5 3.1-1.4l3.3 2.9c-1.6 1.9-4 2.8-6.5 2.8z" fill="#404041"/>
            </svg>
        </div>
        <div class="challenge-title">Security Check</div>
        <div class="challenge-description">Please check the box below to continue to the site.</div>
        
        <form method="POST" id="verification-form">
            <div class="checkbox-container">
                <label class="custom-checkbox">
                    <input type="checkbox" name="i_am_human" value="yes" id="human-checkbox" required>
                    <span class="checkmark"></span>
                    I'm a human
                </label>
            </div>
        </form>
        
        <?php if (!empty($fallback_url)): ?>
            <div class="footer-text">If you cannot complete the verification, you will be redirected to an alternative page.</div>
        <?php endif; ?>
        
        <div class="powered-by">Protected by ShortLink Security</div>
    </div>

    <script>
        // Auto-submit form when checkbox is clicked
        document.getElementById('human-checkbox').addEventListener('change', function() {
            if(this.checked) {
                document.getElementById('verification-form').submit();
            }
        });
    </script>
</body>
</html>