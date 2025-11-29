<?php
// login_otp_sample.php
// Simplified OTP login example.

session_start();

$authKey = "YOUR_AUTH_KEY_HERE";  // replace with real SMS API key
$username = $_SESSION['login_user'] ?? '';
$mobileNumber = $_POST['phone'] ?? '';

$conn = new mysqli("localhost", "root", "", "authentication");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$sql = "SELECT * FROM register WHERE email = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    if ($row['phone'] === $mobileNumber) {
        $rndno = rand(100000, 999999);
        $_SESSION['otp'] = $rndno;
        $message = urlencode("Your login OTP is: " . $rndno);

        $url = "https://api.example-sms.com/send?authkey={$authKey}&mobiles={$mobileNumber}&message={$message}";

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $output = curl_exec($ch);

        if (curl_errno($ch)) {
            echo "cURL error: " . curl_error($ch);
        } else {
            echo "OTP sent to your registered mobile number.";
        }
        curl_close($ch);
    } else {
        echo "Invalid mobile number.";
    }
} else {
    echo "User not found.";
}

$stmt->close();
$conn->close();
?>