<?php
// signup_sample.php
// Simplified user registration with MySQL.

$conn = new mysqli("localhost", "root", "", "authentication");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $name     = $_POST['name'] ?? '';
    $email    = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $phone    = $_POST['phone'] ?? '';

    if ($name === '' || $email === '' || $password === '' || $phone === '') {
        echo "Please fill in all fields.";
        exit;
    }

    $sql = "CREATE TABLE IF NOT EXISTS register (
        id INT(11) NOT NULL AUTO_INCREMENT,
        username VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL UNIQUE,
        PRIMARY KEY (id)
    ) ENGINE=InnoDB";

    $conn->query($sql);

    $stmt = $conn->prepare("INSERT INTO register (username, email, password, phone) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $name, $email, $password, $phone);

    if ($stmt->execute()) {
        echo "Registration successful. Proceed to login.";
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
}

$conn->close();
?>