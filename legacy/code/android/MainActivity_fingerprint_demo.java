// MainActivity_fingerprint_demo.java
// Simplified Android fingerprint authentication example.

package com.example.threefactorauth;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    private TextView statusText;

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        statusText = findViewById(R.id.statusText);

        FingerprintManager fingerprintManager =
                (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
        KeyguardManager keyguardManager =
                (KeyguardManager) getSystemService(KEYGUARD_SERVICE);

        if (!fingerprintManager.isHardwareDetected()) {
            statusText.setText("Fingerprint sensor not detected on this device.");
        } else if (ContextCompat.checkSelfPermission(this,
                Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            statusText.setText("Fingerprint permission not granted.");
        } else if (!keyguardManager.isKeyguardSecure()) {
            statusText.setText("Enable lock screen security in Settings.");
        } else if (!fingerprintManager.hasEnrolledFingerprints()) {
            statusText.setText("No fingerprints enrolled. Add one in Settings.");
        } else {
            statusText.setText("Place your finger on the sensor to verify.");
            // Hook in real FingerprintHandler here in a full implementation.
        }
    }
}