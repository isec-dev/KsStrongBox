package pl.isec.baseapp.strongbox;
import static java.nio.charset.StandardCharsets.UTF_8;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.security.crypto.MasterKeys;

import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

public class MainActivity extends AppCompatActivity {
    private final static String ANDROID_KEYSTORE = "AndroidKeyStore";
    private final static String FILENAME = "encrypted.txt";

    private String mSecurityLevel;
    private SecureFile mSecureFile;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        EditText outputText = findViewById(R.id.editTextTextMultiLine);
        EditText inputText = findViewById(R.id.editTextTextMultiLine2);
        Button readButton = findViewById(R.id.button);
        Button saveButton = findViewById(R.id.button2);
        TextView securityLevelText = findViewById(R.id.textView3);

        try {
            initialize();
        } catch (GeneralSecurityException | IOException e){
            e.printStackTrace();
            notify("Something gone wrong!");
        }

        securityLevelText.setText(mSecurityLevel);

        readButton.setOnClickListener(view ->{
            mSecureFile.openFileInput(new SecureFile.OpenFileInputCallback() {
                @Override
                public void onError(@NonNull CharSequence errString) {
                    MainActivity.this.notify("Authentication failed!");
                    outputText.setText("#" + errString);
                }

                @Override
                public void onInputStreamReady(@NonNull InputStream inputStream) {
                    try {
                        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                        int nextByte = inputStream.read();
                        while (nextByte != -1) {
                            byteArrayOutputStream.write(nextByte);
                            nextByte = inputStream.read();
                        }
                        outputText.setText(
                                byteArrayOutputStream.toString("UTF-8")
                        );
                    } catch(IOException e){
                        e.printStackTrace();
                        MainActivity.this.notify("Reading failed!");
                    }
                }
            });
        });

        saveButton.setOnClickListener(view ->{
            mSecureFile.openFileOutput(new SecureFile.OpenFileOutputCallback() {
                @Override
                public void onError(@NonNull CharSequence errString) {
                    MainActivity.this.notify("Authentication failed!");
                    outputText.setText("#" + errString);
                }

                @Override
                public void onOutputStreamReady(@NonNull OutputStream outputStream) {
                    try {
                        outputStream.write(
                                inputText.getText().toString().getBytes(UTF_8)
                        );
                        outputStream.flush();
                        outputStream.close();
                        inputText.setText("");
                    } catch(IOException e){
                        e.printStackTrace();
                        MainActivity.this.notify("Writing failed!");
                    }
                }
            });
        });
    }

    private void notify(String msg){
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }

    private void initialize() throws GeneralSecurityException, IOException {
        /** Get or create key **/
        String masterKeyAlias = MasterKeys.getOrCreate(
            createAES256GCMKeyGenParameterSpec()
        );

        /** Get security level **/
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        SecretKey secretKey = (SecretKey) ks.getKey(masterKeyAlias, null);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(secretKey.getAlgorithm(), ANDROID_KEYSTORE);
        KeyInfo keyInfo = (KeyInfo) factory.getKeySpec(secretKey, KeyInfo.class);

        switch(keyInfo.getSecurityLevel()){
            case KeyProperties.SECURITY_LEVEL_SOFTWARE:
                mSecurityLevel = "Software"; break;
            case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                mSecurityLevel = "TEE"; break;
            case KeyProperties.SECURITY_LEVEL_STRONGBOX:
                mSecurityLevel = "StrongBox"; break;
            default:
                mSecurityLevel = "Unknown";
        }

        /** Create instance of the SecureFile **/
        mSecureFile = new SecureFileImpl(
            new File(getFilesDir(), FILENAME),
            this,
            masterKeyAlias
        );
    }

    private static KeyGenParameterSpec createAES256GCMKeyGenParameterSpec(){
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
            "_androidx_security_master_key_",
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(true);

        return builder.build();
    }
}