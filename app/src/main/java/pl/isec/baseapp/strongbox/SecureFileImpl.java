package pl.isec.baseapp.strongbox;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.security.crypto.EncryptedFile;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

public final class SecureFileImpl extends SecureFile {
    public SecureFileImpl(
            @NonNull File file,
            @NonNull Context context,
            @NonNull String keyAlias
    ){
        super(file, context, keyAlias);
    }

    @Override
    public void openFileInput(@NonNull OpenFileInputCallback callback) {
        try {
            callback.onInputStreamReady(
                    getEncryptedFile().openFileInput()
            );
        } catch (GeneralSecurityException | IOException e) {
            callback.onError(e.getMessage());
        }
    }

    @Override
    public void openFileOutput(@NonNull OpenFileOutputCallback callback){
        try {
            mFile.delete();
            callback.onOutputStreamReady(
                    getEncryptedFile().openFileOutput()
            );
        } catch (GeneralSecurityException | IOException e) {
            callback.onError(e.getMessage());
        }
    }

    private EncryptedFile getEncryptedFile() throws GeneralSecurityException, IOException {
        return new EncryptedFile.Builder(
                mFile,
                mContext,
                mKeyAlias,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build();
    }
}
