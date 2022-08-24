package com.es.util;

import androidx.annotation.NonNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileUtil {
    public static boolean write(@NonNull byte[] data, @NonNull String filePath) {
        File file = new File(filePath);
        File fileParent = file.getParentFile();
        if(fileParent != null) {
            if (!fileParent.exists() && !fileParent.mkdirs()) {
                return false;
            }
        }
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            fos.write(data);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return false;
    }
}
