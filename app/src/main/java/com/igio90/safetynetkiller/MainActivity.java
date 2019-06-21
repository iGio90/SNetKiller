package com.igio90.safetynetkiller;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import android.app.Dialog;
import android.content.DialogInterface;
import android.content.res.AssetManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.chrisplus.rootmanager.RootManager;
import com.chrisplus.rootmanager.container.Result;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private static final String FRIDA = "frida-inject-12.6.8";
    private static final String AGENT = "agent-2019-06-21.js";
    private static final String TARGET = "com.google.android.gms";

    private File mInjectorPath;
    private File mAgentPath;

    private Button mBtnInject;
    private TextView mPid;

    enum STATE {
        NOT_FOUND,
        NOT_ATTACHED,
        ATTACHED
    }

    private STATE mState = STATE.NOT_FOUND;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mPid = findViewById(R.id.pid);
        mBtnInject = findViewById(R.id.inject);
        mBtnInject.setOnClickListener(this);

        mInjectorPath = new File(getFilesDir(), FRIDA);
        mAgentPath = new File(getFilesDir(), AGENT);

        boolean pass = false;
        if (RootManager.getInstance().hasRooted()) {
            if (RootManager.getInstance().obtainPermission()) {
                pass = true;
            }
        }

        if (pass) {
            extractFrida();
        } else {
            sDialog("Failed to obtain root permissions", true);
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        checkFridaInjected();
    }

    private void extractFrida() {
        if (!mInjectorPath.exists()) {
            String fileName = FRIDA + "-android-arm" + (
                    Build.CPU_ABI.contains("arm64") ? "64" : "");
            if (extractFile(fileName, mInjectorPath)) {
                RootManager.getInstance().runCommand("chmod 755 " + mInjectorPath.getPath());
            } else {
                sDialog("failed to extract frida server", true);
                return;
            }
        }

        // todo: remove this later
        extractFile(AGENT, mAgentPath);

        if (!mAgentPath.exists()) {
            if (!extractFile(AGENT, mAgentPath)) {
                sDialog("failed to extract agent", true);
            }
        }
    }

    private void checkFridaInjected() {
        String res = RootManager.getInstance().runCommand("pidof " + TARGET).getMessage()
                .replace("\n", "");
        if (!res.isEmpty()) {
            try {
                int pid = Integer.parseInt(res);
                mPid.setText("google services pid: " + res);
                res = RootManager.getInstance().runCommand("cat /proc/" + pid + "/maps").getMessage();
                mState = res.contains("frida") ? STATE.ATTACHED : STATE.NOT_ATTACHED;
            } catch (Exception e) {
                mState = STATE.NOT_FOUND;
            }
        } else {
            mState = STATE.NOT_FOUND;
        }

        setupUI();
    }

    private void setupUI() {
        switch (mState) {
            case NOT_FOUND:
                mPid.setText(getString(R.string.proc_not_found));
                mBtnInject.setText(getString(R.string.refresh));
                break;
            case ATTACHED:
                mBtnInject.setText(getString(R.string.restore));
                break;
            case NOT_ATTACHED:
                mBtnInject.setText(getString(R.string.attach));
                break;
        }
    }

    private boolean extractFile(String fileName, File dest) {
        AssetManager assetManager = this.getAssets();
        InputStream in;
        OutputStream out;
        try {
            in = assetManager.open(fileName);
            out = new FileOutputStream(dest);

            byte[] buffer = new byte[1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            in.close();
            out.flush();
            out.close();
        } catch (Exception e) {
            sDialog("Failed to extrace frida injector:\n" + e.toString(), true);
            return false;
        }
        return true;
    }

    private void sDialog(String msg, final boolean fatal) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setMessage(msg);
        builder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialogInterface, int i) {
                if (fatal) {
                    finish();
                }
                dialogInterface.dismiss();
            }
        });
        AlertDialog dialog = builder.create();
        dialog.setCanceledOnTouchOutside(false);
        dialog.show();
    }

    @Override
    public void onClick(View view) {
        switch (mState) {
            case NOT_FOUND:
                break;
            case ATTACHED:
                RootManager.getInstance().killProcessByName(TARGET);
                break;
            case NOT_ATTACHED:
                RootManager.getInstance().runCommand("./" + mInjectorPath + " -n " +
                        TARGET + " -s " + mAgentPath + " -e");
                break;
        }

        checkFridaInjected();
    }
}
