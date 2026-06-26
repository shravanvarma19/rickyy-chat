package com.rickyy.chat;

import android.os.Bundle;
import androidx.activity.OnBackPressedCallback;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
      @Override
      public void handleOnBackPressed() {
        getBridge().getWebView().evaluateJavascript(
          "if(window.currentChat && typeof closeChat==='function'){closeChat();'handled'}else if(history.length>1){history.back();'handled'}else{'exit'}",
          value -> {
            if (value != null && value.contains("exit")) {
              moveTaskToBack(true);
            }
          }
        );
      }
    });
  }
}