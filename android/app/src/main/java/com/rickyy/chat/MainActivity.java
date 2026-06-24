package com.rickyy.chat;

import android.os.Bundle;
import android.view.View;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    getWindow().getDecorView().setSystemUiVisibility(
      View.SYSTEM_UI_FLAG_LAYOUT_STABLE |
      View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN |
      View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
    );
  }

  @Override
  public void onBackPressed() {
    getBridge().getWebView().evaluateJavascript(
      "if(document.querySelector('.modal.show')){document.querySelector('.modal.show').classList.remove('show');true}" +
      "else if(document.getElementById('profileModal')){document.getElementById('profileModal').remove();true}" +
      "else if(window.currentChat){if(typeof closeChat==='function'){closeChat();}else{history.back();}true}" +
      "else{false}",
      value -> {
        if ("false".equals(value)) {
          moveTaskToBack(true);
        }
      }
    );
  }
}