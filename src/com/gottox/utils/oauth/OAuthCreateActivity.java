package com.gottox.utils.oauth;


import oauth.signpost.OAuth;
import oauth.signpost.commonshttp.CommonsHttpOAuthConsumer;
import oauth.signpost.commonshttp.CommonsHttpOAuthProvider;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.webkit.CookieManager;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

public class OAuthCreateActivity extends Activity {
	public final static String OAUTH_CONSUMER_KEY = "OAUTH_CONSUMER_KEY";
	public final static String OAUTH_SECRET_KEY = "OAUTH_SECRET_KEY";
	public final static String OAUTH_ACCESS_URL = "OAUTH_ACCESS_URL";
	public final static String OAUTH_REQUEST_URL = "OAUTH_REQUEST_URL";
	public final static String OAUTH_TOKEN = "OAUTH_TOKEN";
	public final static String OAUTH_TOKEN_SECRET = "OAUTH_TOKEN_SECRET";
	public static final String OAUTH_AUTH_URL = "OAUTH_AUTH_URL";
	enum State {
		INIT, GETTOKEN, LOADLOGIN, ENTERUSER, LOADRESULT, RESULTLOADED, ERROR, SUCCESS
	};

	State state = State.INIT;

	class AuthWebViewClient extends WebViewClient {
		@Override
		public void onPageFinished(WebView view, String url) {
			if (getState() == State.LOADLOGIN) {
				setState(State.ENTERUSER);
			} else if (getState() == State.LOADRESULT) {
				setState(State.RESULTLOADED);
			}
		}

		@Override
		public boolean shouldOverrideUrlLoading(WebView view, String url) {
			if (getState() == State.ENTERUSER) {
				setState(State.LOADRESULT);
			}
			if (url.startsWith(CALLBACK_URI)) {
				returnResult(Uri.parse(url));
				setState(State.SUCCESS);
			} else {
				view.loadUrl(url);
			}
			return true;
		}

		@Override
		public void onReceivedError(WebView view, int errorCode,
				String description, String failingUrl) {
			error(description);
		}

	}

	private static final String CALLBACK_URI = "oauthactivity://authorize";

	private CharSequence accessUrl;
	private CharSequence authUrl;
	private CharSequence reqUrl;
	private Handler handler = new Handler();

	private ProgressBar progress;
	private TextView status;
	private LinearLayout statusLayout;
	private ProgressBar spinner;
	private WebView web;
	private Button finish;

	private CommonsHttpOAuthConsumer consumer;
	private CommonsHttpOAuthProvider provider;
	private Uri authUri = null;

	private CharSequence consumerSecret;
	private CharSequence consumerKey;

	public static void init(Activity context, CharSequence accessUrl,
			CharSequence authUrl, CharSequence reqUrl, CharSequence key,
			CharSequence secret, int id) {
		Intent intent = new Intent(context.getBaseContext(),
				OAuthCreateActivity.class);
		intent.putExtra(OAUTH_CONSUMER_KEY, key);
		intent.putExtra(OAUTH_SECRET_KEY, secret);
		intent.putExtra(OAUTH_ACCESS_URL, accessUrl);
		intent.putExtra(OAUTH_AUTH_URL, authUrl);
		intent.putExtra(OAUTH_REQUEST_URL, reqUrl);
		context.startActivityForResult(intent, id);
	}

	public static void initTwitter(Activity context, CharSequence key,
			CharSequence secret, int id) {
		CharSequence accessUrl = "http://twitter.com/oauth/access_token";
		CharSequence authUrl = "http://twitter.com/oauth/authorize";
		CharSequence reqUrl = "http://twitter.com/oauth/request_token";
		init(context, accessUrl, authUrl, reqUrl, key, secret, id);
	}

	public static CharSequence getToken(Intent i) {
		return i.getCharSequenceExtra("token");
	}

	public static CharSequence getTokenSecret(Intent i) {
		return i.getCharSequenceExtra("tokenSecret");
	}

	public static CharSequence getConsumerKey(Intent i) {
		return i.getCharSequenceExtra("consumerKey");
	}

	public static CharSequence getConsumerSecret(Intent i) {
		return i.getCharSequenceExtra("consumerSecret");
	}

	private void error(CharSequence seq) {
		handler.post(new Runnable() {
			@Override
			public void run() {
				setState(State.ERROR);
			}
		});
	}

	@Override
	public void onCreate(Bundle bundle) {
		super.onCreate(bundle);
		if (getState() == State.INIT) {
			Intent i = getIntent();
			setContentView(R.layout.oauthactivity);
			status = (TextView) this.findViewById(R.id.status);
			finish = (Button) this.findViewById(R.id.finish);
			finish.setOnClickListener(new OnClickListener() {
				@Override
				public void onClick(View v) {
					OAuthCreateActivity.this.finish();
				}
			});
			statusLayout = (LinearLayout) this.findViewById(R.id.statusLayout);
			spinner = (ProgressBar) this.findViewById(R.id.spinner);
			web = (WebView) this.findViewById(R.id.web);
			web.setWebViewClient(new AuthWebViewClient());
			web.getSettings().setSavePassword(false);
			progress = (ProgressBar) this.findViewById(R.id.progress);
			progress.setIndeterminate(false);

			consumerKey = i.getStringExtra(OAUTH_CONSUMER_KEY);
			consumerSecret = i.getStringExtra(OAUTH_SECRET_KEY);
			accessUrl = i.getStringExtra(OAUTH_ACCESS_URL);
			authUrl = i.getStringExtra(OAUTH_AUTH_URL);
			reqUrl = i.getStringExtra(OAUTH_REQUEST_URL);
			startAuth();
		}
	}

	public void startAuth() {
		setState(State.GETTOKEN);
		if (!requestThread.isAlive())
			requestThread.start();
	}

	// TODO replace by AsyncTask
	private Thread requestThread = new Thread("OAuth Consume/provider getter") {
		@Override
		public void run() {
			try {
				consumer = new CommonsHttpOAuthConsumer(consumerKey.toString(),
						consumerSecret.toString());
				provider = new CommonsHttpOAuthProvider(reqUrl.toString(),
						accessUrl.toString(), authUrl.toString());

				provider.setOAuth10a(true); // Must do, according to
											// documentation.
				authUri = Uri.parse(provider.retrieveRequestToken(consumer,
						CALLBACK_URI));
				handler.post(requestFinished);
			} catch (Exception e) {
				Log.e("OAuth", "Cannot retrieve RequestToken", e);
				error("Cannot retrieve RequestToken");
			}
		}
	};

	private Runnable requestFinished = new Runnable() {
		@Override
		public void run() {
			setState(State.LOADLOGIN);
			web.loadUrl(authUri.toString());
		}
	};

	public void returnResult(Uri uri) {
		String verifier = uri.getQueryParameter(OAuth.OAUTH_VERIFIER);
		try {
			provider.retrieveAccessToken(consumer, verifier);
		} catch (Exception e) {
			setResult(Activity.RESULT_CANCELED);
			Log.e(getClass().getName(), "Cannot get AccessToken", e);
			return;
		}
		String token = consumer.getToken();
		String tokenSecret = consumer.getTokenSecret();
		Intent intent = new Intent();
		intent.putExtra(OAUTH_CONSUMER_KEY, consumerKey);
		intent.putExtra(OAUTH_SECRET_KEY, consumerSecret);
		intent.putExtra(OAUTH_TOKEN, token);
		intent.putExtra(OAUTH_TOKEN_SECRET, tokenSecret);
		intent.putExtra(OAUTH_ACCESS_URL, accessUrl);
		intent.putExtra(OAUTH_AUTH_URL, authUrl);
		intent.putExtra(OAUTH_REQUEST_URL, reqUrl);
		setResult(Activity.RESULT_OK, intent);
	}

	@Override
	public void finish() {
		CookieManager cm = CookieManager.getInstance();
		cm.removeAllCookie();
		super.finish();
	}

	public State getState() {
		return state;
	}

	public void setState(State state) {
		int statusString = 0;
		int finishString = 0;
		boolean showbrowser = false;
		boolean active = true;
		int p = 0;
		switch (state) {
		case GETTOKEN:
			statusString = R.string.oauth_gettoken;
			p = 16;
			break;
		case LOADLOGIN:
			statusString = R.string.oauth_loadlogin;
			p = 32;
			break;
		case ENTERUSER:
			showbrowser = true;
			p = 48;
			break;
		case LOADRESULT:
			statusString = R.string.oauth_loadresult;
			p = 64;
			break;
		case RESULTLOADED:
			showbrowser = true;
			p = 80;
			break;
		case ERROR:
			statusString = R.string.oauth_error;
			p = 0;
			active = false;
			finishString = R.string.oauth_dismiss;
			break;
		case SUCCESS:
			statusString = R.string.oauth_success;
			active = false;
			p = 100;
			finishString = R.string.oauth_finish;
			break;
		}
		if (finishString != 0) {
			finish.setText(finishString);
		}
		if (statusString != 0) {
			status.setText(statusString);
		}
		web.setVisibility(showbrowser ? View.VISIBLE : View.INVISIBLE);
		statusLayout
				.setVisibility(!showbrowser ? View.VISIBLE : View.INVISIBLE);
		spinner.setVisibility(active ? View.VISIBLE : View.GONE);
		finish.setVisibility(!active ? View.VISIBLE : View.GONE);
		progress.setProgress(p);
		this.state = state;
	}

	@Override
	protected void onSaveInstanceState(Bundle bundle) {
		super.onSaveInstanceState(bundle);
		bundle.putSerializable("state", state);
	}

	@Override
	protected void onRestoreInstanceState(Bundle bundle) {
		super.onRestoreInstanceState(bundle);
		if (bundle != null)
			setState((State) bundle.getSerializable("state"));
		else
			setState(getState());
	}

	@Override
	protected void onDestroy() {
		super.onDestroy();
	}
}
