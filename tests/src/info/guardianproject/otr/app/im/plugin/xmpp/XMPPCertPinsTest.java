
package info.guardianproject.otr.app.im.plugin.xmpp;

import android.content.Context;
import android.os.Build;
import android.test.AndroidTestCase;
import android.util.Log;

import info.guardianproject.cacheword.PRNGFixes;
import info.guardianproject.otr.app.im.R;
import info.guardianproject.otr.app.im.app.AccountActivity;
import info.guardianproject.util.Debug;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.ConnectionConfiguration.SecurityMode;
import org.jivesoftware.smack.ConnectionListener;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.thoughtcrime.ssl.pinning.PinningTrustManager;
import org.thoughtcrime.ssl.pinning.SystemKeyStore;

public class XMPPCertPinsTest extends AndroidTestCase {
    private static final String TAG = "XMPPCertPinsTest";

    SystemKeyStore systemKeyStore;
    PinningTrustManager pinningTrustManager;
    SecureRandom secureRandom;
    XMPPConnection connection;
    String recommendedDomains[];
    String domainsWithPins[];
    String domainsWithoutPins[] = {
            // signed by cacert.org, can't be pinned with AndroidPinning
            "jabber.ccc.de",
            // "vodka-pomme.net",
            // "jabber.cn"
    };

    @Override
    public void setUp() {
        Context c = getContext();
        PRNGFixes.apply();
        systemKeyStore = SystemKeyStore.getInstance(c);
        pinningTrustManager = new PinningTrustManager(systemKeyStore,
                XMPPCertPins.getPinList(), 0);
        secureRandom = new java.security.SecureRandom();
        recommendedDomains = c.getResources().getStringArray(R.array.account_domains);
        ArrayList<String> domains = new ArrayList<String>(Arrays.asList(recommendedDomains));
        domains.add(AccountActivity.DEFAULT_SERVER_FACEBOOK);
        // this one seems to fail a lot of tests
        //domains.add(AccountActivity.DEFAULT_SERVER_JABBERORG);
        // currently fails here, needs SRV tricks
        // domains.add(AccountActivity.DEFAULT_SERVER_GOOGLE);
        domainsWithPins = domains.toArray(new String[domains.size()]);
        connection = null;
    }

    @Override
    public void tearDown() {
        if (connection != null) {
            connection.disconnect();
            connection = null;
        }
    }

    private SSLContext getSSLContext(String protocol) {
        try {
            return SSLContext.getInstance(protocol);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            assertTrue(false);
        }
        return null;
    }

    private ConnectionConfiguration getConfig(String domain) throws KeyManagementException {
        ConnectionConfiguration config = new ConnectionConfiguration(domain, 5222);
        config.setDebuggerEnabled(Debug.DEBUG_ENABLED);
        config.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
        config.setSecurityMode(SecurityMode.required);
        config.setVerifyChainEnabled(true);
        config.setVerifyRootCAEnabled(true);
        config.setExpiredCertificatesCheckEnabled(true);
        config.setNotMatchingDomainCheckEnabled(true);
        config.setSelfSignedCertificateEnabled(false);

        return config;
    }

    private class ShouldSucceedConnectionListener implements ConnectionListener {

        private final String domain;
        public ShouldSucceedConnectionListener(String domain) {
            this.domain = domain;
        }

        @Override
        public void reconnectionSuccessful() {
            Log.i(TAG, "reconnectionSuccessful " + domain);
            assertTrue(false);
        }

        @Override
        public void reconnectionFailed(Exception e) {
            Log.i(TAG, "reconnectionSuccessful "  + domain);
            e.printStackTrace();
            assertTrue(false);
        }

        @Override
        public void reconnectingIn(int arg0) {
            Log.i(TAG, "reconnectingIn " + arg0 + " " + domain);
            assertTrue(false);
        }

        @Override
        public void connectionClosedOnError(Exception e) {
            Log.i(TAG, "connectionClosedOnError " + domain);
            e.printStackTrace();
            assertTrue(false);
        }

        @Override
        public void connectionClosed() {
            Log.i(TAG, "connectionClosed " + domain);
        }
    }

    public void testDomainsWithPins() {
        try {
            for (String domain : domainsWithPins) {
                Log.i(TAG, "TESTING DOMAINS WITH PINS: " + domain);
                ConnectionConfiguration config = getConfig(domain);
                SSLContext sslContext = getSSLContext("TLS");
                sslContext.init(null, new javax.net.ssl.TrustManager[] {
                        pinningTrustManager
                }, secureRandom);
                config.setCustomSSLContext(sslContext);
                connection = new XMPPConnection(config);
                connection.addConnectionListener(new ShouldSucceedConnectionListener(domain));
                connection.connect();
                assertTrue(connection.isConnected());
                assertTrue(connection.isSecureConnection());
                assertTrue(connection.isUsingTLS());
            }
        } catch (KeyManagementException e) {
            Log.e(TAG, "KeyManagementException");
            e.printStackTrace();
            assertTrue(false);
        } catch (XMPPException e) {
            Log.e(TAG, "XMPPException");
            e.printStackTrace();
            assertTrue(false);
        }
    }

    public void testRecommendedDomainsWithTLSV12() {
        if (Build.VERSION.SDK_INT < 16) // TLS v1.2 added in android-16
            return;
        try {
            for (String domain : recommendedDomains) {
                Log.i(TAG, "TESTING RECOMMENDED DOMAINS USING TLS v1.2: " + domain);
                ConnectionConfiguration config = getConfig(domain);
                SSLContext sslContext = getSSLContext("TLSv1.2");
                sslContext.init(null, new javax.net.ssl.TrustManager[] {
                        pinningTrustManager
                }, secureRandom);
                config.setCustomSSLContext(sslContext);
                connection = new XMPPConnection(config);
                connection.addConnectionListener(new ShouldSucceedConnectionListener(domain));
                connection.connect();
                assertTrue(connection.isConnected());
                assertTrue(connection.isSecureConnection());
                assertTrue(connection.isUsingTLS());
            }
        } catch (KeyManagementException e) {
            Log.e(TAG, "KeyManagementException");
            e.printStackTrace();
            assertTrue(false);
        } catch (XMPPException e) {
            Log.e(TAG, "XMPPException");
            e.printStackTrace();
            assertTrue(false);
        }
    }

    public void testSettingCipherSuites() {
        try {
            SSLContext sslContext = getSSLContext("TLS");
            sslContext.init(null, new javax.net.ssl.TrustManager[] {
                    pinningTrustManager
            }, secureRandom);
            for (String domain : domainsWithPins) {
                Log.i(TAG, "TESTING SETTING CIPHER SUITES: " + domain);
                ConnectionConfiguration config = getConfig(domain);
                config.setCustomSSLContext(sslContext);
                if (Build.VERSION.SDK_INT >= 20) {
                    config.setEnabledCipherSuites(XMPPCertPins.SSL_IDEAL_CIPHER_SUITES_API_20);
                } else {
                    config.setEnabledCipherSuites(XMPPCertPins.SSL_IDEAL_CIPHER_SUITES);
                }
                connection = new XMPPConnection(config);
                connection.addConnectionListener(new ShouldSucceedConnectionListener(domain));
                connection.connect();
                assertTrue(connection.isConnected());
                assertTrue(connection.isSecureConnection());
                assertTrue(connection.isUsingTLS());
            }
        } catch (KeyManagementException e) {
            e.printStackTrace();
            assertTrue(false);
        } catch (XMPPException e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }
}
