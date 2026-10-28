// Frida RPC bridge: exposes the app's native crypto oracle to the host.
//
// The DES layer lives inside libpowervpn.so and calls back into the JVM
// (Cipher/DESKeySpec/IvParameterSpec/Base64). Under ARM translation that code is
// not hookable, so we call it through the Java layer instead:
//   OpenVpnManager.d(ctx, plain) -> cipher   (encrypt)
//   OpenVpnManager.b(ctx, cipher) -> plain   (decrypt)
//   com.shuttlevpn...i6 (C0125i6) is the Context wrapper that spoofs
//   package name + signature, which the key derivation depends on.
rpc.exports = {
    init: function () {
        var out = {};
        Java.perform(function () {
            var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
            var wk = Java.use('i6').$new(ctx);
            var OVM = Java.use('com.free.vpn.openvpn.OpenVpnManager');
            OVM.d(wk, 'warmup');            // force System.loadLibrary("powervpn")
            globalThis.__wk = wk;
            globalThis.__OVM = OVM;
            out.pkg = ctx.getPackageName();
            out.filesDir = ctx.getFilesDir().getAbsolutePath();
            out.spoofPkg = wk.getPackageName();
        });
        return out;
    },
    enc: function (plain) { return globalThis.__OVM.d(globalThis.__wk, plain); },
    dec: function (cipher) { return globalThis.__OVM.f(globalThis.__wk, cipher); },
    decb: function (cipher) { return globalThis.__OVM.b(globalThis.__wk, cipher); },
    encb: function (plain) { return globalThis.__OVM.b(globalThis.__wk, plain); }
};
