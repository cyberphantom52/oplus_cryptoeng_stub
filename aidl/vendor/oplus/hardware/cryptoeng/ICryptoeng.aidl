// ANCHOR: package
package vendor.oplus.hardware.cryptoeng;
// ANCHOR_END: package

// ANCHOR: ICryptoeng
/** Cryptoeng service interface. */
@VintfStability
interface ICryptoeng {
    /** Invoke a cryptoeng command. */
    byte[] cryptoeng_invoke_command(in byte[] request);
}
