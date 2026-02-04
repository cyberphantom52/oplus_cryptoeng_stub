// ANCHOR: package
package vendor.oplus.hardware.cryptoeng;
// ANCHOR_END: package

// ANCHOR: ICryptoeng
/** Cryptoeng service interface. */
@VintfStability
interface ICryptoeng {
    /** Invoke a cryptoeng command. */
    byte[] cryptoeng_invoke_command(in byte[] request);
    
    /** Get the interface version. */
    int getInterfaceVersion();
    
    /** Get the interface hash. */
    String getInterfaceHash();
}
