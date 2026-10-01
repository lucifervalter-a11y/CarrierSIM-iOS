#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CSConnectionCompletion)(NSError * _Nullable error);

/// Owns only local pairing and the optional local packet tunnel. All public
/// entry points and callback blocks run on the main queue.
@interface CSConnectionManager : NSObject

/// Each target owns a separate pairing record and host identity. nil preserves
/// the original on-device storage location.
- (instancetype)initWithTargetIdentifier:(nullable NSString *)identifier;

@property (nonatomic, copy, nullable) void (^onStatus)(NSString *status);
@property (nonatomic, copy, nullable) void (^onPIN)(NSString *pin);
@property (nonatomic, copy, nullable) CSConnectionCompletion onPairingDone;

@property (nonatomic, copy, readonly) NSString *pairingPath;
@property (nonatomic, copy, readonly) NSString *status;
@property (nonatomic, readonly) BOOL isPairing;
@property (nonatomic, readonly) BOOL isImporting;
@property (nonatomic, readonly) BOOL hasPairing;
@property (nonatomic, readonly) BOOL isVPNConnected;
@property (nonatomic, readonly) BOOL isVPNStarting;
@property (nonatomic, readonly) BOOL supportsOnDevicePairing;
@property (nonatomic, readonly) BOOL hasEmbeddedVPN;

/// Starts the embedded idevice Remote Pairing host. It never replaces an
/// existing valid pairing record until native pairing and validation complete.
- (void)startPairing;
/// Cancels the native listener/handshake. isPairing stays YES until Rust returns.
- (void)cancelPairing;

/// Imports an explicitly selected StikPair Remote Pairing or Lockdown plist.
/// The caller must not pass a network URL. Completion runs on the main queue.
- (void)importPairingAtURL:(NSURL *)url completion:(CSConnectionCompletion)completion;

/// Installs/starts this app's optional local VPN profile. The system may ask
/// the user for VPN permission. Success means the tunnel is connected; device
/// service authentication still needs to be checked by the carrier engine.
- (void)startVPN:(CSConnectionCompletion)completion;
- (void)stopVPN;

/// Explicit user action only. Starts LocalDevVPN using its documented source
/// scheme and returns to carriersim://. This is an optional external fallback.
/// Success means the external app opened, not that device pairing is valid.
- (void)openLocalDevVPN:(CSConnectionCompletion)completion;

/// Call on UIApplication becoming active or receiving carriersim:// callback.
/// Updates the status of this app's profile without claiming remote reachability.
- (void)refreshVPNStatus;

@end

NS_ASSUME_NONNULL_END
