//
//  ContainerBridge.h
//  iShieldPro
//
//  Private Framework & Low-Level C/ObjC System Bridge
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#pragma mark - Hidden Private Framework Declarations (MobileContainerManager)

@interface MCMContainer : NSObject
@property (nonatomic, readonly, nullable) NSURL *url;
@property (nonatomic, readonly, nullable) NSString *identifier;
@property (nonatomic, readonly, nullable) NSUUID *uuid;
@property (nonatomic, readonly) BOOL isTemporary;
+ (nullable instancetype)containerWithIdentifier:(NSString *)identifier
                               createIfNecessary:(BOOL)createIfNecessary
                                         existed:(nullable BOOL *)existed
                                           error:(NSError * _Nullable * _Nullable)error;
+ (nullable NSArray<MCMContainer *> *)allContainersForCurrentUserWithError:(NSError * _Nullable * _Nullable)error;
@end

@interface MCMAppDataContainer : MCMContainer
@end

@interface MCMPluginKitPluginDataContainer : MCMContainer
@end

@interface MCMSharedDataContainer : MCMContainer
@end

#pragma mark - Bridge Data Transfer Objects

@interface ISFrameworkLoadStatus : NSObject
@property (nonatomic, readonly) BOOL mobileContainerManagerLoaded;
@property (nonatomic, readonly) BOOL springBoardServicesLoaded;
@property (nonatomic, readonly) BOOL coreServicesLoaded;
@property (nonatomic, readonly) BOOL mcmContainerClassResolved;
@property (nonatomic, readonly) BOOL mcmAppDataClassResolved;
@property (nonatomic, readonly) BOOL mcmPluginKitClassResolved;
@property (nonatomic, readonly) BOOL mcmSharedDataClassResolved;
@property (nonatomic, readonly) BOOL sbsDisplayIdentifiersResolved;
@property (nonatomic, readonly, copy) NSArray<NSString *> *diagnosticLogs;
@end

@interface ISContainerDescriptor : NSObject
@property (nonatomic, readonly, copy) NSString *identifier;
@property (nonatomic, readonly, copy) NSString *containerKind;
@property (nonatomic, readonly, nullable) NSURL *url;
@property (nonatomic, readonly) BOOL existed;
@property (nonatomic, readonly) BOOL isReadable;
@property (nonatomic, readonly) BOOL sandboxTokenConsumed;
@property (nonatomic, readonly, copy, nullable) NSString *uuidString;
@property (nonatomic, readonly, copy, nullable) NSString *errorMessage;
@end

@interface ISInstalledAppDescriptor : NSObject
@property (nonatomic, readonly, copy) NSString *bundleIdentifier;
@property (nonatomic, readonly, copy) NSString *displayName;
@property (nonatomic, readonly, copy) NSString *applicationType;
@property (nonatomic, readonly, copy, nullable) NSString *shortVersion;
@property (nonatomic, readonly, nullable) NSURL *bundleURL;
@property (nonatomic, readonly, nullable) NSURL *dataContainerURL;
@property (nonatomic, readonly, copy) NSDictionary<NSString *, NSURL *> *groupContainerURLs;
@property (nonatomic, readonly, copy) NSArray<NSString *> *pluginIdentifiers;
@property (nonatomic, readonly, copy, nullable) NSString *signerIdentity;
@end

@interface ISDNSResolverSnapshot : NSObject
@property (nonatomic, readonly, copy) NSArray<NSString *> *servers;
@property (nonatomic, readonly) BOOL succeeded;
@property (nonatomic, readonly, copy, nullable) NSString *errorMessage;
@end

@interface ISRuntimeDylibEntry : NSObject
@property (nonatomic, readonly) NSUInteger imageIndex;
@property (nonatomic, readonly, copy) NSString *imagePath;
@property (nonatomic, readonly, copy) NSString *imageName;
@property (nonatomic, readonly, copy, nullable) NSString *architecture;
@end

@interface ISInterfaceTrafficSample : NSObject
@property (nonatomic, readonly, copy) NSString *interfaceName;
@property (nonatomic, readonly) BOOL isUp;
@property (nonatomic, readonly) BOOL isRunning;
@property (nonatomic, readonly) uint64_t receivedBytes;
@property (nonatomic, readonly) uint64_t sentBytes;
@property (nonatomic, readonly) uint64_t receivedPackets;
@property (nonatomic, readonly) uint64_t sentPackets;
@end

@interface ISProcessTelemetrySnapshot : NSObject
@property (nonatomic, readonly) uint64_t residentMemoryBytes;
@property (nonatomic, readonly) uint64_t virtualMemoryBytes;
@property (nonatomic, readonly) NSUInteger activeThreadCount;
@property (nonatomic, readonly) BOOL debuggerAttached;
@end

#pragma mark - ISContainerBridge

@interface ISContainerBridge : NSObject

+ (instancetype)sharedBridge;

/// Dynamically loads MobileContainerManager, SpringBoardServices, and CoreServices via dlopen.
- (ISFrameworkLoadStatus *)loadPrivateFrameworks;

/// Enumerates installed applications using SpringBoardServices, LSApplicationWorkspace, and MCM fallback.
- (nullable NSArray<ISInstalledAppDescriptor *> *)installedApplicationsWithError:(NSError * _Nullable * _Nullable)error;

/// Resolves Data Container URL via MCMAppDataContainer containerWithIdentifier:createIfNecessary:existed:error:.
- (ISContainerDescriptor *)resolveAppDataContainerForBundleIdentifier:(NSString *)bundleIdentifier;

/// Resolves App Group Container URL via MCMSharedDataContainer containerWithIdentifier:createIfNecessary:existed:error:.
- (ISContainerDescriptor *)resolveSharedGroupContainerForIdentifier:(NSString *)groupIdentifier;

/// Resolves PluginKit Container URL via MCMPluginKitPluginDataContainer containerWithIdentifier:createIfNecessary:existed:error:.
- (ISContainerDescriptor *)resolvePluginKitContainerForIdentifier:(NSString *)pluginIdentifier;

/// Reads a preference value through CFPreferencesCopyAppValue (cfprefsd).
- (nullable id)readCFPreferenceValueForKey:(NSString *)key applicationID:(NSString *)applicationID;

/// Reads active system DNS nameservers using <resolv.h> (res_ninit / res_getservers / nsaddr_list).
- (ISDNSResolverSnapshot *)fetchSystemDNSServers;

/// Enumerates all dynamic libraries loaded in the current process via _dyld_image_count / _dyld_get_image_name.
- (NSArray<ISRuntimeDylibEntry *> *)loadedDynamicLibraries;

/// Checks whether the current process is attached to a debugger via sysctl P_TRACED.
- (BOOL)isDebuggerAttached;

/// Probes TCP loopback 127.0.0.1 on the given port with non-blocking timeout (milliseconds).
- (BOOL)isLocalhostPortOpen:(uint16_t)port timeoutMilliseconds:(int)timeoutMs;

/// Samples kernel-level network interface RX/TX byte counters (AF_LINK / if_data).
- (NSArray<ISInterfaceTrafficSample *> *)fetchNetworkTrafficSamples;

/// Captures Mach task memory/thread telemetry and debugger status for background anomaly monitoring.
- (ISProcessTelemetrySnapshot *)fetchProcessTelemetry;

@end

NS_ASSUME_NONNULL_END
