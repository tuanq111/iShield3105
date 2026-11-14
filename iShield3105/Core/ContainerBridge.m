//
//  ContainerBridge.m
//  iShield3105
//
//  Dynamic Private Framework Loader (dlopen / dlsym / NSClassFromString) & Low-Level C Inspectors
//

#import "ContainerBridge.h"
#import <dlfcn.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <resolv.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <sys/sysctl.h>
#import <fcntl.h>
#import <poll.h>
#import <unistd.h>
#import <errno.h>

typedef CFArrayRef _Nullable (*SBSAppIdsFn)(bool onlyActive, bool debuggable);
typedef CFSetRef _Nullable (*SBSSetIdsFn)(void);
typedef CFStringRef _Nullable (*SBSLocalizedAppNameFn)(CFStringRef displayIdentifier);

#pragma mark - Model Implementations

@implementation ISFrameworkLoadStatus
- (instancetype)initWithMCM:(BOOL)mcm
                        sbs:(BOOL)sbs
               coreServices:(BOOL)cs
               mcmContainer:(BOOL)mcmC
                 mcmAppData:(BOOL)mcmA
               mcmPluginKit:(BOOL)mcmP
              mcmSharedData:(BOOL)mcmS
             sbsIdentifiers:(BOOL)sbsIds
                       logs:(NSArray<NSString *> *)logs {
    self = [super init];
    if (self) {
        _mobileContainerManagerLoaded = mcm;
        _springBoardServicesLoaded = sbs;
        _coreServicesLoaded = cs;
        _mcmContainerClassResolved = mcmC;
        _mcmAppDataClassResolved = mcmA;
        _mcmPluginKitClassResolved = mcmP;
        _mcmSharedDataClassResolved = mcmS;
        _sbsDisplayIdentifiersResolved = sbsIds;
        _diagnosticLogs = [logs copy];
    }
    return self;
}
@end

@implementation ISContainerDescriptor
- (instancetype)initWithIdentifier:(NSString *)identifier
                              kind:(NSString *)kind
                               url:(nullable NSURL *)url
                           existed:(BOOL)existed
                        isReadable:(BOOL)isReadable
              sandboxTokenConsumed:(BOOL)sandboxTokenConsumed
                        uuidString:(nullable NSString *)uuidString
                      errorMessage:(nullable NSString *)errorMessage {
    self = [super init];
    if (self) {
        _identifier = [identifier copy];
        _containerKind = [kind copy];
        _url = url;
        _existed = existed;
        _isReadable = isReadable;
        _sandboxTokenConsumed = sandboxTokenConsumed;
        _uuidString = [uuidString copy];
        _errorMessage = [errorMessage copy];
    }
    return self;
}
@end

@implementation ISInstalledAppDescriptor
- (instancetype)initWithBundleID:(NSString *)bundleID
                     displayName:(NSString *)displayName
                 applicationType:(NSString *)appType
                    shortVersion:(nullable NSString *)shortVersion
                dataContainerURL:(nullable NSURL *)dataURL
              groupContainerURLs:(NSDictionary<NSString *, NSURL *> *)groupURLs
               pluginIdentifiers:(NSArray<NSString *> *)plugins
                  signerIdentity:(nullable NSString *)signer {
    self = [super init];
    if (self) {
        _bundleIdentifier = [bundleID copy];
        _displayName = [displayName copy];
        _applicationType = [appType copy];
        _shortVersion = [shortVersion copy];
        _dataContainerURL = dataURL;
        _groupContainerURLs = [groupURLs copy];
        _pluginIdentifiers = [plugins copy];
        _signerIdentity = [signer copy];
    }
    return self;
}
@end

@implementation ISDNSResolverSnapshot
- (instancetype)initWithServers:(NSArray<NSString *> *)servers
                      succeeded:(BOOL)succeeded
                   errorMessage:(nullable NSString *)errorMessage {
    self = [super init];
    if (self) {
        _servers = [servers copy];
        _succeeded = succeeded;
        _errorMessage = [errorMessage copy];
    }
    return self;
}
@end

@implementation ISRuntimeDylibEntry
- (instancetype)initWithIndex:(NSUInteger)index
                         path:(NSString *)path
                         name:(NSString *)name
                 architecture:(nullable NSString *)architecture {
    self = [super init];
    if (self) {
        _imageIndex = index;
        _imagePath = [path copy];
        _imageName = [name copy];
        _architecture = [architecture copy];
    }
    return self;
}
@end

#pragma mark - ISContainerBridge

@interface ISContainerBridge () {
    void *_mcmHandle;
    void *_sbsHandle;
    void *_csHandle;
    void *_libContainerHandle;
    void *_libSandboxHandle;
    BOOL _frameworksAttempted;
}
@property (nonatomic, strong, nullable) ISFrameworkLoadStatus *cachedStatus;
@property (nonatomic, strong) NSMutableSet<NSString *> *consumedSandboxPaths;
@end

@implementation ISContainerBridge

+ (instancetype)sharedBridge {
    static ISContainerBridge *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[ISContainerBridge alloc] init];
        instance.consumedSandboxPaths = [NSMutableSet set];
    });
    return instance;
}

- (ISFrameworkLoadStatus *)loadPrivateFrameworks {
    @synchronized (self) {
        if (_frameworksAttempted && self.cachedStatus != nil) {
            return self.cachedStatus;
        }
        _frameworksAttempted = YES;

        NSMutableArray<NSString *> *logs = [NSMutableArray array];

        const char *mcmPath = "/System/Library/PrivateFrameworks/MobileContainerManager.framework/MobileContainerManager";
        _mcmHandle = dlopen(mcmPath, RTLD_NOW);
        if (_mcmHandle != NULL) {
            [logs addObject:@"dlopen MobileContainerManager.framework: OK"];
        } else {
            const char *err = dlerror();
            [logs addObject:[NSString stringWithFormat:@"dlopen MobileContainerManager.framework failed: %s", err ? err : "unknown"]];
        }

        const char *sbsPath = "/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices";
        _sbsHandle = dlopen(sbsPath, RTLD_NOW);
        if (_sbsHandle != NULL) {
            [logs addObject:@"dlopen SpringBoardServices.framework: OK"];
        } else {
            const char *err = dlerror();
            [logs addObject:[NSString stringWithFormat:@"dlopen SpringBoardServices.framework failed: %s", err ? err : "unknown"]];
        }

        const char *csPath = "/System/Library/Frameworks/CoreServices.framework/CoreServices";
        _csHandle = dlopen(csPath, RTLD_LAZY);
        if (_csHandle == NULL) {
            _csHandle = dlopen("/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_LAZY);
        }
        if (_csHandle != NULL) {
            [logs addObject:@"dlopen CoreServices/MobileCoreServices: OK"];
        } else {
            const char *err = dlerror();
            [logs addObject:[NSString stringWithFormat:@"dlopen CoreServices failed: %s", err ? err : "unknown"]];
        }

        _libContainerHandle = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_LAZY);
        _libSandboxHandle = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_LAZY);
        [logs addObject:[NSString stringWithFormat:@"libsystem_containermanager:%@ libsystem_sandbox:%@",
                         _libContainerHandle ? @"OK" : @"NO",
                         _libSandboxHandle ? @"OK" : @"NO"]];

        Class mcmContainerCls = NSClassFromString(@"MCMContainer");
        Class mcmAppDataCls = NSClassFromString(@"MCMAppDataContainer");
        Class mcmPluginCls = NSClassFromString(@"MCMPluginKitPluginDataContainer");
        Class mcmSharedCls = NSClassFromString(@"MCMSharedDataContainer");

        BOOL sbsFnOk = NO;
        if (_sbsHandle != NULL) {
            void *sym1 = dlsym(_sbsHandle, "SBSCopyApplicationDisplayIdentifiers");
            void *sym2 = dlsym(_sbsHandle, "SBSCopyDisplayIdentifiers");
            sbsFnOk = (sym1 != NULL || sym2 != NULL);
            [logs addObject:[NSString stringWithFormat:@"SpringBoardServices symbols resolved: %@", sbsFnOk ? @"YES" : @"NO"]];
        }

        [logs addObject:[NSString stringWithFormat:@"Classes -> MCMContainer:%@ AppData:%@ PluginKit:%@ Shared:%@",
                         mcmContainerCls ? @"YES" : @"NO",
                         mcmAppDataCls ? @"YES" : @"NO",
                         mcmPluginCls ? @"YES" : @"NO",
                         mcmSharedCls ? @"YES" : @"NO"]];

        ISFrameworkLoadStatus *status = [[ISFrameworkLoadStatus alloc] initWithMCM:(_mcmHandle != NULL)
                                                                               sbs:(_sbsHandle != NULL)
                                                                      coreServices:(_csHandle != NULL)
                                                                      mcmContainer:(mcmContainerCls != nil)
                                                                        mcmAppData:(mcmAppDataCls != nil)
                                                                      mcmPluginKit:(mcmPluginCls != nil)
                                                                     mcmSharedData:(mcmSharedCls != nil)
                                                                    sbsIdentifiers:sbsFnOk
                                                                              logs:logs];
        self.cachedStatus = status;
        return status;
    }
}

#pragma mark - Container Resolution

- (ISContainerDescriptor *)resolveContainerWithClassName:(NSString *)className
                                                    kind:(NSString *)kind
                                              identifier:(NSString *)identifier {
    [self loadPrivateFrameworks];

    NSString *trimmed = [identifier stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (trimmed.length == 0) {
        return [[ISContainerDescriptor alloc] initWithIdentifier:identifier
                                                            kind:kind
                                                             url:nil
                                                         existed:NO
                                                      isReadable:NO
                                            sandboxTokenConsumed:NO
                                                      uuidString:nil
                                                    errorMessage:@"Identifier rỗng."];
    }

    Class containerCls = NSClassFromString(className);
    if (containerCls == nil) {
        return [[ISContainerDescriptor alloc] initWithIdentifier:trimmed
                                                            kind:kind
                                                             url:nil
                                                         existed:NO
                                                      isReadable:NO
                                            sandboxTokenConsumed:NO
                                                      uuidString:nil
                                                    errorMessage:[NSString stringWithFormat:@"Không tìm thấy class %@", className]];
    }

    SEL selector = @selector(containerWithIdentifier:createIfNecessary:existed:error:);
    if (![containerCls respondsToSelector:selector]) {
        return [[ISContainerDescriptor alloc] initWithIdentifier:trimmed
                                                            kind:kind
                                                             url:nil
                                                         existed:NO
                                                      isReadable:NO
                                            sandboxTokenConsumed:NO
                                                      uuidString:nil
                                                    errorMessage:[NSString stringWithFormat:@"%@ không hỗ trợ selector containerWithIdentifier:createIfNecessary:existed:error:", className]];
    }

    typedef id _Nullable (*ContainerWithIdFn)(Class, SEL, NSString *, BOOL, BOOL *, NSError *__autoreleasing *);
    ContainerWithIdFn fn = (ContainerWithIdFn)objc_msgSend;

    BOOL existed = NO;
    NSError *mcmError = nil;
    id containerObj = fn(containerCls, selector, trimmed, NO, &existed, &mcmError);

    if (containerObj == nil) {
        NSString *errMsg = mcmError ? mcmError.localizedDescription : @"Sandbox/Entitlement bị từ chối hoặc Container không tồn tại.";
        return [[ISContainerDescriptor alloc] initWithIdentifier:trimmed
                                                            kind:kind
                                                             url:nil
                                                         existed:existed
                                                      isReadable:NO
                                            sandboxTokenConsumed:NO
                                                      uuidString:nil
                                                    errorMessage:errMsg];
    }

    NSURL *containerURL = nil;
    if ([containerObj respondsToSelector:@selector(url)]) {
        typedef NSURL * _Nullable (*UrlGetterFn)(id, SEL);
        containerURL = ((UrlGetterFn)objc_msgSend)(containerObj, @selector(url));
    }

    // Attempt to consume sandbox extension token if containermanagerd issued one for this MCM container
    BOOL tokenConsumed = NO;
    NSString *containerPath = containerURL.path;
    if (containerPath.length > 0) {
        @synchronized (self) {
            if ([self.consumedSandboxPaths containsObject:containerPath]) {
                tokenConsumed = YES;
            } else {
                SEL lowLevelSel = @selector(getLowLevelContainerObject);
                if ([containerObj respondsToSelector:lowLevelSel] && _libContainerHandle != NULL) {
                    typedef void * _Nullable (*LowLevelObjFn)(id, SEL);
                    typedef char * _Nullable (*CopySandboxTokenFn)(void *);
                    typedef int64_t (*SandboxConsumeFn)(const char *);

                    void *lowLevelObj = ((LowLevelObjFn)objc_msgSend)(containerObj, lowLevelSel);
                    CopySandboxTokenFn copyTokenFn = (CopySandboxTokenFn)dlsym(_libContainerHandle, "container_copy_sandbox_token");
                    SandboxConsumeFn consumeFn = (SandboxConsumeFn)(_libSandboxHandle ? dlsym(_libSandboxHandle, "sandbox_extension_consume") : dlsym(RTLD_DEFAULT, "sandbox_extension_consume"));

                    if (lowLevelObj != NULL && copyTokenFn != NULL && consumeFn != NULL) {
                        char *token = copyTokenFn(lowLevelObj);
                        if (token != NULL) {
                            int64_t handle = consumeFn(token);
                            if (handle >= 0) {
                                tokenConsumed = YES;
                                [self.consumedSandboxPaths addObject:containerPath];
                            }
                            free(token);
                        }
                    }
                }
            }
        }
    }

    BOOL isReadable = NO;
    if (containerPath.length > 0) {
        NSFileManager *fm = [NSFileManager defaultManager];
        if ([fm isReadableFileAtPath:containerPath]) {
            NSError *dirErr = nil;
            NSArray *items = [fm contentsOfDirectoryAtPath:containerPath error:&dirErr];
            isReadable = (items != nil && dirErr == nil);
        }
    }

    NSString *uuidStr = nil;
    if ([containerObj respondsToSelector:@selector(uuid)]) {
        typedef id _Nullable (*UuidGetterFn)(id, SEL);
        id rawUUID = ((UuidGetterFn)objc_msgSend)(containerObj, @selector(uuid));
        if ([rawUUID isKindOfClass:[NSUUID class]]) {
            uuidStr = [(NSUUID *)rawUUID UUIDString];
        } else if ([rawUUID isKindOfClass:[NSString class]]) {
            uuidStr = (NSString *)rawUUID;
        }
    }

    NSString *finalError = nil;
    if (containerURL == nil) {
        finalError = @"Container trả về URL nil.";
    } else if (!isReadable) {
        finalError = @"Đã phân giải URL container nhưng iOS Sandbox chặn đọc thư mục (cần Enterprise MobileHouseArrest trust hoặc phiên bản iOS hỗ trợ).";
    }

    return [[ISContainerDescriptor alloc] initWithIdentifier:trimmed
                                                        kind:kind
                                                         url:containerURL
                                                     existed:existed
                                                  isReadable:isReadable
                                        sandboxTokenConsumed:tokenConsumed
                                                  uuidString:uuidStr
                                                errorMessage:finalError];
}

- (ISContainerDescriptor *)resolveAppDataContainerForBundleIdentifier:(NSString *)bundleIdentifier {
    return [self resolveContainerWithClassName:@"MCMAppDataContainer"
                                          kind:@"AppData"
                                    identifier:bundleIdentifier];
}

- (ISContainerDescriptor *)resolveSharedGroupContainerForIdentifier:(NSString *)groupIdentifier {
    return [self resolveContainerWithClassName:@"MCMSharedDataContainer"
                                          kind:@"AppGroup"
                                    identifier:groupIdentifier];
}

- (ISContainerDescriptor *)resolvePluginKitContainerForIdentifier:(NSString *)pluginIdentifier {
    return [self resolveContainerWithClassName:@"MCMPluginKitPluginDataContainer"
                                          kind:@"PluginKit"
                                    identifier:pluginIdentifier];
}

#pragma mark - Installed App Enumeration

- (nullable NSString *)safeStringFromObject:(id)obj selector:(SEL)sel {
    if (obj != nil && [obj respondsToSelector:sel]) {
        typedef id _Nullable (*IdGetterFn)(id, SEL);
        id val = ((IdGetterFn)objc_msgSend)(obj, sel);
        if ([val isKindOfClass:[NSString class]]) {
            return (NSString *)val;
        }
    }
    return nil;
}

- (nullable NSURL *)safeURLFromObject:(id)obj selector:(SEL)sel {
    if (obj != nil && [obj respondsToSelector:sel]) {
        typedef id _Nullable (*IdGetterFn)(id, SEL);
        id val = ((IdGetterFn)objc_msgSend)(obj, sel);
        if ([val isKindOfClass:[NSURL class]]) {
            return (NSURL *)val;
        }
    }
    return nil;
}

- (nullable NSArray<ISInstalledAppDescriptor *> *)installedApplicationsWithError:(NSError * _Nullable * _Nullable)error {
    (void)error;
    [self loadPrivateFrameworks];

    NSMutableDictionary<NSString *, ISInstalledAppDescriptor *> *byBundleID = [NSMutableDictionary dictionary];

    // 1. Try LSApplicationWorkspace (CoreServices / MobileCoreServices)
    Class workspaceCls = NSClassFromString(@"LSApplicationWorkspace");
    if (workspaceCls != nil && [workspaceCls respondsToSelector:@selector(defaultWorkspace)]) {
        typedef id _Nullable (*DefaultWorkspaceFn)(Class, SEL);
        id workspace = ((DefaultWorkspaceFn)objc_msgSend)(workspaceCls, @selector(defaultWorkspace));
        NSArray *proxies = nil;
        if (workspace != nil) {
            typedef NSArray * _Nullable (*AllAppsFn)(id, SEL);
            if ([workspace respondsToSelector:@selector(allInstalledApplications)]) {
                proxies = ((AllAppsFn)objc_msgSend)(workspace, @selector(allInstalledApplications));
            } else if ([workspace respondsToSelector:@selector(allApplications)]) {
                proxies = ((AllAppsFn)objc_msgSend)(workspace, @selector(allApplications));
            }
        }

        for (id proxy in proxies) {
            NSString *bundleID = [self safeStringFromObject:proxy selector:@selector(applicationIdentifier)]
                              ?: [self safeStringFromObject:proxy selector:@selector(bundleIdentifier)];
            if (bundleID.length == 0) {
                continue;
            }

            NSString *displayName = [self safeStringFromObject:proxy selector:@selector(localizedName)]
                                 ?: [self safeStringFromObject:proxy selector:@selector(itemName)]
                                 ?: bundleID;
            NSString *appType = [self safeStringFromObject:proxy selector:@selector(applicationType)] ?: @"Unknown";
            NSString *shortVersion = [self safeStringFromObject:proxy selector:@selector(shortVersionString)];
            NSString *signer = [self safeStringFromObject:proxy selector:@selector(signerIdentity)];

            NSURL *dataURL = [self safeURLFromObject:proxy selector:@selector(dataContainerURL)];
            if (dataURL == nil) {
                ISContainerDescriptor *resolved = [self resolveAppDataContainerForBundleIdentifier:bundleID];
                dataURL = resolved.url;
            }

            NSMutableDictionary<NSString *, NSURL *> *groupURLs = [NSMutableDictionary dictionary];
            if ([proxy respondsToSelector:@selector(groupContainerURLs)]) {
                typedef id _Nullable (*GroupDictFn)(id, SEL);
                id rawGroups = ((GroupDictFn)objc_msgSend)(proxy, @selector(groupContainerURLs));
                if ([rawGroups isKindOfClass:[NSDictionary class]]) {
                    [(NSDictionary *)rawGroups enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
                        if ([key isKindOfClass:[NSString class]] && [obj isKindOfClass:[NSURL class]]) {
                            groupURLs[(NSString *)key] = (NSURL *)obj;
                        }
                    }];
                }
            }

            NSMutableArray<NSString *> *pluginIDs = [NSMutableArray array];
            if ([proxy respondsToSelector:@selector(plugInKitPlugins)]) {
                typedef id _Nullable (*PluginsFn)(id, SEL);
                id rawPlugins = ((PluginsFn)objc_msgSend)(proxy, @selector(plugInKitPlugins));
                if ([rawPlugins isKindOfClass:[NSArray class]]) {
                    for (id plugin in (NSArray *)rawPlugins) {
                        NSString *pid = [self safeStringFromObject:plugin selector:@selector(pluginIdentifier)]
                                     ?: [self safeStringFromObject:plugin selector:@selector(bundleIdentifier)];
                        if (pid.length > 0) {
                            [pluginIDs addObject:pid];
                        }
                    }
                }
            }

            ISInstalledAppDescriptor *desc = [[ISInstalledAppDescriptor alloc] initWithBundleID:bundleID
                                                                                    displayName:displayName
                                                                                applicationType:appType
                                                                                   shortVersion:shortVersion
                                                                               dataContainerURL:dataURL
                                                                             groupContainerURLs:groupURLs
                                                                              pluginIdentifiers:pluginIDs
                                                                                 signerIdentity:signer];
            byBundleID[bundleID] = desc;
        }
    }

    // 2. Try SpringBoardServices (SBSCopyApplicationDisplayIdentifiers / SBSCopyDisplayIdentifiers)
    if (_sbsHandle != NULL) {
        SBSAppIdsFn sbsCopyAppIds = (SBSAppIdsFn)dlsym(_sbsHandle, "SBSCopyApplicationDisplayIdentifiers");
        SBSSetIdsFn sbsCopyDisplaySet = (SBSSetIdsFn)dlsym(_sbsHandle, "SBSCopyDisplayIdentifiers");
        SBSLocalizedAppNameFn sbsCopyName = (SBSLocalizedAppNameFn)dlsym(_sbsHandle, "SBSCopyLocalizedApplicationNameForDisplayIdentifier");

        NSMutableSet<NSString *> *sbsBundleIDs = [NSMutableSet set];
        if (sbsCopyAppIds != NULL) {
            CFArrayRef arrRef = sbsCopyAppIds(false, false);
            if (arrRef != NULL) {
                NSArray *arr = CFBridgingRelease(arrRef);
                for (id item in arr) {
                    if ([item isKindOfClass:[NSString class]]) {
                        [sbsBundleIDs addObject:(NSString *)item];
                    }
                }
            }
        }
        if (sbsCopyDisplaySet != NULL) {
            CFSetRef setRef = sbsCopyDisplaySet();
            if (setRef != NULL) {
                NSSet *set = CFBridgingRelease(setRef);
                for (id item in set) {
                    if ([item isKindOfClass:[NSString class]]) {
                        [sbsBundleIDs addObject:(NSString *)item];
                    }
                }
            }
        }

        for (NSString *bundleID in sbsBundleIDs) {
            if (byBundleID[bundleID] != nil) {
                continue;
            }
            NSString *name = bundleID;
            if (sbsCopyName != NULL) {
                CFStringRef cfName = sbsCopyName((__bridge CFStringRef)bundleID);
                if (cfName != NULL) {
                    NSString *bridged = CFBridgingRelease(cfName);
                    if (bridged.length > 0) {
                        name = bridged;
                    }
                }
            }
            ISContainerDescriptor *resolved = [self resolveAppDataContainerForBundleIdentifier:bundleID];
            NSString *appType = [bundleID hasPrefix:@"com.apple."] ? @"System" : @"User";
            ISInstalledAppDescriptor *desc = [[ISInstalledAppDescriptor alloc] initWithBundleID:bundleID
                                                                                    displayName:name
                                                                                applicationType:appType
                                                                                   shortVersion:nil
                                                                               dataContainerURL:resolved.url
                                                                             groupContainerURLs:@{}
                                                                              pluginIdentifiers:@[]
                                                                                 signerIdentity:nil];
            byBundleID[bundleID] = desc;
        }
    }

    // 3. Try MCMAppDataContainer bulk enumeration if exposed in current process
    Class mcmAppDataCls = NSClassFromString(@"MCMAppDataContainer");
    SEL allContainersSel = @selector(allContainersForCurrentUserWithError:);
    if (mcmAppDataCls != nil && [mcmAppDataCls respondsToSelector:allContainersSel]) {
        typedef NSArray * _Nullable (*AllContainersFn)(Class, SEL, NSError *__autoreleasing *);
        NSError *mcmListErr = nil;
        NSArray *containers = ((AllContainersFn)objc_msgSend)(mcmAppDataCls, allContainersSel, &mcmListErr);
        for (id container in containers) {
            NSString *bundleID = [self safeStringFromObject:container selector:@selector(identifier)];
            NSURL *url = [self safeURLFromObject:container selector:@selector(url)];
            if (bundleID.length > 0 && byBundleID[bundleID] == nil) {
                NSString *appType = [bundleID hasPrefix:@"com.apple."] ? @"System" : @"User";
                ISInstalledAppDescriptor *desc = [[ISInstalledAppDescriptor alloc] initWithBundleID:bundleID
                                                                                        displayName:bundleID
                                                                                    applicationType:appType
                                                                                       shortVersion:nil
                                                                                   dataContainerURL:url
                                                                                 groupContainerURLs:@{}
                                                                                  pluginIdentifiers:@[]
                                                                                     signerIdentity:nil];
                byBundleID[bundleID] = desc;
            }
        }
    }

    // 4. Always ensure current app container is represented + probe well-known bundles if listing was restricted
    NSString *selfBundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"com.apple.mobile.MobileHouseArrest";
    if (byBundleID[selfBundleID] == nil) {
        NSURL *selfHome = [NSURL fileURLWithPath:NSHomeDirectory() isDirectory:YES];
        ISInstalledAppDescriptor *selfDesc = [[ISInstalledAppDescriptor alloc] initWithBundleID:selfBundleID
                                                                                    displayName:@"iShield3105 (Self)"
                                                                                applicationType:@"User"
                                                                                   shortVersion:[[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"]
                                                                               dataContainerURL:selfHome
                                                                             groupContainerURLs:@{}
                                                                              pluginIdentifiers:@[]
                                                                                 signerIdentity:@"Active Runtime"];
        byBundleID[selfBundleID] = selfDesc;
    }

    if (byBundleID.count <= 1) {
        NSArray<NSString *> *probeBundleIDs = @[
            @"com.apple.mobilesafari",
            @"com.apple.mobilenotes",
            @"com.apple.MobileSMS",
            @"com.apple.Preferences",
            @"com.apple.mobilemail",
            @"com.apple.AppStore",
            @"com.apple.DocumentsApp",
            @"com.apple.camera",
            @"com.apple.mobilecal",
            @"com.apple.weather"
        ];
        for (NSString *probeID in probeBundleIDs) {
            if (byBundleID[probeID] != nil) { continue; }
            ISContainerDescriptor *probeDesc = [self resolveAppDataContainerForBundleIdentifier:probeID];
            if (probeDesc.url != nil) {
                ISInstalledAppDescriptor *appDesc = [[ISInstalledAppDescriptor alloc] initWithBundleID:probeID
                                                                                           displayName:probeID
                                                                                       applicationType:@"System"
                                                                                          shortVersion:nil
                                                                                      dataContainerURL:probeDesc.url
                                                                                    groupContainerURLs:@{}
                                                                                     pluginIdentifiers:@[]
                                                                                        signerIdentity:nil];
                byBundleID[probeID] = appDesc;
            }
        }
    }

    NSArray<ISInstalledAppDescriptor *> *sorted = [[byBundleID allValues] sortedArrayUsingComparator:^NSComparisonResult(ISInstalledAppDescriptor *a, ISInstalledAppDescriptor *b) {
        if (![a.applicationType isEqualToString:b.applicationType]) {
            if ([a.applicationType isEqualToString:@"User"]) return NSOrderedAscending;
            if ([b.applicationType isEqualToString:@"User"]) return NSOrderedDescending;
        }
        return [a.displayName localizedCaseInsensitiveCompare:b.displayName];
    }];

    return sorted;
}

#pragma mark - CFPreferences / cfprefsd Helper

- (nullable id)readCFPreferenceValueForKey:(NSString *)key applicationID:(NSString *)applicationID {
    if (key.length == 0 || applicationID.length == 0) {
        return nil;
    }
    CFPropertyListRef value = CFPreferencesCopyAppValue((__bridge CFStringRef)key, (__bridge CFStringRef)applicationID);
    if (value == NULL) {
        return nil;
    }
    return CFBridgingRelease(value);
}

#pragma mark - DNS Resolver via <resolv.h>

- (ISDNSResolverSnapshot *)fetchSystemDNSServers {
    NSMutableArray<NSString *> *servers = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];

    struct __res_state *res = calloc(1, sizeof(struct __res_state));
    if (res == NULL) {
        return [[ISDNSResolverSnapshot alloc] initWithServers:@[]
                                                    succeeded:NO
                                                 errorMessage:@"Không đủ bộ nhớ cấp phát __res_state."];
    }

    int initResult = res_ninit(res);
    if (initResult != 0) {
        int errCode = errno;
        free(res);
        return [[ISDNSResolverSnapshot alloc] initWithServers:@[]
                                                    succeeded:NO
                                                 errorMessage:[NSString stringWithFormat:@"res_ninit thất bại (errno=%d).", errCode]];
    }

    int nsCount = res->nscount;
    if (nsCount > 0 && nsCount <= MAXNS * 4) {
        union res_9_sockaddr_union *addrUnion = calloc((size_t)nsCount, sizeof(union res_9_sockaddr_union));
        if (addrUnion != NULL) {
            int found = res_getservers(res, addrUnion, nsCount);
            for (int i = 0; i < found; i++) {
                char hostBuffer[NI_MAXHOST] = {0};
                sa_family_t family = addrUnion[i].sin.sin_family;
                if (family == AF_INET) {
                    if (inet_ntop(AF_INET, &(addrUnion[i].sin.sin_addr), hostBuffer, sizeof(hostBuffer)) != NULL) {
                        NSString *ip = [NSString stringWithUTF8String:hostBuffer];
                        if (ip.length > 0 && ![seen containsObject:ip]) {
                            [seen addObject:ip];
                            [servers addObject:ip];
                        }
                    }
                } else if (family == AF_INET6) {
#ifdef IN6ADDR_ANY_INIT
                    if (inet_ntop(AF_INET6, &(addrUnion[i].sin6.sin6_addr), hostBuffer, sizeof(hostBuffer)) != NULL) {
                        NSString *ip = [NSString stringWithUTF8String:hostBuffer];
                        if (ip.length > 0 && ![seen containsObject:ip]) {
                            [seen addObject:ip];
                            [servers addObject:ip];
                        }
                    }
#endif
                }
            }
            free(addrUnion);
        }
    }

    // Fallback to IPv4 nsaddr_list in __res_state if res_getservers yielded nothing
    if (servers.count == 0 && res->nscount > 0) {
        int limit = res->nscount < MAXNS ? res->nscount : MAXNS;
        for (int i = 0; i < limit; i++) {
            struct sockaddr_in sin = res->nsaddr_list[i];
            if (sin.sin_family == AF_INET && sin.sin_addr.s_addr != 0) {
                char ipBuf[INET_ADDRSTRLEN] = {0};
                if (inet_ntop(AF_INET, &sin.sin_addr, ipBuf, sizeof(ipBuf)) != NULL) {
                    NSString *ip = [NSString stringWithUTF8String:ipBuf];
                    if (ip.length > 0 && ![seen containsObject:ip]) {
                        [seen addObject:ip];
                        [servers addObject:ip];
                    }
                }
            }
        }
    }

    res_ndestroy(res);
    free(res);

    return [[ISDNSResolverSnapshot alloc] initWithServers:servers
                                                succeeded:YES
                                             errorMessage:nil];
}

#pragma mark - Dynamic Libraries & Anti-Debug & Loopback Socket Checks

- (NSArray<ISRuntimeDylibEntry *> *)loadedDynamicLibraries {
    uint32_t count = _dyld_image_count();
    NSMutableArray<ISRuntimeDylibEntry *> *entries = [NSMutableArray arrayWithCapacity:count];

    for (uint32_t i = 0; i < count; i++) {
        const char *cName = _dyld_get_image_name(i);
        if (cName == NULL) {
            continue;
        }
        NSString *path = [NSString stringWithUTF8String:cName];
        if (path.length == 0) {
            continue;
        }
        NSString *fileName = [path lastPathComponent] ?: path;

        NSString *arch = nil;
        const struct mach_header *header = _dyld_get_image_header(i);
        if (header != NULL) {
            if (header->cputype == CPU_TYPE_ARM64) {
                cpu_subtype_t subtype = (header->cpusubtype & ~CPU_SUBTYPE_MASK);
                arch = (subtype == CPU_SUBTYPE_ARM64E) ? @"arm64e" : @"arm64";
            } else if (header->cputype == CPU_TYPE_X86_64) {
                arch = @"x86_64";
            }
        }

        [entries addObject:[[ISRuntimeDylibEntry alloc] initWithIndex:i
                                                                 path:path
                                                                 name:fileName
                                                         architecture:arch]];
    }

    return entries;
}

- (BOOL)isDebuggerAttached {
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));

    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) {
        return NO;
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

- (BOOL)isLocalhostPortOpen:(uint16_t)port timeoutMilliseconds:(int)timeoutMs {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return NO;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    int conn = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    BOOL isOpen = NO;

    if (conn == 0) {
        isOpen = YES;
    } else if (errno == EINPROGRESS) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;

        int waitRes = poll(&pfd, 1, timeoutMs);
        if (waitRes > 0 && (pfd.revents & POLLOUT)) {
            int soError = 0;
            socklen_t len = sizeof(soError);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len) == 0 && soError == 0) {
                isOpen = YES;
            }
        }
    }

    close(fd);
    return isOpen;
}

@end
