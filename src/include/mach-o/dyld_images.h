#ifndef _DYLD_IMAGES_
#define _DYLD_IMAGES_

typedef	unsigned char	__darwin_uuid_t[16];
typedef __darwin_uuid_t	uuid_t;

enum dyld_image_mode
{
  dyld_image_adding = 0,
  dyld_image_removing = 1,
  dyld_image_info_change = 2
};

struct dyld_image_info
{
  const struct mach_header* imageLoadAddress;
  const char* imageFilePath;
  uintptr_t imageFileModDate;
};

struct dyld_uuid_info
{
  const struct mach_header* imageLoadAddress;
  uuid_t imageUUID;
};

typedef void (*dyld_image_notifier)(enum dyld_image_mode mode, uint32_t infoCount, const struct dyld_image_info info[]);

enum
{
  dyld_error_kind_none = 0,
  dyld_error_kind_dylib_missing = 1,
  dyld_error_kind_dylib_wrong_arch = 2,
  dyld_error_kind_dylib_version = 3,
  dyld_error_kind_symbol_missing = 4
};

struct dyld_all_image_infos
{
  uint32_t version;
  uint32_t infoArrayCount;
  const struct dyld_image_info* infoArray;
  dyld_image_notifier notification;
  bool processDetachedFromSharedRegion;

  bool libSystemInitialized;
  const struct mach_header* dyldImageLoadAddress;

  void* jitInfo;

  const char* dyldVersion;
  const char* errorMessage;
  uintptr_t terminationFlags;

  void* coreSymbolicationShmPage;

  uintptr_t systemOrderFlag;

  uintptr_t uuidArrayCount;
  const struct dyld_uuid_info* uuidArray;

  struct dyld_all_image_infos* dyldAllImageInfosAddress;

  uintptr_t initialImageCount;

  uintptr_t errorKind;
  const char* errorClientOfDylibPath;
  const char* errorTargetDylibPath;
  const char* errorSymbol;

  uintptr_t sharedCacheSlide;

  uint8_t sharedCacheUUID[16];

  uintptr_t reserved[16];
};

struct dyld_shared_cache_ranges
{
  uintptr_t sharedRegionsCount;
  struct
  {
    uintptr_t start;
    uintptr_t length;
  } ranges[4];
};

#endif
