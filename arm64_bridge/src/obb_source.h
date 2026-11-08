#pragma once

#include <android/asset_manager.h>

#include <cstdint>
#include <string>

constexpr char kBridgeObbName[] = "main.507.com.stainlessgames.carmageddon.obb";
constexpr uint32_t kBridgeObbSize = 78692000u;

// A caller owns and closes fd. offset is the start of the whole, original OBB;
// DATA_ANDROID.WAD begins 40 bytes later. Never treat this as a loose WAD.
struct BridgeObbHandle {
    int fd = -1;
    int64_t offset = 0;
    uint32_t length = 0;
};

// The framework's ANativeActivity::obbPath is a directory, not a file. This
// selects one fully checked source for the entire process: embedded first,
// then a pre-existing external OBB. There is no device-side extraction.
bool BridgeInitializeObbSource(AAssetManager* manager, const char* obb_directory);
bool BridgeOpenSelectedObb(BridgeObbHandle* out);
bool BridgeIsObbPath(const char* path);
std::string BridgeObbGuestPath();
const char* BridgeSelectedObbSourceName();
