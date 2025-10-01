#include "network.h"
#include <string.h>
#include <zephyr/kernel.h>
#include <openthread/thread.h>
#include <openthread/dataset.h>
#include <openthread/ip6.h>
#include <openthread/error.h>

void configure_thread_network_leader(otInstance *instance)
{
    otOperationalDataset dataset;
    memset(&dataset, 0, sizeof(dataset));

    // Samme netværksnavn som leader
    const char *networkName = "TestNet";
    memcpy(dataset.mNetworkName.m8, networkName, strlen(networkName));
    dataset.mComponents.mIsNetworkNamePresent = true;

    // Samme Network Key
    const uint8_t networkKey[OT_NETWORK_KEY_SIZE] =
        { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    memcpy(dataset.mNetworkKey.m8, networkKey, sizeof(networkKey));
    dataset.mComponents.mIsNetworkKeyPresent = true;

    // PAN ID
    dataset.mPanId = 0x1234;
    dataset.mComponents.mIsPanIdPresent = true;

    // Channel
    dataset.mChannel = 20;
    dataset.mComponents.mIsChannelPresent = true;

    // Extended PAN ID
    const uint8_t extPanId[OT_EXT_PAN_ID_SIZE] =
        { 0x68, 0xdd, 0x05, 0x98, 0x63, 0x26, 0x54, 0x3b };
    memcpy(dataset.mExtendedPanId.m8, extPanId, sizeof(extPanId));
    dataset.mComponents.mIsExtendedPanIdPresent = true;

    // Mesh Local Prefix
    otIp6Prefix prefix;
    memset(&prefix, 0, sizeof(prefix));
    prefix.mPrefix.mFields.m8[0] = 0xfd;
    prefix.mPrefix.mFields.m8[1] = 0xc2;
    prefix.mPrefix.mFields.m8[2] = 0x26;
    prefix.mPrefix.mFields.m8[3] = 0x5f;
    prefix.mPrefix.mFields.m8[4] = 0x92;
    prefix.mPrefix.mFields.m8[5] = 0x88;
    prefix.mPrefix.mFields.m8[6] = 0x9e;
    prefix.mPrefix.mFields.m8[7] = 0x0a;
    prefix.mLength = 64;
    memcpy(&dataset.mMeshLocalPrefix, &prefix, sizeof(prefix));
    dataset.mComponents.mIsMeshLocalPrefixPresent = true;

    // Active Timestamp (samme struktur som Leader)
    dataset.mActiveTimestamp.mSeconds = 1;
    dataset.mActiveTimestamp.mTicks = 0;
    dataset.mActiveTimestamp.mAuthoritative = 0;
    dataset.mComponents.mIsActiveTimestampPresent = true;

    // Commit dataset
    otDatasetSetActive(instance, &dataset);

    // Konfigurer som Sleepy End Device (SED)
    otLinkModeConfig mode;
    memset(&mode, 0, sizeof(mode));
    mode.mRxOnWhenIdle = false; // Sparer strøm
    mode.mDeviceType   = false; // false = end device (ikke router)
    mode.mNetworkData  = false; // ikke fuld netværksdata
    otThreadSetLinkMode(instance, mode);

    // Poll interval (hvor tit den spørger parent om trafik) i ms
    otLinkSetPollPeriod(instance, 10000);

    // Enable IPv6 + Thread
    otIp6SetEnabled(instance, true);
    otThreadSetEnabled(instance, true);
}
