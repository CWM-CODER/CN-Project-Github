#ifndef CSMA_CD_HPP
#define CSMA_CD_HPP

#include <string>
#include <vector>
#include <functional>
#include "dll_frame.hpp"
#include "compat_threading.hpp"

namespace DLL {

enum class ChannelState {
    IDLE,
    BUSY,
    COLLISION
};

inline std::string channelStateToString(ChannelState state) {
    switch (state) {
        case ChannelState::IDLE: return "IDLE";
        case ChannelState::BUSY: return "BUSY";
        case ChannelState::COLLISION: return "COLLISION";
        default: return "UNKNOWN";
    }
}

struct CSMACDStats {
    int totalTransmissions;
    int successfulTransmissions;
    int busySenses;
    int collisionsDetected;
    int jamSignalsSent;

    CSMACDStats() : totalTransmissions(0), successfulTransmissions(0),
                    busySenses(0), collisionsDetected(0), jamSignalsSent(0) {}
};

class SharedChannel {
private:
    FastMutex mtx;
    ChannelState state;
    int activeTransmitters;
    int currentTransmitterId;
    uint64_t busyUntilMs;

    // CSMA timing parameters (in milliseconds)
    int slotTimeMs;
    int propagationDelayMs;
    double collisionProbability;

    CSMACDStats stats;

public:
    SharedChannel(int slotTime = 50, int propDelay = 15, double colProb = 0.0);

    // Check if channel is currently idle
    bool isIdle();

    // CSMA/CD Non-persistent transmit attempt
    // Returns true if transmission succeeded, false if aborted due to excessive collisions
    bool attemptTransmit(int nodeId, const DLLFrame& frame,
                         std::function<void(const std::string&)> logCallback,
                         std::function<void(const DLLFrame&)> sendCallback);

    // Force collision simulation
    void triggerSimulatedCollision();

    CSMACDStats getStats();
    void resetStats();
};

} // namespace DLL

#endif // CSMA_CD_HPP
