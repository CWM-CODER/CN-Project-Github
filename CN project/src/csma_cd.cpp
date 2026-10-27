#include "../include/csma_cd.hpp"
#include <iostream>
#include <sstream>
#include <cstdlib>

namespace DLL {

SharedChannel::SharedChannel(int slotTime, int propDelay, double colProb)
    : state(ChannelState::IDLE), activeTransmitters(0), currentTransmitterId(-1),
      busyUntilMs(0), slotTimeMs(slotTime), propagationDelayMs(propDelay),
      collisionProbability(colProb) {}

bool SharedChannel::isIdle() {
    FastLock lock(mtx);
    uint64_t now = getTimestampMs();
    return (state == ChannelState::IDLE && now >= busyUntilMs && activeTransmitters == 0);
}

bool SharedChannel::attemptTransmit(int nodeId, const DLLFrame& frame,
                                    std::function<void(const std::string&)> logCallback,
                                    std::function<void(const DLLFrame&)> sendCallback) {
    const int maxAttempts = 16;
    int collisionCount = 0;

    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        // Step 1: Carrier Sensing (Non-persistent strategy)
        bool channelFree = false;
        {
            FastLock lock(mtx);
            uint64_t now = getTimestampMs();
            if (state == ChannelState::IDLE && now >= busyUntilMs && activeTransmitters == 0) {
                channelFree = true;
            }
        }

        if (!channelFree) {
            stats.busySenses++;
            // Non-persistent CSMA: Do NOT continuously sense!
            // Wait a random duration before checking again.
            int waitSlots = (std::rand() % 4) + 1; // 1 to 4 slots
            int waitMs = waitSlots * slotTimeMs + (std::rand() % 25);

            std::ostringstream ss;
            ss << "[CSMA/CD] Node " << nodeId << " senses channel: BUSY! "
               << "(Non-persistent: backoff " << waitMs << "ms before re-sensing)";
            logCallback(ss.str());

            sleepMs(waitMs);
            continue; // Re-sense after waiting
        }

        // Step 2: Channel is Idle -> Begin Transmission immediately
        {
            FastLock lock(mtx);
            state = ChannelState::BUSY;
            activeTransmitters++;
            currentTransmitterId = nodeId;
        }

        {
            std::ostringstream ss;
            ss << "[CSMA/CD] Node " << nodeId << " senses channel: IDLE. "
               << "Initiating transmission (Attempt " << attempt << "/" << maxAttempts << ")...";
            logCallback(ss.str());
        }

        // Step 3: Collision Detection during propagation window (tau)
        sleepMs(propagationDelayMs);

        bool collisionOccurred = false;
        {
            FastLock lock(mtx);
            if (activeTransmitters > 1 || state == ChannelState::COLLISION) {
                collisionOccurred = true;
            } else if (collisionProbability > 0.0) {
                double r = static_cast<double>(std::rand()) / RAND_MAX;
                if (r < collisionProbability) {
                    collisionOccurred = true;
                }
            }
        }

        if (collisionOccurred) {
            collisionCount++;
            stats.collisionsDetected++;

            // Step 4: Collision Handling -> Abort & Send Jam Signal
            {
                FastLock lock(mtx);
                state = ChannelState::COLLISION;
            }

            {
                std::ostringstream ss;
                ss << "[CSMA/CD] !!! COLLISION DETECTED on medium for Node " << nodeId << "!";
                logCallback(ss.str());
            }

            // Broadcast 32-bit JAM Signal
            DLLFrame jamFrame = DLLFrame::createJam(static_cast<uint8_t>(nodeId));
            sendCallback(jamFrame);
            stats.jamSignalsSent++;

            {
                std::ostringstream ss;
                ss << "[CSMA/CD] Node " << nodeId << " broadcasting 32-bit JAM SIGNAL (0xAAAAAAAA) to clear channel...";
                logCallback(ss.str());
            }

            // Release channel after jam signal
            sleepMs(20);
            {
                FastLock lock(mtx);
                activeTransmitters = 0;
                state = ChannelState::IDLE;
            }

            // Step 5: Truncated Binary Exponential Backoff (BEB)
            int k = (collisionCount < 10) ? collisionCount : 10;
            int maxSlotVal = (1 << k) - 1;
            int chosenSlot = (maxSlotVal > 0) ? (std::rand() % (maxSlotVal + 1)) : 0;
            int backoffTimeMs = chosenSlot * slotTimeMs + (std::rand() % 15);

            {
                std::ostringstream ss;
                ss << "[CSMA/CD] Node " << nodeId << " applying Binary Exponential Backoff: "
                   << "k=" << k << " (range [0.." << maxSlotVal << "]), chosen slot=" << chosenSlot
                   << " -> Waiting " << backoffTimeMs << "ms before retransmission";
                logCallback(ss.str());
            }

            sleepMs(backoffTimeMs);
            continue; // Retry after backoff
        }

        // Step 6: Successful transmission without collision
        int txTimeMs = 30 + static_cast<int>(frame.payload.size() * 2);
        {
            FastLock lock(mtx);
            busyUntilMs = getTimestampMs() + txTimeMs;
            activeTransmitters = 0;
            state = ChannelState::IDLE;
            stats.successfulTransmissions++;
            stats.totalTransmissions++;
        }

        {
            std::ostringstream ss;
            ss << "[CSMA/CD] Node " << nodeId << " medium capture verified. Channel clear! Sending frame onto wire...";
            logCallback(ss.str());
        }

        sendCallback(frame);
        return true;
    }

    {
        std::ostringstream ss;
        ss << "[CSMA/CD] Error: Node " << nodeId << " exceeded maximum collision retries (16). Frame aborted!";
        logCallback(ss.str());
    }
    return false;
}

void SharedChannel::triggerSimulatedCollision() {
    FastLock lock(mtx);
    state = ChannelState::COLLISION;
    activeTransmitters = 2;
}

CSMACDStats SharedChannel::getStats() {
    FastLock lock(mtx);
    return stats;
}

void SharedChannel::resetStats() {
    FastLock lock(mtx);
    stats = CSMACDStats();
}

} // namespace DLL
