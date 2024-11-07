#include <iostream>
#include <unordered_map>
#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstdint>   
#include <stdexcept>
#include <iomanip>
#include <set>

const size_t MAX_CACHE_SIZE = 2;

// Struct to represent an IP address
struct IPAddress {
    uint32_t address; // 32-bit encoded IP address

    IPAddress() : address(0) {}

    explicit IPAddress(const std::string& addr) {
        address = encodeIPAddress(addr);
    }

    explicit IPAddress(uint32_t addr) : address(addr) {}

    // Function to encode a dotted-decimal IP string into a 32-bit integer
    uint32_t encodeIPAddress(const std::string& addr) {
        uint32_t result = 0;
        std::istringstream iss(addr);
        std::string token;
        int shift = 24; // Start with the highest byte
        while (std::getline(iss, token, '.')) {
            result |= (std::stoi(token) << shift);
            shift -= 8;
        }
        return result;
    }

    // Function to decode a 32-bit integer back into a dotted-decimal IP string
    std::string decodeIPAddress() const {
        std::ostringstream oss;
        for (int i = 3; i >= 0; --i) {
            oss << ((address >> (i * 8)) & 0xFF);
            if (i != 0) oss << ".";
        }
        return oss.str();
    }

    // Display the IP address in human-readable form
    friend std::ostream& operator<<(std::ostream& os, const IPAddress& ip) {
        os << ip.decodeIPAddress();
        return os;
    }

    // Equality operator for unordered_map to use IPAddress as a key
    bool operator==(const IPAddress& other) const {
        return address == other.address;
    }

    bool operator!=(const IPAddress& other) const {
        return !(*this == other);
    }
};

// Specialization of std::hash for IPAddress
namespace std {
    template <>
    struct hash<IPAddress> {
        std::size_t operator()(const IPAddress& ip) const noexcept {
            return std::hash<uint32_t>()(ip.address);
        }
    };
}

// Struct to represent a MAC address
struct MACAddress {
    uint64_t address; // 48-bit MAC address stored in a 64-bit integer

    MACAddress() : address(0) {}

    // Constructor to take a string and convert it to a 48-bit MAC address
    explicit MACAddress(const std::string& addr) {
        address = encodeMACAddress(addr);
    }

    // Constructor to take a 48-bit integer directly
    explicit MACAddress(uint64_t addr) : address(addr) {}

    // Function to encode a MAC address string into a 48-bit integer
    uint64_t encodeMACAddress(const std::string& addr) {
        uint64_t result = 0;
        std::istringstream iss(addr);
        std::string byte;
        int shift = 40; // Start with the highest byte (6 bytes total, so 40 bits)

        while (std::getline(iss, byte, ':')) {
            result |= (std::stoul(byte, nullptr, 16) << shift);
            shift -= 8;
        }
        return result;
    }

    // Function to decode a 48-bit integer back into a MAC address string
    std::string decodeMACAddress() const {
        std::ostringstream oss;
        for (int i = 5; i >= 0; --i) { // 6 bytes in total
            oss << std::hex << std::setw(2) << std::setfill('0') << ((address >> (i * 8)) & 0xFF);
            if (i != 0) oss << ":";
        }
        return oss.str();
    }

    // Display the MAC address in human-readable form
    friend std::ostream& operator<<(std::ostream& os, const MACAddress& mac) {
        os << mac.decodeMACAddress();
        return os;
    }

    bool operator==(const MACAddress& other) const {
        return address == other.address;
    }

    bool operator!=(const MACAddress& other) const {
        return address != other.address;
    }

    bool operator<(const MACAddress& other) const {
        return address < other.address;
    }
};

// Specialization of std::hash for MACAddress
namespace std {
    template <>
    struct hash<MACAddress> {
        std::size_t operator()(const MACAddress& mac) const noexcept {
            return std::hash<uint64_t>()(mac.address);
        }
    };
}

// Struct to represent an ARP entry
struct ARPEntry {
    IPAddress ip;
    MACAddress mac;

    ARPEntry() = default;
    ARPEntry(const IPAddress& ipAddr, const MACAddress& macAddr)
        : ip(ipAddr), mac(macAddr) {}
};

struct CacheEntry {
    ARPEntry arpEntry;
    uint64_t timestamp; // Last access timestamp

    CacheEntry(const ARPEntry& _arpEntry = ARPEntry(), uint64_t _timestamp = 0)
        : arpEntry(_arpEntry), timestamp(_timestamp) {}
};

class LRUCache {
public:
    LRUCache(size_t capacity) : cap(capacity), cacheAccessCount(0) {}

    MACAddress get(const IPAddress& ip) {
        if (cache.find(ip) != cache.end()) {
            // Update the timestamp
            updateTimestamp(ip);
            return cache[ip].arpEntry.mac;
        }
        return MACAddress(); // Return an empty MACAddress if not found
    }

    void put(const ARPEntry& arpEntry) {
        const IPAddress& ip = arpEntry.ip;

        if (cache.find(ip) != cache.end()) {
            // Update existing entry
            updateTimestamp(ip);
            cache[ip].arpEntry.mac = arpEntry.mac;
        } else {
            if (cache.size() == cap) {
                // Evict the LRU entry
                evict();
            }
            // Insert the new entry
            cacheAccessCount++;
            CacheEntry newEntry(arpEntry, cacheAccessCount);
            cache[ip] = newEntry;
            timestampMap[cacheAccessCount] = ip;
        }
    }

    void display() const {
        for (const auto& entry : cache) {
            std::cout << entry.second.arpEntry.ip << " -> " << entry.second.arpEntry.mac 
                      << " (timestamp: " << entry.second.timestamp << ")\n";
        }
    }

    const std::unordered_map<IPAddress, CacheEntry>& getCache() const {
        return cache;
    }

private:
    size_t cap;
    uint64_t cacheAccessCount; // Global iterator for timestamps
    std::unordered_map<IPAddress, CacheEntry> cache; // Quick access by IP
    std::map<uint64_t, IPAddress> timestampMap; // Ordered map by timestamp

    void updateTimestamp(const IPAddress& ip) {
        // Remove the old timestamp entry
        timestampMap.erase(cache[ip].timestamp);

        // Update the timestamp to the current iterator value
        cacheAccessCount++;
        cache[ip].timestamp = cacheAccessCount;

        // Insert the new timestamp entry
        timestampMap[cacheAccessCount] = ip;
    }

    void evict() {
        // The first entry in the timestamp map is the oldest
        auto lru = timestampMap.begin();
        IPAddress lruIP = lru->second;

        // Remove it from both maps
        cache.erase(lruIP);
        timestampMap.erase(lru);

        std::cout << "Evicting LRU IP: " << lruIP << "\n";
    }
};

// Struct to represent an ARP packet
struct ARPPacket {
    IPAddress sourceIP;
    MACAddress sourceMAC;
    IPAddress targetIP;
    MACAddress targetMAC;

    ARPPacket(const IPAddress& srcIP, const MACAddress& srcMAC,
              const IPAddress& tgtIP, const MACAddress& tgtMAC)
        : sourceIP(srcIP), sourceMAC(srcMAC), targetIP(tgtIP), targetMAC(tgtMAC) {}
};

// ARPEntry operator<<
std::ostream& operator<<(std::ostream& os, const ARPEntry& entry) {
    os << "IP: " << entry.ip << ", MAC: " << entry.mac;
    return os;
}

// ARPPacket operator<<
std::ostream& operator<<(std::ostream& os, const ARPPacket& packet) {
    os << "Source IP: " << packet.sourceIP << ", Source MAC: " << packet.sourceMAC
       << ", Target IP: " << packet.targetIP << ", Target MAC: " << packet.targetMAC;
    return os;
}

// Structure to represent a Computer with its ARP cache
class Computer {
    IPAddress ipAddress;
    MACAddress macAddress;
    LRUCache arpCache;
    std::string cacheFileName;
    std::string logFileName;

public:
    Computer() : ipAddress(0), macAddress(0), arpCache(MAX_CACHE_SIZE) {};

    Computer(const IPAddress& ip, const MACAddress& mac, size_t cacheSize)
        : ipAddress(ip), macAddress(mac), arpCache(cacheSize) {
        std::string ipDotted = ip.decodeIPAddress();
        std::replace(ipDotted.begin(), ipDotted.end(), '.', '_'); // Replace dots with underscores
        cacheFileName = "data/cache_" + ipDotted + ".bin";
        logFileName = "logs/log_" + ipDotted + ".log";

        loadARPCache();
    }

    // Getter for IP address
    IPAddress getIPAddress() const {
        return ipAddress;
    }

    // Getter for MAC address
    MACAddress getMACAddress() const {
        return macAddress;
    }

    void saveARPCache() const {
        std::ofstream outFile(cacheFileName, std::ios::binary);
        if (outFile.is_open()) {
            std::cout << "Saving ARP cache to " << cacheFileName << std::endl;
            const auto& cacheMap = arpCache.getCache(); 

            for (const auto& entry : cacheMap) {
                std::cout << "Saving: " << entry.first.decodeIPAddress() << " -> " << entry.second.arpEntry.mac.decodeMACAddress() << std::endl;

                outFile.write(reinterpret_cast<const char*>(&entry.first.address), sizeof(entry.first.address));
                
                uint64_t macAddress = entry.second.arpEntry.mac.address & 0xFFFFFFFFFFFF;
                outFile.write(reinterpret_cast<const char*>(&macAddress), 6); 
            }

            outFile.close();
        } else {
            std::cerr << "Failed to open file for saving: " << cacheFileName << std::endl;
        }
    }

    void loadARPCache() {
        std::ifstream inFile(cacheFileName, std::ios::binary);
        if (inFile.is_open()) {
            std::cout << "Loading ARP cache from " << cacheFileName << std::endl;
            while (inFile) {
                ARPEntry entry;
                inFile.read(reinterpret_cast<char*>(&entry.ip.address), sizeof(entry.ip.address));
                if (inFile.gcount() != sizeof(entry.ip.address)) break;

                uint64_t macAddress = 0;
                inFile.read(reinterpret_cast<char*>(&macAddress), 6);
                if (inFile.gcount() != 6) break;
                entry.mac = MACAddress(macAddress & 0xFFFFFFFFFFFF);

                std::cout << "Loaded: " << entry.ip.decodeIPAddress() << " -> " << entry.mac.decodeMACAddress() << std::endl;

                arpCache.put(entry);
            }
            inFile.close();
        } else {
            std::cerr << "Failed to open file for loading: " << cacheFileName << std::endl;
        }
    }


    MACAddress replyToArpPacket(const ARPPacket& packet) {
        IPAddress targetIP = packet.targetIP;

        // Handle ARP spoofing detection
        if (handleArpSpoofing(packet.sourceIP, packet.sourceMAC)) {
            return MACAddress(0); // If spoofing is detected, return an empty MAC address
        }

        // If no spoofing is detected, respond with own MAC address if IP matches
        if (ipAddress == targetIP) {
            updateARPCache(targetIP, packet.targetMAC);
            return macAddress; // Respond with own MAC address if IP matches
        }

        return MACAddress(0); // Return an empty MACAddress if IP doesn't match
    }

    MACAddress resolveMAC(const IPAddress& targetIP) {
        MACAddress mac = arpCache.get(targetIP);
        if (mac.address != 0) {
            return mac;
        } else {
            return MACAddress();  // Return an empty MACAddress
        }
    }

    bool handleArpSpoofing(const IPAddress& ip_of_source, const MACAddress& mac_of_source) {
        MACAddress existingMAC = arpCache.get(ip_of_source);
        if (existingMAC.address != 0 && existingMAC != mac_of_source) {
            // Detected ARP spoofing attempt
            std::cerr << "Suspicious ARP reply detected! IP " << ip_of_source
                      << " was previously resolved to MAC " << existingMAC
                      << " but now resolves to MAC " << mac_of_source << std::endl;
            logSuspiciousActivity(ip_of_source, existingMAC, mac_of_source);
            // Reject suspicious ip addr
            return true;
        }
        return false;
    }

    void logSuspiciousActivity(const IPAddress& targetIP, const MACAddress& oldMAC, const MACAddress& newMAC) {
        std::ofstream logFile(logFileName, std::ios::app); // Append mode
        if (logFile.is_open()) {
            logFile << "Suspicious ARP Reply Detected! Target IP: " << targetIP.decodeIPAddress()
                    << " was previously mapped to MAC: " << oldMAC.decodeMACAddress()
                    << " but now maps to MAC: " << newMAC.decodeMACAddress() << std::endl;
            logFile.close();
        } else {
            std::cerr << "Unable to open log file for suspicious activity: " << logFileName << std::endl;
        }
    }

    void updateARPCache(const IPAddress& targetIP, const MACAddress& targetMAC) {
        std::cout << "Updating ARP cache in computer " << ipAddress << ": " << targetIP << " -> " << targetMAC << std::endl;
        arpCache.put(ARPEntry(targetIP, targetMAC));
        saveARPCache();
    }

    void displayARPCache() const {
        std::cout << "\nARP Cache for " << ipAddress << ":\n";
        std::cout << "IP Address\t\tMAC Address\n";
        std::cout << "----------------------------------------\n";
        arpCache.display();
    }
};


// Class to manage the network arena (connected computers)
class NetworkArena {
private:
    std::unordered_map<IPAddress, Computer> computers; // Maps IP to Computer
    std::set<MACAddress> usedMacAddresses;
    const std::string persistenceFile = "data/network_persistence.bin";


    MACAddress generateUniqueRandomMACAddress() {
        MACAddress newMac;
        do {
            newMac = generateRandomMACAddress(); // Generate a random MAC address
        } while (usedMacAddresses.find(newMac) != usedMacAddresses.end()); // Repeat if the MAC is not unique

        usedMacAddresses.insert(newMac); // Add the new MAC to the set of used MACs
        return newMac;
    }
    // Generate a random MAC address
    MACAddress generateRandomMACAddress() const {
        const char hexDigits[] = "0123456789ABCDEF";
        std::string macAddress;
        for (int i = 0; i < 6; ++i) {
            macAddress += hexDigits[rand() % 16];
            macAddress += hexDigits[rand() % 16];
            if (i != 5) macAddress += ":";
        }
        return MACAddress(macAddress);
    }

    // Save the network state to a file
    void saveNetworkState() const {
        std::ofstream outFile(persistenceFile, std::ios::binary);
        if (outFile.is_open()) {
            for (const auto& [ip, computer] : computers) {
                // Write the IP address (32 bits)
                outFile.write(reinterpret_cast<const char*>(&ip.address), sizeof(ip.address));

                // Write the MAC address (48 bits, stored in a 64-bit integer but using only the lower 48 bits)
                uint64_t macAddress = computer.getMACAddress().address & 0xFFFFFFFFFFFF; // Mask to ensure only the lower 48 bits are used
                outFile.write(reinterpret_cast<const char*>(&macAddress), 6); // Write only 6 bytes (48 bits) of the MAC address
            }
            outFile.close();
        } else {
            std::cerr << "Error: Could not open persistence file: " << persistenceFile << std::endl;
        }
    }



    // Load the network state from a file
    void loadNetworkState() {
        std::ifstream inFile(persistenceFile, std::ios::binary);
        if (inFile.is_open()) {
            while (inFile) {
                uint32_t ipAddressValue;
                uint64_t macAddressValue = 0;

                // Read the IP address (32 bits)
                inFile.read(reinterpret_cast<char*>(&ipAddressValue), sizeof(ipAddressValue));
                if (inFile.gcount() != sizeof(ipAddressValue)) break; // End of file or read error

                // Read the MAC address (48 bits)
                inFile.read(reinterpret_cast<char*>(&macAddressValue), 6); // Read only 6 bytes (48 bits)
                if (inFile.gcount() != 6) break; // End of file or read error

                IPAddress ipAddress(ipAddressValue);
                MACAddress macAddress(macAddressValue);

                usedMacAddresses.insert(macAddress);
                computers[ipAddress] = Computer(ipAddress, macAddress, MAX_CACHE_SIZE);
            }
            inFile.close();
        } else {
            std::cerr << "Error: Could not open persistence file: " << persistenceFile << std::endl;
        }
    }



public:
    // Constructor to load the network state
    NetworkArena() {
        srand(static_cast<unsigned>(time(nullptr))); // Seed for random MAC generation
        loadNetworkState();
    }

    ~NetworkArena() {
        for (auto& [ip, computer] : computers) {
            computer.saveARPCache(); // Save each computer's ARP cache
        }
    }

    // Add a computer to the network
    void addComputer(const IPAddress& ipAddress) {
        if (computers.find(ipAddress) != computers.end()) {
            std::cout << "Computer with IP " << ipAddress << " already exists in the network!\n";
            return;
        }
        MACAddress macAddress = generateUniqueRandomMACAddress();
        computers[ipAddress] = Computer(ipAddress, macAddress, MAX_CACHE_SIZE);
        saveNetworkState();
        std::cout << "Computer with IP " << ipAddress << " and MAC " << macAddress << " added to the network.\n";
    }

    // Remove a computer from the network
    void removeComputer(const IPAddress& ipAddress) {
        if (computers.erase(ipAddress)) {
            std::cout << "Computer with IP " << ipAddress << " removed from the network.\n";
            saveNetworkState();
        } else {
            std::cout << "No computer with IP " << ipAddress << " found in the network.\n";
        }
    }

    // Get a reference to a computer by IP address
    Computer* getComputer(const IPAddress& ipAddress) {
        if (computers.find(ipAddress) != computers.end()) {
            return &computers[ipAddress];
        }
        return nullptr;
    }

    std::unordered_map<IPAddress, Computer>& getComputers() {
        return computers;
    }

    // Display all computers in the network
    void displayNetwork() const {
        std::cout << "\nCurrent Network Computers:\n";
        std::cout << "IP Address\t\tMAC Address\n";
        std::cout << "----------------------------------------\n";
        for (const auto& [ip, computer] : computers) {
            std::cout << ip << "\t\t" << computer.getMACAddress() << "\n";
        }
    }
};

// Class to handle network communication (ARP packets)
class Network {
private:
    NetworkArena& arena;

public:
    Network(NetworkArena& arena) : arena(arena) {}

    // Process an ARP packet
    void processArpPacket(const ARPPacket& packet) {
        IPAddress sourceIP = packet.sourceIP;
        IPAddress targetIP = packet.targetIP;

        Computer* sourceComputer = arena.getComputer(sourceIP);
        Computer* targetComputer = arena.getComputer(targetIP);

        if (!sourceComputer) {
            std::cout << "Source computer with IP " << sourceIP << " does not exist in the network!\n";
            return;
        }

        if (!targetComputer) {
            std::cout << "Target computer with IP " << targetIP << " does not exist in the network!\n";
            return;
        }

        // First, try to resolve using the source computer's cache
        MACAddress targetMAC = sourceComputer->resolveMAC(targetIP);

        if (targetMAC.address == 0) { // Cache miss, send ARP request to all computers in the network
            std::cout << "Broadcasting ARP Request: " << packet << "\n";

            bool responseReceived = false;
            for (auto& [ip, computer] : arena.getComputers()) {
                if (ip != sourceIP) { // Do not send to the source computer itself
                    targetMAC = computer.replyToArpPacket(packet);
                    if (targetMAC.address != 0) { // If a valid response is received
                        responseReceived = true;
                        break;
                    }
                }
            }

            if (responseReceived) { // If a valid response is received and no spoofing was detected
                std::cout << "ARP Response received: " << targetIP << " is at MAC " << targetMAC << "\n";
            } else {
                std::cout << "ARP Request for " << targetIP << " timed out. No response received.\n";
            }
        } else {
            std::cout << "ARP Cache Hit: " << targetIP << " is at MAC " << targetMAC << "\n";
        }
    }

};

enum CommandType {
    add_computer,
    remove_computer,
    arp_packet,
    arp_raw,
    show_network,
    show_arp_cache,
    exit_simulation,
    unknown
};

CommandType parseCommand(const std::string& cmd) {
    if (cmd == "add_computer") return add_computer;
    if (cmd == "remove_computer") return remove_computer;
    if (cmd == "arp_packet") return arp_packet;
    if (cmd == "arp_raw") return arp_raw;
    if (cmd == "show_network") return show_network;
    if (cmd == "show_arp_cache") return show_arp_cache;
    if (cmd == "exit") return exit_simulation;
    return unknown;
}

std::string getFullIPAddress(const std::string& lastOctetStr) {
    try {
        int lastOctet = std::stoi(lastOctetStr); // Convert the input to an integer

        // Check if the value is within the valid range for an IP octet (1-255)
        if (lastOctet < 1 || lastOctet > 255) {
            throw std::out_of_range("IP addr out of range for Class C network (ensure it lies between 1 and 255)");
        }

        // Construct the full IP address with the prefix "192.168.1."
        std::string fullIPAddress = "192.168.1." + std::to_string(lastOctet);
        return fullIPAddress;
    } catch (const std::invalid_argument&) {
        throw std::invalid_argument("IP addr NaN");
    } catch (const std::out_of_range&) {
        throw std::out_of_range("IP addr out of range for Class C network (ensure it lies between 1 and 255)");
    }
}

void commandLoop(NetworkArena& arena, Network& network) {
    std::string command;

    while (true) {
        std::cout << "arp_simulation> ";
        std::getline(std::cin, command);

        std::istringstream iss(command);
        std::string cmd;
        iss >> cmd;

        CommandType commandType = parseCommand(cmd);

        switch (commandType) {
            case add_computer: {
                std::string ipAddressStrLastOctet;
                iss >> ipAddressStrLastOctet;
                try {
                    // Validate the last octet and construct the full IP address
                    std::string fullIPAddressStr = getFullIPAddress(ipAddressStrLastOctet);

                    // Pass the full IP address to the IPAddress constructor
                    IPAddress ipAddress(fullIPAddressStr);
                    
                    // Add the computer to the network
                    arena.addComputer(ipAddress);
                } catch (const std::exception& e) {
                    std::cerr << "parser error: " << e.what() << std::endl;
                }
                break;
            }
            case remove_computer: {
                std::string ipAddressStrLastOctet;
                iss >> ipAddressStrLastOctet;
                try {
                    // Validate the last octet and construct the full IP address
                    std::string fullIPAddressStr = getFullIPAddress(ipAddressStrLastOctet);

                    // Pass the full IP address to the IPAddress constructor
                    IPAddress ipAddress(fullIPAddressStr);
                    
                    // Remove the computer from the network
                    arena.removeComputer(ipAddress);
                } catch (const std::exception& e) {
                    std::cerr << "parser error: " << e.what() << std::endl;
                }
                break;
            }
            case arp_packet: {
                std::string sourceIPStrLastOctet, targetIPStrLastOctet;
                iss >> sourceIPStrLastOctet >> targetIPStrLastOctet;
                
                try {
                    // Construct the full IP addresses
                    std::string fullSourceIPStr = getFullIPAddress(sourceIPStrLastOctet);
                    std::string fullTargetIPStr = getFullIPAddress(targetIPStrLastOctet);

                    // Convert strings to IP address objects
                    IPAddress sourceIP(fullSourceIPStr);
                    IPAddress targetIP(fullTargetIPStr);

                    // Use getComputer to retrieve the source computer
                    Computer* sourceComputer = arena.getComputer(sourceIP);
                    if (!sourceComputer) {
                        std::cerr << "Source computer with IP " << sourceIP << " not found in the network.\n";
                        break;
                    }
                    MACAddress sourceMAC = sourceComputer->getMACAddress();

                    // Create the ARP packet with the retrieved source MAC
                    ARPPacket packet(sourceIP, sourceMAC, targetIP, MACAddress(0));

                    // Process the ARP packet
                    network.processArpPacket(packet);

                } catch (const std::exception& e) {
                    std::cerr << "parser error: " << e.what() << std::endl;
                }
                break;
            }
            case arp_raw: {
                std::string sourceIPStrLastOctet, targetIPStrLastOctet;
                std::string sourceMACStr;
                iss >> sourceIPStrLastOctet >> sourceMACStr >> targetIPStrLastOctet;

                try {
                    std::string fullSourceIPStr = getFullIPAddress(sourceIPStrLastOctet);
                    std::string fullTargetIPStr = getFullIPAddress(targetIPStrLastOctet);
                    IPAddress sourceIP(fullSourceIPStr);
                    MACAddress sourceMAC(sourceMACStr);
                    IPAddress targetIP(fullTargetIPStr);

                    // Create a custom ARP packet
                    ARPPacket packet(sourceIP, sourceMAC, targetIP, MACAddress(0));

                    Computer* sourceComputer = arena.getComputer(sourceIP);
                    if (sourceComputer) {
                        network.processArpPacket(packet);
                    } else {
                        std::cerr << "Source computer with IP " << sourceIP << " does not exist.\n";
                    }
                } catch (const std::exception& e) {
                    std::cerr << "parser error: " << e.what() << std::endl;
                }
                break;
            }
            case show_network: {
                arena.displayNetwork();
                break;
            }
            case show_arp_cache: {
                std::string ipAddressStrLastOctet;
                iss >> ipAddressStrLastOctet;
                try {
                    // Validate the last octet and construct the full IP address
                    std::string fullIPAddressStr = getFullIPAddress(ipAddressStrLastOctet);

                    // Pass the full IP address to the IPAddress constructor
                    IPAddress ipAddress(fullIPAddressStr);

                    // Show the ARP cache for the specific computer
                    Computer* computer = arena.getComputer(ipAddress);
                    if (computer) {
                        computer->displayARPCache();
                    } else {
                        std::cout << "Computer with IP " << fullIPAddressStr << " does not exist in the network!\n";
                    }
                } catch (const std::exception& e) {
                    std::cerr << "parser error: " << e.what() << std::endl;
                }
                break;
            }
            case exit_simulation: {
                return;
            }
            case unknown:
            default:
                std::cout << "unknown command at token: \"" << cmd << "\"\n";
                break;
        }
    }
}

int main() {
    NetworkArena arena;
    Network network(arena);    
    // Start the command loop to process user input
    commandLoop(arena, network);

    return 0;
}
