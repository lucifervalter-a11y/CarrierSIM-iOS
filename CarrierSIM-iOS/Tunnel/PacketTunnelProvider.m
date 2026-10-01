// Local-only loopback tunnel, adapted from LocalDevVPN / SideStore StosVPN.
// Original by Stossy11 and the SideStore Team; see Licenses/LocalDevVPN.txt.
// CarrierSIM adds strict packet/endpoint validation and lifecycle cancellation.
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <sys/socket.h>
#import <arpa/inet.h>

@interface PacketTunnelProvider : NEPacketTunnelProvider
@property (atomic) BOOL processingPackets;
@property (atomic) NSUInteger lifecycle;
@end

@implementation PacketTunnelProvider

- (void)startTunnelWithOptions:(NSDictionary<NSString *, NSObject *> *)options
             completionHandler:(void (^)(NSError * _Nullable))completionHandler {
    NSUInteger generation = self.lifecycle + 1;
    self.lifecycle = generation;
    self.processingPackets = NO;
    NEPacketTunnelNetworkSettings *settings = [[NEPacketTunnelNetworkSettings alloc]
                                               initWithTunnelRemoteAddress:@"10.7.0.1"];
    NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc] initWithAddresses:@[@"10.7.1.1"]
                                                      subnetMasks:@[@"255.255.255.255"]];
    // Only this synthetic peer is routed into this extension. Internet traffic
    // and DNS configuration retain the user's normal route and resolvers.
    ipv4.includedRoutes = @[[[NEIPv4Route alloc] initWithDestinationAddress:@"10.7.0.1"
                                                              subnetMask:@"255.255.255.255"]];
    ipv4.excludedRoutes = @[[NEIPv4Route defaultRoute]];
    settings.IPv4Settings = ipv4;
    settings.MTU = @1500;
    __weak PacketTunnelProvider *weakSelf = self;
    [self setTunnelNetworkSettings:settings completionHandler:^(NSError *error) {
        PacketTunnelProvider *strongSelf = weakSelf;
        if (!strongSelf || strongSelf.lifecycle != generation) {
            completionHandler([NSError errorWithDomain:@"CarrierSIM.Tunnel" code:NSUserCancelledError
                                               userInfo:@{NSLocalizedDescriptionKey: @"Запуск VPN отменён."}]);
            return;
        }
        if (error) { completionHandler(error); return; }
        strongSelf.processingPackets = YES;
        [strongSelf readNextPackets:generation];
        completionHandler(nil);
    }];
}

- (void)readNextPackets:(NSUInteger)generation {
    if (!self.processingPackets || generation != self.lifecycle) return;
    __weak PacketTunnelProvider *weakSelf = self;
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
        PacketTunnelProvider *strongSelf = weakSelf;
        if (!strongSelf || !strongSelf.processingPackets || generation != strongSelf.lifecycle) return;
        NSMutableArray<NSData *> *outgoing = [NSMutableArray arrayWithCapacity:packets.count];
        NSMutableArray<NSNumber *> *families = [NSMutableArray arrayWithCapacity:packets.count];
        const uint8_t expectedSource[4] = {10, 7, 1, 1};
        const uint8_t expectedDestination[4] = {10, 7, 0, 1};
        NSUInteger count = MIN(packets.count, protocols.count);
        for (NSUInteger i = 0; i < count; i++) {
            NSData *packet = packets[i];
            if (protocols[i].intValue != AF_INET || packet.length < 20) continue;
            const uint8_t *input = packet.bytes;
            NSUInteger headerLength = (input[0] & 0x0F) * 4;
            NSUInteger totalLength = ((NSUInteger)input[2] << 8) | input[3];
            if ((input[0] >> 4) != 4 || headerLength < 20 || headerLength > packet.length ||
                totalLength < headerLength || totalLength != packet.length ||
                memcmp(input + 12, expectedSource, 4) != 0 ||
                memcmp(input + 16, expectedDestination, 4) != 0) continue;
            NSMutableData *copy = [packet mutableCopy];
            uint8_t *output = copy.mutableBytes;
            // Swapping the two addresses preserves the IPv4 header checksum
            // and the TCP/UDP pseudoheader sum. memcpy avoids alignment traps.
            uint8_t source[4];
            memcpy(source, output + 12, 4);
            memcpy(output + 12, output + 16, 4);
            memcpy(output + 16, source, 4);
            [outgoing addObject:copy];
            [families addObject:@(AF_INET)];
        }
        if (outgoing.count && strongSelf.processingPackets && generation == strongSelf.lifecycle) {
            [strongSelf.packetFlow writePackets:outgoing withProtocols:families];
        }
        [strongSelf readNextPackets:generation];
    }];
}

- (void)stopTunnelWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    self.processingPackets = NO;
    self.lifecycle += 1;
    [self setTunnelNetworkSettings:nil completionHandler:^(NSError *error) { completionHandler(); }];
}

@end
