/*
 * Copyright (C) 2026 Velocity Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Netty-based UDP listener for detecting UDP flood attacks.
 * Reads the proxy host and port from velocity.toml.
 */
public class NettyUDPChannel {

    private final UDPFloodDetector detector;
    private NioEventLoopGroup group;
    private Channel channel;

    /**
     * Creates a new NettyUDPChannel with the specified detector.
     *
     * @param detector the UDP flood detector to use
     */
    public NettyUDPChannel(UDPFloodDetector detector) {
        this.detector = detector;
    }

    /**
     * Starts the UDP listener on the specified host and port.
     *
     * @param host the host to bind to
     * @param port the port to bind to
     * @throws InterruptedException if interrupted while binding
     */
    public void start(String host, int port) throws InterruptedException {
        group = new NioEventLoopGroup(2);

        Bootstrap bootstrap = new Bootstrap()
            .group(group)
            .channel(NioDatagramChannel.class)
            .option(io.netty.channel.ChannelOption.SO_BROADCAST, true)
            .handler(new ChannelInitializer<NioDatagramChannel>() {
                @Override
                protected void initChannel(NioDatagramChannel ch) {
                    ch.pipeline().addLast(new UDPPacketHandler(detector));
                }
            });

        channel = bootstrap.bind(host, port).sync().channel();
    }

    /**
     * Stops the UDP listener and shuts down the event loop group.
     */
    public void stop() {
        if (channel != null) {
            channel.close();
        }
        if (group != null) {
            group.shutdownGracefully();
        }
    }

    /**
     * Reads the proxy bind address from velocity.toml.
     *
     * @param configPath the path to velocity.toml
     * @return a String array with [host, port] or ["0.0.0.0", "25565"] as default
     */
    public static String[] readProxyAddressFromToml(String configPath) {
        Pattern bindPattern = Pattern.compile("bind\\s*=\\s*\"([^\"]+)\"");
        try (BufferedReader reader = new BufferedReader(new FileReader(configPath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                Matcher matcher = bindPattern.matcher(line);
                if (matcher.find()) {
                    String bind = matcher.group(1);
                    String[] parts = bind.split(":");
                    if (parts.length == 2) {
                        return new String[]{parts[0], parts[1]};
                    }
                }
            }
        } catch (IOException e) {
            // ignore
        }
        return new String[]{"0.0.0.0", "25565"};
    }

    /**
     * UDP packet handler that passes packets to the flood detector.
     */
    private static class UDPPacketHandler extends SimpleChannelInboundHandler<io.netty.channel.socket.DatagramPacket> {
        private final UDPFloodDetector detector;

        UDPPacketHandler(UDPFloodDetector detector) {
            this.detector = detector;
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, io.netty.channel.socket.DatagramPacket msg) {
            InetSocketAddress sender = msg.sender();
            if (sender != null) {
                String ip = sender.getAddress().getHostAddress();
                detector.handlePacket(ip);
                // If not blacklisted, packet is allowed (MC UDP queries handled elsewhere)
                // If blacklisted, packet is dropped (already handled in detector)
            }
        }
    }
}
