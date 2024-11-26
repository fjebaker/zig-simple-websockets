const std = @import("std");

const logger = std.log.scoped(.websockets);

const MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OpCode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

pub const Frame = struct {
    pub const Header = packed struct {
        len: u7,
        mask_set: bool,
        opcode: OpCode,
        reserved: u3 = 0,
        fin: bool,
    };

    header: Header,
    mask: [4]u8 = .{0} ** 4,
    payload: []const u8 = &.{},

    pub fn decode(self: Frame, allocator: std.mem.Allocator) ![]const u8 {
        const out = try allocator.alloc(u8, self.payload.len);
        errdefer allocator.free(out);

        const mask: [4]u8 = @bitCast(self.mask);
        for (self.payload, 0..) |d, i| {
            out[i] = d ^ mask[i % 4];
        }
        return out;
    }

    pub fn init(opcode: OpCode, payload: []const u8) Frame {
        const header: Header = .{
            .len = @intCast(payload.len),
            .mask_set = false,
            .opcode = opcode,
            .fin = true,
        };
        return .{
            .header = header,
            .payload = payload,
        };
    }

    pub fn write(self: Frame, stream: std.net.Stream) !void {
        var bytes: [2]u8 = @bitCast(self.header);
        // endian things
        std.mem.reverse(u8, &bytes);
        try stream.writeAll(&bytes);
        try stream.writeAll(self.payload);
    }
};

fn secWebSocketAcceptKey(allocator: std.mem.Allocator, key: []const u8) ![]const u8 {
    const k = try std.mem.concat(allocator, u8, &.{ key, MAGIC_STRING });
    defer allocator.free(k);

    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(k);
    const res = hasher.finalResult();

    var encoder = std.base64.Base64Encoder.init(
        std.base64.standard_alphabet_chars,
        '=',
    );

    const size = encoder.calcSize(res.len);

    const dest = try allocator.alloc(u8, size);
    errdefer allocator.free(dest);

    return encoder.encode(dest, &res);
}

test "secWebSocketAcceptKey" {
    const output = try secWebSocketAcceptKey(
        std.testing.allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
    );
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", output);
}

pub const State = struct {
    closed: bool = false,
};

pub const Request = struct {
    frame: Frame,
    stream: std.net.Stream,
    state: *State,

    pub fn reply(self: Request, opcode: OpCode, payload: []const u8) !void {
        try Frame.init(opcode, payload).write(self.stream);
    }

    pub fn pong(self: Request) !void {
        try Frame.init(.pong, self.frame.payload).write(self.stream);
    }

    pub fn close(self: Request) !void {
        try Frame.init(.close, self.frame.payload).write(self.stream);
        self.state.closed = true;
    }
};

pub fn WebsocketCallback(comptime T: type) type {
    return fn (T, Request) anyerror!void;
}

pub const WebSocket = struct {
    const Self = @This();
    allocator: std.mem.Allocator,
    buf: [128]u8 = undefined,
    big_buf: ?[]const u8 = null,
    stream: std.net.Stream,
    addr: std.net.Address,
    state: State = .{},

    pub fn init(
        self: *WebSocket,
        allocator: std.mem.Allocator,
        conn: std.net.Server.Connection,
    ) void {
        self.* = .{
            .allocator = allocator,
            .stream = conn.stream,
            .addr = conn.address,
        };
    }

    pub fn initCreate(
        allocator: std.mem.Allocator,
        conn: std.net.Server.Connection,
    ) !*Self {
        const self = try allocator.create(Self);
        init(self, allocator, conn);
        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.big_buf) |b| {
            self.allocator.free(b);
        }
        self.stream.close();
        self.* = undefined;
    }

    fn readHeader(self: *Self) !Frame.Header {
        var buf: [2]u8 = undefined;
        const size = try self.stream.readAll(&buf);
        std.debug.assert(buf.len == size);

        // bit ordering
        std.mem.reverse(u8, &buf);

        // reinterpret the header
        return std.mem.bytesToValue(Frame.Header, &buf);
    }

    pub fn readFrame(self: *Self) !Frame {
        const header = try self.readHeader();

        // read more header information?
        const len = if (header.len > 126) {
            return error.FrameOverSize;
        } else header.len;

        // read mask information?
        var mask: [4]u8 = .{0} ** 4;
        if (header.mask_set) {
            _ = try self.stream.readAll(&mask);
        }

        // read the payload into the static buffer
        _ = try self.stream.readAll(self.buf[0..len]);
        return .{
            .header = header,
            .payload = self.buf[0..len],
            .mask = mask,
        };
    }

    fn handle(
        self: *Self,
        ctx: anytype,
        comptime Callback: WebsocketCallback(@TypeOf(ctx)),
    ) void {
        defer self.state.closed = true;
        self.innerHandle(ctx, Callback) catch |err| {
            logger.err(
                "[{d}]: {!}",
                .{ self.addr.getPort(), err },
            );
        };
    }

    fn innerHandle(
        self: *Self,
        ctx: anytype,
        comptime Callback: WebsocketCallback(@TypeOf(ctx)),
    ) !void {
        logger.debug(
            "[{d}]: thread spawned",
            .{self.addr.getPort()},
        );
        while (true) {
            const f = try self.readFrame();
            logger.debug(
                "[{d}]: {any}",
                .{ self.addr.getPort(), f.header.opcode },
            );

            try Callback(
                ctx,
                .{
                    .frame = f,
                    .stream = self.stream,
                    .state = &self.state,
                },
            );

            if (self.state.closed) {
                break;
            }
        }
    }

    pub fn send(self: *Self, payload: []const u8) !void {
        logger.debug("Sending message", .{});
        try Frame.init(.text, payload).write(self.stream);
    }
};

pub const WebSocketServer = struct {
    pub const Options = struct {
        threads: u32 = 8,
    };
    allocator: std.mem.Allocator,
    pool: *std.Thread.Pool,
    sockets: std.AutoHashMap(u16, WebSocket), // port to websocket

    pub fn init(allocator: std.mem.Allocator, opts: Options) !WebSocketServer {
        const ptr = try allocator.create(std.Thread.Pool);
        errdefer allocator.destroy(ptr);
        try std.Thread.Pool.init(
            ptr,
            .{ .allocator = allocator, .n_jobs = opts.threads },
        );
        errdefer ptr.deinit();

        return .{
            .pool = ptr,
            .allocator = allocator,
            .sockets = std.AutoHashMap(u16, WebSocket).init(allocator),
        };
    }

    pub fn deinit(self: *WebSocketServer) void {
        self.pool.deinit();
        for (self.sockets.items) |*sock| {
            sock.deinit();
        }
        self.sockets.deinit();
        self.* = undefined;
    }

    pub fn upgradeConnection(
        self: *WebSocketServer,
        ctx: anytype,
        comptime f: WebsocketCallback(@TypeOf(ctx)),
        req: *std.http.Server.Request,
        key: []const u8,
    ) !*WebSocket {
        const server_key = try secWebSocketAcceptKey(self.allocator, key);
        defer self.allocator.free(server_key);

        try req.respond("", .{
            .extra_headers = &.{
                .{ .name = "Upgrade", .value = "websocket" },
                .{ .name = "Connection", .value = "Upgrade" },
                .{ .name = "Sec-WebSocket-Accept", .value = server_key },
            },
            .status = .switching_protocols,
        });

        const conn = req.server.connection;
        const port = conn.address.getPort();

        var sock: WebSocket = undefined;
        WebSocket.init(&sock, self.allocator, conn);
        errdefer sock.deinit();
        if (self.sockets.contains(port)) {
            self.sockets.getPtr(port).?.deinit();
        }
        try self.sockets.put(port, sock);
        const ptr = self.sockets.getPtr(port).?;

        try self.pool.spawn(WebSocket.handle, .{ ptr, ctx, f });
        return ptr;
    }

    fn cleanup(self: *WebSocketServer) void {
        var itt = self.sockets.iterator();
        while (itt.next()) |item| {
            if (item.value_ptr.state.closed) {
                logger.debug("cleaning up [{d}]", .{item.key_ptr.*});
                item.value_ptr.deinit();
                _ = self.sockets.remove(item.key_ptr.*);
                // restart the iteration
                itt = self.sockets.iterator();
            }
        }
    }

    pub fn broadcast(self: *WebSocketServer, payload: []const u8) !void {
        self.cleanup();

        var itt = self.sockets.iterator();
        while (itt.next()) |item| {
            item.value_ptr.send(payload) catch |err| {
                logger.warn(
                    "could not message [{d}] {!}",
                    .{ item.key_ptr.*, err },
                );
            };
        }
    }
};
