const Date = @This();
const std = @import("std");
const Io = std.Io;

/// RFC 2616 Section 3.3.1: HTTP-date
///
/// HTTP/1.1 uses RFC 1123 format:
///   Sun, 06 Nov 1994 08:49:37 GMT
///
/// RFC 2616 Section 14.18: Origin servers MUST include a Date header
/// in every response. The date MUST be in GMT.

const day_names = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/// Format a timestamp as RFC 1123 date string.
/// Returns a slice into the provided buffer.
///
/// RFC 2616 Section 3.3.1:
///   rfc1123-date = wkday "," SP date1 SP time SP "GMT"
///   date1        = 2DIGIT SP month SP 4DIGIT
///   time         = 2DIGIT ":" 2DIGIT ":" 2DIGIT
pub fn formatRfc1123(timestamp: i64, buf: *[29]u8) []const u8 {
    const epoch_secs: u64 = if (timestamp >= 0) @intCast(timestamp) else 0;
    const days_since_epoch = epoch_secs / 86400;
    const time_of_day = epoch_secs % 86400;

    const hours = time_of_day / 3600;
    const minutes = (time_of_day % 3600) / 60;
    const seconds = time_of_day % 60;

    // Day of week: Jan 1 1970 was a Thursday (4)
    const dow: usize = @intCast((days_since_epoch + 4) % 7);

    // Convert days since epoch to year/month/day
    const ymd = daysToYmd(days_since_epoch);

    // "Sun, 06 Nov 1994 08:49:37 GMT"
    const dn = day_names[dow];
    buf[0] = dn[0];
    buf[1] = dn[1];
    buf[2] = dn[2];
    buf[3] = ',';
    buf[4] = ' ';
    writeDecimal2(buf[5..7], ymd.day);
    buf[7] = ' ';
    const mn = month_names[ymd.month - 1];
    buf[8] = mn[0];
    buf[9] = mn[1];
    buf[10] = mn[2];
    buf[11] = ' ';
    writeDecimal4(buf[12..16], ymd.year);
    buf[16] = ' ';
    writeDecimal2(buf[17..19], @intCast(hours));
    buf[19] = ':';
    writeDecimal2(buf[20..22], @intCast(minutes));
    buf[22] = ':';
    writeDecimal2(buf[23..25], @intCast(seconds));
    buf[25] = ' ';
    buf[26] = 'G';
    buf[27] = 'M';
    buf[28] = 'T';

    return buf[0..29];
}

const YearMonthDay = struct {
    year: u16,
    month: u8,
    day: u8,
};

fn daysToYmd(days: u64) YearMonthDay {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    const z = days + 719468;
    const era = z / 146097;
    const doe = z - era * 146097;
    const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp = (5 * doy + 2) / 153;
    const d = doy - (153 * mp + 2) / 5 + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const year = if (m <= 2) y + 1 else y;

    return .{
        .year = @intCast(year),
        .month = @intCast(m),
        .day = @intCast(d),
    };
}

fn writeDecimal2(buf: *[2]u8, val: u8) void {
    buf[0] = '0' + val / 10;
    buf[1] = '0' + val % 10;
}

fn writeDecimal4(buf: *[4]u8, val: u16) void {
    buf[0] = '0' + @as(u8, @intCast(val / 1000));
    buf[1] = '0' + @as(u8, @intCast(val % 1000 / 100));
    buf[2] = '0' + @as(u8, @intCast(val % 100 / 10));
    buf[3] = '0' + @as(u8, @intCast(val % 10));
}

/// Get the current timestamp using the Io real (wall-clock) time.
pub fn now(io: Io) i64 {
    const timestamp = Io.Clock.real.now(io);
    return timestamp.toSeconds();
}

// --- Tests ---

const testing = std.testing;

// RFC 2616 Section 3.3.1: RFC 1123 date format
test "Date: format epoch" {
    var buf: [29]u8 = undefined;
    const result = formatRfc1123(0, &buf);
    try testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", result);
}

// RFC 2616 Section 3.3.1: Known date
test "Date: format known date" {
    // 1994-11-06 08:49:37 UTC = 784111777 epoch seconds
    var buf: [29]u8 = undefined;
    const result = formatRfc1123(784111777, &buf);
    try testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", result);
}

// RFC 2616 Section 3.3.1: Year 2000
test "Date: Y2K date" {
    // 2000-01-01 00:00:00 UTC = 946684800
    var buf: [29]u8 = undefined;
    const result = formatRfc1123(946684800, &buf);
    try testing.expectEqualStrings("Sat, 01 Jan 2000 00:00:00 GMT", result);
}

// RFC 2616 Section 3.3.1: Recent date
test "Date: 2024 date" {
    // 2024-03-15 12:30:45 UTC = 1710506245 (Friday)
    var buf: [29]u8 = undefined;
    const result = formatRfc1123(1710506245, &buf);
    try testing.expectEqualStrings("Fri, 15 Mar 2024 12:37:25 GMT", result);
}

// Edge case: end of day
test "Date: end of day" {
    // 1970-01-01 23:59:59 = 86399
    var buf: [29]u8 = undefined;
    const result = formatRfc1123(86399, &buf);
    try testing.expectEqualStrings("Thu, 01 Jan 1970 23:59:59 GMT", result);
}

// Edge case: leap year
test "Date: leap year date" {
    // 2000-02-29 00:00:00 UTC = 951782400
    var buf: [29]u8 = undefined;
    const result = formatRfc1123(951782400, &buf);
    try testing.expectEqualStrings("Tue, 29 Feb 2000 00:00:00 GMT", result);
}
